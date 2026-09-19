"""External adapters for Events.

- EventPublisher       — 9 domain event types, batched at the API maximum of 10.
- S3Storage            — presigned-URL broker, fails closed.
- ContributionsClient  — point values, parallel + timeout-bounded + cached.
- TeamsProvider        — interface + stub adapter (D1).
- SettingsCache        — Teams enablement, fails closed to disabled.

All external calls fail closed (RESILIENCY-10, SECURITY-15). Presigned URLs are
minted per request and NEVER stored: a URL signed with the Lambda role's
temporary credentials dies when the session token expires regardless of its
stated expiry, and a stored URL cannot be revoked. Both were learned the hard
way during the Settings file-share rework and are avoided here by construction.
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib import error as urlerror
from urllib import request as urlrequest

from _conventions.envelope import build_event
from _conventions.errors import AppError
from _conventions.logger import get_logger, log

_logger = get_logger("events")

_MAX_PRESIGN_SECONDS = 7 * 24 * 3600  # SigV4 hard ceiling
_PUT_EVENTS_BATCH = 10                # EventBridge PutEvents maximum


class EventPublisher:
    """Post-commit, best-effort publication. Never raises to the caller: the
    primary write has already committed, so failing the request would report a
    false negative for work that actually happened."""

    def __init__(self, client=None, bus: str | None = None):
        self._c = client
        self.bus = bus or os.environ.get("EVENT_BUS_NAME", "")
        self.published: list[dict] = []  # visible to tests without a fake

    @property
    def client(self):
        if self._c is None:
            import boto3
            self._c = boto3.client("events")
        return self._c

    def publish(self, event_type: str, data: dict, *, correlation_id: str | None = None) -> None:
        self.publish_many([(event_type, data)], correlation_id=correlation_id)

    def publish_many(self, items: list[tuple[str, dict]], *,
                     correlation_id: str | None = None) -> None:
        """Chunked at 10 (N4). One `AttendanceRecorded` per attendee means a
        180-person event publishes 18 batches, which is why this is chunked
        rather than looped one-by-one."""
        entries = []
        for event_type, data in items:
            envelope = build_event(event_type, "events", data, correlation_id=correlation_id)
            self.published.append(envelope)
            entries.append({
                "EventBusName": self.bus,
                "Source": "events",
                "DetailType": event_type,
                "Detail": json.dumps(envelope, default=str),
            })
        if not self.bus:
            log(_logger, 20, "events (no bus configured)", count=len(entries))
            return
        for start in range(0, len(entries), _PUT_EVENTS_BATCH):
            chunk = entries[start:start + _PUT_EVENTS_BATCH]
            try:
                self.client.put_events(Entries=chunk)
            except Exception:  # noqa: BLE001 — publish failure must not fail a committed write
                log(_logger, 40, "event publish failed (write already committed)",
                    count=len(chunk))


class S3Storage:
    """Presigned-URL broker over the shared community bucket, scoped to the
    `events/` prefix by IAM (SECURITY-06)."""

    def __init__(self, client=None, bucket: str | None = None):
        self._c = client
        self.bucket = bucket or os.environ.get("FILE_SHARE_BUCKET", "")

    @property
    def client(self):
        if self._c is None:
            import boto3
            from botocore.config import Config
            # signature_version MUST be explicit: the default presign is legacy
            # SigV2, which signs Content-Type into the string-to-sign (as empty,
            # since none is passed at mint time). Browsers always send the
            # file's Content-Type on a fetch PUT of a File body, so every
            # browser upload against a SigV2 URL fails 403 SignatureDoesNotMatch
            # — found live 2026-08-07 (UGL 40MB PPT materials upload; size was a
            # red herring). curl -T sends no Content-Type, which is why every
            # curl-based check passed. SigV4 validates only the headers it
            # signed (host), so the browser's Content-Type is accepted.
            self._c = boto3.client("s3", config=Config(signature_version="s3v4"))
        return self._c

    def _require_bucket(self) -> None:
        if not self.bucket:
            raise AppError(code="NOT_CONFIGURED",
                           message="File storage is not configured.", status=503)

    def presign_put(self, key: str, *, expires_in: int,
                    content_length: int | None = None) -> str:
        self._require_bucket()
        params = {"Bucket": self.bucket, "Key": key}
        if content_length:
            # Under SigV4, ContentLength is a SIGNED header: the upload's actual
            # Content-Length must equal this value EXACTLY or S3 rejects it with
            # 403 SignatureDoesNotMatch. Callers pass the caller-declared exact
            # size, never a ceiling. This turns the pre-mint size check into a
            # real enforcement — a client cannot declare 1 MB and stream 5 GB.
            # (Under the SigV2 URLs this service originally minted, the param
            # was silently ignored, which is how a ceiling was once passed here
            # without anything failing.)
            params["ContentLength"] = content_length
        try:
            return self.client.generate_presigned_url(
                "put_object", Params=params, ExpiresIn=min(expires_in, _MAX_PRESIGN_SECONDS))
        except Exception as err:  # noqa: BLE001 — fail closed, no partial upload target
            log(_logger, 40, "presign_put failed", key=key)
            raise AppError(code="STORAGE_ERROR",
                           message="Unable to create the upload link.", status=502) from err

    def presign_get(self, key: str, *, expires_in: int) -> str:
        self._require_bucket()
        try:
            return self.client.generate_presigned_url(
                "get_object", Params={"Bucket": self.bucket, "Key": key},
                ExpiresIn=min(expires_in, _MAX_PRESIGN_SECONDS))
        except Exception as err:  # noqa: BLE001
            log(_logger, 40, "presign_get failed", key=key)
            raise AppError(code="STORAGE_ERROR",
                           message="Unable to create the download link.", status=502) from err

    def object_exists(self, key: str) -> bool:
        return self.head_object_size(key) is not None

    def head_object_size(self, key: str) -> int | None:
        """Size of a stored object, or None if it does not exist (or storage is
        unreachable — indistinguishable here, and both mean 'do not stamp').

        This is the confirm-time half of the upload race (BR-M6): when S3's
        Object Created event beats the confirm POST, the consumer finds no row
        to stamp and drops the event — the confirm step must then discover the
        already-landed object itself, or the material stays undownloadable
        forever (found live 2026-08-07). The size reported here is S3's own,
        never the client's claim, so the trust model is unchanged."""
        if not self.bucket:
            return None
        try:
            head = self.client.head_object(Bucket=self.bucket, Key=key)
            return int(head.get("ContentLength") or 0)
        except Exception:  # noqa: BLE001 — missing/404 -> not there
            return None

    def delete_object(self, key: str) -> None:
        """Fails closed: the caller must NOT delete the metadata row if this
        raises, or the object would be orphaned with no owning record (BR-M7)."""
        self._require_bucket()
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except Exception as err:  # noqa: BLE001
            log(_logger, 40, "delete_object failed", key=key)
            raise AppError(code="STORAGE_ERROR",
                           message="Unable to delete the stored file.", status=502) from err

    def list_folder(self, prefix: str) -> list[dict]:
        """Paginated — a single ListObjectsV2 returns at most 1000 keys, and the
        missing resume loop is exactly what silently truncated long listings in
        the Settings implementation before its rework."""
        if not self.bucket:
            return []
        out: list[dict] = []
        token = None
        try:
            while True:
                kwargs = {"Bucket": self.bucket, "Prefix": prefix}
                if token:
                    kwargs["ContinuationToken"] = token
                resp = self.client.list_objects_v2(**kwargs)
                for obj in resp.get("Contents", []):
                    out.append({
                        "name": obj["Key"].split("/")[-1],
                        "key": obj["Key"],
                        "sizeBytes": obj.get("Size", 0),
                        "uploadedAt": obj["LastModified"].isoformat() if obj.get("LastModified") else None,
                    })
                token = resp.get("NextContinuationToken")
                if not resp.get("IsTruncated") or not token:
                    break
        except Exception:  # noqa: BLE001 — degrade to partial rather than fail the page
            log(_logger, 30, "list_folder failed (degrading to partial)", prefix=prefix)
        return out


class ContributionsClient:
    """Point values from Contributions & Scoring (BR-P1).

    Two layers, both required:
    * per-call timeout + individual fault isolation, so a scoring outage degrades
      the points field rather than the page (P-REL-1);
    * a per-warm-container cache with a short TTL, so a 25-row list costs at most
      one downstream call for values that change perhaps monthly (P-REL-2, N6).

    On ANY failure the value is None and the caller OMITS the field. Absence is
    the documented degrade signal — returning 0 would be a lie that shows
    "+0 pts" in the UI.
    """

    _cache: dict[str, tuple[float, dict]] = {}
    CACHE_TTL_SECONDS = 60

    # NFR-EV-PERF-3 set a 300 ms target and deferred the real value until the
    # downstream services were deployed. Measured 2026-08-05 against the dev
    # stack: a same-account call to API Gateway from a Lambda in a private subnet
    # (NAT -> API GW -> another Lambda, sometimes cold) takes 490-760 ms. At
    # 300 ms EVERY call timed out, so the degrade path was permanently engaged
    # and no points tag ever rendered — the feature silently did not work.
    # 1.5 s covers the measured spread with headroom. The 60-second cache means
    # only the first request per warm container pays it.
    DEFAULT_TIMEOUT_SECONDS = 1.5

    def __init__(self, base_url: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS, opener=None):
        self.base_url = (base_url or os.environ.get("API_BASE_URL", "")).rstrip("/")
        self.timeout = timeout
        self._opener = opener or urlrequest.urlopen

    def _get(self, path: str, *, bearer_token: str | None,
             claim_headers: dict | None = None) -> dict | None:
        if not self.base_url or not self.base_url.startswith("https://"):
            # Only https:// same-account API Gateway endpoints are permitted
            # (SECURITY-01/07); reject anything else before building a request.
            return None
        req = urlrequest.Request(f"{self.base_url}{path}", method="GET")  # noqa: S310 — scheme validated
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")
        for hk, hv in (claim_headers or {}).items():
            req.add_header(hk, hv)
        try:
            with self._opener(req, timeout=self.timeout) as resp:  # noqa: S310 — scheme validated
                body = resp.read()
                return json.loads(body) if body else None
        except (urlerror.URLError, TimeoutError, ValueError, OSError) as err:
            log(_logger, 30, "contributions call failed (degrading gracefully)",
                path=path, error=str(err))
            return None

    def points_for(self, event_type: str, *, bearer_token: str | None = None,
                   claim_headers: dict | None = None) -> dict:
        """Returns {"attendance": int|None, "delivery": int|None}."""
        cached = self._cache.get(event_type)
        if cached and (time.monotonic() - cached[0]) < self.CACHE_TTL_SECONDS:
            return cached[1]
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self._get, "/contributions/framework",
                                 bearer_token=bearer_token, claim_headers=claim_headers)
            framework = future.result()
        values = {"attendance": None, "delivery": None}
        for row in ((framework or {}).get("items") or []):
            activity = str(row.get("activity", "")).lower()
            if event_type.lower() in activity or activity in ("event attendance", "attendance"):
                if "deliver" in activity or "present" in activity:
                    values["delivery"] = row.get("points")
                else:
                    values["attendance"] = row.get("points")
        if framework is not None:
            self._cache[event_type] = (time.monotonic(), values)
        return values

    @classmethod
    def reset_cache(cls) -> None:
        cls._cache = {}


class DirectoryClient:
    """Designee role lookup against Member Profiles (BR-P3, decision Q3-A).

    Called at DESIGNATION time only — never on the read path — so the cost is
    one GET per designee on a rare write. Forwards the caller's own JWT (the
    same no-service-credential pattern Member Profiles uses for its fan-out).

    FAIL-CLOSED FOR POINTS: on any failure the caller stores the designation
    but marks it NOT eligible with reason "role unverified". The old behavior
    (default everyone to Member) silently made every designee — leaders
    included — points-eligible, which is why this exists.
    """

    DEFAULT_TIMEOUT_SECONDS = 1.5  # same measured NAT->API GW->Lambda floor

    def __init__(self, base_url: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS, opener=None):
        self.base_url = (base_url or os.environ.get("API_BASE_URL", "")).rstrip("/")
        self.timeout = timeout
        self._opener = opener or urlrequest.urlopen

    def lookup(self, user_id: str, *, bearer_token: str | None = None,
               claim_headers: dict | None = None) -> dict | None:
        """Returns {"role": str, "displayName": str} or None when unverifiable."""
        if not self.base_url or not self.base_url.startswith("https://"):
            return None  # SECURITY-01/07 — https same-account API GW only
        if not user_id or "/" in user_id or "?" in user_id:
            return None  # never build a request from a malformed id
        req = urlrequest.Request(f"{self.base_url}/members/{user_id}", method="GET")  # noqa: S310 — scheme validated
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")
        for hk, hv in (claim_headers or {}).items():
            req.add_header(hk, hv)
        try:
            with self._opener(req, timeout=self.timeout) as resp:  # noqa: S310 — scheme validated
                body = resp.read()
                member = json.loads(body) if body else None
        except (urlerror.URLError, TimeoutError, ValueError, OSError) as err:
            log(_logger, 30, "designee role lookup failed (failing closed for points)",
                user=user_id, error=str(err))
            return None
        if not member or not member.get("role"):
            return None
        # Fallback chain matters: a profile created as a STUB by Member Profiles'
        # event consumer (role/group event consumed before UserProvisioned) has a
        # role but no names — email is what a human recognises, the raw id is the
        # last resort (live finding, 2026-08-06).
        name = " ".join(p for p in (member.get("firstName"), member.get("lastName")) if p)
        return {"role": member["role"],
                "displayName": name or member.get("email") or user_id}


class TeamsProvider:
    """MS Teams attendance fetch (US-2.12), D1 = interface + stub.

    The stub returns no participants. Everything downstream of the fetch — email
    matching, the review screen, include/exclude, apply-and-award — is real and
    fully tested, so swapping in a Microsoft Graph adapter later is a change to
    this class only. Writing an untestable Graph client now would add a
    dependency and a credential path with no way to verify either.
    """

    def __init__(self, enabled: bool = False):
        self.enabled = enabled

    def fetch_participants(self, meeting_id: str) -> list[dict]:
        if not self.enabled:
            raise AppError(code="NOT_CONFIGURED",
                           message="MS Teams integration is not enabled.", status=503)
        log(_logger, 20, "teams stub fetch (no real Graph adapter yet)", meeting=meeting_id)
        return []


class SettingsCache:
    """Cached read of Settings-owned flags. Fails CLOSED: if Settings cannot be
    reached, Teams is treated as disabled rather than assumed enabled.

    Reads `GET /internal/settings` (private-API-only). Until 2026-08-28 this read
    `/public/settings`, whose projection never contained `teamsEnabled` at all —
    so `.get("teamsEnabled", False)` resolved to the default on every call and the
    stored value was never actually consulted. Nothing was broken by that: MS
    Teams is locked OFF by platform policy in settings_service.update_settings,
    which forces teamsEnabled=False server-side regardless of the request, so
    False was the correct answer anyway. This read was dead wiring reaching a
    field that was not there; it now reaches a route that carries it, so the gate
    reflects the store if policy is ever unlocked."""

    _cache: tuple[float, dict] | None = None
    TTL_SECONDS = 30
    # Same measurement as ContributionsClient — 300 ms was below the floor for a
    # NAT -> API Gateway -> Lambda round trip, so this read always failed and
    # Teams was always reported disabled regardless of the real setting.
    DEFAULT_TIMEOUT_SECONDS = 1.5

    def __init__(self, base_url: str | None = None,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS, opener=None):
        self.base_url = (base_url or os.environ.get("API_BASE_URL", "")).rstrip("/")
        self.timeout = timeout
        self._opener = opener or urlrequest.urlopen

    def _fetch(self) -> dict:
        if not self.base_url or not self.base_url.startswith("https://"):
            return {}
        req = urlrequest.Request(f"{self.base_url}/internal/settings", method="GET")  # noqa: S310
        try:
            with self._opener(req, timeout=self.timeout) as resp:  # noqa: S310
                body = resp.read()
                return json.loads(body) if body else {}
        except (urlerror.URLError, TimeoutError, ValueError, OSError):
            log(_logger, 30, "settings read failed (failing closed)")
            return {}

    def get(self) -> dict:
        now = time.monotonic()
        if self._cache and (now - self._cache[0]) < self.TTL_SECONDS:
            return self._cache[1]
        data = self._fetch()
        type(self)._cache = (now, data)
        return data

    def teams_enabled(self) -> bool:
        env = os.environ.get("MS_TEAMS_ENABLED", "").lower()
        if env in ("true", "1"):
            return True
        return bool(self.get().get("teamsEnabled", False))

    @classmethod
    def reset_cache(cls) -> None:
        cls._cache = None
