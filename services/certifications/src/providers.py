"""External adapters for Certifications.

- EventPublisher  — 5 domain event types, batched at the PutEvents max of 10;
                    post-commit best-effort (a publish failure never fails a
                    committed write).
- S3Broker        — presigned POST grants (the policy enforces the 5 MB cap and
                    exact content type AT THE STORAGE DOOR — J1/N2), per-request
                    evidence GETs (never stored), badge copy to the public SPA
                    bucket (N3=B, the trust-promotion step).
- IdentityClient  — the unit's ONLY sync cross-service call: membership read at
                    submission, led-group fallback. Fails CLOSED (D3/BR-C3):
                    an unverifiable creditedGroupId would corrupt routing and
                    points attribution, so submission 503s rather than guesses.
- Metrics         — emitted datapoints for the alarms shipped in the app stack.
                    Every alarm has an emitter (the Events lesson: an alarm on a
                    metric nobody emits reads as coverage while providing none).
"""
from __future__ import annotations

import json
import os
from urllib import error as urlerror
from urllib import request as urlrequest

from _conventions.envelope import build_event
from _conventions.errors import AppError
from _conventions.logger import get_logger, log

_logger = get_logger("certifications")

_PUT_EVENTS_BATCH = 10
_EVIDENCE_GET_TTL = 300           # 5 min (BR-P2)
_UPLOAD_GRANT_TTL = 900           # 15 min to complete the browser upload
_IDENTITY_TIMEOUT = 1.5           # NFR-CT-PERF-1 — measured 490-760ms live (Events)


class EventPublisher:
    """Post-commit, best-effort. Never raises to the caller."""

    def __init__(self, client=None, bus: str | None = None, metrics=None):
        self._c = client
        self.bus = bus if bus is not None else os.environ.get("EVENT_BUS_NAME", "")
        self.published: list[dict] = []  # visible to tests without a fake
        self._metrics = metrics

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
        entries = []
        for event_type, data in items:
            envelope = build_event(event_type, "certifications", data,
                                   correlation_id=correlation_id)
            self.published.append(envelope)
            entries.append({
                "EventBusName": self.bus,
                "Source": "certifications",
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
                if self._metrics:
                    self._metrics.emit("EventPublishFailure", len(chunk))


class S3Broker:
    """Presigned URLs minted per request and NEVER stored (the Settings lesson:
    a URL signed with Lambda temp creds dies with the session token and cannot
    be revoked). Grants are presigned POSTs, not PUTs, because only a POST
    policy can carry `content-length-range` — the 5 MB rule is enforced by S3
    itself, not by trusting the client (J1)."""

    def __init__(self, client=None, bucket: str | None = None,
                 spa_bucket: str | None = None):
        self._c = client
        self.bucket = bucket if bucket is not None else os.environ.get("FILE_SHARE_BUCKET", "")
        self.spa_bucket = spa_bucket if spa_bucket is not None else os.environ.get("SPA_BUCKET", "")

    @property
    def client(self):
        if self._c is None:
            import boto3
            self._c = boto3.client("s3")
        return self._c

    def grant_upload(self, key: str, *, content_type: str, max_bytes: int) -> dict:
        if not self.bucket:
            raise AppError(code="STORAGE_UNAVAILABLE",
                           message="File storage is not configured.", status=503)
        post = self.client.generate_presigned_post(
            Bucket=self.bucket,
            Key=key,
            Fields={"Content-Type": content_type},
            Conditions=[
                {"Content-Type": content_type},
                ["content-length-range", 1, max_bytes],
                {"key": key},
            ],
            ExpiresIn=_UPLOAD_GRANT_TTL,
        )
        return {"fileKey": key, "uploadUrl": post["url"], "fields": post["fields"],
                "expiresInSeconds": _UPLOAD_GRANT_TTL}

    def object_exists(self, key: str) -> bool:
        """HeadObject at submission: a claim must never reference a file that
        was granted but never uploaded (keeps the SCANWATCH watchdog truthful)."""
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:  # noqa: BLE001 — any failure means "not usable evidence"
            return False

    def evidence_get_url(self, key: str) -> dict:
        url = self.client.generate_presigned_url(
            "get_object", Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=_EVIDENCE_GET_TTL)
        return {"url": url, "expiresInSeconds": _EVIDENCE_GET_TTL}

    def promote_badge(self, key: str) -> str:
        """Copy a scan-Clean badge image to the public SPA bucket (J5, N3=B).
        The public bucket never receives an unscanned byte, and because keys are
        unique per upload, a re-upload is a new URL — no CDN invalidation path
        exists or is needed. Returns the public path (served via CloudFront)."""
        public_key = f"badges/{key.rsplit('/', 1)[-1]}"
        # TaggingDirective REPLACE (live defect, 2026-08-06): by the time this
        # copy runs the source object carries GuardDuty's scan-status TAG, and
        # CopyObject's default TaggingDirective=COPY then requires
        # GetObjectTagging/PutObjectTagging — permissions this role deliberately
        # lacks — so the copy failed AccessDenied. REPLACE-with-no-tags needs
        # neither permission, and a public asset should not carry internal scan
        # metadata anyway. Invisible to moto (it doesn't enforce IAM) — the
        # same class as Settings' s3:DeleteObject 502.
        self.client.copy_object(
            Bucket=self.spa_bucket, Key=public_key,
            CopySource={"Bucket": self.bucket, "Key": key},
            MetadataDirective="COPY",
            TaggingDirective="REPLACE",
            Tagging="",
        )
        return f"/{public_key}"

    def purge_object(self, key: str) -> None:
        """HARD-delete EVERY version of `key`, not just the current one.

        Called only on a GuardDuty QUARANTINED verdict, where the requirement is
        that the infected bytes cease to EXIST — not merely that a plain GET
        stops returning them.

        WHY THIS IS NOT delete_object (which is what this used to be).
        FileShareBucket is now VERSIONED (Checkov CKV_AWS_21). On a versioned
        bucket a DeleteObject without a VersionId deletes NOTHING: it adds a
        delete marker, and the infected object survives underneath as a
        noncurrent version until NoncurrentVersionExpiration lapses. It stays
        readable the whole time to any principal holding s3:GetObjectVersion —
        and MalwareProtectionRole holds exactly that. So the naive call would
        have silently downgraded "quarantined" to "hidden", on the one bucket
        that accepts untrusted member uploads. Enumerating versions and deleting
        each by id is what keeps the guarantee the caller's comment claims.

        DELETE MARKERS ARE PURGED TOO. list_object_versions returns them
        separately under DeleteMarkers; leaving them would strand a marker over
        nothing and keep the key listable.

        THE Key == key FILTER IS LOAD-BEARING. Prefix is a prefix match, not an
        exact one, so paginating on Prefix=key would also sweep
        `certifications/abc-2` while purging `certifications/abc`. There is no
        exact-match variant of this API, so the filter is the only guard.

        Correct on an UNVERSIONED bucket as well: list_object_versions there
        reports a single version whose VersionId is the literal "null", and
        deleting that id removes the object. So this does not depend on the
        template change having been applied first.

        Best-effort, exactly like the delete_object it replaces — a purge
        failure must not fail the verdict consumer, because it is the scan-state
        write that gates serving. Logged at WARNING so the DLQ/alarm path sees
        it, and worth alarming on: a repeated failure here means infected bytes
        are lingering.
        """
        try:
            paginator = self.client.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=key):
                targets = [
                    {"Key": v["Key"], "VersionId": v["VersionId"]}
                    for v in (page.get("Versions", [])
                              + page.get("DeleteMarkers", []))
                    if v["Key"] == key
                ]
                if targets:
                    # Each page is <= 1000 entries, which is also delete_objects'
                    # per-call ceiling, so paginating is what keeps this legal.
                    self.client.delete_objects(
                        Bucket=self.bucket, Delete={"Objects": targets})
        except Exception:  # noqa: BLE001 — best-effort cleanup, never fail the caller
            log(_logger, 30, "object purge failed", key=key)


class IdentityClient:
    """Led-group fallback (D4) for UGL claims when the JWT lacks led_group_id.
    Same JWT-forwarding pattern as member-profiles' FanOutClient — the caller's
    own token, so Identity's authZ applies unchanged; no service credential.
    FAILS CLOSED: None here must become a 503 upstream.

    Member group membership is no longer read here — it rides in the
    authorizer-injected claims (fresh-claims-at-the-edge)."""

    def __init__(self, base_url: str | None = None, opener=None,
                 timeout: float = _IDENTITY_TIMEOUT):
        self.base_url = (base_url if base_url is not None
                         else os.environ.get("API_BASE_URL", "")).rstrip("/")
        self._opener = opener or urlrequest.urlopen
        self.timeout = timeout

    def _get(self, path: str, *, bearer_token: str | None) -> dict | None:
        if not self.base_url or not self.base_url.startswith("https://"):
            return None
        req = urlrequest.Request(f"{self.base_url}{path}", method="GET")  # noqa: S310 — scheme validated above
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")
        attempts = 2  # one retry max (NFR-CT-REL-1) — no retry storms
        for attempt in range(attempts):
            try:
                with self._opener(req, timeout=self.timeout) as resp:  # noqa: S310
                    body = resp.read()
                    return json.loads(body) if body else None
            except (urlerror.URLError, TimeoutError, ValueError, OSError) as err:
                log(_logger, 30, "identity call failed",
                    path=path, attempt=attempt, error=str(err))
        return None

    def led_group_id(self, user_id: str, *, bearer_token: str | None) -> str | None:
        """Fallback when the JWT lacks led_group_id (D4). None = unresolvable
        -> the caller must DENY (fail closed, BR-A4)."""
        data = self._get(f"/users/{user_id}", bearer_token=bearer_token)
        if not isinstance(data, dict):
            return None
        return data.get("ledGroupId") or None


class Metrics:
    """CloudWatch custom metrics, namespace certifications/<stage>. Failures are
    swallowed — observability must never break the feature it observes."""

    def __init__(self, client=None, namespace: str | None = None):
        self._c = client
        self.namespace = namespace or (
            f"CommunityPortal/certifications-{os.environ.get('STAGE', 'dev')}")
        self.emitted: list[tuple[str, float]] = []  # test hook

    @property
    def client(self):
        if self._c is None:
            import boto3
            self._c = boto3.client("cloudwatch")
        return self._c

    def emit(self, name: str, value: float, unit: str = "Count") -> None:
        self.emitted.append((name, value))
        try:
            self.client.put_metric_data(
                Namespace=self.namespace,
                MetricData=[{"MetricName": name, "Value": value, "Unit": unit}])
        except Exception:  # noqa: BLE001 — metrics must never break the feature
            log(_logger, 30, "metric emit failed", metric=name)
