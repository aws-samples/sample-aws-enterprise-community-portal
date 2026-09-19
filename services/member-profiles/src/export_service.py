"""Async CSV export of the Member Directory (US-3.4/3.5 export action).

Replaces a synchronous export that could not survive the platform's growth. The
old path (`DirectoryService.browse` with no limit/cursor) did a full DynamoDB
`Scan` of the whole single table — reading every shoutout and reaction item as
well as profiles — and returned every row in one JSON response. At 25k members
that breaches Lambda's 6 MB payload limit and API Gateway's 29 s integration
timeout, and it can report no progress.

Shape mirrors identity-access's user export:

    POST /members/export        -> create the job, invoke the worker async,
                                   return the job id immediately
    (worker)                    -> stream rows from OpenSearch to CSV in S3,
                                   updating `processed` as it goes
    GET  /members/export/{id}   -> polled for progress; once ready it carries a
                                   freshly minted, short-lived download URL

Three decisions specific to THIS export:

* RESTRICTED TO COMMUNITY LEADERS AND USER GROUP LEADERS. `GET /members` itself
  is open to any authenticated principal (member-profiles has no OP_AUTHZ table),
  which meant any of ~25k Members could previously download the entire directory
  — every name and email address — as a file. The async endpoint is gated
  deliberately. Administrators are excluded too: they have the richer
  Admin > Users export in identity-access.
* GROUP NAMES, NOT IDS. The old CSV had a `groups` column that the browser
  rendered from an array of objects, so it literally read
  "[object Object],[object Object]". Real names are required, so the id -> name
  map is resolved HERE, at request time, where the caller's bearer token exists —
  the worker runs without a request context and cannot fan out.
* ROWS COME FROM OPENSEARCH. This reverses the note in directory_service.py that
  the export used DynamoDB "so it is authoritative and not subject to OpenSearch
  indexing lag". The index makes an exact count cheap (needed for a real progress
  percentage) and avoids the whole-table scan; the accepted cost is that an
  export is a snapshot of the index and can lag the roster.
"""
from __future__ import annotations

import json
import os

from _conventions.errors import ForbiddenError, NotFoundError, ValidationError
from _conventions.logger import get_logger, log
from models import epoch, new_id, now_iso

_logger = get_logger("member-profiles.export")

# Only these roles may export the directory. See the module docstring.
EXPORT_ROLES = ("CommunityLeader", "UserGroupLeader")

# Aligned with the export bucket's 1-day object expiry so a job record never
# outlives the file it describes, nor the reverse.
EXPORT_JOB_TTL_SECONDS = 86_400

# An export is treated as abandoned after this long, releasing the per-leader
# lock for a retry. Comfortably beyond the worker's own 900 s Lambda timeout.
EXPORT_STALE_AFTER_SECONDS = 1_800

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_READY = "ready"
STATUS_FAILED = "failed"

# Filters the export honours — the CSV matches the filtered table the leader is
# looking at. `certId` is absent on purpose: resolving cert holders needs a
# fan-out with the caller's JWT, which the worker does not have.
EXPORT_FILTER_KEYS = ("q", "role", "groupId")

# Safety cap on the id -> name map stored on the job record. DynamoDB items are
# limited to 400 KB; a few hundred groups is a few tens of KB, but an unbounded
# map would eventually fail the write. Past the cap the worker falls back to
# emitting raw group ids, which is degraded but still correct.
MAX_GROUP_NAMES = 500


class ExportService:
    def __init__(self, repo, storage, fan_out=None, lambda_client=None,
                 worker_function: str | None = None):
        self._repo = repo
        self._storage = storage
        self._fan_out = fan_out
        self._lambda = lambda_client
        self._worker_function = worker_function or os.environ.get(
            "EXPORT_WORKER_FUNCTION",
            f"member-profiles-export-{os.environ.get('STAGE', 'dev')}")

    # ---------------- start (POST /members/export) ----------------
    def start_export(self, body: dict, *, principal, bearer_token: str | None = None,
                     claim_headers: dict | None = None) -> dict:
        role = getattr(principal, "role", None)
        if role not in EXPORT_ROLES:
            # Not a 404: the caller is authenticated and the route exists — they
            # simply are not permitted. Members are refused here by design.
            raise ForbiddenError(
                message="Only Community Leaders and User Group Leaders can export the directory.")

        actor = principal.user_id
        filters = {k: (body.get(k) or "").strip() for k in EXPORT_FILTER_KEYS}
        filters = {k: v for k, v in filters.items() if v}

        job_id = new_id("mexp")
        now = epoch()
        file_name = f"member-directory-{now_iso()[:19].replace(':', '').replace('-', '')}.csv"

        # One in-flight export per leader. The SPA also disables the button, but
        # that is presentation only — a refresh re-enables it.
        if not self._repo.acquire_export_lock(actor, job_id,
                                              ttl_seconds=EXPORT_STALE_AFTER_SECONDS):
            raise ValidationError(
                message="An export is already running for your account. "
                        "Wait for it to finish before starting another.")

        job = {
            "jobId": job_id,
            "actor": actor,
            "status": STATUS_QUEUED,
            "processed": 0,
            "total": None,
            "filters": filters,
            # Resolved now, while we still hold the caller's token.
            "groupNames": self._group_names(bearer_token=bearer_token, claim_headers=claim_headers),
            "fileName": file_name,
            "fileKey": f"members/{job_id}.csv",
            "error": None,
            "startedAt": now_iso(),
            "completedAt": None,
            "expiresAt": now + EXPORT_JOB_TTL_SECONDS,
            "ttl": now + EXPORT_JOB_TTL_SECONDS,
        }
        self._repo.put_export_job(job)

        # Invoke AFTER the record exists, so the SPA's first poll can never find
        # a job id the worker is already writing to but that does not yet exist.
        try:
            self._invoke_worker(job_id)
        except Exception as exc:  # noqa: BLE001 — reported as a failed job, not a 500
            log(_logger, 40, "export worker invoke failed", jobId=job_id)
            self._repo.update_export_job(job_id, {
                "status": STATUS_FAILED,
                "error": "Could not start the export worker.",
                "completedAt": now_iso(),
            })
            self._repo.release_export_lock(actor)
            raise ValidationError(
                message="Unable to start the export. Please try again.") from exc

        return self._public(job)

    def _group_names(self, *, bearer_token: str | None, claim_headers: dict | None = None) -> dict:
        """id -> name for every group, for the CSV's `groups` column.

        Done here rather than in the worker because the fan-out forwards the
        CALLER's JWT (no service credential exists), and the worker has no
        caller. Best-effort: if Identity & Access is unreachable the export still
        runs and the worker falls back to raw group ids rather than failing.
        """
        if self._fan_out is None:
            return {}
        try:
            result = self._fan_out.fan_out({"groups": "/groups"}, bearer_token=bearer_token,
                                           claim_headers=claim_headers)
            items = ((result or {}).get("groups") or {}).get("items") or []
        except Exception:  # noqa: BLE001 — degraded column beats a failed export
            log(_logger, 30, "group-name lookup failed; export will emit group ids")
            return {}
        names = {g["id"]: g.get("name") or g["id"]
                 for g in items if isinstance(g, dict) and g.get("id")}
        if len(names) > MAX_GROUP_NAMES:
            log(_logger, 30, "too many groups to store on the job record",
                count=len(names))
            return {}
        return names

    def _invoke_worker(self, job_id: str) -> None:
        client = self._lambda
        if client is None:
            import boto3  # noqa: PLC0415 — lazy, mirrors the other providers
            client = boto3.client("lambda")
        client.invoke(
            FunctionName=self._worker_function,
            InvocationType="Event",   # async — returns 202, does not wait
            Payload=json.dumps({"source": "member-csv-export", "jobId": job_id}).encode(),
        )

    # ---------------- status (GET /members/export/{id}) ----------------
    def get_export(self, job_id: str, *, principal) -> dict:
        role = getattr(principal, "role", None)
        if role not in EXPORT_ROLES:
            raise ForbiddenError(
                message="Only Community Leaders and User Group Leaders can export the directory.")

        job = self._repo.get_export_job(job_id)
        # Scoped to the requesting leader, and a mismatch is reported as absent
        # rather than forbidden so the response cannot confirm that another
        # leader's job id exists.
        if not job or job.get("actor") != principal.user_id:
            raise NotFoundError()

        out = self._public(job)
        if job.get("status") == STATUS_READY:
            # Minted per request and never stored.
            out.update(self._storage.download_url(job["fileKey"]))
        return out

    # ---------------- serialization ----------------
    @staticmethod
    def _public(job: dict) -> dict:
        total = job.get("total")
        processed = int(job.get("processed") or 0)
        total_int = int(total) if total not in (None, "") else None

        # None => the UI shows an indeterminate bar rather than a fabricated
        # percentage. Clamped because the count is taken once at the start and
        # members can be created while the export runs.
        percent: int | None = None
        if total_int:
            percent = min(100, int(processed * 100 / total_int))
        elif job.get("status") == STATUS_READY:
            percent = 100

        out = {
            "jobId": job.get("jobId"),
            "status": job.get("status"),
            "processed": processed,
            "total": total_int,
            "percent": percent,
            "fileName": job.get("fileName"),
        }
        if job.get("status") == STATUS_FAILED:
            out["error"] = job.get("error") or "The export failed."
        return out
