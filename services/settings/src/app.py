"""REAL Lambda handler for settings (replaces mock_handler as the deployed
entrypoint). Routes API Gateway proxy events to domain services with
in-service fail-closed authZ (SECURITY-08). Wrapped by global_handler so no
exception escapes (SECURITY-15).

Three authorizer regimes on the same function:
  `/settings*`        Cognito authorizer, needs a principal.
  `/public/settings`  No authorizer, INTERNET-REACHABLE (`/public` base path,
                      same mechanism as `/auth`) for the pre-login
                      Self-Registration gate and branding (US-1.30). Everything
                      it returns is world-readable — see PUBLIC_FIELDS.
  `/internal/settings` No authorizer, but emitted ONLY into the private REST API
                      (PRIVATE_ONLY_BASES), so it has no internet path. Carries
                      the admin config that other services enforce server-side
                      and that must not leak pre-login — see INTERNAL_FIELDS.
See infra/tools/gen_api_edge.py for both base-path sets.
"""
from __future__ import annotations

import json
import os
import re
import uuid

from _conventions.authz import Principal, extract_claims
from _conventions.errors import (
    AppError,
    ForbiddenError,
    UnauthorizedError,
    ValidationError,
    global_handler,
    to_response,
)
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import get_logger, log, set_correlation_id
from email_template_service import EmailTemplateService
from file_share_event_consumer import CONSUMED_S3_EVENTS, FileShareEventConsumer
from file_share_service import FileShareService
from nightly_jobs_service import NightlyJobsService
from providers import EventPublisher, FileShareStorage
from repository import SettingsRepository
from settings_service import SettingsService

# _logger was USED further down (the "already running" guard in the scheduled-job
# path) but never defined in this module, so that branch raised NameError instead
# of logging and skipping — it turned a benign concurrency guard into a 500.
# Every sibling module in this service defines its logger the same way.
_logger = get_logger("settings.app")

OPERATIONS = {
    ("GET", "/settings"): "getSettings",
    ("PUT", "/settings"): "updateSettings",
    ("GET", "/public/settings"): "getPublicSettings",
    ("GET", "/internal/settings"): "getInternalSettings",
    ("GET", "/settings/email-templates"): "listEmailTemplates",
    ("PUT", "/settings/email-templates/{id}"): "updateEmailTemplate",
    ("GET", "/settings/file-share"): "listFileShareLinks",
    ("POST", "/settings/file-share"): "createFileShareLink",
    ("GET", "/settings/file-share/folders"): "listFileShareFolders",
    ("GET", "/settings/file-share/{id}/upload-url"): "getFileShareUploadUrl",
    ("GET", "/settings/file-share/{id}/files"): "listFileShareFiles",
    ("POST", "/settings/file-share/{id}/revoke"): "revokeFileShareLink",
    ("DELETE", "/settings/file-share/{id}"): "deleteFileShareLink",
    ("GET", "/settings/nightly-jobs"): "listNightlyJobs",
    # ONE way to run the jobs (2026-08-27). The per-job
    # POST /settings/nightly-jobs/{id}/trigger route was REMOVED rather than
    # merely hidden from the UI: it fanned out its own async invocation per job,
    # so any caller using it bypassed the sequencing the state machine exists to
    # guarantee. An endpoint that can silently break the ordering contract is not
    # worth keeping around for convenience.
    ("POST", "/settings/nightly-jobs/run"): "startJobBatch",
    ("GET", "/settings/nightly-jobs/batch/{id}"): "getJobBatch",
    ("GET", "/settings/nightly-jobs/runs/active"): "getActiveRuns",
    ("GET", "/settings/nightly-jobs/runs/{id}"): "getRunStatus",
    ("POST", "/settings/nightly-jobs/runs/{id}/complete"): "completeRun",
}

PUBLIC_OPS = {"getPublicSettings"}

# Operations reachable without a principal because the ROUTE is network-isolated,
# not because the data is public. `/internal` is emitted only into the private
# REST API (PRIVATE_ONLY_BASES in infra/tools/gen_api_edge.py), which is
# reachable solely via the execute-api VPC endpoint and whose resource policy
# denies anything not arriving through it. Callers are same-account Lambdas with
# no JWT. Kept separate from PUBLIC_OPS so the two reasons never get conflated:
# adding an op to PUBLIC_OPS publishes its data to the internet, adding one here
# does not.
NETWORK_SCOPED_OPS = {"getInternalSettings"}

# Administrator-only write operations.
ADMIN_ONLY_OPS = {"updateSettings", "updateEmailTemplate", "completeRun"}

# Nightly-job run/monitor operations. Administrators AND Community Leaders may
# trigger and watch on-demand nightly jobs (community-wide rollups/tiers) — a CL
# is a community-wide operator, so this mirrors the CL dashboard's remit.
# (completeRun stays Admin-only: it's the internal write-back path, not user UI.)
NIGHTLY_JOB_OPS = {"listNightlyJobs", "startJobBatch", "getJobBatch",
                   "getActiveRuns", "getRunStatus"}


def _json_default(o):
    """DynamoDB numbers come back as Decimal; serialize them as JSON numbers
    (int when whole) so contract-typed integers don't degrade to strings on
    read -> edit -> save round-trips. Everything else falls back to str."""
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status: int, body) -> dict:
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body, default=_json_default)}


def _compile(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", path) + "$")


_COMPILED = [(m, _compile(p), op) for (m, p), op in OPERATIONS.items()]


class Context:
    """Wires repository + providers + services. Injected in tests."""

    def __init__(self, table=None, events=None, storage=None, idempotency_table=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = SettingsRepository(table)
        self.events = events or EventPublisher()
        self.storage = storage or FileShareStorage()
        idem_table = idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", "")
        self.idempotency = IdempotencyStore(idem_table) if idem_table else None
        self.settings_service = SettingsService(self.repo, self.events)
        self.email_template_service = EmailTemplateService(self.repo, self.events)
        self.file_share_service = FileShareService(self.repo, self.storage, self.events)
        self.file_share_events = FileShareEventConsumer(self.repo, self.idempotency)
        self.nightly_jobs = NightlyJobsService(self.repo)


def _match(method: str, path: str):
    for m, rx, op in _COMPILED:
        if m == method:
            mm = rx.match(path)
            if mm:
                return op, mm.groupdict()
    return None, None


def _principal(event) -> Principal | None:
    claims = extract_claims(event)
    if not claims:
        return None
    return Principal.from_claims(claims)


def _authorize(op: str, principal: Principal | None) -> None:
    if op in PUBLIC_OPS or op in NETWORK_SCOPED_OPS:
        return
    if principal is None:
        raise UnauthorizedError()
    if op in ADMIN_ONLY_OPS and principal.role != "Administrator":
        raise ForbiddenError(message="Only Administrators can change settings.")
    if op in NIGHTLY_JOB_OPS and principal.role not in ("Administrator", "CommunityLeader"):
        raise ForbiddenError(message="Only Administrators and Community Leaders can run nightly jobs.")


def _actor_email(event) -> str:
    """The caller's `email` claim, denormalized onto new file-share slots so the
    Community Leader listing can render "Created By" without a per-row lookup.
    Cognito puts `email` on the ID token; absent for the local-admin path."""
    claims = extract_claims(event)
    email = claims.get("email") or ""
    return email.strip().lower() if isinstance(email, str) else ""


def _parse_limit(raw: str | None) -> int | None:
    """Page size for listFileShareLinks: optional, integer, 1..200.
    Malformed/out-of-range input is a client error, not an unhandled 500."""
    if raw is None or raw == "":
        return None
    try:
        limit = int(raw)
    except (ValueError, TypeError):
        raise ValidationError("limit must be an integer.") from None
    if not 1 <= limit <= 200:
        raise ValidationError("limit must be between 1 and 200.")
    return limit


def dispatch(event: dict, ctx: Context) -> dict:
    # EventBridge branch: S3 Object Created/Deleted on the community file-share
    # bucket, which maintains stored upload state. Not an HTTP route.
    detail_type = event.get("detail-type") or event.get("type")
    if detail_type in CONSUMED_S3_EVENTS:
        ctx.file_share_events.handle(event)
        return _resp(200, {"status": "processed"})

    # Scheduled branch: the nightly cron (settings-scheduled-jobs-nightly-<stage>,
    # cron(0 3)) sends exactly {"source": "nightly"}. It MUST land here.
    #
    # Until 2026-08-30 that rule targeted the JobsStateMachine directly, and the
    # machine's Map reads its work from `$.jobs` with Finalize reading `$.batchId`
    # — neither of which that input carries. Every scheduled run therefore died
    # instantly with States.ReferencePathConflict and the nightly jobs never ran.
    # The rule's own comment said "the job list is built by the settings service
    # and passed in", which is the correct design; the target just skipped the
    # service that does the building. start_batch() is that builder: it mints a
    # batchId, resolves the job registry, writes every run record as `queued`,
    # then starts the machine with a well-formed input.
    #
    # Same failure family as the events-reminders payload described in
    # _assert_step_succeeded: a scheduled event that matches no branch here falls
    # through to the HTTP router and 404s, which is why this is an explicit,
    # tested branch rather than a default.
    if event.get("source") == "nightly":
        try:
            batch = ctx.nightly_jobs.start_batch()
        except ValidationError as err:
            # Most likely a batch already running (a manual run overlapping the
            # cron). Not an error worth failing the invocation over, but it must
            # not read as a successful start either.
            log(_logger, 30, "scheduled nightly batch not started", reason=str(err))
            return _resp(200, {"status": "skipped", "reason": str(err)})
        log(_logger, 20, "scheduled nightly batch started",
            batchId=batch.get("batchId"), jobs=len(batch.get("jobs") or []))
        return _resp(200, {"status": "started", "batchId": batch.get("batchId")})

    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    set_correlation_id((event.get("headers") or {}).get("X-Correlation-Id"))

    op, params = _match(method, path)
    if op is None:
        return _resp(404, {"code": "NOT_FOUND", "message": "Resource not found."})

    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except (ValueError, TypeError):
            return _resp(400, {"code": "VALIDATION_ERROR", "message": "Invalid JSON body."})

    try:
        principal = _principal(event)
        _authorize(op, principal)
        return _execute(ctx, op, params, body, principal, event)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message})


def _execute(ctx: Context, op: str, params: dict, body: dict, principal: Principal | None,
             event: dict | None = None) -> dict:
    actor = principal.user_id if principal else "anonymous"
    role = principal.role if principal else ""
    qs = ((event or {}).get("queryStringParameters")) or {}
    s, t, f = ctx.settings_service, ctx.email_template_service, ctx.file_share_service

    if op == "getSettings":
        return _resp(200, s.get_settings())
    if op == "updateSettings":
        return _resp(200, s.update_settings(body, actor=actor))
    if op == "getPublicSettings":
        return _resp(200, s.get_public_settings())
    if op == "getInternalSettings":
        return _resp(200, s.get_internal_settings())
    if op == "listEmailTemplates":
        return _resp(200, t.list_templates())
    if op == "updateEmailTemplate":
        return _resp(200, t.update_template(params["id"], body, actor=actor))
    if op == "listFileShareLinks":
        return _resp(200, f.list_links(actor=actor, role=role,
                                       limit=_parse_limit(qs.get("limit")), cursor=qs.get("cursor")))
    if op == "createFileShareLink":
        return _resp(201, f.create_link(body, actor=actor, role=role,
                                        actor_email=_actor_email(event or {})))
    if op == "listFileShareFolders":
        return _resp(200, f.list_folders(actor=actor, role=role))
    if op == "getFileShareUploadUrl":
        return _resp(200, f.get_upload_url(params["id"], actor=actor, role=role))
    if op == "listFileShareFiles":
        return _resp(200, f.list_files(params["id"], actor=actor, role=role))
    if op == "revokeFileShareLink":
        return _resp(200, f.revoke_link(params["id"], actor=actor, role=role))
    if op == "deleteFileShareLink":
        f.delete_link(params["id"], actor=actor, role=role)
        return _resp(204, {})

    # ---------- Nightly Jobs (Admin on-demand trigger) ----------
    nj = ctx.nightly_jobs
    if op == "startJobBatch":
        # 202: nothing has run yet. A full pass is minutes of work, so the only
        # honest synchronous answer is a receipt the page can poll.
        return _resp(202, nj.start_batch())
    if op == "getJobBatch":
        return _resp(200, nj.get_batch(params["id"]))
    if op == "listNightlyJobs":
        return _resp(200, nj.list_jobs())
    if op == "getActiveRuns":
        return _resp(200, nj.get_active_runs())
    if op == "getRunStatus":
        return _resp(200, nj.get_run_status(params["id"]))
    if op == "completeRun":
        nj.complete_run(params["id"], result=body.get("result"), error=body.get("error"))
        return _resp(200, {"status": "updated"})

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)


def _assert_step_succeeded(fn: str, raw, result, expect: str | None) -> None:
    """Raise unless the step genuinely did its work.

    WHY THIS EXISTS. `FunctionError` — the only check here before 2026-08-27 — is
    set solely when a Lambda actually crashes: an unhandled throw, a timeout, an
    OOM. But every service handler is wrapped in `global_handler`, whose entire
    purpose is that "no exception escapes": it catches the exception and returns a
    proxy-envelope error response. The invocation therefore SUCCEEDS from Lambda's
    point of view, `FunctionError` is absent, and the run was recorded as
    `completed`. A nightly job could fail every night and the page showed green.

    Found via `events-reminders`, whose registered payload `{"source":
    "scheduled-sweep"}` matched no dispatch branch in the events service, fell
    through to the HTTP router, and returned 404. The run record ended up storing
    `{"code": "NOT_FOUND"}` as its RESULT while its STATUS said completed — the
    evidence was captured and then ignored.

    Two independent checks, because they catch different failures:

    1. The response envelope. A 4xx/5xx in the proxy shape means the handler
       refused or blew up. Note `statusCode` is checked for PRESENCE first:
       `contributions-sweep` returns a bare dict (`{"swept": n}`) with no envelope
       at all, so a missing status must read as "fine", never as failure.

    2. The declared result key (`expect`). The envelope check cannot catch a job
       that returned 200 and did nothing — a misrouted payload that happens to hit
       a healthy no-op, or a sweep that silently processed zero groups because its
       registry was empty. Each job declares one key its result must carry, so
       "the invoke succeeded" and "the job did its work" stop being the same claim.
    """
    status = raw.get("statusCode") if isinstance(raw, dict) else None
    if status is not None:
        try:
            code = int(status)
        except (TypeError, ValueError):
            code = 0
        if code >= 400:
            raise RuntimeError(f"Step '{fn}' returned HTTP {code}: {result}")

    if expect and not (isinstance(result, dict) and expect in result):
        raise RuntimeError(
            f"Step '{fn}' returned no '{expect}' in its result, so it did not do "
            f"its work: {result}")


def _record_on_batch(repo, batch_id, job_id: str, fields: dict) -> None:
    """Merge one job's outcome into its batch record.

    Read-modify-write on a single item. Safe here ONLY because the state machine
    runs the jobs with MaxConcurrency 1, so there is never a second writer racing
    for the same batch. If that concurrency ever changes this needs to become an
    UpdateExpression on the nested map instead.

    Silent no-op when there is no batch id: the same runner still serves a
    single-job invocation, which has no batch to update.
    """
    if not batch_id or not job_id:
        return
    batch = repo.get_job_batch(batch_id)
    if not batch:
        return
    jobs = dict(batch.get("jobs") or {})
    jobs[job_id] = {**(jobs.get(job_id) or {}), **fields}
    batch["jobs"] = jobs
    # How far along the sequence we are, for the page's progress line. Derived
    # rather than incremented so a retried step cannot double-count it.
    batch["currentIndex"] = sum(
        1 for st in jobs.values() if st.get("status") in ("completed", "failed"))
    repo.put_job_batch(batch)


@global_handler
def job_runner_handler(event, context):
    """Execute nightly job Lambdas synchronously and record the result.

    Two invocation paths:

    1. On-demand (triggered by NightlyJobsService.trigger_job):
       runId is already in DynamoDB.
       Event: { "runId": "...", "jobId": "...", "function"/"steps": ... }

    2. Scheduled (triggered by EventBridge nightly rule):
       No runId — create one and check the running guard to prevent overlap
       with an in-progress on-demand run.
       Event: { "jobId": "opensearch-reindex", "steps": [...] }

    Steps always execute sequentially (RequestResponse). Aborts on first
    failure and marks the run as failed. Result written back to DynamoDB.
    """
    from datetime import datetime
    from datetime import timezone as _tz

    import boto3 as _boto3

    # Initialise once — shared by guard check and execution.
    table    = _boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
    repo     = SettingsRepository(table)
    lm       = _boto3.client("lambda")
    now_ts   = datetime.now(_tz.utc)
    now_iso  = now_ts.isoformat(timespec="seconds")

    # ── Finalize path (state machine's last state) ───────────────────────
    # Runs whether or not individual jobs failed: the BATCH finished either way,
    # and leaving the in-flight pointer set would strand the page on a spinner
    # forever. Separate from the per-job path because there is no job and no run
    # to record here — only the batch to close out.
    finalize_batch_id = event.get("finalizeBatchId")
    if finalize_batch_id:
        batch = repo.get_job_batch(finalize_batch_id)
        if batch:
            jobs = batch.get("jobs") or {}
            failed = [j for j, st in jobs.items() if st.get("status") == "failed"]
            batch["status"] = "completed"
            batch["completedAt"] = now_iso
            batch["failedJobs"] = failed
            repo.put_job_batch(batch)
        # Cleared unconditionally — a batch record that vanished must not leave a
        # pointer behind claiming something is still running.
        repo.clear_active_batch()
        return {"ok": True, "finalized": finalize_batch_id}

    run_id = event.get("runId")
    job_id = event.get("jobId", "")
    batch_id = event.get("batchId")

    if not run_id:
        # ── Scheduled path ───────────────────────────────────────────────
        # Running guard: skip if the same job is already running (e.g. an
        # on-demand run is still in progress).  Treat runs older than 1800s
        # as stuck and skip the guard — they will be overwritten on the next
        # successful run.
        for r in repo.list_active_runs():
            if r.get("jobId") != job_id:
                continue
            started = r.get("startedAt", "")
            try:
                started_dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
                age = (now_ts - started_dt).total_seconds()
            except (ValueError, TypeError):
                age = 0
            if age < 1800:
                _logger.warning(
                    "Scheduled %s skipped — already running (runId=%s, age=%ss)",
                    job_id, r.get("runId"), int(age),
                )
                return {"ok": True, "skipped": "already running"}

        # No conflict — create the run record.
        run_id = str(uuid.uuid4())
        repo.put_job_run({
            "runId": run_id, "jobId": job_id, "status": "running",
            "startedAt": now_iso, "completedAt": None, "result": None, "error": None,
        })

    # ── Normalise single-step and multi-step into the same steps list ────
    steps = event.get("steps")
    if not steps:
        fn = event.get("function")
        if not fn:
            repo.update_job_run(run_id, {
                "status": "failed", "completedAt": now_iso,
                "error": "Missing function or steps in event payload.",
            })
            return {"error": "Missing function or steps"}
        # `expect` must survive this normalisation or the result-shape check is
        # silently skipped for every single-step job — which is most of them.
        steps = [{"function": fn, "payload": event.get("payload", {}),
                  "expect": event.get("expect")}]

    # ── Execute steps sequentially ───────────────────────────────────────
    combined_result: dict = {}
    try:
        for step in steps:
            fn      = step["function"]
            payload = step.get("payload", {})
            resp = lm.invoke(
                FunctionName=fn,
                InvocationType="RequestResponse",
                Payload=json.dumps(payload).encode(),
            )
            raw = json.loads(resp["Payload"].read().decode()) if resp.get("Payload") else {}
            if resp.get("FunctionError"):
                raise RuntimeError(f"Step '{fn}' failed: {resp['FunctionError']}")
            # Parse Lambda proxy response body if present.
            body = raw.get("body") if isinstance(raw, dict) else None
            if isinstance(body, str):
                try:
                    body = json.loads(body)
                except Exception:  # noqa: BLE001
                    pass
            result = body if isinstance(body, dict) else raw
            _assert_step_succeeded(fn, raw, result, step.get("expect"))
            combined_result[fn] = result

        finished = datetime.now(_tz.utc).isoformat(timespec="seconds")
        repo.update_job_run(run_id, {
            "status": "completed", "completedAt": finished,
            "result": combined_result,
        })
        _record_on_batch(repo, batch_id, job_id, {
            "status": "completed", "runId": run_id, "completedAt": finished})
    except Exception as exc:
        finished = datetime.now(_tz.utc).isoformat(timespec="seconds")
        repo.update_job_run(run_id, {
            "status": "failed", "completedAt": finished, "error": str(exc),
        })
        _record_on_batch(repo, batch_id, job_id, {
            "status": "failed", "runId": run_id, "completedAt": finished,
            "error": str(exc)})
        # SWALLOWED DELIBERATELY. The state machine catches errors to keep the
        # batch going, but re-raising would still mark this Map iteration failed
        # and show a red state in the execution history for something already
        # recorded on the run. The run record is the source of truth the page
        # reads; the orchestrator only needs to know it may proceed.

    return {"ok": True}

