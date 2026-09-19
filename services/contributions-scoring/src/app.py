"""Lambda entrypoints for Contributions & Scoring (Unit 7).

FIVE purpose-separated functions (NFR Design Q1=A) share this one code package;
each infra function points at its own handler:
  api_handler            — authenticated HTTP /contributions*
  consumer_handler       — SQS: EventCompleted (expander) + Forum/Cert/Identity events
  award_worker_handler   — SQS: per-earner award jobs (reserved concurrency 25)
  rollup_handler         — DynamoDB Stream (ledger) -> rollups
  sweep_handler          — EventBridge Scheduler -> nightly aggregates

AuthZ is enforced fail-closed inside the domain services (Member-only earning,
CL/UGL scope, Admin 403). Everything is wrapped by global_handler (SECURITY-15).
"""
from __future__ import annotations

import json
import os
import re

from _conventions.authz import Principal, extract_claims
from _conventions.errors import AppError, UnauthorizedError, global_handler, to_response
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import set_correlation_id
from adjustment_service import AdjustmentService
from consumers import (
    AwardWorker,
    CertConsumer,
    ForumConsumer,
    MembershipConsumer,
    NightlySweep,
    RollupMaintainer,
)
from export_service import ExportService
from framework_service import FrameworkService
from providers import EventPublisher, ExportStorage, Metrics
from read_service import ReadService
from repository import ContributionsRepository
from scoring_service import ScoringService
from submission_service import SubmissionService

OPERATIONS = [
    ("GET", "/contributions/framework", "getFramework"),
    ("POST", "/contributions/framework", "createActivity"),
    ("PUT", "/contributions/framework/{id}", "editActivity"),
    ("DELETE", "/contributions/framework/{id}", "deleteActivity"),
    ("PUT", "/contributions/event-points/{eventType}", "editEventPoints"),
    ("PUT", "/contributions/tiers", "editTiers"),
    ("GET", "/contributions/me", "getOwnPoints"),
    ("GET", "/contributions/history", "getHistory"),
    ("GET", "/contributions/tiers-earned", "tiersEarned"),
    ("GET", "/contributions/leaderboard", "getLeaderboard"),
    ("GET", "/contributions/rollups", "getRollups"),
    ("GET", "/contributions/summary/{scope}", "getSummary"),
    ("GET", "/contributions/group-trend", "groupTrend"),
    # Export routes MUST precede the bare group-ledger GET only for readability —
    # the matcher is exact-per-method — but the {jobId} route must not be written
    # as a bare {id} on /contributions/group-ledger or "export" would bind to it.
    ("POST", "/contributions/group-ledger/export", "startPointLedgerExport"),
    ("GET", "/contributions/group-ledger/export/{jobId}", "getPointLedgerExport"),
    ("GET", "/contributions/group-ledger", "groupLedger"),
    ("GET", "/contributions/community-trend", "communityTrend"),
    ("GET", "/contributions/export", "exportContributions"),
    ("GET", "/contributions/ledger", "memberLedger"),
    ("GET", "/contributions/submissions", "listOwnSubmissions"),
    ("POST", "/contributions/submissions", "submitContribution"),
    ("DELETE", "/contributions/submissions/{id}", "withdrawSubmission"),
    ("GET", "/contributions/approvals", "listPending"),
    ("POST", "/contributions/submissions/{id}/decision", "decideSubmission"),
    ("POST", "/contributions/adjustments", "adjustPoints"),
    ("POST", "/contributions/adjustments/reverse", "reverseEntry"),
]


def _compile(path):
    return re.compile("^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", path) + "$")


_COMPILED = [(m, _compile(p), op) for m, p, op in OPERATIONS]


def _json_default(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status, body):
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body, default=_json_default)}


def _no_content():
    return {"statusCode": 204, "headers": {"Access-Control-Allow-Origin": "*"}, "body": ""}


class Context:
    def __init__(self, table=None, idempotency_table=None, events=None, metrics=None,
                 export_storage=None, lambda_client=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = ContributionsRepository(table)
        idem = idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", "")
        self.idempotency = IdempotencyStore(idem) if idem else None
        self.metrics = metrics or Metrics()
        self.events = events or EventPublisher(metrics=self.metrics)

        self.framework = FrameworkService(self.repo, self.events)
        self.scoring = ScoringService(self.repo, self.framework, self.events)
        self.submissions = SubmissionService(self.repo, self.framework, self.events)
        self.adjustments = AdjustmentService(self.repo, self.events)
        self.reads = ReadService(self.repo, self.framework)
        self.export_storage = export_storage or ExportStorage()
        self.exports = ExportService(self.repo, self.export_storage,
                                     lambda_client=lambda_client)

        # AwardWorker consumes Events' per-earner award events directly (no
        # read-back). Other domain events go through the topic consumers.
        self.award_worker = AwardWorker(self.scoring, self.idempotency)
        self.forum_consumer = ForumConsumer(self.scoring, self.idempotency)
        self.cert_consumer = CertConsumer(self.scoring, self.idempotency)
        self.membership_consumer = MembershipConsumer(self.repo, self.events, self.idempotency)
        self.rollup = RollupMaintainer(self.repo, self.metrics)
        self.sweep = NightlySweep(self.repo, self.framework)


# ---------------------------------------------------------------- HTTP branch

def _match(method, path):
    for expected, rx, op in _COMPILED:
        if expected == method:
            found = rx.match(path)
            if found:
                return op, found.groupdict()
    return None, None


def _principal(event):
    claims = extract_claims(event)
    if not claims:
        raise UnauthorizedError()
    p = Principal.from_claims(claims)
    p.name = " ".join(x for x in (claims.get("given_name", "").strip(),
                                  claims.get("family_name", "").strip()) if x)
    return p


def dispatch_http(event, ctx):
    set_correlation_id((event.get("headers") or {}).get("X-Correlation-Id"))
    method, path = event.get("httpMethod", "GET"), event.get("path", "/")
    op, params = _match(method, path)
    if op is None:
        return _resp(404, {"code": "NOT_FOUND", "message": "Resource not found."})
    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except (ValueError, TypeError):
            return _resp(400, {"code": "VALIDATION_ERROR", "message": "Invalid JSON body."})
    qs = event.get("queryStringParameters") or {}
    try:
        p = _principal(event)
        # member_group_ids are provided fresh by the edge claims authorizer on
        # every request (fresh-claims-at-the-edge); no live refresh is needed.
        return _execute(ctx, op, params, body, qs, p)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _execute(ctx, op, params, body, qs, p):
    if op == "getFramework":
        return _resp(200, ctx.framework.view(principal=p))
    if op == "createActivity":
        return _resp(201, ctx.framework.create_activity(body, principal=p))
    if op == "editActivity":
        activity, _deactivated, _rejected = ctx.framework.edit_activity(params["id"], body, principal=p)
        return _resp(200, activity)
    if op == "deleteActivity":
        ctx.framework.delete_activity(params["id"], principal=p)
        return _no_content()
    if op == "editEventPoints":
        return _resp(200, ctx.framework.edit_event_points(params["eventType"], body, principal=p))
    if op == "editTiers":
        return _resp(200, {"tiers": ctx.framework.edit_tiers(body, principal=p)})
    if op == "getOwnPoints":
        return _resp(200, ctx.reads.own_points(qs, principal=p))
    if op == "getHistory":
        return _resp(200, ctx.reads.history(qs, principal=p))
    if op == "tiersEarned":
        return _resp(200, ctx.reads.tiers_earned(qs))
    if op == "getLeaderboard":
        return _resp(200, ctx.reads.leaderboard(qs, principal=p))
    if op == "getRollups":
        return _resp(200, ctx.reads.rollups(qs, principal=p))
    if op == "getSummary":
        return _resp(200, ctx.reads.summary(params["scope"], qs, principal=p))
    if op == "groupTrend":
        return _resp(200, ctx.reads.group_trend(qs, principal=p))
    if op == "groupLedger":
        return _resp(200, ctx.reads.group_ledger(qs, principal=p))
    if op == "startPointLedgerExport":
        # 202: the job is accepted, not finished — matches the users export.
        return _resp(202, ctx.exports.start_export(body, principal=p))
    if op == "getPointLedgerExport":
        return _resp(200, ctx.exports.get_export(params["jobId"], principal=p))
    if op == "communityTrend":
        return _resp(200, ctx.reads.community_trend(qs, principal=p))
    if op == "exportContributions":
        return _resp(200, ctx.reads.export(qs, principal=p))  # US-6.14 aggregated per-member-per-group
    if op == "memberLedger":
        return _resp(200, ctx.adjustments.member_ledger(qs, principal=p))
    if op == "listOwnSubmissions":
        return _resp(200, ctx.submissions.my_submissions(principal=p))
    if op == "submitContribution":
        return _resp(201, ctx.submissions.submit(body, principal=p))
    if op == "withdrawSubmission":
        ctx.submissions.withdraw(params["id"], principal=p)
        return _no_content()
    if op == "listPending":
        return _resp(200, ctx.submissions.queue(qs, principal=p))
    if op == "decideSubmission":
        return _resp(200, ctx.submissions.decide(params["id"], body, principal=p))
    if op == "adjustPoints":
        return _resp(200, ctx.adjustments.adjust(body, principal=p))
    if op == "reverseEntry":
        return _resp(200, ctx.adjustments.reverse(body, principal=p))
    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


# ---------------------------------------------------------------- entrypoints

# Module-level Context singleton, reused across warm Lambda invocations.
# Building a fresh Context per request threw away FrameworkService's warm-container
# cache (and rebuilt the boto3 resource, idempotency store, and clients every
# time), so every getFramework re-ran three sequential DynamoDB queries (~1160ms).
# The cache still invalidates correctly on CL writes via FrameworkService._bust();
# the 60s TTL bounds staleness across other warm containers. Lazily initialized so
# cold-start env/resource setup happens on first invocation, matching prior timing.
_CONTEXT = None


def _context():
    global _CONTEXT
    if _CONTEXT is None:
        _CONTEXT = Context()
    return _CONTEXT


@global_handler
def api_handler(event, context):
    try:
        return dispatch_http(event, _context())
    except AppError as err:
        return to_response(err)


def _sqs_records(event):
    for rec in event.get("Records", []):
        try:
            yield json.loads(rec["body"])
        except (ValueError, TypeError, KeyError):
            continue


@global_handler
def consumer_handler(event, context):
    """SQS: Forum / Certification / Identity domain events. Each SQS body is the
    EventBridge event; the domain envelope is under `detail`."""
    ctx = _context()
    for msg in _sqs_records(event):
        env = msg.get("detail") or msg
        etype = env.get("type") or msg.get("detail-type") or ""
        if etype in ("ForumPostCreated", "ReplyAccepted"):
            ctx.forum_consumer.handle(env)
        elif etype == "CertificationApproved":
            ctx.cert_consumer.handle(env)
        elif etype in ("MemberJoinedGroup", "MemberLeftGroup", "MemberRemoved",
                       "UserDeactivated", "UserReactivated", "UserProvisioned",
                       "UserRoleChanged", "MembershipChanged",
                       # Member-Profiles' photo/name change. This allowlist is a
                       # SECOND gate after the EventBridge rule — adding the type
                       # to the rule alone delivers the message here and drops it
                       # silently, which is exactly what happened on first deploy.
                       "MemberProfileUpserted"):
            ctx.membership_consumer.handle(env)
    return {"ok": True}


@global_handler
def award_worker_handler(event, context):
    """SQS: Events' per-earner award events (AttendanceRecorded / EventDelivered
    / EventOrganized), routed from EventBridge. Bounded reserved concurrency."""
    ctx = _context()
    for record in _sqs_records(event):
        ctx.award_worker.handle(record)
    return {"ok": True}


@global_handler
def rollup_handler(event, context):
    """DynamoDB Stream (ledger) -> rollups (exactly-once, Q2=A′)."""
    ctx = _context()
    return ctx.rollup.handle(event.get("Records", []))


@global_handler
def sweep_handler(event, context):
    """Nightly EventBridge Scheduler -> the four DL14 aggregates."""
    ctx = _context()
    group_ids = event.get("groupIds") or []
    return ctx.sweep.run(group_ids=group_ids)


# Default handler (mock scaffold parity): route HTTP.
handler = api_handler
