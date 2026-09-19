"""REAL Lambda handler for events (replaces mock_handler as the deployed entrypoint).

FOUR dispatch branches converge on one function (J4):
  1. authenticated HTTP  — /events*            (Cognito authorizer at the edge)
  2. public HTTP         — /event-uploads/{token}  (NO authorizer, token-gated)
  3. domain event        — GroupSoftDeleted
  4. object events       — S3 Object Created/Deleted, GuardDuty scan results

Separate functions per branch would triple the deployment surface for workloads
measured in single-digit invocations per minute; Member Profiles and Settings
already establish the shared-branch pattern.

Everything is wrapped by `global_handler` so no exception escapes (SECURITY-15).
The public branch is checked FIRST and never consults claims, so an authorizer
misconfiguration cannot accidentally make it require or leak identity.
"""
from __future__ import annotations

import json
import os
import re

from _conventions.authz import Principal, claims_to_headers, extract_claims
from _conventions.errors import (
    AppError,
    ForbiddenError,
    ValidationError,
    global_handler,
    to_response,
)
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import set_correlation_id
from attendance_service import AttendanceService
from consumers import GroupEventConsumer, MalwareScanConsumer, S3ObjectConsumer
from designation_service import DesignationService
from event_service import EventService
from event_ideas_service import EventIdeasService
from library_consumers import ContributionApprovedConsumer
from library_repository import LibraryRepository
from library_service import LibraryService
from material_service import MaterialService
from providers import (
    ContributionsClient,
    DirectoryClient,
    EventPublisher,
    S3Storage,
    SettingsCache,
    TeamsProvider,
)
from repository import EventRepository
from repository import EventIdeasRepository
from rsvp_service import RsvpService
from upload_link_service import UploadLinkService

# (method, path) -> operationId. Mirrors contracts/services/events/openapi.yaml.
# Literal segments MUST precede templated ones so /events/calendar is not
# swallowed by /events/{id}.
OPERATIONS = [
    ("GET", "/events"), ("POST", "/events"),
    ("GET", "/events/calendar"),
    # Literal, and listed before the templated paths so "stats" is never taken
    # for an event id (same reason as /events/calendar above).
    ("GET", "/events/stats/by-type"),
    ("GET", "/events/stats/by-group"),
    ("GET", "/events/{id}/ics"),
    ("POST", "/events/{id}/complete"),
    ("POST", "/events/{id}/rsvp"),
    ("GET", "/events/{id}/rsvps"),
    ("POST", "/events/{id}/materials/upload-url"),
    ("GET", "/events/{id}/materials"), ("POST", "/events/{id}/materials"),
    ("PUT", "/events/{id}/materials/{materialId}"),
    ("DELETE", "/events/{id}/materials/{materialId}"),
    ("POST", "/events/{id}/attendance/teams/apply"),
    ("GET", "/events/{id}/attendance/teams"),
    ("POST", "/events/{id}/attendance/import"),
    ("POST", "/events/{id}/attendance"),
    ("GET", "/events/{id}/designations"), ("PUT", "/events/{id}/designations"),
    ("GET", "/events/{id}/upload-links"), ("POST", "/events/{id}/upload-links"),
    ("GET", "/events/{id}/upload-links/{linkId}/url"),
    ("GET", "/events/{id}/upload-links/{linkId}/files"),
    ("DELETE", "/events/{id}/upload-links/{linkId}"),
    # Event Ideas (US-14) — MUST be before ("/events/{id}") or /{id} will match "ideas"
    ("POST", "/events/ideas"),
    ("GET", "/events/ideas"),
    ("GET", "/events/ideas/backlog"),
    ("GET", "/events/ideas/sweep"),
    ("POST", "/events/ideas/{id}/vote"),
    ("POST", "/events/ideas/{id}/greenlight"),
    ("POST", "/events/ideas/{id}/decline"),
    ("GET", "/events/ideas/{id}"),
    ("GET", "/events/{id}"), ("PUT", "/events/{id}"), ("DELETE", "/events/{id}"),
    # Content Library (US-2.20 rework) — standalone /library base path
    ("GET", "/library"),
    ("GET", "/library/tags"),
    ("POST", "/library"),
    ("PUT", "/library/{id}"),
    ("DELETE", "/library/{id}"),
]

OPERATION_IDS = {
    ("GET", "/events"): "listEvents",
    ("POST", "/events"): "createEvent",
    ("GET", "/events/calendar"): "calendar",
    ("GET", "/events/stats/by-type"): "eventStatsByType",
    ("GET", "/events/stats/by-group"): "eventStatsByGroup",
    ("GET", "/events/{id}"): "getEvent",
    ("PUT", "/events/{id}"): "editEvent",
    ("DELETE", "/events/{id}"): "cancelEvent",
    ("POST", "/events/{id}/complete"): "completeEvent",
    ("GET", "/events/{id}/ics"): "getEventIcs",
    ("POST", "/events/{id}/rsvp"): "rsvpEvent",
    ("GET", "/events/{id}/rsvps"): "listRsvps",
    ("GET", "/events/{id}/materials"): "listMaterials",
    ("POST", "/events/{id}/materials"): "addMaterial",
    ("POST", "/events/{id}/materials/upload-url"): "getMaterialUploadUrl",
    ("PUT", "/events/{id}/materials/{materialId}"): "replaceMaterial",
    ("DELETE", "/events/{id}/materials/{materialId}"): "removeMaterial",
    ("POST", "/events/{id}/attendance"): "recordAttendance",
    ("POST", "/events/{id}/attendance/import"): "importAttendanceCsv",
    ("GET", "/events/{id}/attendance/teams"): "teamsAttendance",
    ("POST", "/events/{id}/attendance/teams/apply"): "applyTeamsAttendance",
    ("GET", "/events/{id}/designations"): "listDesignations",
    ("PUT", "/events/{id}/designations"): "setDesignations",
    ("GET", "/events/{id}/upload-links"): "listUploadLinks",
    ("POST", "/events/{id}/upload-links"): "createUploadLink",
    ("GET", "/events/{id}/upload-links/{linkId}/url"): "getUploadLinkUrl",
    ("DELETE", "/events/{id}/upload-links/{linkId}"): "revokeUploadLink",
    ("GET", "/events/{id}/upload-links/{linkId}/files"): "listUploadedFiles",
    # Event Ideas
    ("POST", "/events/ideas"): "submitIdea",
    ("GET", "/events/ideas"): "browseIdeas",
    ("GET", "/events/ideas/backlog"): "ideasBacklog",
    ("GET", "/events/ideas/sweep"): "ideasSweep",
    ("POST", "/events/ideas/{id}/vote"): "voteIdea",
    ("POST", "/events/ideas/{id}/greenlight"): "greenlightIdea",
    ("POST", "/events/ideas/{id}/decline"): "declineIdea",
    ("GET", "/events/ideas/{id}"): "getIdea",
    # Content Library (US-2.20 rework)
    ("GET", "/library"): "searchLibrary",
    ("GET", "/library/tags"): "listLibraryTags",
    ("POST", "/library"): "addLibraryResource",
    ("PUT", "/library/{id}"): "updateLibraryResource",
    ("DELETE", "/library/{id}"): "deleteLibraryResource",
}

PUBLIC_UPLOAD_PATH = re.compile(r"^/event-uploads/(?P<token>[^/]+)$")

CONSUMED_EVENT_TYPES = {"GroupSoftDeleted", "ContributionApproved"}
S3_EVENT_TYPES = {"Object Created", "Object Deleted"}


def _json_default(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status: int, body) -> dict:
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body, default=_json_default)}


def _text_resp(status: int, body: str, content_type: str, filename: str) -> dict:
    return {"statusCode": status,
            "headers": {"Content-Type": content_type,
                        "Content-Disposition": f'attachment; filename="{filename}"',
                        "Access-Control-Allow-Origin": "*"},
            "body": body}


def _compile(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", path) + "$")


_COMPILED = [(method, _compile(path), OPERATION_IDS[(method, path)])
             for method, path in OPERATIONS]


class Context:
    """Wires repository + providers + services. Injected wholesale in tests."""

    def __init__(self, table=None, idempotency_table=None, storage=None, events=None,
                 contributions=None, teams=None, settings=None, directory=None,
                 ideas_table=None, library_table=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = EventRepository(table)
        # Separate ideas table (Event Ideas feature, US-14)
        if ideas_table is None and os.environ.get("IDEAS_TABLE_NAME"):
            import boto3
            ideas_table = boto3.resource("dynamodb").Table(os.environ["IDEAS_TABLE_NAME"])
        self.ideas_repo = EventIdeasRepository(ideas_table) if ideas_table else None
        self.repo = EventRepository(table)
        idem_name = idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", "")
        self.idempotency = IdempotencyStore(idem_name) if idem_name else None
        self.storage = storage or S3Storage()
        self.events = events or EventPublisher()
        self.contributions = contributions or ContributionsClient()
        self.settings = settings or SettingsCache()
        self.teams = teams or TeamsProvider(enabled=self.settings.teams_enabled())

        self.directory = directory or DirectoryClient()
        self.designations = DesignationService(self.repo, self.events, self.contributions,
                                               directory=self.directory)

        # Content Library (US-2.20 rework) — wired before EventService/MaterialService
        # so both can hold a reference.
        lib_table_name = os.environ.get("LIBRARY_TABLE_NAME", "")
        if library_table is None and lib_table_name:
            import boto3
            library_table = boto3.resource("dynamodb").Table(lib_table_name)
        self.library_repo = LibraryRepository(library_table) if library_table else None
        self.library = (LibraryService(self.library_repo, self.repo, self.storage, self.events)
                        if self.library_repo else None)

        self.event_service = EventService(self.repo, self.events, self.contributions,
                                          self.designations,
                                          library=self.library)
        self.ideas = EventIdeasService(self.ideas_repo, self.events) if self.ideas_repo else None
        self.rsvps = RsvpService(self.repo, self.events)
        self.attendance = AttendanceService(self.repo, self.events, self.contributions,
                                           self.teams, self.settings, self.event_service)
        self.materials = MaterialService(self.repo, self.storage, self.events,
                                         library=self.library)
        self.upload_links = UploadLinkService(self.repo, self.storage, self.events)

        self.group_consumer = GroupEventConsumer(self.event_service, self.idempotency)
        self.s3_consumer = S3ObjectConsumer(self.repo, self.idempotency, library=self.library)
        self.scan_consumer = MalwareScanConsumer(self.repo, self.events, self.idempotency,
                                                 library=self.library)
        self.contribution_consumer = ContributionApprovedConsumer(
            self.library, self.idempotency) if self.library else None


def _match(method: str, path: str):
    for expected, rx, op in _COMPILED:
        if expected == method:
            found = rx.match(path)
            if found:
                return op, found.groupdict()
    return None, None


def _principal(event) -> Principal | None:
    claims = extract_claims(event)
    if not claims:
        return None
    principal = Principal.from_claims(claims)
    # `email`/`name` are not part of the shared Principal but several operations
    # denormalise them (RSVP rows, upload-link ownership) to avoid a per-row
    # cross-service lookup — the anti-pattern removed from Settings. given_name/
    # family_name are standard Cognito claims, set at user creation (US-1.30/1.31).
    principal.email = claims.get("email", "")
    principal.name = " ".join(
        p for p in (claims.get("given_name", "").strip(),
                    claims.get("family_name", "").strip()) if p)
    return principal


def _bearer_token(event) -> str | None:
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:]
    return auth


def _parse_limit(raw, *, default: int = 25) -> int:
    if raw is None or raw == "":
        return default
    try:
        limit = int(raw)
    except (ValueError, TypeError):
        raise ValidationError("limit must be an integer.") from None
    if not 1 <= limit <= 200:
        raise ValidationError("limit must be between 1 and 200.")
    return limit


def dispatch(event: dict, ctx: Context) -> dict:
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    set_correlation_id((event.get("headers") or {}).get("X-Correlation-Id"))
    correlation_id = (event.get("headers") or {}).get("X-Correlation-Id")

    # --- backfill / reconciliation: full DynamoDB -> OpenSearch reindex ------
    # Not an HTTP route. Invoked directly (aws lambda invoke) with
    # {"source": "library-reindex"} by scripts/backfill_library_opensearch.py.
    # MUST run in-VPC: the AOSS collection is VPC-only (foundation network policy
    # AllowFromPublic:false), so a local script cannot reach the endpoint. This
    # mirrors member-profiles' scheduled-reindex branch.
    if event.get("source") == "library-reindex":
        if ctx.library_repo is None:
            return _resp(503, {"code": "SERVICE_UNAVAILABLE",
                               "message": "Content Library table not configured."})
        return _resp(200, {"indexed": ctx.library_repo.reindex_all()})

    # --- branch 3/4: event-driven inputs (no HTTP context) -------------------
    detail_type = event.get("detail-type") or event.get("type")
    if detail_type == "ContributionApproved":
        if ctx.contribution_consumer:
            ctx.contribution_consumer.handle(event)
        return _resp(200, {"status": "processed"})
    if detail_type in CONSUMED_EVENT_TYPES:
        ctx.group_consumer.handle(event.get("detail") or event, correlation_id=correlation_id)
        return _resp(200, {"status": "processed"})
    if detail_type in S3_EVENT_TYPES:
        return _resp(200, ctx.s3_consumer.handle(event))
    if detail_type and "Malware Protection" in str(detail_type):
        return _resp(200, ctx.scan_consumer.handle(event, correlation_id=correlation_id))

    body = {}
    if event.get("body"):
        try:
            body = json.loads(event["body"])
        except (ValueError, TypeError):
            return _resp(400, {"code": "VALIDATION_ERROR", "message": "Invalid JSON body."})

    # --- branch 2: PUBLIC upload mint (unauthenticated) ----------------------
    # Deliberately before any claims handling: this route must never depend on,
    # or leak, caller identity.
    public = PUBLIC_UPLOAD_PATH.match(path)
    # (The /event-uploads/{token} public-mint path was removed in the 2026-08-13
    # rework — external uploads now use a direct presigned S3 PUT URL minted
    # via the Copy Link action, with no portal API token exchange needed.)

    # --- branch 1: authenticated HTTP ----------------------------------------
    op, params = _match(method, path)
    if op is None:
        return _resp(404, {"code": "NOT_FOUND", "message": "Resource not found."})

    try:
        principal = _principal(event)
        if principal is None:
            return _resp(401, {"code": "UNAUTHORIZED", "message": "Authentication required."})
        # BR-A1 — Administrators have NO event permissions, including reads. One
        # check at the boundary rather than per-operation, so a new operation
        # cannot accidentally be exposed to them.
        if principal.role == "Administrator":
            raise ForbiddenError(message="Administrators do not participate in events.")
        qs = event.get("queryStringParameters") or {}
        return _execute(ctx, op, params, body, qs, principal, event, correlation_id)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _execute(ctx, op, params, body, qs, principal, event, correlation_id) -> dict:
    token = _bearer_token(event)
    # Fresh claims forwarded on internal (private-API) calls (points framework,
    # designee directory lookup) so the downstream builds its principal from them.
    ch = claims_to_headers(principal)
    event_id = params.get("id")

    if op == "listEvents":
        return _resp(200, ctx.event_service.list(
            principal=principal, filters=qs, limit=_parse_limit(qs.get("limit")),
            cursor=qs.get("cursor"), bearer_token=token, claim_headers=ch))
    if op == "createEvent":
        return _resp(201, ctx.event_service.create(
            body, principal=principal, correlation_id=correlation_id,
            bearer_token=token, claim_headers=ch))
    if op == "calendar":
        return _resp(200, ctx.event_service.calendar(
            principal=principal, filters=qs, bearer_token=token, claim_headers=ch))
    if op == "eventStatsByGroup":
        qs = event.get("queryStringParameters") or {}
        return _resp(200, ctx.event_service.stats_by_group(qs, principal=principal))
    if op == "eventStatsByType":
        return _resp(200, ctx.event_service.stats_by_type(qs, principal=principal))
    if op == "getEvent":
        return _resp(200, ctx.event_service.get(
            event_id, principal=principal, bearer_token=token, claim_headers=ch))
    if op == "editEvent":
        return _resp(200, ctx.event_service.edit(
            event_id, body, principal=principal, correlation_id=correlation_id))
    if op == "cancelEvent":
        ctx.event_service.cancel(event_id, principal=principal, correlation_id=correlation_id)
        return {"statusCode": 204, "headers": {"Access-Control-Allow-Origin": "*"}, "body": ""}
    if op == "completeEvent":
        return _resp(200, ctx.event_service.complete(
            event_id, principal=principal, correlation_id=correlation_id, bearer_token=token,
            claim_headers=ch))
    if op == "getEventIcs":
        ics = ctx.rsvps.ics_for(event_id, principal=principal)
        return _text_resp(200, ics, "text/calendar", f"{event_id}.ics")
    if op == "rsvpEvent":
        return _resp(200, ctx.rsvps.respond(
            event_id, body, principal=principal, correlation_id=correlation_id))
    if op == "listRsvps":
        return _resp(200, ctx.rsvps.list_for_event(event_id, principal=principal))
    if op == "listMaterials":
        return _resp(200, ctx.materials.list_for_event(event_id, principal=principal))
    if op == "addMaterial":
        return _resp(201, ctx.materials.add(
            event_id, body, principal=principal, correlation_id=correlation_id))
    if op == "getMaterialUploadUrl":
        return _resp(200, ctx.materials.upload_url(event_id, body, principal=principal))
    if op == "replaceMaterial":
        return _resp(200, ctx.materials.replace(
            event_id, params["materialId"], body, principal=principal))
    if op == "removeMaterial":
        ctx.materials.remove(event_id, params["materialId"], principal=principal)
        return {"statusCode": 204, "headers": {"Access-Control-Allow-Origin": "*"}, "body": ""}
    if op == "recordAttendance":
        return _resp(200, ctx.attendance.record(
            event_id, body, principal=principal, correlation_id=correlation_id,
            bearer_token=token))
    if op == "importAttendanceCsv":
        return _resp(200, ctx.attendance.import_csv(
            event_id, body, principal=principal, correlation_id=correlation_id,
            bearer_token=token))
    if op == "teamsAttendance":
        return _resp(200, ctx.attendance.teams_fetch(event_id, principal=principal))
    if op == "applyTeamsAttendance":
        return _resp(200, ctx.attendance.teams_apply(
            event_id, body, principal=principal, correlation_id=correlation_id,
            bearer_token=token))
    if op == "listDesignations":
        return _resp(200, ctx.designations.list_for(event_id, principal=principal,
                                                    bearer_token=token, claim_headers=ch))
    if op == "setDesignations":
        return _resp(200, ctx.designations.set(event_id, body, principal=principal,
                                               bearer_token=token, claim_headers=ch))
    if op == "listUploadLinks":
        return _resp(200, ctx.upload_links.list_for_event(event_id, principal=principal))
    if op == "createUploadLink":
        return _resp(201, ctx.upload_links.create(
            event_id, body, principal=principal, correlation_id=correlation_id))
    if op == "getUploadLinkUrl":
        return _resp(200, ctx.upload_links.get_upload_url(
            event_id, params["linkId"], principal=principal))
    if op == "revokeUploadLink":
        ctx.upload_links.delete(event_id, params["linkId"], principal=principal,
                                correlation_id=correlation_id)
        return {"statusCode": 204, "headers": {"Access-Control-Allow-Origin": "*"}, "body": ""}
    if op == "listUploadedFiles":
        return _resp(200, ctx.upload_links.list_files(
            event_id, params["linkId"], principal=principal))

    # ── Content Library (US-2.20 rework) ────────────────────────────────────
    if op in ("searchLibrary", "listLibraryTags", "addLibraryResource",
              "updateLibraryResource", "deleteLibraryResource"):
        if ctx.library is None:
            return _resp(503, {"code": "SERVICE_UNAVAILABLE",
                               "message": "Content Library table not configured."})
        if op == "searchLibrary":
            return _resp(200, ctx.library.search(
                principal=principal, filters=qs,
                limit=_parse_limit(qs.get("limit"), default=10),
                cursor=qs.get("cursor")))
        if op == "listLibraryTags":
            return _resp(200, ctx.library.get_tags(
                principal=principal, prefix=qs.get("prefix", "")))
        if op == "addLibraryResource":
            return _resp(201, ctx.library.add(body, principal=principal))
        if op == "updateLibraryResource":
            return _resp(200, ctx.library.edit(params["id"], body, principal=principal))
        if op == "deleteLibraryResource":
            ctx.library.remove(params["id"], principal=principal)
            return {"statusCode": 204,
                    "headers": {"Access-Control-Allow-Origin": "*"}, "body": ""}

    # ── Event Ideas (US-14) ──────────────────────────────────────────────────
    ideas = ctx.ideas
    if ideas is None:
        return _resp(503, {"code": "SERVICE_UNAVAILABLE", "message": "Event Ideas table not configured."})

    if op == "submitIdea":
        return _resp(201, ideas.submit(body, principal=principal))
    if op == "browseIdeas":
        return _resp(200, ideas.browse(
            principal=principal,
            group_id=qs.get("groupId"),
            status=qs.get("status"),
            submitter_id=qs.get("submitterId"),
            limit=int(qs.get("limit", "20")),
            cursor=qs.get("cursor"),
        ))
    if op == "ideasBacklog":
        return _resp(200, ideas.backlog(
            principal=principal,
            group_id=qs.get("groupId"),
            # Supplied by the CL's "All groups" view so the fan-out knows which
            # partitions exist — this service keeps no group registry.
            group_ids=qs.get("groupIds"),
            status=qs.get("status", "Open"),
            limit=int(qs.get("limit", "50")),
            cursor=qs.get("cursor"),
        ))
    if op == "ideasSweep":
        return _resp(200, ideas.sweep_stale())
    if op == "voteIdea":
        return _resp(200, ideas.toggle_vote(params["id"], principal=principal))
    if op == "greenlightIdea":
        return _resp(200, ideas.greenlight(params["id"], body, principal=principal))
    if op == "declineIdea":
        return _resp(200, ideas.decline(params["id"], body, principal=principal))
    if op == "getIdea":
        return _resp(200, ideas.get(params["id"], principal=principal))

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)
