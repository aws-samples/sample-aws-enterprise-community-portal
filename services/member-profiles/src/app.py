"""REAL Lambda handler for member-profiles (replaces mock_handler as the deployed
entrypoint). Routes API Gateway proxy events to domain services with in-service
fail-closed authZ (SECURITY-08), and handles the EventBridge-rule branch for the
6 Identity & Access events this service consumes (US-3.1/3.3/3.4 data freshness).
Wrapped by global_handler so no exception escapes (SECURITY-15).
"""
from __future__ import annotations

import json
import os
import re

from _conventions.authz import Principal, claims_to_headers, extract_claims
from _conventions.errors import AppError, ValidationError, global_handler, to_response
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import set_correlation_id
from activity_service import ActivityService
from directory_service import DirectoryService
from event_consumer import EventConsumer
from export_service import ExportService
from fan_out_client import FanOutClient
from profile_service import ProfileService
from providers import AvatarStorage, EventPublisher, ExportStorage, SettingsCache
from repository import ProfileRepository
from shoutout_service import ShoutoutService

# Operation table: (method, path) -> operationId. Mirrors the frozen OpenAPI
# (US-3.8/3.9's /admin/members removed — reassigned to Identity & Access).
OPERATIONS = {
    ("GET", "/members"): "browseDirectory",
    ("GET", "/members/me"): "getOwnProfile",
    ("PUT", "/members/me"): "updateOwnProfile",
    ("POST", "/members/me/avatar-upload"): "grantAvatarUpload",
    # Async directory CSV export (CL/UGL only). Placed BEFORE the "/members/{id}"
    # patterns: routes are matched in order, so "export" would otherwise bind as
    # {id} — the same ordering requirement "/members/me" above already relies on.
    ("POST", "/members/export"): "startDirectoryExport",
    ("GET", "/members/export/{id}"): "getDirectoryExport",
    ("GET", "/members/{id}"): "getMember",
    ("GET", "/members/{id}/activity"): "memberActivity",
    ("POST", "/members/reindex"): "reindexMembers",
    ("POST", "/shoutouts"): "sendShoutout",
    ("GET", "/shoutouts/recent"): "recentShoutouts",
    ("GET", "/shoutouts/all"): "allShoutouts",
    ("GET", "/shoutouts/my-sent"): "mySentShoutouts",
    ("GET", "/shoutouts/my-received"): "myReceivedShoutouts",
    ("GET", "/shoutouts/quota"): "shoutoutQuota",
    ("GET", "/shoutouts/member/{id}"): "memberShoutouts",
    ("DELETE", "/shoutouts/{id}"): "deleteShoutout",
    ("POST", "/shoutouts/{id}/react"): "reactShoutout",
}

# Identity & Access event detail-types this service consumes (Infra Design Q3).
CONSUMED_EVENT_TYPES = {
    "UserProvisioned", "UserRoleChanged", "UserDeactivated", "UserReactivated",
    "MemberJoinedGroup", "MemberLeftGroup", "MemberRemoved",
}


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
    """Wires repository + fan-out client + providers + services. Injected in tests."""

    def __init__(self, table=None, idempotency_table=None, fan_out=None, events=None,
                 settings_cache=None, export_storage=None, lambda_client=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = ProfileRepository(table)
        self.idempotency = IdempotencyStore(
            idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", ""),
        ) if (idempotency_table or os.environ.get("IDEMPOTENCY_TABLE")) else None
        self.fan_out = fan_out or FanOutClient()
        self.events = events or EventPublisher()
        self.settings_cache = settings_cache or SettingsCache()
        self.avatar_storage = AvatarStorage()
        self.event_consumer = EventConsumer(self.repo, self.idempotency)
        self.profile_service = ProfileService(self.repo, self.fan_out, self.events,
                                              self.avatar_storage)
        self.activity_service = ActivityService(self.repo, self.fan_out)
        self.directory_service = DirectoryService(self.repo, self.fan_out, self.settings_cache)
        self.shoutout_service = ShoutoutService(self.repo, self.events, self.fan_out)
        self.export_storage = export_storage or ExportStorage()
        self.export_service = ExportService(self.repo, self.export_storage,
                                           fan_out=self.fan_out, lambda_client=lambda_client)


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


def _bearer_token(event) -> str | None:
    """Forward the calling principal's own JWT to fan-out calls (Infra Design Q2) —
    no service-to-service credential is minted; downstream authz applies unchanged."""
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:]
    return auth


def dispatch(event: dict, ctx: Context) -> dict:
    # EventBridge rule branch (Identity & Access's consumed events) — not an HTTP route.
    detail_type = event.get("detail-type") or event.get("type")
    if detail_type in CONSUMED_EVENT_TYPES:
        ctx.event_consumer.handle(event.get("detail") or event)
        return _resp(200, {"status": "processed"})

    # Nightly / on-schedule OpenSearch reindex — not an HTTP route.
    if event.get("source") == "scheduled-reindex":
        return _resp(200, ctx.directory_service.reindex_members())

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
        if principal is None:
            return _resp(401, {"code": "UNAUTHORIZED", "message": "Authentication required."})
        qs = event.get("queryStringParameters") or {}
        return _execute(ctx, op, params, body, qs, principal, event)
    except AppError as err:
        # Include per-field `details` when present so a validation failure is
        # readable ("bio: length must be 1-2000") instead of a bare
        # "Validation failed." — the SPA's apiFetch already appends them.
        # Matches certifications / contributions-scoring.
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _validate_choice(raw: str | None, name: str, allowed: set[str]) -> None:
    if raw and raw not in allowed:
        from _conventions.errors import ValidationError as _VE  # noqa: PLC0415
        raise _VE(f"{name} must be one of: {', '.join(sorted(allowed))}.")


def _parse_limit(raw: str | None) -> int | None:
    """Page size for browseDirectory (D-P4): optional, integer, 1..200.
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


def _execute(ctx, op, params, body, qs, principal, event) -> dict:
    token = _bearer_token(event)
    # Fresh claims forwarded on every internal (private-API) call so the
    # downstream builds its principal from them (the private API has no
    # authorizer). Sent alongside the JWT during rollout.
    ch = claims_to_headers(principal)
    p, a, d = ctx.profile_service, ctx.activity_service, ctx.directory_service

    if op == "getOwnProfile":
        return _resp(200, p.get_own_profile(principal.user_id, bearer_token=token, claim_headers=ch))
    if op == "updateOwnProfile":
        return _resp(200, p.update_own_profile(principal.user_id, body, bearer_token=token, claim_headers=ch))
    if op == "grantAvatarUpload":
        return _resp(200, p.grant_avatar_upload(principal.user_id, body))
    if op == "getMember":
        return _resp(200, p.get_member(params["id"], principal_role=principal.role,
                                      principal=principal, bearer_token=token, claim_headers=ch))
    if op == "browseDirectory":
        _validate_choice(qs.get("sort"), "sort",
                         {"firstName", "lastName", "email", "role", "city",
                          "country", "status", "awsProject"})
        _validate_choice(qs.get("sortDir"), "sortDir", {"asc", "desc"})
        # The whole Principal, not just its role: the listing is group-scoped for
        # Members and needs `member_group_ids`. Passing only `principal.role` is
        # what kept this endpoint community-wide for every caller.
        return _resp(200, d.browse(
            principal=principal,
            q=qs.get("q"), role=qs.get("role"), group_id=qs.get("groupId"),
            cert_id=qs.get("certId"),
            limit=_parse_limit(qs.get("limit")), cursor=qs.get("cursor"),
            sort=qs.get("sort", "firstName"), sort_dir=qs.get("sortDir", "asc"),
            bearer_token=token, claim_headers=ch,
        ))
    if op == "startDirectoryExport":
        # 202: the CSV does not exist yet. The worker builds it asynchronously
        # and the SPA polls getDirectoryExport for progress. Role is enforced in
        # the service (CL/UGL only), which is a STRICTER gate than the listing's
        # own group scoping — a Member can browse their groups but cannot export.
        return _resp(202, ctx.export_service.start_export(
            body, principal=principal, bearer_token=token, claim_headers=ch))
    if op == "getDirectoryExport":
        return _resp(200, ctx.export_service.get_export(params["id"], principal=principal))
    if op == "reindexMembers":
        return _resp(200, d.reindex_members())
    if op == "memberActivity":
        return _resp(200, a.get_activity(
            params["id"], principal_role=principal.role,
            principal_led_group_id=principal.led_group_id,
            date_from=qs.get("from"), date_to=qs.get("to"), bearer_token=token,
            claim_headers=ch,
        ))

    # ---- Shoutouts (US-13) ----
    s = ctx.shoutout_service
    if op == "sendShoutout":
        return _resp(201, s.send(body, principal=principal, bearer_token=token, claim_headers=ch))
    if op == "recentShoutouts":
        return _resp(200, s.recent_feed())
    if op == "allShoutouts":
        qs = event.get("queryStringParameters") or {}
        return _resp(200, s.all_feed(cursor=qs.get("cursor"), limit=int(qs.get("limit", "20"))))
    if op == "mySentShoutouts":
        qs = event.get("queryStringParameters") or {}
        return _resp(200, s.my_sent(principal=principal, cursor=qs.get("cursor"), limit=int(qs.get("limit", "20"))))
    if op == "myReceivedShoutouts":
        qs = event.get("queryStringParameters") or {}
        return _resp(200, s.member_shoutouts(principal.user_id, cursor=qs.get("cursor"), limit=int(qs.get("limit", "20"))))
    if op == "shoutoutQuota":
        return _resp(200, s.my_quota(principal=principal, bearer_token=token, claim_headers=ch))
    if op == "memberShoutouts":
        return _resp(200, s.member_shoutouts(params["id"]))
    if op == "deleteShoutout":
        s.delete(params["id"], principal=principal)
        return _resp(204, {})
    if op == "reactShoutout":
        return _resp(200, s.toggle_reaction(params["id"], principal=principal))

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)
