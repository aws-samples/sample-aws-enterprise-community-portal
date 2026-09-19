"""REAL Lambda handler for identity-access (replaces mock_handler as the deployed
entrypoint). Routes API Gateway proxy events to domain services with in-service
fail-closed authZ (SECURITY-08). Wrapped by global_handler so no exception
escapes (SECURITY-15).
"""
from __future__ import annotations

import json
import os
import pathlib
import re

from _conventions.authz import Authorizer, Principal, extract_claims
from _conventions.errors import (
    AppError,
    ForbiddenError,
    UnauthorizedError,
    ValidationError,
    global_handler,
    to_response,
)
from _conventions.logger import set_correlation_id
from auth_service import AuthService
from export_service import ExportService
from group_service import GroupService
from otp_service import OtpService
from providers import (
    CognitoAuthProvider,
    EventPublisher,
    ExportStorage,
    SesAdapter,
    SettingsClient,
    SettingsView,
)
from repository import IdentityRepository
from user_service import UserService

# Operation table: (method, path) -> operationId. Mirrors the frozen OpenAPI.
OPERATIONS = {
    ("POST", "/auth/login"): "login",
    ("POST", "/auth/otp"): "verifyOtp",
    ("POST", "/auth/register"): "selfRegister",
    ("POST", "/auth/reset"): "resetPassword",
    ("POST", "/auth/reset/confirm"): "confirmResetPassword",
    ("POST", "/auth/logout"): "logout",
    ("GET", "/groups"): "listGroups",
    ("POST", "/groups"): "createGroup",
    ("GET", "/groups/my-memberships"): "myMemberships",
    ("GET", "/groups/{id}"): "getGroup",
    ("PUT", "/groups/{id}"): "editGroup",
    ("DELETE", "/groups/{id}"): "deleteGroup",
    ("POST", "/groups/{id}/join"): "joinGroup",
    ("POST", "/groups/{id}/join/withdraw"): "withdrawJoinRequest",
    ("POST", "/groups/{id}/leave"): "leaveGroup",
    ("GET", "/groups/{id}/requests"): "listJoinRequests",
    ("POST", "/groups/{id}/requests/{requestId}"): "decideJoinRequest",
    ("POST", "/groups/{id}/restore"): "restoreGroup",
    ("GET", "/join-requests"): "listAllJoinRequests",
    # MUST precede /groups/{id}/members: routes are matched in order and "stats"
    # would otherwise bind as {id}, silently serving a member list for a group
    # that does not exist.
    ("GET", "/groups/stats/members"): "membersByGroup",
    # Async roster CSV export (UGL > My Group > Export, and CL viewing a group).
    # Listed before "/groups/{id}/members" for readability; unlike the
    # /users/export case there is no shadowing risk here, because that pattern
    # anchors at the end of "members" and cannot swallow a longer path.
    ("POST", "/groups/{id}/members/export"): "startGroupMemberExport",
    ("GET", "/groups/{id}/members/export/{jobId}"): "getGroupMemberExport",
    ("GET", "/groups/{id}/members"): "listGroupMembers",
    ("GET", "/groups/{id}/growth"): "groupGrowth",
    ("POST", "/groups/{id}/leaders"): "assignLeader",
    ("DELETE", "/groups/{id}/members/{memberId}"): "removeMember",
    ("GET", "/users"): "listUsers",
    ("POST", "/users"): "createUser",
    # Async CSV export (US-1.4 export action). MUST precede the "/users/{id}"
    # patterns: routes are matched in order and "export" would otherwise bind as
    # {id} — the same trap documented above for /groups/stats/members.
    ("POST", "/users/export"): "startUserExport",
    ("GET", "/users/export/{id}"): "getUserExport",
    ("PUT", "/users/{id}"): "editUser",
    ("POST", "/users/{id}/disable"): "disableUser",
    ("POST", "/users/{id}/enable"): "enableUser",
    ("POST", "/users/import"): "bulkImport",
    ("POST", "/admin/reindex-users"): "reindexUsers",
    ("GET", "/membership-history"): "membershipHistory",
    ("GET", "/community-stats"): "communityStats",
    ("GET", "/auth/claims"): "refreshClaims",
    ("POST", "/auth/refresh"): "refreshSession",
}

# `refreshSession` is public for the same reason `login` is: the refresh token IS
# the credential being presented, and the ID token it replaces may be the stale
# one the caller is trying to get rid of. /auth/* carries no Cognito authorizer,
# so an authenticated-only op here would be unreachable, not merely stricter.
PUBLIC_OPS = {"login", "verifyOtp", "selfRegister", "resetPassword",
              "confirmResetPassword", "refreshSession"}

# operationId -> (action, resource) in the permission matrix. None => any authenticated user.
OP_AUTHZ = {
    "listUsers": ("list", "admin-member-list"),
    # Single Add User (US-1.35) is the same Administrator capability class as
    # bulk import (row-of-one) — reuses the bulk-import permission.
    "createUser": ("bulk-import", "user"),
    "editUser": ("edit", "user"),
    "disableUser": ("disable-enable", "user"),
    "enableUser": ("disable-enable", "user"),
    "bulkImport": ("bulk-import", "user"),
    # Reindex triggers a full DynamoDB → OpenSearch reconciliation.
    # Same Administrator-only capability class as bulk-import.
    "reindexUsers": ("bulk-import", "user"),
    # CSV export IS a read of the admin member list, so it shares listUsers'
    # capability. Note the resource matters beyond naming: _authorize passes
    # params["id"] as owner_id whenever resource == "user", and for
    # getUserExport that {id} is an EXPORT JOB id, not a user id — feeding it to
    # the ownership guard would be meaningless. "admin-member-list" takes no
    # owner, so the job id is never mistaken for a subject.
    "startUserExport": ("list", "admin-member-list"),
    "getUserExport": ("list", "admin-member-list"),
    "createGroup": ("create", "user-group"),
    "editGroup": ("edit", "user-group"),
    "deleteGroup": ("delete", "user-group"),
    "assignLeader": ("assign", "user-group-leader"),
    "listGroupMembers": ("view", "user-group-directory"),
    # The roster export IS a read of the group directory, so it shares
    # listGroupMembers' capability exactly: whoever may view the list may export
    # it, and nobody gains a new power. That grants Community Leaders and User
    # Group Leaders; Administrators hold no user-group-directory permission and
    # are refused here just as they are on the listing itself.
    #
    # `resource` contains "group", so _authorize below passes params["id"] as the
    # resource_group_id — the GROUP id, which is what scope checks need. Note for
    # getGroupMemberExport the job id arrives as {jobId}, deliberately not {id},
    # so it can never be mistaken for the group being authorized.
    "startGroupMemberExport": ("view", "user-group-directory"),
    "getGroupMemberExport": ("view", "user-group-directory"),
    "removeMember": ("remove", "group-member"),
    "joinGroup": ("join", "user-group"),
    "withdrawJoinRequest": ("join", "user-group"),  # withdrawing = own join lifecycle
    "leaveGroup": ("leave", "user-group"),
    "listJoinRequests": ("approve", "join-request"),
    "decideJoinRequest": ("approve", "join-request"),
    # Delete + restore are the same CL-only capability class (US-1.11).
    "restoreGroup": ("delete", "user-group"),
    # Cross-group queue: CL's approve/join-request is global scope; UGL's is
    # group-scoped and no group id is passed here, so UGLs are denied (they
    # use the per-group tab instead).
    "listAllJoinRequests": ("approve", "join-request"),
}

_MATRIX_PATH = os.environ.get(
    "PERMISSION_MATRIX_PATH",
    str(pathlib.Path(__file__).with_name("permission_matrix.json")),
)

# Warm-container settings client (cache survives across invocations).
_SETTINGS_CLIENT: SettingsClient | None = None


def _settings_client() -> SettingsClient:
    global _SETTINGS_CLIENT  # noqa: PLW0603 — intentional warm-container singleton
    if _SETTINGS_CLIENT is None:
        domains = [d.strip() for d in os.environ.get("ALLOWED_EMAIL_DOMAINS", "").split(",") if d.strip()]
        _SETTINGS_CLIENT = SettingsClient(env_defaults={
            "allowedEmailDomains": domains,
            # Defaults to FALSE (fail closed, SECURITY-15). This value is only
            # consulted when the Settings service is UNREACHABLE; a default of
            # "true" meant a settings outage silently re-enabled self-registration
            # — the one path that emails nothing and asserts email_verified itself
            # — while the SPA correctly kept the tab hidden, so nobody would see it.
            # Matches allowedEmailDomains, whose empty-list fallback already blocks.
            "selfRegistrationEnabled": os.environ.get("SELF_REGISTRATION_ENABLED", "false").lower() == "true",
            "otpIntervalDays": int(os.environ.get("OTP_INTERVAL_DAYS", "30")),
        })
    return _SETTINGS_CLIENT


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

    def __init__(self, table=None, auth_provider=None, events=None,
                 ses=None, authorizer=None, settings=None,
                 export_storage=None, lambda_client=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = IdentityRepository(table)
        self.auth_provider = auth_provider or CognitoAuthProvider()
        self.events = events or EventPublisher()
        self.ses = ses or SesAdapter()
        self.otp = OtpService(self.repo, self.ses)
        self.settings = settings or self._default_settings()
        self.authorizer = authorizer or self._load_authorizer()
        self.auth_service = AuthService(self.repo, self.auth_provider, self.otp,
                                        self.events, self.settings, self.ses)
        self.user_service = UserService(self.repo, self.auth_provider, self.events, self.ses)
        self.group_service = GroupService(self.repo, self.events)
        self.export_storage = export_storage or ExportStorage()
        self.export_service = ExportService(self.repo, self.export_storage,
                                           lambda_client=lambda_client)

    @staticmethod
    def _load_authorizer() -> Authorizer:
        try:
            return Authorizer.from_file(_MATRIX_PATH)
        except OSError:
            return Authorizer({"permissions": {}})  # fail closed (deny all writes)

    @staticmethod
    def _default_settings() -> SettingsView:
        """Live read of US-8.3 admin config from the real Settings service
        (GET /internal/settings, same-account, private-API-only, short-TTL
        cached — see SettingsClient), falling back to CFN-Parameter env vars if that call
        fails for any reason. ALLOWED_EMAIL_DOMAINS is a comma-separated list
        env fallback (BR-P3: empty list blocks self-registration). auditEnabled
        has no Settings-service equivalent yet and stays a local env toggle.

        The SettingsClient is a module-level singleton (warm-container scoped),
        NOT per-Context: Context is constructed per invocation, so an
        instance-scoped cache would never hit and every request would pay a
        settings HTTP round-trip."""
        return SettingsView(_settings_client(), local_defaults={
            "auditEnabled": os.environ.get("AUDIT_ENABLED", "true").lower() == "true",
        })


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


def _audit_enabled(ctx: Context) -> bool:
    return bool(ctx.settings.get("auditEnabled", True))


def _authorize(ctx: Context, op: str, principal: Principal | None, params: dict, body: dict) -> None:
    if op in PUBLIC_OPS:
        return
    if principal is None:
        raise UnauthorizedError()
    mapping = OP_AUTHZ.get(op)
    if mapping is None:
        return  # any authenticated user (directory reads, logout, membership history view)
    action, resource = mapping
    group_id = params.get("id") if "group" in resource or op in (
        "joinGroup", "leaveGroup", "removeMember", "assignLeader",
        "listGroupMembers", "listJoinRequests", "decideJoinRequest") else None
    owner_id = params.get("id") if resource == "user" else None
    ctx.authorizer.authorize(principal, action, resource,
                             owner_id=owner_id, resource_group_id=group_id)


def dispatch(event: dict, ctx: Context) -> dict:
    # Nightly / on-schedule OpenSearch reindex — not an HTTP route.
    if event.get("source") == "scheduled-reindex":
        return _resp(200, ctx.user_service.reindex_users())
    # Nightly / on-schedule community roster recount (US-7.1) — feeds the CL
    # dashboard's "Total Members" card. Not an HTTP route. Independent of the
    # OpenSearch reindex above — this is a pure DynamoDB roster recount.
    if event.get("source") == "scheduled-community-counts":
        return _resp(200, ctx.user_service.recompute_community_counts())
    # Nightly per-group member breakdown (US-7.1) — feeds the CL dashboard's
    # "Members by User Group" chart. Its own job rather than part of the roster
    # recount above: the two write separate items, so one failing leaves the
    # other's data intact and the dashboard degrades per panel.
    if event.get("source") == "scheduled-group-member-stats":
        return _resp(200, ctx.group_service.recompute_group_member_stats())

    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
    set_correlation_id((event.get("headers") or {}).get("X-Correlation-Id"))
    ip = (((event.get("requestContext") or {}).get("identity") or {}).get("sourceIp"))

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
        _authorize(ctx, op, principal, params, body)
        return _execute(ctx, op, params, body, principal, event, ip)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _parse_quarters(raw: str | None, default: int = 4) -> int:
    """Trend window size (US-7.3): optional, integer, 1..12. Bounded so a client
    cannot ask for an unbounded number of snapshots."""
    if raw is None or raw == "":
        return default
    try:
        quarters = int(raw)
    except (ValueError, TypeError):
        raise ValidationError("quarters must be an integer.") from None
    if not 1 <= quarters <= 12:
        raise ValidationError("quarters must be between 1 and 12.")
    return quarters


def _parse_limit(raw: str | None) -> int | None:
    """Page size for listUsers / listGroupMembers (D-U5): optional, integer, 1..200.
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


def _validate_choice(raw: str | None, name: str, allowed: set[str]) -> None:
    if raw and raw not in allowed:
        raise ValidationError(f"{name} must be one of: {', '.join(sorted(allowed))}.")


def _execute(ctx, op, params, body, principal, event, ip) -> dict:
    audit_enabled = _audit_enabled(ctx)
    a, u, g = ctx.auth_service, ctx.user_service, ctx.group_service
    actor = principal.user_id if principal else "anonymous"

    # ---- auth ----
    if op == "login":
        return _resp(200, a.login(body, ip=ip, audit_enabled=audit_enabled))
    if op == "verifyOtp":
        return _resp(200, a.verify_otp(body, ip=ip, audit_enabled=audit_enabled))
    if op == "selfRegister":
        return _resp(201, a.self_register(body, ip=ip, audit_enabled=audit_enabled))
    if op == "resetPassword":
        return _resp(200, a.reset_password(body, principal=principal, ip=ip, audit_enabled=audit_enabled))
    if op == "confirmResetPassword":
        return _resp(200, a.confirm_reset_password(body, principal=principal, ip=ip, audit_enabled=audit_enabled))
    if op == "logout":
        return _resp(200, a.logout(principal=principal, audit_enabled=audit_enabled))
    if op == "refreshClaims":
        return _resp(200, a.refresh_claims(principal=principal))
    if op == "refreshSession":
        return _resp(200, a.refresh_session(body))

    # ---- users ----
    if op == "listUsers":
        qs = event.get("queryStringParameters") or {}
        limit = _parse_limit(qs.get("limit"))
        _validate_choice(qs.get("role"), "role", {"Administrator", "CommunityLeader", "UserGroupLeader", "Member"})
        _validate_choice(qs.get("status"), "status", {"Active", "Inactive"})
        _validate_choice(qs.get("sort"), "sort", {"email", "name", "role", "status"})
        _validate_choice(qs.get("sortDir"), "sortDir", {"asc", "desc"})
        if limit or any(qs.get(k) for k in ("cursor", "q", "role", "status", "groupId", "sort", "sortDir")):
            # Paged mode: OpenSearch (fast path) or DynamoDB GSI2 fallback.
            return _resp(200, u.list_users_page(
                q=qs.get("q"), role=qs.get("role"), status=qs.get("status"),
                group_id=qs.get("groupId"), limit=limit or 50, cursor=qs.get("cursor"),
                sort=qs.get("sort", "name"), sort_dir=qs.get("sortDir", "asc"),
            ))
        # Unpaged full listing (CSV export — always DynamoDB, authoritative).
        items = u.list_users()
        return _resp(200, {"items": items, "count": len(items)})
    if op == "createUser":
        return _resp(201, u.create_user(body, actor=actor,
                                        allowed_domains=ctx.settings.get("allowedEmailDomains", []),
                                        audit_enabled=audit_enabled))
    if op == "editUser":
        return _resp(200, u.edit_user(params["id"], body, actor=actor, audit_enabled=audit_enabled))
    if op == "disableUser":
        return _resp(200, u.set_enabled(params["id"], False, actor=actor, audit_enabled=audit_enabled))
    if op == "enableUser":
        return _resp(200, u.set_enabled(params["id"], True, actor=actor, audit_enabled=audit_enabled))
    if op == "bulkImport":
        rows = body.get("rows") or []
        return _resp(200, u.bulk_import(rows, actor=actor, file_name=body.get("fileName", ""),
                                        allowed_domains=ctx.settings.get("allowedEmailDomains", []),
                                        audit_enabled=audit_enabled))
    if op == "reindexUsers":
        # Full DynamoDB → OpenSearch reconciliation (on-demand admin trigger).
        # Also called nightly via the scheduled-reindex EventBridge rule.
        return _resp(200, u.reindex_users())
    if op == "startUserExport":
        # 202: the CSV does not exist yet. The worker builds it asynchronously
        # and the SPA polls getUserExport for progress.
        return _resp(202, ctx.export_service.start_export(body, actor=actor))
    if op == "getUserExport":
        return _resp(200, ctx.export_service.get_export(params["id"], actor=actor))

    # ---- groups ----
    if op == "listGroups":
        qs = event.get("queryStringParameters") or {}
        # Soft-deleted rows (grace period, US-1.11) are CL-only visibility.
        include_deleted = (qs.get("includeDeleted") == "true"
                           and principal is not None and principal.role == "CommunityLeader")
        limit = _parse_limit(qs.get("limit"))
        if limit or qs.get("cursor"):
            # Paged mode (2026-08-08, high-volume CL "All Groups" table) — each
            # row costs a member-count read + leader resolution, so the page
            # bounds the work. myState is omitted here (CL table only).
            return _resp(200, g.list_groups_page(
                include_deleted=include_deleted, limit=limit or 25, cursor=qs.get("cursor")))
        items = g.list_groups(include_deleted=include_deleted, caller_id=actor)
        return _resp(200, {"items": items, "count": len(items)})
    if op == "createGroup":
        return _resp(201, g.create_group(body, actor=actor, audit_enabled=audit_enabled))
    if op == "getGroup":
        return _resp(200, g.get_group(params["id"], caller_id=actor))
    if op == "editGroup":
        return _resp(200, g.edit_group(params["id"], body, actor=actor, audit_enabled=audit_enabled))
    if op == "deleteGroup":
        g.delete_group(params["id"], actor=actor, audit_enabled=audit_enabled)
        return _resp(204, {})
    if op == "joinGroup":
        return _resp(200, g.join_group(params["id"], actor, message=body.get("message", ""),
                                       audit_enabled=audit_enabled))
    if op == "withdrawJoinRequest":
        return _resp(200, g.withdraw_join_request(params["id"], actor, audit_enabled=audit_enabled))
    if op == "leaveGroup":
        return _resp(200, g.leave_group(params["id"], actor, audit_enabled=audit_enabled))
    if op == "listJoinRequests":
        qs = event.get("queryStringParameters") or {}
        limit = _parse_limit(qs.get("limit"))
        if limit or qs.get("cursor"):
            # Paged mode (2026-08-05) — each row costs a profile read for the
            # requester's display name, so the page bounds the work.
            return _resp(200, g.list_join_requests_page(
                params["id"], limit=limit or 50, cursor=qs.get("cursor")))
        items = g.list_join_requests(params["id"])
        return _resp(200, {"items": items, "count": len(items)})
    if op == "decideJoinRequest":
        return _resp(200, g.decide_join_request(
            params["id"], params["requestId"], body.get("decision") == "approve",
            actor=actor, reason=body.get("reason", ""), audit_enabled=audit_enabled))
    if op == "restoreGroup":
        return _resp(200, g.restore_group(params["id"], actor=actor, audit_enabled=audit_enabled))
    if op == "listAllJoinRequests":
        qs = event.get("queryStringParameters") or {}
        limit = _parse_limit(qs.get("limit"))
        if limit or qs.get("cursor"):
            # Paged mode (2026-08-08, high-volume) — enrichment (a profile read
            # per row) is bounded to the page window; `total` drives the badge.
            return _resp(200, g.list_all_pending_requests_page(
                limit=limit or 50, cursor=qs.get("cursor")))
        items = g.list_all_pending_requests()
        return _resp(200, {"items": items, "count": len(items)})
    if op == "listGroupMembers":
        qs = event.get("queryStringParameters") or {}
        limit = _parse_limit(qs.get("limit"))
        if limit or qs.get("cursor") or qs.get("q"):
            # Paged mode (2026-08-05, 13k+ member groups) — same contract shape
            # as /users and /members: search + opaque cursor.
            return _resp(200, g.list_group_members_page(
                params["id"], q=qs.get("q"), limit=limit or 25, cursor=qs.get("cursor"),
            ))
        # Unpaged full listing (pre-existing callers). No longer used by the CSV
        # export, which is now the async job below.
        items = g.list_group_members(params["id"])
        return _resp(200, {"items": items, "count": len(items)})
    if op == "startGroupMemberExport":
        # 202: the CSV does not exist yet. The worker builds it asynchronously and
        # the SPA polls getGroupMemberExport for progress.
        return _resp(202, ctx.export_service.start_group_member_export(
            params["id"], body, actor=actor))
    if op == "getGroupMemberExport":
        return _resp(200, ctx.export_service.get_group_member_export(
            params["id"], params["jobId"], actor=actor))
    if op == "groupGrowth":
        qs = event.get("queryStringParameters") or {}
        return _resp(200, g.group_growth(params["id"], quarters=_parse_quarters(qs.get("quarters"))))
    if op == "assignLeader":
        return _resp(200, g.assign_leader(params["id"], body["memberId"], actor=actor,
                                          audit_enabled=audit_enabled))
    if op == "removeMember":
        g.remove_member(params["id"], params["memberId"], actor=actor, audit_enabled=audit_enabled)
        return _resp(204, {})
    if op == "communityStats":
        # Community-wide analytics is a Community Leader capability (US-7.1):
        # Administrators do not access it and a UGL sees their own group instead.
        if principal.role != "CommunityLeader":
            raise ForbiddenError()
        return _resp(200, u.community_counts())
    if op == "membersByGroup":
        # Cross-group comparison is community-wide analytics, so the same rule as
        # communityStats: Community Leader only. A UGL sees their single group's
        # figure on their own dashboard instead.
        if principal.role != "CommunityLeader":
            raise ForbiddenError()
        qs = event.get("queryStringParameters") or {}
        return _resp(200, g.members_by_group(quarter=qs.get("quarter")))
    if op == "membershipHistory":
        qs = event.get("queryStringParameters") or {}
        limit = _parse_limit(qs.get("limit"))
        if qs.get("groupId") and (limit or qs.get("cursor")):
            # Paged mode (2026-08-05, 13k+ scale) — newest first. Only the
            # per-group view needs it; a single member's history is small.
            return _resp(200, g.membership_history_page(
                group_id=qs["groupId"], limit=limit or 25, cursor=qs.get("cursor")))
        items = g.membership_history(member_id=qs.get("memberId"), group_id=qs.get("groupId"))
        return _resp(200, {"items": items, "count": len(items)})
    if op == "myMemberships":
        return _resp(200, a.refresh_claims(principal=principal))

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)
