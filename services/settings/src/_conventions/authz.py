"""In-service authorization from the permission matrix (SECURITY-08, FQ3a).

Reference convention — copied per service by the scaffold generator (FQ1).
AuthN happens at the API Gateway Cognito authorizer; this enforces authZ
in-service, fail-closed, including object-level (own) and group-scope checks.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ForbiddenError, UnauthorizedError

# --- Fresh-claims-at-the-edge: request-source resolution -----------------------
# AuthN happens at the PUBLIC API's edge authorizer, which injects fresh claims
# into requestContext.authorizer. Internal service-to-service calls arrive on the
# PRIVATE API with the caller's fresh claims propagated as X-Claims-* headers.
# extract_claims() reads whichever source applies, honoring the trust boundary:
# claim headers are trusted ONLY on the private-API path (apiId == PRIVATE_API_ID),
# never on the public path — so a client cannot forge identity via headers.

_CLAIM_HEADER_PREFIX = "x-claims-"


def _claims_from_headers(headers: dict) -> dict:
    """Build a claims dict from X-Claims-* internal headers (private path only).
    Returns {} when the identifying header is absent."""
    h = {k.lower(): v for k, v in (headers or {}).items()}
    sub = h.get("x-claims-sub")
    if not sub:
        return {}
    return {
        "sub": sub,
        "role": h.get("x-claims-role", "Member"),
        "account_type": h.get("x-claims-account-type", "cognito"),
        "led_group_id": h.get("x-claims-led-group") or None,
        "member_group_ids": h.get("x-claims-member-groups", ""),
        "email": h.get("x-claims-email", ""),
        "given_name": h.get("x-claims-given-name", ""),
        "family_name": h.get("x-claims-family-name", ""),
    }


def extract_claims(event: dict) -> dict:
    """Return the caller's claims for this request, from the correct source.

    Public path (default): ONLY the authorizer context. Both authorizer shapes
    are supported — the Cognito authorizer nests claims under `.claims`; the
    custom edge authorizer puts them flat on `.authorizer`. Client-supplied
    X-Claims-* headers are IGNORED here (impersonation guard).

    Private path (apiId == PRIVATE_API_ID): trusted X-Claims-* headers; during
    rollout, falls back to the authorizer context when headers are not yet sent
    (the private Cognito authorizer still populates it until it is removed).
    """
    rc = event.get("requestContext") or {}
    authz = rc.get("authorizer") or {}
    ctx_claims = authz.get("claims") or (authz if authz.get("sub") else {})
    private_id = os.environ.get("PRIVATE_API_ID", "")
    if private_id and rc.get("apiId") == private_id:
        header_claims = _claims_from_headers(event.get("headers") or {})
        return header_claims or ctx_claims
    return ctx_claims


def claims_to_headers(principal) -> dict:
    """Outbound X-Claims-* headers a caller forwards on a private-API call, so the
    downstream builds its principal from the caller's FRESH claims. Mirror of
    _claims_from_headers. given_name/family_name are omitted (not needed on the
    internal read paths; downstreams that denormalise a name use the request
    author's own claims, not a fanned-out caller's)."""
    return {
        "X-Claims-Sub": principal.user_id,
        "X-Claims-Role": principal.role,
        "X-Claims-Account-Type": getattr(principal, "account_type", "cognito"),
        "X-Claims-Led-Group": principal.led_group_id or "",
        "X-Claims-Member-Groups": ",".join(principal.member_group_ids or []),
        "X-Claims-Email": getattr(principal, "email", "") or "",
    }


@dataclass
class Principal:
    """Authenticated caller, derived from validated Cognito JWT claims."""
    user_id: str
    role: str  # Administrator | CommunityLeader | UserGroupLeader | Member
    account_type: str = "cognito"  # or "local-admin"
    led_group_id: str | None = None       # for UserGroupLeader
    member_group_ids: list[str] = field(default_factory=list)  # for Member

    @classmethod
    def from_claims(cls, claims: dict) -> Principal:
        if not claims or not claims.get("sub"):
            raise UnauthorizedError()
        groups = claims.get("member_group_ids")
        if isinstance(groups, str):
            groups = [g for g in groups.split(",") if g]
        return cls(
            user_id=claims["sub"],
            role=claims.get("role", "Member"),
            account_type=claims.get("account_type", "cognito"),
            led_group_id=claims.get("led_group_id") or None,
            member_group_ids=groups or [],
        )


class Authorizer:
    """Loads the permission matrix and enforces checks."""

    def __init__(self, matrix: dict):
        self._perms = matrix.get("permissions", {})

    @classmethod
    def from_file(cls, path: str | Path) -> Authorizer:
        return cls(json.loads(Path(path).read_text()))

    def _find(self, role: str, action: str, resource: str) -> dict | None:
        for perm in self._perms.get(role, []):
            if perm["action"] == action and perm["resource"] == resource:
                return perm
        return None

    def authorize(
        self,
        principal: Principal,
        action: str,
        resource: str,
        *,
        owner_id: str | None = None,
        resource_group_id: str | None = None,
    ) -> None:
        """Raise ForbiddenError unless the principal may perform action on resource.

        scope=global -> role suffices.
        scope=own    -> principal.user_id must equal owner_id (IDOR guard).
        scope=group  -> resource_group_id must be in the principal's led/member groups.
        """
        perm = self._find(principal.role, action, resource)
        if perm is None:
            raise ForbiddenError()
        scope = perm.get("scope", "global")
        if scope == "global":
            return
        if scope == "own":
            if owner_id is None or owner_id != principal.user_id:
                raise ForbiddenError()
            return
        if scope == "group":
            allowed = set(principal.member_group_ids)
            if principal.led_group_id:
                allowed.add(principal.led_group_id)
            if resource_group_id is None or resource_group_id not in allowed:
                raise ForbiddenError()
            return
        raise ForbiddenError()
