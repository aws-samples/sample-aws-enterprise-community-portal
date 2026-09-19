"""REAL Lambda handler for certifications (replaces mock_handler as the entrypoint).

THREE dispatch branches converge on one function (house convention, Units 2/3/4/11):
  1. authenticated HTTP — /certifications*  (Cognito authorizer at the edge)
  2. events             — Identity MembershipChanged (MemberLeftGroup/MemberRemoved)
                          + GuardDuty scan verdicts (prefix-filtered rule, F-B)
  3. scheduler          — daily expiry sweep + 15-minute scan watchdog (J4)

AuthZ is the declarative OP_AUTHZ map (identity-access pattern) behind a
boundary rule: Administrator -> 403 on EVERYTHING (D7, user decision — the
matrix's Admin catalog row was removed as a transcription error).

Everything is wrapped by `global_handler` so no exception escapes (SECURITY-15).
"""
from __future__ import annotations

import json
import os
import re

from _conventions.errors import AppError, global_handler, to_response
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import set_correlation_id
from _conventions.authz import extract_claims
from authz import Principal, check, load_authorizer
from claim_service import ClaimService
from consumers import MembershipConsumer, ScanVerdictConsumer
from definition_service import DefinitionService
from expiry_service import ExpiryService, WatchdogService
from ledger_service import LedgerService
from providers import EventPublisher, IdentityClient, Metrics, S3Broker
from repository import CertificationRepository
from revocation_service import RevocationService
from upload_service import UploadService
from verification_service import VerificationService

# Literal segments MUST precede templated ones so /certifications/claims/me is
# not swallowed by /certifications/{id} (same rule the contract documents).
OPERATIONS = [
    ("GET", "/certifications/claims/me", "myClaims"),
    ("POST", "/certifications/claims/{id}/decision", "decideClaim"),
    ("POST", "/certifications/claims/{id}/revoke", "revokeClaim"),
    ("GET", "/certifications/claims/{id}/evidence-url", "evidenceUrl"),
    ("DELETE", "/certifications/claims/{id}", "withdrawClaim"),
    ("GET", "/certifications/claims", "listClaims"),
    ("POST", "/certifications/claims", "submitClaim"),
    ("GET", "/certifications/verifications", "verificationQueue"),
    ("GET", "/certifications/ledger", "listLedger"),
    ("GET", "/certifications/stats/growth", "statsGrowth"),
    ("GET", "/certifications/stats/snapshot", "statsSnapshot"),
    ("POST", "/certifications/evidence-uploads", "grantEvidenceUpload"),
    ("POST", "/certifications/badge-uploads", "grantBadgeUpload"),
    ("GET", "/certifications", "browseCatalog"),
    ("POST", "/certifications", "createCert"),
    ("PUT", "/certifications/{id}", "editCert"),
]

CONSUMED_EVENT_TYPES = {"MemberLeftGroup", "MemberRemoved"}


def _compile(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", path) + "$")


_COMPILED = [(method, _compile(path), op) for method, path, op in OPERATIONS]


def _json_default(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status: int, body) -> dict:
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body, default=_json_default)}


def _no_content() -> dict:
    return {"statusCode": 204, "headers": {"Access-Control-Allow-Origin": "*"}, "body": ""}


class Context:
    """Wires repository + providers + services. Injected wholesale in tests."""

    def __init__(self, table=None, idempotency_table=None, storage=None, events=None,
                 identity=None, metrics=None, authorizer=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = CertificationRepository(table)
        idem_name = idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", "")
        self.idempotency = IdempotencyStore(idem_name) if idem_name else None
        self.metrics = metrics or Metrics()
        self.storage = storage or S3Broker()
        self.events = events or EventPublisher(metrics=self.metrics)
        self.identity = identity or IdentityClient()
        self.authorizer = authorizer or load_authorizer()

        self.uploads = UploadService(self.repo, self.storage)
        self.definitions = DefinitionService(self.repo, self.storage, self.uploads)
        self.claims = ClaimService(self.repo, self.storage, self.identity,
                                   self.events, self.uploads)
        self.verifications = VerificationService(self.repo, self.storage,
                                                 self.identity, self.events)
        self.revocations = RevocationService(self.repo, self.events, self.identity)
        self.ledger = LedgerService(self.repo, self.identity)
        self.expiry = ExpiryService(self.repo, self.events, self.metrics)
        self.watchdog = WatchdogService(self.repo, self.metrics, self.storage)

        self.membership_consumer = MembershipConsumer(self.repo, self.events,
                                                      self.idempotency)
        self.scan_consumer = ScanVerdictConsumer(self.repo, self.storage,
                                                 self.idempotency, self.metrics)


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
    # Denormalised onto claims at submission so queue rows render without
    # per-row identity lookups (the anti-pattern removed from Settings).
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


def dispatch(event: dict, ctx: Context) -> dict:
    set_correlation_id((event.get("headers") or {}).get("X-Correlation-Id"))
    correlation_id = (event.get("headers") or {}).get("X-Correlation-Id")

    # --- branch 2: event-driven inputs (no HTTP context) ---------------------
    detail_type = event.get("detail-type") or event.get("type")
    if detail_type in CONSUMED_EVENT_TYPES:
        envelope = event.get("detail") or event
        return _resp(200, ctx.membership_consumer.handle(
            envelope, correlation_id=correlation_id))
    if detail_type and "Malware Protection" in str(detail_type):
        return _resp(200, ctx.scan_consumer.handle(event, correlation_id=correlation_id))

    # --- branch 3: scheduler --------------------------------------------------
    if event.get("source") == "aws.scheduler" or event.get("job"):
        if event.get("job") == "scanwatch":
            return _resp(200, ctx.watchdog.run())
        return _resp(200, ctx.expiry.sweep(correlation_id=correlation_id))

    # --- branch 1: authenticated HTTP ----------------------------------------
    method = event.get("httpMethod", "GET")
    path = event.get("path", "/")
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
        # Own-scope ops bind to the token subject; claim-level ownership (which
        # would need a read) is enforced inside the services with 404-not-403.
        check(ctx.authorizer, principal, op, owner_id=principal.user_id)
        return _execute(ctx, op, params, body, qs, principal, event, correlation_id)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _execute(ctx, op, params, body, qs, principal, event, correlation_id) -> dict:
    token = _bearer_token(event)
    claim_id = params.get("id")

    if op == "browseCatalog":
        include_inactive = (str(qs.get("includeInactive", "")).lower() == "true"
                            and principal.role in ("CommunityLeader", "UserGroupLeader"))
        return _resp(200, ctx.definitions.catalog(
            principal=principal, include_inactive=include_inactive))
    if op == "createCert":
        return _resp(201, ctx.definitions.create(body, principal=principal))
    if op == "editCert":
        return _resp(200, ctx.definitions.edit(claim_id, body, principal=principal))
    if op == "submitClaim":
        return _resp(201, ctx.claims.submit(
            body, principal=principal, bearer_token=token, correlation_id=correlation_id))
    if op == "myClaims":
        limit = min(int(qs.get("limit", "20")), 100)
        return _resp(200, ctx.claims.my_claims(
            principal=principal, limit=limit, cursor=qs.get("cursor")))
    if op == "listClaims":
        return _resp(200, ctx.claims.list_claims(qs, principal=principal))
    if op == "withdrawClaim":
        ctx.claims.withdraw(claim_id, principal=principal)
        return _no_content()
    if op == "verificationQueue":
        return _resp(200, ctx.verifications.queue(
            qs, principal=principal, bearer_token=token))
    if op == "listLedger":
        return _resp(200, ctx.ledger.list_ledger(qs, principal=principal, bearer_token=token))
    if op == "statsGrowth":
        return _resp(200, ctx.ledger.growth(qs, principal=principal, bearer_token=token))
    if op == "statsSnapshot":
        return _resp(200, ctx.ledger.snapshot(qs, principal=principal, bearer_token=token))
    if op == "decideClaim":
        return _resp(200, ctx.verifications.decide(
            claim_id, body, principal=principal, bearer_token=token,
            correlation_id=correlation_id))
    if op == "revokeClaim":
        return _resp(200, ctx.revocations.revoke(
            claim_id, body, principal=principal, bearer_token=token,
            correlation_id=correlation_id))
    if op == "evidenceUrl":
        return _resp(200, ctx.verifications.evidence_url(
            claim_id, principal=principal, bearer_token=token))
    if op == "grantEvidenceUpload":
        return _resp(200, ctx.claims.grant_evidence_upload(body, principal=principal))
    if op == "grantBadgeUpload":
        return _resp(200, ctx.definitions.grant_badge_upload(body, principal=principal))

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)
