"""REAL Lambda handler for announcements (replaces mock_handler as the deployed
entrypoint). Routes API Gateway proxy events to the domain services with in-service
fail-closed authZ (SECURITY-08), and handles the EventBridge-rule branch for the
events this service consumes (EventCreated, GroupSoftDeleted, GroupRestored).
Wrapped by global_handler so no exception escapes (SECURITY-15).

Dismissal is client-side only (BR-11) — POST /announcements/{id}/dismiss is
intentionally NOT handled here (removed from the contract, v2.0.0); the router
returns 404 for it, and the SPA maintains dismissed ids in localStorage.
"""
from __future__ import annotations

import json
import os
import re

from _conventions.authz import Principal, extract_claims
from _conventions.errors import AppError, ForbiddenError, global_handler, to_response
from _conventions.idempotency import IdempotencyStore
from _conventions.logger import set_correlation_id
from active_set_cache import ActiveSetCache
from announcement_service import AnnouncementService
from consumers import CONSUMED_EVENT_TYPES, EventConsumer
from directory_client import DirectoryClient
from panel_query import PanelQuery
from providers import EventPublisher
from repository import AnnouncementRepository

OPERATIONS = {
    ("GET", "/announcements"): "listAnnouncements",
    ("POST", "/announcements"): "createAnnouncement",
    ("PUT", "/announcements/{id}"): "editAnnouncement",
    ("DELETE", "/announcements/{id}"): "deleteAnnouncement",
}


def _json_default(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _resp(status: int, body) -> dict:
    return {"statusCode": status,
            "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
            "body": json.dumps(body, default=_json_default) if body is not None else ""}


def _compile(path: str) -> re.Pattern:
    return re.compile("^" + re.sub(r"\{([^}]+)\}", r"(?P<\1>[^/]+)", path) + "$")


_COMPILED = [(m, _compile(p), op) for (m, p), op in OPERATIONS.items()]


class Context:
    """Wires repository + cache + directory + events + services. Injected in tests."""

    def __init__(self, table=None, idempotency_table=None, directory=None, events=None,
                 cache_ttl=None):
        if table is None:
            import boto3
            table = boto3.resource("dynamodb").Table(os.environ["TABLE_NAME"])
        self.repo = AnnouncementRepository(table)
        self.cache = ActiveSetCache(self.repo, ttl_seconds=cache_ttl)
        self.directory = directory or DirectoryClient()
        self.events = events or EventPublisher()
        idem_name = idempotency_table or os.environ.get("IDEMPOTENCY_TABLE", "")
        self.idempotency = IdempotencyStore(idem_name) if idem_name else None
        self.service = AnnouncementService(self.repo, self.cache, self.directory, self.events)
        self.panel = PanelQuery(self.cache)
        self.consumer = EventConsumer(self.service, self.repo, self.cache, self.idempotency)


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
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:]
    return auth


def dispatch(event: dict, ctx: Context) -> dict:
    # EventBridge rule branch (EventCreated / GroupSoftDeleted / GroupRestored).
    detail_type = event.get("detail-type") or event.get("type")
    if detail_type in CONSUMED_EVENT_TYPES:
        envelope = event.get("detail") or event
        ctx.consumer.handle(envelope)
        return _resp(200, {"status": "processed"})

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
        if principal.role == "Administrator":
            raise ForbiddenError()  # Administrators do not participate (BR-3)
        qs = event.get("queryStringParameters") or {}
        return _execute(ctx, op, params, body, qs, principal, event)
    except AppError as err:
        return _resp(err.status, {"code": err.code, "message": err.message,
                                  **({"details": err.details} if err.details else {})})


def _execute(ctx, op, params, body, qs, principal, event) -> dict:
    token = _bearer_token(event)
    correlation_id = (event.get("headers") or {}).get("X-Correlation-Id")
    svc = ctx.service

    if op == "listAnnouncements":
        view = (qs.get("view") or "panel").lower()
        if view == "mine":
            if (qs.get("scope") or "").lower() == "all":
                return _resp(200, svc.list_moderation(principal))
            return _resp(200, svc.list_mine(principal))
        return _resp(200, ctx.panel.panel(principal))
    if op == "createAnnouncement":
        return _resp(201, svc.create(body, principal, bearer_token=token, correlation_id=correlation_id))
    if op == "editAnnouncement":
        return _resp(200, svc.edit(params["id"], body, principal, bearer_token=token,
                                   correlation_id=correlation_id))
    if op == "deleteAnnouncement":
        svc.delete(params["id"], principal, correlation_id=correlation_id)
        return _resp(204, None)

    return _resp(501, {"code": "NOT_IMPLEMENTED", "message": "This feature is not yet available."})


@global_handler
def handler(event, context):
    try:
        ctx = Context()
        return dispatch(event, ctx)
    except AppError as err:
        return to_response(err)
