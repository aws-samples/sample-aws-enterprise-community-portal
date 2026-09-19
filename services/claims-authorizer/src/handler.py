"""Claims edge authorizer (fresh-claims-at-the-edge, Step 2).

An API Gateway REQUEST authorizer (wired to the PUBLIC API with result TTL=0, so
it runs on every request). On each call it:

  1. verifies the Cognito ID token — signature against the pool JWKS (cached in
     module memory; bundled-key fallback), plus exp / iss / aud / token_use=id —
     everything the Cognito authorizer did natively;
  2. reads the caller's materialized CLAIMS item from the identity table
     (pk=MEMBER#<sub>, sk=CLAIMS) — the fresh role / ledGroupId / memberGroupIds;
  3. returns an Allow policy plus a context map carrying those claims to the
     backend service (which then trusts them instead of the stale JWT / a live
     fan-out).

Fail-closed: an invalid/expired/wrong token → 401 (raise "Unauthorized"); a
verified token with NO CLAIMS item → explicit Deny (403). The backfill + deploy
ordering ensure the CLAIMS item always exists in normal operation; denying rather
than reconstructing keeps the pathological case honest.

VPC placement: this Lambda runs IN the portal VPC. JWKS reachability over the
cognito-idp interface endpoint was verified empirically (design §7); we still
cache JWKS in memory and fall back to bundled keys so an undocumented routing
change can never take down auth.
"""
from __future__ import annotations

import json
import os
import pathlib
import urllib.request

from jose import jwt
from jose.exceptions import JWTError

REGION = os.environ.get("AWS_REGION", "us-east-1")
POOL_ID = os.environ.get("USER_POOL_ID", "")
CLIENT_ID = os.environ.get("USER_POOL_CLIENT_ID", "")
TABLE_NAME = os.environ.get("IDENTITY_TABLE", "")
JWKS_TIMEOUT = float(os.environ.get("JWKS_TIMEOUT_SECONDS", "3"))

ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL_ID}"
JWKS_URL = f"{ISSUER}/.well-known/jwks.json"
_BUNDLED_PATH = pathlib.Path(__file__).with_name("bundled_jwks.json")

# Module-memory JWKS cache — populated on first use, reused across warm invocations.
_jwks_keys: list[dict] | None = None
_ddb_table = None


class Unauthorized(Exception):
    """Maps to API Gateway 401. API Gateway only returns 401 for a Lambda
    authorizer when the raised error's MESSAGE is exactly 'Unauthorized'
    (an empty message yields a 500), so default the message to that."""

    def __init__(self, message: str = "Unauthorized"):
        super().__init__(message)


# ---------------------------------------------------------------- JWKS

def _load_bundled_keys() -> list[dict]:
    try:
        return json.loads(_BUNDLED_PATH.read_text()).get("keys", [])
    except (OSError, ValueError):
        return []


def _fetch_jwks() -> list[dict]:
    with urllib.request.urlopen(JWKS_URL, timeout=JWKS_TIMEOUT) as r:  # noqa: S310 — https cognito-idp
        return json.loads(r.read()).get("keys", [])


def _get_jwks(force: bool = False) -> list[dict]:
    """Return the pool's signing keys. Cached in module memory; on a fetch
    failure with no cache, fall back to bundled keys so verification still
    works if the network path is briefly unavailable."""
    global _jwks_keys
    if _jwks_keys is not None and not force:
        return _jwks_keys
    try:
        keys = _fetch_jwks()
        if keys:
            _jwks_keys = keys
            return _jwks_keys
    except Exception:  # noqa: BLE001 — degrade to cache/bundled rather than fail auth outright
        pass
    if _jwks_keys is None:
        _jwks_keys = _load_bundled_keys()
    return _jwks_keys


def _key_for(kid: str) -> dict | None:
    key = next((k for k in _get_jwks() if k.get("kid") == kid), None)
    if key is None:
        # Unknown kid: keys may have rotated — refresh once and retry.
        key = next((k for k in _get_jwks(force=True) if k.get("kid") == kid), None)
    return key


# ---------------------------------------------------------------- verify

def _verify(token: str) -> dict:
    """Verify a Cognito ID token; return its claims or raise Unauthorized."""
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as err:
        raise Unauthorized() from err
    key = _key_for(header.get("kid", ""))
    if key is None:
        raise Unauthorized()
    try:
        claims = jwt.decode(
            token, key, algorithms=["RS256"],
            audience=CLIENT_ID, issuer=ISSUER,
            options={"require": ["exp", "sub"]},
        )
    except JWTError as err:  # bad sig / expired / wrong aud or iss
        raise Unauthorized() from err
    if claims.get("token_use") != "id":
        # Access tokens carry token_use="access" and no `aud`; only the ID token
        # is accepted (it is what the SPA presents).
        raise Unauthorized()
    return claims


# ---------------------------------------------------------------- claims read

def _table():
    global _ddb_table
    if _ddb_table is None:
        import boto3  # runtime-provided; imported lazily to keep cold start lean
        _ddb_table = boto3.resource("dynamodb").Table(TABLE_NAME)
    return _ddb_table


def _member_claims(sub: str) -> dict | None:
    item = _table().get_item(Key={"pk": f"MEMBER#{sub}", "sk": "CLAIMS"}).get("Item")
    if not item:
        return None
    groups = item.get("memberGroupIds")
    return {
        "role": item.get("role", "Member"),
        "ledGroupId": item.get("ledGroupId") or "",
        "memberGroupIds": sorted(groups) if groups else [],
    }


# ---------------------------------------------------------------- policy

def _api_arn(method_arn: str) -> str:
    """Scope the policy to this API+stage (all methods), from the method ARN
    `arn:aws:execute-api:region:acct:apiId/stage/VERB/resource`."""
    parts = method_arn.split("/")
    return "/".join(parts[:2]) + "/*" if len(parts) >= 2 else method_arn


def _policy(principal_id: str, effect: str, method_arn: str,
            context: dict | None = None) -> dict:
    out = {
        "principalId": principal_id or "unknown",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": _api_arn(method_arn),
            }],
        },
    }
    if context:
        out["context"] = context
    return out


def _bearer(event: dict) -> str:
    headers = event.get("headers") or {}
    auth = headers.get("Authorization") or headers.get("authorization") or ""
    return auth[7:] if auth.lower().startswith("bearer ") else auth


def handler(event: dict, _context) -> dict:
    method_arn = event.get("methodArn", "*")
    token = _bearer(event)
    if not token:
        raise Unauthorized()
    claims = _verify(token)  # raises Unauthorized -> 401
    sub = claims["sub"]

    member = _member_claims(sub)
    if member is None:
        # Verified caller but no materialized claims: fail closed (403), do NOT
        # reconstruct. Backfill + deploy ordering make this a pathological case.
        return _policy(sub, "Deny", method_arn)

    context = {
        "sub": sub,
        "email": claims.get("email", ""),
        "given_name": claims.get("given_name", ""),
        "family_name": claims.get("family_name", ""),
        "account_type": "cognito",
        "role": member["role"],
        "led_group_id": member["ledGroupId"],
        # Authorizer context is a flat string map — no arrays. Comma-join the
        # group ids; Principal.from_claims already parses the CSV form.
        "member_group_ids": ",".join(member["memberGroupIds"]),
    }
    return _policy(sub, "Allow", method_arn, context)
