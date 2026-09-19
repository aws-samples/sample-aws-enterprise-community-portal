"""Tests for the shared request-source resolver (_conventions/authz.py).

extract_claims() enforces the public/private trust boundary that makes the
"no authorizer on the private API" design safe:
  - public path  -> ONLY the authorizer context; client X-Claims-* headers ignored;
  - private path -> trusted X-Claims-* headers, else fall back to context.

This module (_conventions/authz.py) is byte-identical across all services, so
testing it once here covers every service.
"""
from __future__ import annotations

import pytest

from _conventions.authz import Principal, claims_to_headers, extract_claims

PRIV = "private-api-id"
PUB = "public-api-id"


def _event(*, api_id=PUB, authorizer=None, headers=None):
    rc = {"apiId": api_id}
    if authorizer is not None:
        rc["authorizer"] = authorizer
    return {"requestContext": rc, "headers": headers or {}}


def test_public_cognito_shape_returns_nested_claims():
    ev = _event(authorizer={"claims": {"sub": "u1", "role": "Member",
                                       "member_group_ids": "g-a,g-b"}})
    claims = extract_claims(ev)
    p = Principal.from_claims(claims)
    assert p.user_id == "u1" and p.role == "Member"
    assert p.member_group_ids == ["g-a", "g-b"]


def test_public_flat_custom_authorizer_context_returned():
    """The custom edge authorizer puts claims flat on `authorizer` (no `claims`)."""
    ev = _event(authorizer={"sub": "u1", "role": "UserGroupLeader",
                            "led_group_id": "g-lead", "member_group_ids": ""})
    p = Principal.from_claims(extract_claims(ev))
    assert p.role == "UserGroupLeader" and p.led_group_id == "g-lead"


def test_public_path_ignores_client_supplied_claim_headers(monkeypatch):
    """SECURITY: a client hitting the PUBLIC API cannot forge identity via
    X-Claims-* headers — only the authorizer context is read."""
    monkeypatch.setenv("PRIVATE_API_ID", PRIV)
    ev = _event(
        api_id=PUB,  # public API
        authorizer={"claims": {"sub": "real-user", "role": "Member"}},
        headers={"X-Claims-Sub": "attacker", "X-Claims-Role": "Administrator",
                 "X-Claims-Member-Groups": "g-secret"},
    )
    p = Principal.from_claims(extract_claims(ev))
    assert p.user_id == "real-user"
    assert p.role == "Member"          # NOT Administrator
    assert p.member_group_ids == []    # forged groups ignored


def test_private_path_uses_claim_headers(monkeypatch):
    monkeypatch.setenv("PRIVATE_API_ID", PRIV)
    ev = _event(
        api_id=PRIV,
        authorizer={"claims": {"sub": "stale", "role": "Member",
                               "member_group_ids": "g-old"}},  # should be bypassed
        headers={"X-Claims-Sub": "u1", "X-Claims-Role": "Member",
                 "X-Claims-Member-Groups": "g-a,g-b", "X-Claims-Email": "u1@x.com"},
    )
    p = Principal.from_claims(extract_claims(ev))
    assert p.user_id == "u1"
    assert p.member_group_ids == ["g-a", "g-b"]  # fresh headers win over stale context


def test_private_path_falls_back_to_context_when_no_headers(monkeypatch):
    """Rollout window: private authorizer still present, headers not sent yet."""
    monkeypatch.setenv("PRIVATE_API_ID", PRIV)
    ev = _event(api_id=PRIV,
                authorizer={"claims": {"sub": "u1", "role": "Member"}},
                headers={})
    p = Principal.from_claims(extract_claims(ev))
    assert p.user_id == "u1"


def test_headers_ignored_when_private_id_unset(monkeypatch):
    """With PRIVATE_API_ID unset (pre-wiring), every request is treated as public
    and claim headers are never trusted."""
    monkeypatch.delenv("PRIVATE_API_ID", raising=False)
    ev = _event(api_id=PRIV,  # even though it's the private api id
                authorizer={"claims": {"sub": "real", "role": "Member"}},
                headers={"X-Claims-Sub": "attacker", "X-Claims-Role": "Administrator"})
    p = Principal.from_claims(extract_claims(ev))
    assert p.user_id == "real" and p.role == "Member"


def test_claims_to_headers_round_trips(monkeypatch):
    monkeypatch.setenv("PRIVATE_API_ID", PRIV)
    src = Principal(user_id="u1", role="UserGroupLeader", account_type="cognito",
                    led_group_id="g-lead", member_group_ids=["g-a", "g-b"])
    headers = claims_to_headers(src)
    ev = _event(api_id=PRIV, headers=headers)
    out = Principal.from_claims(extract_claims(ev))
    assert out.user_id == "u1"
    assert out.role == "UserGroupLeader"
    assert out.led_group_id == "g-lead"
    assert out.member_group_ids == ["g-a", "g-b"]


def test_no_authorizer_no_headers_returns_empty():
    assert extract_claims(_event(authorizer=None, headers={})) == {}
