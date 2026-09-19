"""Unit tests for the claims edge authorizer (Step 2)."""
from __future__ import annotations

import pytest

from conftest import event_for


def test_valid_token_with_claims_allows_and_injects_context(handler_mod, claims_table, signing):
    claims_table.seed("u1", role="Member", groups=["g-a", "g-b"])
    tok = signing.token(sub="u1", email="u1@x.com", given_name="Al", family_name="Morgan")
    res = handler_mod.handler(event_for(tok), None)

    assert res["policyDocument"]["Statement"][0]["Effect"] == "Allow"
    ctx = res["context"]
    assert ctx["sub"] == "u1"
    assert ctx["role"] == "Member"
    assert ctx["member_group_ids"] == "g-a,g-b"   # CSV, sorted
    assert ctx["led_group_id"] == ""
    assert ctx["email"] == "u1@x.com"
    assert ctx["given_name"] == "Al" and ctx["family_name"] == "Morgan"


def test_ugl_led_group_in_context(handler_mod, claims_table, signing):
    claims_table.seed("ugl1", role="UserGroupLeader", led="g-lead")
    tok = signing.token(sub="ugl1")
    res = handler_mod.handler(event_for(tok), None)
    assert res["policyDocument"]["Statement"][0]["Effect"] == "Allow"
    assert res["context"]["role"] == "UserGroupLeader"
    assert res["context"]["led_group_id"] == "g-lead"
    assert res["context"]["member_group_ids"] == ""


def test_policy_scoped_to_api_and_stage(handler_mod, claims_table, signing):
    claims_table.seed("u1")
    tok = signing.token(sub="u1")
    res = handler_mod.handler(event_for(tok), None)
    resource = res["policyDocument"]["Statement"][0]["Resource"]
    assert resource == "arn:aws:execute-api:us-east-1:111:api123/dev/*"


def test_verified_token_but_no_claims_item_denies(handler_mod, claims_table, signing):
    # no seed for u-missing
    tok = signing.token(sub="u-missing")
    res = handler_mod.handler(event_for(tok), None)
    assert res["policyDocument"]["Statement"][0]["Effect"] == "Deny"
    assert "context" not in res


def test_missing_token_unauthorized(handler_mod, claims_table):
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(None), None)


def test_expired_token_unauthorized(handler_mod, claims_table, signing):
    claims_table.seed("u1")
    tok = signing.token(sub="u1", exp_delta=-60)
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(tok), None)


def test_wrong_audience_unauthorized(handler_mod, claims_table, signing):
    claims_table.seed("u1")
    tok = signing.token(sub="u1", aud="some-other-client")
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(tok), None)


def test_wrong_issuer_unauthorized(handler_mod, claims_table, signing):
    claims_table.seed("u1")
    tok = signing.token(sub="u1", iss="https://evil.example.com/pool")
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(tok), None)


def test_access_token_rejected(handler_mod, claims_table, signing):
    """Only the ID token is accepted (token_use=id)."""
    claims_table.seed("u1")
    tok = signing.token(sub="u1", token_use="access")
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(tok), None)


def test_bad_signature_unauthorized(handler_mod, claims_table, signing):
    """A token signed by a different key (kid matches, key doesn't) is rejected."""
    import rsa
    other_priv = rsa.newkeys(2048)[1].save_pkcs1().decode()
    claims_table.seed("u1")
    tok = signing.token(sub="u1", key_pem=other_priv)
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(tok), None)


def test_unknown_kid_triggers_refresh_then_denies(handler_mod, claims_table, signing, monkeypatch):
    """A token with an unrecognised kid forces one JWKS refresh; if still unknown → Unauthorized."""
    refreshed = {"n": 0}

    def fake_fetch():
        refreshed["n"] += 1
        return list(signing.keys)  # refresh returns the same (still no matching kid)

    monkeypatch.setattr(handler_mod, "_fetch_jwks", fake_fetch)
    tok = signing.token(sub="u1", kid="unknown-kid")
    with pytest.raises(handler_mod.Unauthorized):
        handler_mod.handler(event_for(tok), None)
    assert refreshed["n"] >= 1  # a rotation refresh was attempted


def test_unauthorized_message_is_exactly_unauthorized(handler_mod):
    """API Gateway maps a Lambda authorizer error to 401 ONLY when the raised
    error's message is exactly 'Unauthorized' (an empty message yields 500).
    Lock that contract: the default message must be 'Unauthorized'."""
    assert str(handler_mod.Unauthorized()) == "Unauthorized"
    assert str(handler_mod.Unauthorized("Unauthorized")) == "Unauthorized"
