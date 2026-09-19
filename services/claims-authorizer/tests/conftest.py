"""Test harness for the claims edge authorizer.

Signs real RS256 tokens with a locally-generated RSA key, primes the handler's
JWKS cache with the matching public key (no network), and backs the CLAIMS read
with a moto DynamoDB table. Env is set BEFORE importing the handler because the
handler reads issuer/audience/table from env at import time.
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

import pytest

SRC = str(pathlib.Path(__file__).resolve().parents[1] / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# Must be set before `import handler`.
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ["AWS_REGION"] = "us-east-1"
os.environ["USER_POOL_ID"] = "us-east-1_test"
os.environ["USER_POOL_CLIENT_ID"] = "test-client-id"
os.environ["IDENTITY_TABLE"] = "identity-access-test"

TABLE_NAME = "identity-access-test"
KID = "test-kid"


@pytest.fixture(scope="session")
def signing():
    """Session-scoped RSA keypair + JWKS + a token factory (keygen is slow)."""
    import rsa
    from jose import jwk

    pub, priv = rsa.newkeys(2048)
    priv_pem = priv.save_pkcs1().decode()

    jwk_dict = jwk.construct(pub.save_pkcs1().decode(), algorithm="RS256").to_dict()
    # jose may return n/e as bytes — normalise to str for clean JSON/matching.
    jwk_dict = {k: (v.decode() if isinstance(v, bytes) else v) for k, v in jwk_dict.items()}
    jwk_dict.update({"kid": KID, "alg": "RS256", "use": "sig"})
    jwks_keys = [jwk_dict]

    import handler as h

    def make_token(*, sub="u1", aud=None, iss=None, token_use="id",
                   exp_delta=3600, kid=KID, key_pem=None, **extra):
        from jose import jwt
        now = int(time.time())
        claims = {
            "sub": sub,
            "aud": aud if aud is not None else h.CLIENT_ID,
            "iss": iss if iss is not None else h.ISSUER,
            "token_use": token_use,
            "iat": now,
            "exp": now + exp_delta,
            **extra,
        }
        return jwt.encode(claims, key_pem or priv_pem, algorithm="RS256",
                          headers={"kid": kid})

    import types
    return types.SimpleNamespace(keys=jwks_keys, token=make_token, priv_pem=priv_pem)


@pytest.fixture()
def handler_mod(signing, monkeypatch):
    """The handler with its JWKS cache primed to the test key (no network)."""
    import handler as h
    monkeypatch.setattr(h, "_jwks_keys", list(signing.keys), raising=False)
    monkeypatch.setattr(h, "_ddb_table", None, raising=False)
    return h


@pytest.fixture()
def claims_table():
    """moto DynamoDB table for the CLAIMS read; returns a seeder."""
    from moto import mock_aws

    with mock_aws():
        import boto3
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        def seed(sub, *, role="Member", led=None, groups=None):
            item = {"pk": f"MEMBER#{sub}", "sk": "CLAIMS", "role": role, "version": 1}
            if led:
                item["ledGroupId"] = led
            if groups:
                item["memberGroupIds"] = set(groups)
            table.put_item(Item=item)

        class NS:
            pass
        ns = NS()
        ns.table = table
        ns.seed = seed
        yield ns


def event_for(token, method_arn="arn:aws:execute-api:us-east-1:111:api123/dev/GET/members"):
    return {"type": "REQUEST", "methodArn": method_arn,
            "headers": {"Authorization": f"Bearer {token}"} if token else {}}
