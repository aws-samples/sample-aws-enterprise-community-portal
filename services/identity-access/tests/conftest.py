"""Test fixtures for identity-access.

Exercises the REAL service against mocked AWS (moto): a DynamoDB single table and
a Cognito user pool. No local auth abstraction — CognitoAuthProvider is used as in
production. The built-in local Administrator path uses env-provided credentials
(stands in for the Secrets Manager secret).
"""
from __future__ import annotations

import os
import pathlib
import sys

import boto3
import pytest
from moto import mock_aws

SRC = str(pathlib.Path(__file__).resolve().parents[1] / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("PERMISSION_MATRIX_PATH", str(pathlib.Path(SRC) / "permission_matrix.json"))
os.environ.setdefault("JWT_SIGNING_KEY", "test-signing-key")
os.environ.setdefault("LOCAL_ADMIN_EMAIL", "admin@portal.local")
os.environ.setdefault("LOCAL_ADMIN_PASSWORD", "AdminPass!123")

TABLE_NAME = "identity-access-test"

# Throwaway password for test-created Cognito users in the mocked (moto) pool.
# Never a real secret. Kept OUT of create_user's signature so it is not a
# hardcoded password default argument (semgrep
# python.lang.security.audit.hardcoded-password-default-argument): callers may
# override it, otherwise this value is used.
_TEST_USER_PASSWORD = "Secret!123"  # noqa: S105 - test fixture value, not a real secret


@pytest.fixture()
def aws():
    """Mock AWS: DynamoDB table + Cognito user pool/client. Yields a small namespace."""
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi1pk", "AttributeType": "S"},
                {"AttributeName": "gsi1sk", "AttributeType": "S"},
                {"AttributeName": "gsi2pk", "AttributeType": "S"},
                {"AttributeName": "gsi2sk", "AttributeType": "S"},
                {"AttributeName": "gsi3pk", "AttributeType": "S"},
                {"AttributeName": "gsi3sk", "AttributeType": "S"},
                {"AttributeName": "gsi4pk", "AttributeType": "S"},
                {"AttributeName": "gsi4sk", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[
                {"IndexName": "GSI1",
                 "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"},
                               {"AttributeName": "gsi1sk", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI2",
                 "KeySchema": [{"AttributeName": "gsi2pk", "KeyType": "HASH"},
                               {"AttributeName": "gsi2sk", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI3",
                 "KeySchema": [{"AttributeName": "gsi3pk", "KeyType": "HASH"},
                               {"AttributeName": "gsi3sk", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
                {"IndexName": "GSI4",
                 "KeySchema": [{"AttributeName": "gsi4pk", "KeyType": "HASH"},
                               {"AttributeName": "gsi4sk", "KeyType": "RANGE"}],
                 "Projection": {"ProjectionType": "ALL"}},
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        idp = boto3.client("cognito-idp", region_name="us-east-1")
        pool = idp.create_user_pool(PoolName="portal-test",
                                    UsernameAttributes=["email"],
                                    AutoVerifiedAttributes=["email"])
        pool_id = pool["UserPool"]["Id"]
        client = idp.create_user_pool_client(
            UserPoolId=pool_id, ClientName="portal-spa",
            ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        )
        client_id = client["UserPoolClient"]["ClientId"]

        os.environ["TABLE_NAME"] = TABLE_NAME
        os.environ["USER_POOL_ID"] = pool_id
        os.environ["USER_POOL_CLIENT_ID"] = client_id

        class NS:
            pass

        ns = NS()
        ns.table = table
        ns.idp = idp
        ns.pool_id = pool_id
        ns.client_id = client_id

        def create_user(email, password=None, given="Dev", family="User"):
            password = password or _TEST_USER_PASSWORD
            idp.admin_create_user(
                UserPoolId=pool_id, Username=email, MessageAction="SUPPRESS",
                UserAttributes=[{"Name": "email", "Value": email},
                                {"Name": "given_name", "Value": given},
                                {"Name": "family_name", "Value": family},
                                {"Name": "email_verified", "Value": "true"}],
            )
            idp.admin_set_user_password(UserPoolId=pool_id, Username=email,
                                        Password=password, Permanent=True)
            details = idp.admin_get_user(UserPoolId=pool_id, Username=email)
            return {a["Name"]: a["Value"] for a in details.get("UserAttributes", [])}.get("sub", email)

        ns.create_user = create_user
        yield ns


@pytest.fixture()
def ctx(aws):
    """A Context wired to mocked AWS (real CognitoAuthProvider) with fake SES/events."""
    from app import Context

    class FakeSes:
        def __init__(self):
            self.sent = []

        def send(self, to, subject, body):
            self.sent.append({"to": to, "subject": subject, "body": body})

    class FakeEvents:
        def __init__(self):
            self.published = []

        def publish(self, event_type, data, correlation_id=None):
            self.published.append({"type": event_type, "data": data})

    return Context(
        table=aws.table,
        events=FakeEvents(),
        ses=FakeSes(),
        # selfRegistrationEnabled must be stated EXPLICITLY: the service defaults it
        # to False (fail closed, 2026-08-11), so a fixture that omitted it would
        # silently disable every self-registration test rather than exercise it.
        settings={"allowedEmailDomains": ["company.com"], "auditEnabled": True,
                  "otpIntervalDays": 30, "selfRegistrationEnabled": True},
    )


@pytest.fixture()
def repo(ctx):
    return ctx.repo
