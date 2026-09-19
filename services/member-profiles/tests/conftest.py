"""Test fixtures for member-profiles.

Exercises the REAL service against mocked AWS (moto) for DynamoDB, and a fake
FanOutClient (no real HTTP) for cross-service reads — this lets tests control
exactly what each downstream call returns, including simulated failures for the
degrade-path suite (NFR-MP-MAINT-1).
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

TABLE_NAME = "member-profiles-test"
IDEM_TABLE_NAME = "member-profiles-idem-test"


@pytest.fixture()
def aws():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        idem_table = ddb.create_table(
            TableName=IDEM_TABLE_NAME,
            KeySchema=[{"AttributeName": "eventId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "eventId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        os.environ["TABLE_NAME"] = TABLE_NAME
        os.environ["IDEMPOTENCY_TABLE"] = IDEM_TABLE_NAME

        class NS:
            pass

        ns = NS()
        ns.table = table
        ns.idem_table = idem_table
        yield ns


class FakeFanOut:
    """Test double for FanOutClient — returns whatever `responses` maps a service
    name to, or None (simulating a failed/timed-out call) if configured to fail."""

    def __init__(self):
        self.responses: dict[str, dict | None] = {}
        self.failing: set[str] = set()
        self.calls: list[dict] = []

    def fan_out(self, calls: dict[str, str], *, bearer_token: str | None = None,
                claim_headers: dict | None = None) -> dict:
        self.calls.append({"calls": calls, "token": bearer_token,
                           "claim_headers": claim_headers})
        out = {}
        for svc in calls:
            out[svc] = None if svc in self.failing else self.responses.get(svc)
        return out


class FakeEvents:
    def __init__(self):
        self.published = []

    def publish(self, event_type, data, correlation_id=None):
        self.published.append({"type": event_type, "data": data})


class FakeSettingsCache:
    def __init__(self, enabled: bool = False):
        self._enabled = enabled

    def semantic_search_enabled(self) -> bool:
        return self._enabled


@pytest.fixture()
def fan_out():
    return FakeFanOut()


@pytest.fixture()
def events():
    return FakeEvents()


@pytest.fixture()
def ctx(aws, fan_out, events):
    """A Context wired to mocked DynamoDB + a fake fan-out client + fake events."""
    from app import Context

    return Context(
        table=aws.table,
        idempotency_table=IDEM_TABLE_NAME,
        fan_out=fan_out,
        events=events,
        settings_cache=FakeSettingsCache(enabled=False),
    )


@pytest.fixture()
def repo(ctx):
    return ctx.repo
