"""Test fixtures for announcements.

Exercises the REAL service against mocked AWS (moto) for DynamoDB, with a fake
DirectoryClient (no real HTTP) so tests control author/group name resolution
including simulated timeouts (degrade suite, NFR-AN-MAINT-1). Cache TTL is 0 so
each panel read sees the latest writes deterministically.
"""
from __future__ import annotations

import json
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

TABLE_NAME = "announcements-test"
IDEM_TABLE_NAME = "announcements-idem-test"


@pytest.fixture()
def aws():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                  {"AttributeName": "sk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        idem = ddb.create_table(
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
        ns.idem = idem
        yield ns


class FakeDirectory:
    """Test double for DirectoryClient. `names`/`groups` map ids to values;
    ids in `failing` return None (simulating a timeout / fail-closed)."""

    def __init__(self):
        self.names: dict[str, str] = {}
        self.groups: dict[str, str] = {}
        self.failing: set[str] = set()

    def member_name(self, member_id, *, bearer_token=None, claim_headers=None):
        if member_id in self.failing:
            return None
        return self.names.get(member_id)

    def group_name(self, group_id, *, bearer_token=None, claim_headers=None):
        if group_id in self.failing:
            return None
        return self.groups.get(group_id)


class FakeEvents:
    def __init__(self):
        self.published: list[dict] = []

    def publish(self, event_type, data, *, correlation_id=None):
        self.published.append({"type": event_type, "data": data})


@pytest.fixture()
def directory():
    return FakeDirectory()


@pytest.fixture()
def events():
    return FakeEvents()


@pytest.fixture()
def ctx(aws, directory, events):
    from app import Context
    return Context(table=aws.table, idempotency_table=IDEM_TABLE_NAME,
                   directory=directory, events=events, cache_ttl=0)


# ---- helpers ----
def claims(sub="u1", role="Member", groups=None, led=None):
    c = {"sub": sub, "role": role}
    if groups:
        c["member_group_ids"] = ",".join(groups)
    if led:
        c["led_group_id"] = led
    return c


def proxy_event(method, path, *, role="Member", sub="u1", groups=None, led=None,
                body=None, qs=None):
    return {
        "httpMethod": method,
        "path": path,
        "headers": {"Authorization": "Bearer test-token"},
        "requestContext": {"authorizer": {"claims": claims(sub, role, groups, led)}},
        "queryStringParameters": qs,
        "body": json.dumps(body) if body is not None else None,
    }


def bridge_event(detail_type, data, *, event_id="evt-1", source="events"):
    """An EventBridge-rule delivery: detail carries the platform envelope."""
    return {
        "detail-type": detail_type,
        "source": source,
        "detail": {"id": event_id, "type": detail_type, "version": 1,
                   "source": source, "time": "2026-08-07T00:00:00Z", "data": data},
    }
