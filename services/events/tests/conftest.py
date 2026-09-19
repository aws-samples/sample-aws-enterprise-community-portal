"""Test fixtures for events.

Exercises the REAL service against mocked AWS (moto) for DynamoDB **with all four
GSIs** and S3, plus fakes for the cross-service reads so tests can control what
Contributions returns — including failure, which the degrade-path suite requires.

Creating the table with GSI1-4 here is deliberate and worth stating: the Settings
file-share defect (a live 500) happened precisely because the test table was
created WITH an index that the deployed table did not have, so the missing index
was invisible to the suite. The index definitions here are kept identical to
`infra/services/service-events-data.yaml`; if they ever diverge, tests pass while
production fails.
"""
from __future__ import annotations

import os
import pathlib
import sys
from datetime import datetime, timedelta

import boto3
import pytest
from moto import mock_aws

SRC = str(pathlib.Path(__file__).resolve().parents[1] / "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

TABLE_NAME = "events-test"
IDEM_TABLE_NAME = "events-idem-test"
IDEAS_TABLE_NAME = "events-ideas-test"
BUCKET = "community-files-test"

# Must mirror service-events-data.yaml exactly.
GSI_DEFS = [
    ("GSI1", "gsi1pk", "gsi1sk"),
    ("GSI2", "gsi2pk", "gsi2sk"),
    ("GSI3", "gsi3pk", "gsi3sk"),
    ("GSI4", "gsi4pk", "gsi4sk"),
]


@pytest.fixture()
def aws():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        attrs = [{"AttributeName": "pk", "AttributeType": "S"},
                 {"AttributeName": "sk", "AttributeType": "S"}]
        indexes = []
        for name, hash_key, range_key in GSI_DEFS:
            attrs.append({"AttributeName": hash_key, "AttributeType": "S"})
            attrs.append({"AttributeName": range_key, "AttributeType": "S"})
            indexes.append({
                "IndexName": name,
                "KeySchema": [{"AttributeName": hash_key, "KeyType": "HASH"},
                              {"AttributeName": range_key, "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            })
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=attrs,
            GlobalSecondaryIndexes=indexes,
            BillingMode="PAY_PER_REQUEST",
        )
        idem_table = ddb.create_table(
            TableName=IDEM_TABLE_NAME,
            KeySchema=[{"AttributeName": "eventId", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "eventId", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        # Event Ideas live in their own table (all four GSI slots on the events
        # table are taken). Mirrors IdeasTable in service-events-data.yaml: one
        # GSI, ProjectionType ALL — same reasoning as the note above about the
        # test table matching the deployed one.
        ideas_table = ddb.create_table(
            TableName=IDEAS_TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi1pk", "AttributeType": "S"},
                {"AttributeName": "gsi1sk", "AttributeType": "S"},
            ],
            GlobalSecondaryIndexes=[{
                "IndexName": "GSI1",
                "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"},
                              {"AttributeName": "gsi1sk", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            }],
            BillingMode="PAY_PER_REQUEST",
        )
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET)

        os.environ["TABLE_NAME"] = TABLE_NAME
        os.environ["IDEMPOTENCY_TABLE"] = IDEM_TABLE_NAME
        os.environ["IDEAS_TABLE_NAME"] = IDEAS_TABLE_NAME
        os.environ["FILE_SHARE_BUCKET"] = BUCKET

        class NS:
            pass

        ns = NS()
        ns.table = table
        ns.idem_table = idem_table
        ns.ideas_table = ideas_table
        ns.s3 = s3
        ns.bucket = BUCKET
        yield ns


class FakePrincipal:
    """Mirrors _conventions.authz.Principal plus the `email` attribute the router
    attaches from claims."""

    def __init__(self, user_id, role, led_group_id=None, member_group_ids=None, email="",
                 name=""):
        self.user_id = user_id
        self.role = role
        self.account_type = "cognito"
        self.led_group_id = led_group_id
        self.member_group_ids = member_group_ids or []
        self.email = email
        self.name = name


@pytest.fixture()
def cl():
    return FakePrincipal("u-cl", "CommunityLeader", email="cl@portal.test")


@pytest.fixture()
def ugl():
    return FakePrincipal("u-ugl", "UserGroupLeader", led_group_id="g-serverless",
                         email="ugl@portal.test")


@pytest.fixture()
def member():
    return FakePrincipal("u-mem-1", "Member", member_group_ids=["g-serverless", "g-ml"],
                         email="mem1@portal.test", name="Mem One")


@pytest.fixture()
def other_member():
    return FakePrincipal("u-mem-9", "Member", member_group_ids=["g-other"],
                         email="mem9@portal.test")


@pytest.fixture()
def peer_member():
    """A SECOND member of the same groups as `member` — for tests that just need
    two distinct voters on one idea.

    Distinct from `other_member`, whose whole purpose is to be OUT of scope
    (test_authz.py and test_rsvp_service.py rely on that). Once ideas became
    group-scoped, reusing `other_member` as a warm body to bump a vote count
    started asserting the opposite of the intended rule: that an outsider may
    vote in a group they do not belong to.
    """
    return FakePrincipal("u-mem-2", "Member", member_group_ids=["g-serverless", "g-ml"],
                         email="mem2@portal.test", name="Mem Two")


@pytest.fixture()
def admin():
    return FakePrincipal("u-admin", "Administrator", email="admin@portal.test")


class FakeEvents:
    def __init__(self):
        self.published: list[dict] = []

    def publish(self, event_type, data, correlation_id=None):
        self.published.append({"type": event_type, "data": data})

    def publish_many(self, items, correlation_id=None):
        for event_type, data in items:
            self.publish(event_type, data, correlation_id)

    def types(self) -> list[str]:
        return [p["type"] for p in self.published]

    def of_type(self, event_type: str) -> list[dict]:
        return [p for p in self.published if p["type"] == event_type]


class FakeContributions:
    """Point values. `failing=True` reproduces a Contributions outage, which must
    OMIT the points fields rather than error (BR-P1)."""

    def __init__(self, attendance=10, delivery=20, failing=False):
        self.attendance = attendance
        self.delivery = delivery
        self.failing = failing
        self.calls = 0

    def points_for(self, event_type, *, bearer_token=None, claim_headers=None):
        self.calls += 1
        if self.failing:
            return {"attendance": None, "delivery": None}
        return {"attendance": self.attendance, "delivery": self.delivery}


class FakeSettings:
    def __init__(self, teams=False):
        self._teams = teams

    def teams_enabled(self):
        return self._teams

    def get(self):
        return {"teamsEnabled": self._teams}


class FakeTeams:
    def __init__(self, participants=None, enabled=True):
        self.participants = participants or []
        self.enabled = enabled

    def fetch_participants(self, meeting_id):
        return self.participants


class FakeDirectory:
    """Designee role lookup (BR-P3). `roles` maps userId -> role; unknown ids
    resolve as Member (the common case) unless `failing=True`, which simulates
    an unreachable directory — the FAIL-CLOSED path (stored, not eligible)."""

    def __init__(self, roles=None, failing=False):
        self.roles = roles or {}
        self.failing = failing
        self.calls = 0

    def lookup(self, user_id, *, bearer_token=None, claim_headers=None):
        self.calls += 1
        if self.failing:
            return None
        role = self.roles.get(user_id, "Member")
        return {"role": role, "displayName": f"Name of {user_id}"}


@pytest.fixture()
def events():
    return FakeEvents()


@pytest.fixture()
def contributions():
    return FakeContributions()


@pytest.fixture()
def settings():
    return FakeSettings(teams=False)


@pytest.fixture()
def teams():
    return FakeTeams()


@pytest.fixture()
def directory():
    return FakeDirectory(roles={
        "u-cl": "CommunityLeader",
        "u-ugl": "UserGroupLeader",
        "u-admin": "Administrator",
    })


@pytest.fixture()
def ctx(aws, events, contributions, settings, teams, directory):
    from app import Context
    from providers import S3Storage

    return Context(
        table=aws.table,
        idempotency_table=IDEM_TABLE_NAME,
        storage=S3Storage(bucket=aws.bucket),
        events=events,
        contributions=contributions,
        teams=teams,
        settings=settings,
        directory=directory,
        ideas_table=aws.ideas_table,
    )


@pytest.fixture()
def repo(ctx):
    return ctx.repo


FUTURE = "2027-06-12T14:00:00+00:00"
FUTURE_END = "2027-06-12T15:30:00+00:00"
PAST = "2020-06-12T14:00:00+00:00"
PAST_END = "2020-06-12T15:30:00+00:00"


def event_input(**overrides) -> dict:
    base = {
        "title": "Serverless Deep Dive",
        "description": "Advanced Lambda patterns.",
        "type": "Workshop",
        "deliveryMode": "Virtual",
        "groupId": "g-serverless",
        "startsAt": FUTURE,
        "endsAt": FUTURE_END,
        "location": "https://teams.example.com/meet/abc",
    }
    base.update(overrides)
    # A test that overrides only startsAt would otherwise keep the default
    # endsAt, which may fall before the new start. Derive a 90-minute span so the
    # helper always produces a valid [startsAt, endsAt].
    if "startsAt" in overrides and "endsAt" not in overrides:
        start = datetime.fromisoformat(str(overrides["startsAt"]).replace("Z", "+00:00"))
        base["endsAt"] = (start + timedelta(minutes=90)).isoformat()
    return base


def make_event(ctx, principal, **overrides) -> dict:
    return ctx.event_service.create(event_input(**overrides), principal=principal)


def make_past_event(ctx, principal, **overrides) -> dict:
    """Create then back-date. Creation legitimately rejects a past start
    (BR-V4), so a completable event is produced by writing the past timestamps
    directly — the same thing time passing would do. Completion keys on endsAt,
    so both ends are moved into the past."""
    created = make_event(ctx, principal, **overrides)
    stored = ctx.repo.get_event(created["id"])
    stored["startsAt"] = PAST
    stored["endsAt"] = PAST_END
    ctx.repo.put_event({k: v for k, v in stored.items()
                        if k not in ("pk", "sk", "gsi1pk", "gsi1sk")})
    return ctx.repo.get_event(created["id"])
