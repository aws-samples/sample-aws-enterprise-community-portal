"""Test fixtures for Forums.

Exercises the REAL service against mocked AWS (moto) DynamoDB with 4 GSIs,
fake MentionClient, and fake EventPublisher. Matches the established pattern
from Announcements/Contributions.
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
# https, not http: MentionClient rejects any other scheme at construction, and
# Context() builds a real one when the fixture does not inject a fake.
os.environ.setdefault("API_BASE_URL", "https://localhost:3000")
os.environ.setdefault("MENTION_TIMEOUT_MS", "1500")
os.environ.setdefault("SWEEP_TIME_CAP_SECONDS", "600")

TABLE_NAME = "forums-test"
IDEM_TABLE_NAME = "forums-idem-test"

# GSI attribute definitions needed for the table
_ATTRIBUTE_DEFS = [
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
]

_GSIS = [
    {
        "IndexName": "GSI1",
        "KeySchema": [{"AttributeName": "gsi1pk", "KeyType": "HASH"},
                      {"AttributeName": "gsi1sk", "KeyType": "RANGE"}],
        "Projection": {"ProjectionType": "ALL"},
    },
    {
        "IndexName": "GSI2",
        "KeySchema": [{"AttributeName": "gsi2pk", "KeyType": "HASH"},
                      {"AttributeName": "gsi2sk", "KeyType": "RANGE"}],
        "Projection": {"ProjectionType": "ALL"},
    },
    {
        "IndexName": "GSI3",
        "KeySchema": [{"AttributeName": "gsi3pk", "KeyType": "HASH"},
                      {"AttributeName": "gsi3sk", "KeyType": "RANGE"}],
        "Projection": {"ProjectionType": "KEYS_ONLY"},
    },
    {
        "IndexName": "GSI4",
        "KeySchema": [{"AttributeName": "gsi4pk", "KeyType": "HASH"},
                      {"AttributeName": "gsi4sk", "KeyType": "RANGE"}],
        "Projection": {"ProjectionType": "ALL"},
    },
]


@pytest.fixture()
def aws():
    with mock_aws():
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        table = ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                       {"AttributeName": "sk", "KeyType": "RANGE"}],
            AttributeDefinitions=_ATTRIBUTE_DEFS,
            GlobalSecondaryIndexes=_GSIS,
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
        os.environ["EVENT_BUS_NAME"] = "test-bus"

        class NS:
            pass

        ns = NS()
        ns.table = table
        ns.idem = idem
        ns.client = ddb.meta.client
        yield ns


class FakeMentionClient:
    """Test double for MentionClient. Controls suggest and validation results."""

    def __init__(self):
        self.candidates: list[dict] = []
        self.valid_ids: list[str] = []
        self.should_fail: bool = False

    def suggest(self, q, group_id, bearer_token=None, claim_headers=None):
        if self.should_fail:
            return []
        return [c for c in self.candidates if q.lower() in c.get("displayName", "").lower()]

    def validate_mentions(self, user_ids, group_id, bearer_token=None, claim_headers=None):
        if self.should_fail:
            return []
        return [uid for uid in user_ids if uid in self.valid_ids]


class FakeEvents:
    """Test double for EventPublisher. Records all emitted events."""

    def __init__(self):
        self.published: list[dict] = []

    def emit(self, event_type, data):
        self.published.append({"type": event_type, "data": data})

    def forum_post_created(self, post, follower_ids):
        self.published.append({"type": "ForumPostCreated", "data": {**post, "followerIds": follower_ids}})

    def forum_reply_created(self, reply, post, follower_ids):
        self.published.append({"type": "ForumReplyCreated", "data": {**reply, "followerIds": follower_ids}})

    def member_mentioned(self, mentioned_user_id, author_id, author_name, post_id, group_id, context_type):
        self.published.append({"type": "MemberMentioned", "data": {
            "mentionedUserId": mentioned_user_id, "authorId": author_id,
            "postId": post_id, "groupId": group_id, "contextType": context_type,
        }})

    def post_reported(self, report):
        self.published.append({"type": "PostReported", "data": report})

    def post_deleted(self, post_id, group_id, deleted_by):
        self.published.append({"type": "PostDeleted", "data": {"postId": post_id, "groupId": group_id}})

    def forum_channel_deleted(self, channel_id, forum_id, group_id, deleted_by):
        self.published.append({"type": "ForumChannelDeleted", "data": {"channelId": channel_id}})

    def reply_accepted(self, reply, accepted):
        self.published.append({"type": "ReplyAccepted", "data": {**reply, "accepted": accepted}})


@pytest.fixture()
def mention_client():
    return FakeMentionClient()


@pytest.fixture()
def events():
    return FakeEvents()


@pytest.fixture()
def ctx(aws, mention_client, events):
    from app import Context
    return Context(table=aws.table, idempotency_table=IDEM_TABLE_NAME,
                   mention_client=mention_client, events=events)


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


def bridge_event(detail_type, data, *, event_id="evt-1", source="identity-access"):
    """An EventBridge-rule delivery: detail carries the platform envelope."""
    return {
        "detail-type": detail_type,
        "source": source,
        "detail": {"id": event_id, "type": detail_type, "version": 1,
                   "source": source, "time": "2026-08-13T00:00:00Z", "data": data},
    }
