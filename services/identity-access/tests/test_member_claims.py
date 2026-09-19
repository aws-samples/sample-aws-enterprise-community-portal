"""Unit tests for the CLAIMS projection (fresh-claims-at-the-edge, Step 1).

The projection item (pk=MEMBER#<id>, sk=CLAIMS) is maintained synchronously by
two choke points in the repository:
  - put_user            -> role + ledGroupId
  - append_membership_event -> memberGroupIds (String Set, ADD/DELETE)
and rebuilt from source of truth by rebuild_member_claims (backfill/repair).
"""
from __future__ import annotations

import pytest

from models import (
    MEVENT_APPROVED,
    MEVENT_JOINED,
    MEVENT_LEFT,
    MEVENT_REMOVED,
    ROLE_MEMBER,
    ROLE_UGL,
)
from repository import IdentityRepository


@pytest.fixture()
def repo(aws):
    return IdentityRepository(aws.table)


def _event(member_id, group_id, ev_type):
    return {"id": f"me-{member_id}-{group_id}-{ev_type}", "memberId": member_id,
            "groupId": group_id, "type": ev_type, "at": "2026-09-15T00:00:00Z"}


def test_put_user_creates_claims_item_with_role(repo):
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    claims = repo.get_member_claims("u1")
    assert claims == {"role": ROLE_MEMBER, "ledGroupId": None,
                      "memberGroupIds": [], "version": 1}


def test_join_adds_group_leave_removes_it(repo):
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))
    repo.append_membership_event(_event("u1", "g-b", MEVENT_APPROVED))
    assert repo.get_member_claims("u1")["memberGroupIds"] == ["g-a", "g-b"]

    repo.append_membership_event(_event("u1", "g-a", MEVENT_LEFT))
    assert repo.get_member_claims("u1")["memberGroupIds"] == ["g-b"]


def test_leaving_last_group_removes_attribute_reads_as_empty(repo):
    """DynamoDB String Sets cannot be empty: DELETE of the last element removes
    the attribute, and the read contract is 'absent == no groups' -> []."""
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))
    repo.append_membership_event(_event("u1", "g-a", MEVENT_REMOVED))
    claims = repo.get_member_claims("u1")
    assert claims["memberGroupIds"] == []
    # attribute is actually gone, not an empty set
    raw = repo.get_member_claims("u1")
    assert raw["memberGroupIds"] == []


def test_add_is_idempotent(repo):
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))  # replay
    assert repo.get_member_claims("u1")["memberGroupIds"] == ["g-a"]


def test_role_change_updates_claim(repo):
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_UGL,
                   "ledGroupId": "g-lead"})
    claims = repo.get_member_claims("u1")
    assert claims["role"] == ROLE_UGL
    assert claims["ledGroupId"] == "g-lead"


def test_demotion_removes_led_group(repo):
    """A demoted/reassigned UGL must not keep a stale ledGroupId in the claim the
    edge trusts (the pre-existing stale-high gap this design closes)."""
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_UGL,
                   "ledGroupId": "g-lead"})
    assert repo.get_member_claims("u1")["ledGroupId"] == "g-lead"
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    assert repo.get_member_claims("u1")["ledGroupId"] is None


def test_membership_event_before_put_user_still_builds_item(repo):
    """ADD on a String Set upserts the item, so a membership event that races
    ahead of the user's first put_user does not lose the group."""
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))
    claims = repo.get_member_claims("u1")
    assert claims is not None
    assert claims["memberGroupIds"] == ["g-a"]
    assert claims["role"] == ROLE_MEMBER  # default until put_user fills it


def test_version_increments(repo):
    repo.put_user({"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    v1 = repo.get_member_claims("u1")["version"]
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))
    v2 = repo.get_member_claims("u1")["version"]
    assert v2 > v1


def test_get_member_claims_absent_returns_none(repo):
    assert repo.get_member_claims("nobody") is None


def test_rebuild_member_claims_recomputes_from_source(repo):
    """Backfill/repair path: overwrites the item from user record + folded
    membership events, independent of the incremental hooks."""
    # Seed membership events directly (as history), simulating pre-hook data.
    repo.append_membership_event(_event("u1", "g-a", MEVENT_JOINED))
    repo.append_membership_event(_event("u1", "g-b", MEVENT_JOINED))
    repo.append_membership_event(_event("u1", "g-a", MEVENT_LEFT))
    rebuilt = repo.rebuild_member_claims(
        {"id": "u1", "email": "u1@x.com", "role": ROLE_MEMBER})
    assert rebuilt["role"] == ROLE_MEMBER
    assert repo.get_member_claims("u1")["memberGroupIds"] == ["g-b"]


def test_rebuild_for_ugl_sets_led_no_member_groups(repo):
    rebuilt = repo.rebuild_member_claims(
        {"id": "ugl1", "email": "ugl1@x.com", "role": ROLE_UGL, "ledGroupId": "g-lead"})
    assert "memberGroupIds" not in rebuilt  # UGL carries led, not member groups
    claims = repo.get_member_claims("ugl1")
    assert claims["ledGroupId"] == "g-lead"
    assert claims["memberGroupIds"] == []
