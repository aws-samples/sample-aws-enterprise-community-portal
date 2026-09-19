"""Shoutout service (US-13.1–13.10).

Leader-to-member recognition. CL can shout out any member; UGL can shout out
own group members only. Informational only — never awards points.

Performance contract (13k+ member groups):
- All access patterns are single-partition DynamoDB Queries (no Scans, no GSIs).
- Recipient picker uses existing server-side search — never loads full member list.
- Weekly limit check: Query SHOUTOUT_SENT#<senderId> with SK > weekStart (≤3 items).
- Home feed: Query SHOUTOUT_FEED with limit 5.
- Reaction: conditional put + atomic counter increment.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone, timedelta

from _conventions.errors import ForbiddenError, NotFoundError, ValidationError
from _conventions.logger import get_logger, log
from _conventions.validation import require

_logger = get_logger("member-profiles.shoutout_service")


ROLE_CL = "CommunityLeader"
ROLE_UGL = "UserGroupLeader"
ROLE_MEMBER = "Member"

MAX_MESSAGE_LENGTH = 280
# Default weekly quotas — overridden by settings if available
DEFAULT_LEADER_CL_LIMIT = 10
DEFAULT_LEADER_UGL_LIMIT = 6
DEFAULT_MEMBER_LIMIT = 3
FEED_LIMIT = 5
FEED_DAYS = 7


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _week_start_iso() -> str:
    """Monday 00:00 UTC of the current week."""
    now = datetime.now(timezone.utc)
    monday = now - timedelta(days=now.weekday())
    return monday.replace(hour=0, minute=0, second=0, microsecond=0).isoformat()


def _feed_cutoff_iso() -> str:
    """7 days ago."""
    return (datetime.now(timezone.utc) - timedelta(days=FEED_DAYS)).isoformat()


# ---------------------------------------------------------------------------
# Eligibility, as ONE definition per rule.
#
# `send()` below evaluates these to raise a specific message, and the API also
# publishes the combined verdict as `canShoutout` on a member payload so the UI
# can decide whether to offer the button. Before this existed the UI guessed:
# the profile page keyed the button off the VIEWER's role being "Member", so
# leaders — who the backend explicitly allows — got no button at all, while a
# member looking at a leader's profile got one that always failed.
#
# Quota is deliberately NOT part of this. "You may not recognise this person"
# and "you have used this week's allowance" are different states: the first
# should hide the button, the second is a temporary condition that the modal
# reports with the exact number and reset day (US-13.3).
# ---------------------------------------------------------------------------

def sender_may_shout(role: str) -> bool:
    """Administrators cannot; every other role can. Note this is NOT
    leaders-only — US-13.11 added peer shoutouts, so Members send too."""
    return role in (ROLE_CL, ROLE_UGL, ROLE_MEMBER)


def recipient_may_receive(recipient: dict) -> bool:
    """Recipients must be Members. This is how "leaders recognise members, not
    each other" is implemented — as a property of the recipient, so it holds for
    every sender rather than only for leaders."""
    return recipient.get("role", ROLE_MEMBER) == ROLE_MEMBER


def ugl_in_scope(principal, recipient: dict) -> bool:
    """A UGL may only recognise members of the group they lead."""
    led_group = getattr(principal, "led_group_id", None)
    if not led_group:
        return False
    return led_group in {g.get("groupId") for g in (recipient.get("groups") or [])}


def can_send_shoutout(principal, recipient: dict) -> bool:
    """Combined verdict for one (sender, recipient) pair."""
    if not recipient or not sender_may_shout(getattr(principal, "role", "")):
        return False
    if recipient.get("id") and recipient["id"] == getattr(principal, "user_id", None):
        return False  # no self-shoutouts
    if not recipient_may_receive(recipient):
        return False
    if principal.role == ROLE_UGL:
        return ugl_in_scope(principal, recipient)
    return True


class ShoutoutService:
    def __init__(self, repo, events=None, fan_out=None):
        self._repo = repo
        self._events = events
        self._fan_out = fan_out

    def _weekly_limit(self, role: str, bearer_token: str | None = None,
                      claim_headers: dict | None = None) -> int:
        """Fetch configurable limits from settings, fall back to defaults."""
        limits = {
            ROLE_CL: DEFAULT_LEADER_CL_LIMIT,
            ROLE_UGL: DEFAULT_LEADER_UGL_LIMIT,
            ROLE_MEMBER: DEFAULT_MEMBER_LIMIT,
        }
        if self._fan_out:
            try:
                result = self._fan_out.fan_out({"settings": "/settings"}, bearer_token=bearer_token,
                                               claim_headers=claim_headers)
                s = result.get("settings") or {}
                if "shoutoutLimitCl" in s:
                    limits[ROLE_CL] = int(s["shoutoutLimitCl"])
                if "shoutoutLimitUgl" in s:
                    limits[ROLE_UGL] = int(s["shoutoutLimitUgl"])
                if "shoutoutLimitMember" in s:
                    limits[ROLE_MEMBER] = int(s["shoutoutLimitMember"])
            except Exception as exc:  # noqa: BLE001 — never fail on settings lookup
                log(_logger, 30, "settings lookup failed — using default shoutout limits", error=str(exc))
        return limits.get(role, DEFAULT_MEMBER_LIMIT)

    # ---- Send (US-13.1/13.2/13.3) ----

    def send(self, body: dict, *, principal, bearer_token: str | None = None,
             claim_headers: dict | None = None) -> dict:
        """Send a shoutout. CL: any member. UGL: own group members. Member: any other member."""
        if not sender_may_shout(principal.role):
            raise ForbiddenError()

        recipient_id = (body.get("recipientId") or "").strip()
        message = (body.get("message") or "").strip()
        require(bool(recipient_id), "recipientId", "is required")
        require(bool(message), "message", "is required")
        require(len(message) <= MAX_MESSAGE_LENGTH, "message",
                f"must be {MAX_MESSAGE_LENGTH} characters or fewer")

        # Cannot shout out yourself
        if recipient_id == principal.user_id:
            raise ValidationError("You cannot send a shoutout to yourself.")

        # Resolve recipient profile
        recipient = self._repo.get_profile(recipient_id)
        if not recipient:
            raise NotFoundError()
        if not recipient_may_receive(recipient):
            raise ValidationError("Shoutouts can only be sent to Members.")

        # UGL scope check: can only shout out own group members
        if principal.role == ROLE_UGL and not ugl_in_scope(principal, recipient):
            raise ForbiddenError()

        # Weekly limit check (US-13.3) — role-based quotas from settings
        is_leader = principal.role in (ROLE_CL, ROLE_UGL)
        weekly_limit = self._weekly_limit(principal.role, bearer_token, claim_headers)
        week_start = _week_start_iso()
        sent_this_week = self._repo.list_shoutouts_sent_since(principal.user_id, week_start)
        if len(sent_this_week) >= weekly_limit:
            if is_leader:
                raise ValidationError(
                    f"You've used all {weekly_limit} shoutouts for this week. Resets Monday.")
            else:
                raise ValidationError(
                    "You've used your shoutout for this week. Resets Monday.")

        # 1 per recipient per sender per week
        if any(s.get("recipientId") == recipient_id for s in sent_this_week):
            raise ValidationError(
                "You've already sent a shoutout to this member this week.")

        # Build shoutout record
        shoutout_id = uuid.uuid4().hex[:16]
        now = _now_iso()
        recipient_name = f"{recipient.get('firstName', '')} {recipient.get('lastName', '')}".strip()
        # Determine recipient's primary group + resolve name via fan-out
        groups = recipient.get("groups") or []
        recipient_group_id = groups[0].get("groupId", "") if groups else ""
        recipient_group_name = ""
        if recipient_group_id and self._fan_out:
            try:
                result = self._fan_out.fan_out(
                    {"group": f"/groups/{recipient_group_id}"}, bearer_token=bearer_token,
                    claim_headers=claim_headers)
                g = result.get("group") or {}
                recipient_group_name = g.get("name") or ""
            except Exception as exc:  # noqa: BLE001
                log(_logger, 30, "group name lookup failed — falling back to groupId",
                    groupId=recipient_group_id, error=str(exc))
        if not recipient_group_name:
            recipient_group_name = recipient_group_id

        sender_name = ""
        sender_profile = self._repo.get_profile(principal.user_id)
        if sender_profile:
            sender_name = f"{sender_profile.get('firstName', '')} {sender_profile.get('lastName', '')}".strip()

        record = {
            "shoutoutId": shoutout_id,
            "recipientId": recipient_id,
            "recipientName": recipient_name or recipient_id,
            "recipientAvatar": recipient.get("avatar") or "",
            "recipientGroupId": recipient_group_id,
            "recipientGroupName": recipient_group_name,
            "senderId": principal.user_id,
            "senderName": sender_name or principal.user_id,
            "senderRole": principal.role,
            "isLeaderPick": is_leader,
            "message": message,
            "createdAt": now,
            "reactionCount": 0,
        }

        self._repo.put_shoutout(record)

        # Publish event for notifications + milestone evaluator
        if self._events:
            self._events.publish("ShoutoutReceived", {
                "shoutoutId": shoutout_id,
                "recipientId": recipient_id,
                "senderId": principal.user_id,
                "senderName": sender_name,
                "message": message[:50],
            })

        return _public(record)

    # ---- Read (US-13.4/13.5) ----

    def recent_feed(self) -> dict:
        """Home page feed: last 7 days, max 5."""
        cutoff = _feed_cutoff_iso()
        items = self._repo.query_shoutout_feed(cutoff, limit=FEED_LIMIT)
        return {"items": [_public(s) for s in items], "count": len(items)}

    def all_feed(self, *, cursor: str | None = None, limit: int = 20) -> dict:
        """Full paginated feed: last 30 days, for the detailed shoutouts page."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        limit = min(max(1, limit), 50)
        items, next_cursor = self._repo.query_shoutout_feed_page(cutoff, limit=limit, cursor=cursor)
        result: dict = {"items": [_public(s) for s in items], "count": len(items)}
        if next_cursor:
            result["cursor"] = next_cursor
        return result

    def member_shoutouts(self, member_id: str, *, cursor: str | None = None, limit: int = 20) -> dict:
        """Shoutouts received by a specific member (profile view), paginated."""
        limit = min(max(1, limit), 50)
        items, next_cursor = self._repo.query_shoutouts_for_recipient_page(member_id, limit=limit, cursor=cursor)
        result: dict = {"items": [_public(s) for s in items], "count": len(items)}
        if next_cursor:
            result["cursor"] = next_cursor
        return result

    def my_sent(self, *, principal, cursor: str | None = None, limit: int = 20) -> dict:
        """Shoutouts sent by the calling user, last 30 days, paginated."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        limit = min(max(1, limit), 50)
        items, next_cursor = self._repo.query_shoutouts_sent_page(principal.user_id, cutoff, limit=limit, cursor=cursor)
        result: dict = {"items": [_public(s) for s in items], "count": len(items)}
        if next_cursor:
            result["cursor"] = next_cursor
        return result

    # ---- React (US-13.6) ----

    def toggle_reaction(self, shoutout_id: str, *, principal) -> dict:
        """Toggle 👏 reaction. Returns new state."""
        shoutout = self._repo.get_shoutout(shoutout_id)
        if not shoutout:
            raise NotFoundError()

        reacted = self._repo.toggle_shoutout_reaction(shoutout_id, principal.user_id)
        new_count = self._repo.get_shoutout_reaction_count(shoutout_id)
        return {"reacted": reacted, "reactionCount": new_count}

    # ---- Delete (US-13.9/13.10) ----

    def delete(self, shoutout_id: str, *, principal) -> None:
        """Delete a shoutout. Sender or CL only."""
        shoutout = self._repo.get_shoutout(shoutout_id)
        if not shoutout:
            raise NotFoundError()
        # Only the sender or a CL can delete
        if principal.user_id != shoutout.get("senderId") and principal.role != ROLE_CL:
            raise ForbiddenError()
        self._repo.delete_shoutout(shoutout)

    # ---- Quota info (for the modal display) ----

    def my_quota(self, *, principal, bearer_token: str | None = None,
                 claim_headers: dict | None = None) -> dict:
        """How many shoutouts the user has remaining this week."""
        if principal.role not in (ROLE_CL, ROLE_UGL, ROLE_MEMBER):
            return {"remaining": 0, "limit": 0}
        weekly_limit = self._weekly_limit(principal.role, bearer_token, claim_headers)
        week_start = _week_start_iso()
        sent = self._repo.list_shoutouts_sent_since(principal.user_id, week_start)
        return {"remaining": max(0, weekly_limit - len(sent)), "limit": weekly_limit,
                "sent": len(sent)}


def _public(record: dict) -> dict:
    """Serialize a shoutout for the API response."""
    return {
        "id": record.get("shoutoutId"),
        "recipientId": record.get("recipientId"),
        "recipientName": record.get("recipientName"),
        "recipientAvatar": record.get("recipientAvatar"),
        "recipientGroupId": record.get("recipientGroupId"),
        "recipientGroupName": record.get("recipientGroupName"),
        "senderId": record.get("senderId"),
        "senderName": record.get("senderName"),
        "senderRole": record.get("senderRole"),
        "isLeaderPick": bool(record.get("isLeaderPick")),
        "message": record.get("message"),
        "createdAt": record.get("createdAt"),
        "reactionCount": int(record.get("reactionCount") or 0),
    }
