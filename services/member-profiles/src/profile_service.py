"""ProfileService — getOwnProfile / updateOwnProfile / getMember (US-3.1/3.2/3.3).

Merges the profile-extension record with read-time fan-out results (rollup/tier
from Contributions, basic activity counts from Events/Forums/Certifications) —
BR-9: each fan-out call degrades independently, never fails the whole response.
"""
from __future__ import annotations

import uuid

from _conventions.errors import ForbiddenError, NotFoundError, ValidationError
from _conventions.validation import require_int, require_str
from models import (
    AVATAR_CONTENT_TYPES,
    AVATAR_MAX_BYTES,
    BIO_MAX_LEN,
    EDITABLE_FIELDS,
    SHORT_TEXT_MAX_LEN,
    SKILL_MAX_LEN,
    now_iso,
    profile_public,
)
from shoutout_service import can_send_shoutout


class ProfileService:
    def __init__(self, repo, fan_out, events, avatar_storage=None):
        self._repo = repo
        self._fan_out = fan_out
        self._events = events
        self._avatar_storage = avatar_storage

    # ---------------- grantAvatarUpload (US-3.2) ----------------
    def grant_avatar_upload(self, member_id: str, body: dict) -> dict:
        """Mint a short-lived presigned POST so the browser uploads the picture
        straight to the dedicated avatar bucket. Content type and size are
        validated BEFORE minting, so a disallowed type/size never gets an upload
        target. The client then saves the returned avatarUrl on the profile."""
        content_type = require_str(body.get("contentType"), "contentType", max_len=100)
        if content_type not in AVATAR_CONTENT_TYPES:
            raise ValidationError(details=[{
                "field": "contentType",
                "message": f"must be one of {sorted(AVATAR_CONTENT_TYPES)}"}])
        size = require_int(int(body.get("sizeBytes") or 0), "sizeBytes",
                           minimum=1, maximum=AVATAR_MAX_BYTES)
        ext = AVATAR_CONTENT_TYPES[content_type]
        # Server-derived key (never trust a client path) scoped to the caller.
        key = f"avatars/{member_id}/{uuid.uuid4().hex}.{ext}"
        return self._avatar_storage.grant_upload(
            key, content_type=content_type, max_bytes=size)

    # ---------------- getOwnProfile (US-3.1) ----------------
    def get_own_profile(self, member_id: str, *, bearer_token: str | None = None,
                        claim_headers: dict | None = None) -> dict:
        profile = self._repo.get_profile(member_id) or {"id": member_id, "groups": []}
        rollup, tiers, activity = self._fan_out_basic(
            member_id, bearer_token=bearer_token, claim_headers=claim_headers)
        return profile_public(profile, rollup=rollup, tiers=tiers, activity_summary=activity)

    # ---------------- updateOwnProfile (US-3.2) ----------------
    def update_own_profile(self, member_id: str, body: dict, *, bearer_token: str | None = None,
                           claim_headers: dict | None = None) -> dict:
        profile = self._repo.get_profile(member_id) or {"id": member_id, "groups": [], "createdAt": now_iso()}
        for field in EDITABLE_FIELDS:
            if field not in body:
                continue
            value = body[field]
            # Bio is prose with its own generous cap; the others are short fields.
            # Empty values are allowed (clears the field) and skip the min-length
            # check, matching the prior behaviour.
            if field in ("city", "country", "professionalRole", "avatar"):
                value = require_str(value, field, max_len=SHORT_TEXT_MAX_LEN) if value else value
                if field == "avatar" and value and not (
                        value.startswith("/avatars/") or value.startswith("https://")):
                    # Avatars are uploaded to the SPA bucket and stored as the
                    # relative served path (/avatars/...); reject anything else
                    # (e.g. javascript:/data:/http: URIs) so an image src is safe.
                    raise ValidationError(details=[
                        {"field": "avatar", "message": "must be an uploaded /avatars/ path"}])
            if field == "bio":
                value = require_str(value, field, max_len=BIO_MAX_LEN) if value else value
            if field == "skills":
                # BR-17: skills are free text and were previously unvalidated —
                # any length, any content, including angle brackets. Validate each.
                if value is not None:
                    if not isinstance(value, list):
                        raise ValidationError(details=[{"field": "skills", "message": "must be a list"}])
                    value = [require_str(s, "skills", max_len=SKILL_MAX_LEN) for s in value]
            if field == "timezone":
                profile["timeZone"] = value
                continue
            profile[field] = value
        profile["updatedAt"] = now_iso()
        self._repo.put_profile(profile)
        # `avatar` is on the payload so other services can keep their own member
        # projection's photo current (Contributions-Scoring uses it for the
        # leaderboard chips). It is the stable relative `/avatars/...` path, so a
        # denormalised copy stays valid; an empty string means "photo removed"
        # and must overwrite, not be skipped.
        self._events.publish("MemberProfileUpserted", {
            "userId": member_id, "firstName": profile.get("firstName", ""),
            "lastName": profile.get("lastName", ""), "email": profile.get("email", ""),
            "avatar": profile.get("avatar", ""),
            "skills": profile.get("skills", []), "bio": profile.get("bio", ""),
            "city": profile.get("city"), "country": profile.get("country"),
            "professionalRole": profile.get("professionalRole"), "status": profile.get("status"),
        })
        rollup, tiers, activity = self._fan_out_basic(
            member_id, bearer_token=bearer_token, claim_headers=claim_headers)
        return profile_public(profile, rollup=rollup, tiers=tiers, activity_summary=activity)

    # ---------------- getMember (US-3.3) ----------------
    def get_member(self, member_id: str, *, principal_role: str, principal=None,
                   bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        if principal_role == "Administrator":
            raise ForbiddenError()  # BR-4 — Admins use Identity's /users instead
        profile = self._repo.get_profile(member_id)
        if profile is None:
            raise NotFoundError()
        rollup, tiers, activity = self._fan_out_basic(
            member_id, bearer_token=bearer_token, claim_headers=claim_headers)
        # `principal` is optional so older callers/tests keep working; without it
        # the flag stays False and the button simply is not offered.
        can_shout = bool(principal) and can_send_shoutout(principal, profile)
        return profile_public(profile, rollup=rollup, tiers=tiers, activity_summary=activity,
                              can_shoutout=can_shout)

    # ---------------- shared fan-out (basic block, plan Q2 / BR-12) ----------------
    def _fan_out_basic(self, member_id: str, *, bearer_token: str | None,
                       claim_headers: dict | None = None):
        results = self._fan_out.fan_out({
            "contributions": f"/contributions/me?memberId={member_id}",
            "events": f"/events?memberId={member_id}&countOnly=true",
            # /forums has no cross-channel author-count endpoint (no author GSI exists).
            # The contributions ledger records every "Create a forum post" entry;
            # count those rows as the forum-post stat. The activity param filters
            # to only forum-post ledger entries and countOnly skips serialisation.
            "forums": f"/contributions/history?memberId={member_id}&scope=all&activityFilter=Create+a+forum+post&countOnly=true",
            "certifications": f"/certifications/claims?memberId={member_id}&status=Approved&countOnly=true",
        }, bearer_token=bearer_token, claim_headers=claim_headers)

        contrib = results.get("contributions") or {}
        rollup = {"points": contrib.get("points", 0), "quarter": contrib.get("quarter", "")} if contrib else None
        tiers = [{"groupId": contrib.get("groupId"), "tier": contrib.get("tier")}] if contrib.get("tier") else []

        activity = {
            "eventsAttended": (results.get("events") or {}).get("count", 0),
            "forumPosts": (results.get("forums") or {}).get("count", 0),
            "contributions": (results.get("contributions") or {}).get("submissionCount", 0),
            "certifications": (results.get("certifications") or {}).get("count", 0),
        }
        return rollup, tiers, activity
