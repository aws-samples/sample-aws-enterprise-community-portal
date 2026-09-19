"""ActivityService — memberActivity (US-3.10), the leader-only detailed drill-down.

Distinct from ProfileService's basic inline activity block (BR-12): this adds
points (current-quarter + lifetime) and a date-range filter, and is scoped to
Community Leader (any member) / User Group Leader (own led group only) — 403 for
Administrator (BR-4) and for any Member caller (BR-13; a member's own basic
counts come from getOwnProfile, not this endpoint).
"""
from __future__ import annotations

from _conventions.errors import ForbiddenError, NotFoundError


class ActivityService:
    def __init__(self, repo, fan_out):
        self._repo = repo
        self._fan_out = fan_out

    def get_activity(self, member_id: str, *, principal_role: str, principal_led_group_id: str | None,
                      date_from: str | None = None, date_to: str | None = None,
                      bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        if principal_role in ("Administrator", "Member"):
            raise ForbiddenError()  # BR-4 (Admin), BR-13 (Member — self-view not offered here)

        target = self._repo.get_profile(member_id)
        if target is None:
            raise NotFoundError()

        if principal_role == "UserGroupLeader":
            member_group_ids = {g.get("groupId") for g in target.get("groups", [])}
            if not principal_led_group_id or principal_led_group_id not in member_group_ids:
                raise ForbiddenError()  # BR-13 — UGL scoped to their own led group

        qs = ""
        if date_from:
            qs += f"&from={date_from}"
        if date_to:
            qs += f"&to={date_to}"

        results = self._fan_out.fan_out({
            "events": f"/events?memberId={member_id}{qs}",
            "forums": f"/forums/posts?authorId={member_id}{qs}",
            "contributions": f"/contributions/me?memberId={member_id}{qs}",
            "certifications": f"/certifications/claims?memberId={member_id}{qs}",
        }, bearer_token=bearer_token, claim_headers=claim_headers)

        events = (results.get("events") or {}).get("items", [])
        forums = (results.get("forums") or {}).get("items", [])
        certs = (results.get("certifications") or {}).get("items", [])
        contrib = results.get("contributions") or {}

        items = [
            *[{"kind": "Event attended", "detail": e.get("title", ""), "at": e.get("startsAt")} for e in events],
            *[{"kind": "Forum post", "detail": p.get("title", ""), "at": p.get("createdAt")} for p in forums],
            *[{"kind": "Certification earned", "detail": c.get("certId", ""), "at": c.get("decidedAt")} for c in certs],
        ]

        return {
            "items": items,
            "count": len(items),
            "points": {
                "currentQuarter": contrib.get("points", 0),
                "lifetime": contrib.get("lifetimePoints", contrib.get("points", 0)),
            },
        }
