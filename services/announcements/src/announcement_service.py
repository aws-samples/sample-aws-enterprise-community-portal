"""AnnouncementService — create/edit/delete/list orchestration (US-10.1/10.2/10.3).

Authorization is enforced inline by role (mirrors the working Member Profiles
pattern; the permission-matrix JSON is not packaged into service Lambdas), matching
role-permission-matrix.v1.json semantics: create = CL(global)/UGL(group-own);
edit = author only; delete = author or any CL (moderation); Administrator denied on
everything (BR-1..4). Every announcement is a single stored definition — post/edit/
delete are O(1) writes, no fan-out (BR-7).
"""
from __future__ import annotations

import uuid

import models
from _conventions.authz import claims_to_headers
from _conventions.errors import ForbiddenError, NotFoundError
from _conventions.logger import set_correlation_id
from _conventions.validation import require_str

LEADER_ROLES = {"CommunityLeader", "UserGroupLeader"}


class AnnouncementService:
    def __init__(self, repo, cache, directory, events):
        self._repo = repo
        self._cache = cache
        self._directory = directory
        self._events = events

    # ---- authorization helpers (inline, matrix-equivalent) ----
    @staticmethod
    def _require_author_role(principal) -> None:
        if principal.role not in LEADER_ROLES:
            raise ForbiddenError()  # Member / Administrator cannot create (BR-1/3)

    # ---- commands ----
    def create(self, body: dict, principal, *, bearer_token: str | None = None,
               correlation_id: str | None = None) -> dict:
        self._require_author_role(principal)
        title = require_str(body.get("title"), "title", max_len=models.TITLE_MAX)

        ch = claims_to_headers(principal)

        def _group_name(gid: str):
            return self._directory.group_name(gid, bearer_token=bearer_token, claim_headers=ch)

        target, source = models.normalize_target(body, principal, group_name_lookup=_group_name)
        expires_at = models.resolve_expiry(body.get("expiresAt"))
        author_name = self._directory.member_name(principal.user_id, bearer_token=bearer_token,
                                                  claim_headers=ch) \
            or principal.user_id
        email_opt_in = bool(body.get("emailOptIn", False))

        item = self._build_item(
            title=title, body=body.get("body"), target=target, source=source,
            author_id=principal.user_id, author_role=principal.role,
            email_opt_in=email_opt_in, expires_at=expires_at,
        )
        item["authorName"] = author_name
        self._repo.put(item)
        self._cache.invalidate()
        self._publish(item, correlation_id=correlation_id)
        return models.announcement_public(item)

    def edit(self, ann_id: str, body: dict, principal, *, bearer_token: str | None = None,
             correlation_id: str | None = None) -> dict:
        item = self._repo.get(ann_id)
        if item is None:
            raise NotFoundError()
        if item.get("authorId") != principal.user_id:  # author-only (BR-4); IDOR guard
            raise ForbiddenError()

        if "title" in body:
            item["title"] = require_str(body.get("title"), "title", max_len=models.TITLE_MAX)
        if "body" in body:
            from body import normalize_body
            item["body"] = normalize_body(body.get("body"))
        if "target" in body:
            def _group_name(gid: str):
                return self._directory.group_name(gid, bearer_token=bearer_token,
                                                  claim_headers=claims_to_headers(principal))
            target, source = models.normalize_target(body, principal, group_name_lookup=_group_name)
            item["targetScope"] = target["scope"]
            item["targetGroupIds"] = target["groupIds"]
            item["source"] = source
        was_opt_in = bool(item.get("emailOptIn", False))
        if "expiresAt" in body:
            expires_at = models.resolve_expiry(body.get("expiresAt"))
            item["expiresAt"] = models.to_iso(expires_at)
            item["ttl"] = models.epoch(expires_at)
        if "emailOptIn" in body:
            item["emailOptIn"] = bool(body.get("emailOptIn"))

        self._repo.put(item)
        self._cache.invalidate()
        # Re-publish only if email was newly opted in (avoid duplicate blasts, BR-10).
        if not was_opt_in and item.get("emailOptIn"):
            item["emailSent"] = True
            self._repo.put(item)
            self._publish(item, correlation_id=correlation_id)
        return models.announcement_public(item)

    def delete(self, ann_id: str, principal, *, correlation_id: str | None = None) -> None:
        item = self._repo.get(ann_id)
        if item is None:
            raise NotFoundError()
        is_author = item.get("authorId") == principal.user_id
        is_cl_moderator = principal.role == "CommunityLeader"  # delete/global (BR-4)
        if not (is_author or is_cl_moderator):
            raise ForbiddenError()
        self._repo.delete(ann_id)
        self._cache.invalidate()

    # ---- queries (management) ----
    def list_mine(self, principal) -> dict:
        self._require_author_role(principal)  # Member/Administrator have nothing authored
        items = self._repo.by_author(principal.user_id)
        items.sort(key=lambda i: i.get("createdAt", ""), reverse=True)
        return models.listing(items)

    def list_moderation(self, principal) -> dict:
        if principal.role != "CommunityLeader":  # scope=all is CL-only (BR-4)
            raise ForbiddenError()
        items = self._repo.scan_all()
        items.sort(key=lambda i: i.get("createdAt", ""), reverse=True)
        return models.listing(items)

    # ---- event-triggered auto-post (US-2.1, BR-17) ----
    def auto_post_from_event(self, data: dict, *, correlation_id: str | None = None) -> dict | None:
        """Create an announcement from an EventCreated payload when announce=true.
        System-triggered (no principal/JWT); name lookups fail closed to ids."""
        if not data.get("announce"):
            return None
        event_id = data.get("eventId") or data.get("seriesId")
        title = data.get("title") or "New event"
        group_id = data.get("groupId")
        if group_id:
            target = {"scope": models.SCOPE_GROUPS, "groupIds": [group_id]}
            source = group_id
        else:
            target = {"scope": models.SCOPE_COMMUNITY, "groupIds": []}
            source = models.COMMUNITY_SOURCE_LABEL
        expires_at = models.resolve_expiry(None)  # default +2d
        item = self._build_item(
            title=f"New event: {title}",
            body=f"A new event has been scheduled: {title}.",
            target=target, source=source,
            author_id=data.get("createdBy") or "system", author_role="UserGroupLeader",
            email_opt_in=bool(data.get("announceByEmail", False)), expires_at=expires_at,
        )
        item["authorName"] = item["authorId"]
        item["originEventId"] = event_id
        self._repo.put(item)
        self._cache.invalidate()
        self._publish(item, correlation_id=correlation_id)
        return models.announcement_public(item)

    # ---- internals ----
    def _build_item(self, *, title, body, target, source, author_id, author_role,
                    email_opt_in, expires_at) -> dict:
        from body import normalize_body
        return {
            "id": str(uuid.uuid4()),
            "title": title,
            "body": normalize_body(body),
            "targetScope": target["scope"],
            "targetGroupIds": target["groupIds"],
            "authorId": author_id,
            "authorRoleLabel": models.role_label(author_role),
            "source": source,
            "emailOptIn": email_opt_in,
            "emailSent": email_opt_in,  # "dispatched to Notifications"; delivery owned by Unit 10
            "createdAt": models.now_iso(),
            "expiresAt": models.to_iso(expires_at),
            "ttl": models.epoch(expires_at),
            "groupHidden": False,
            "originEventId": None,
        }

    def _publish(self, item: dict, *, correlation_id: str | None) -> None:
        if correlation_id:
            set_correlation_id(correlation_id)
        self._events.publish("AnnouncementPublished", {
            "announcementId": item["id"],
            "title": item["title"],
            "bodyPreview": (item.get("body") or "")[:280],
            "target": {"scope": item["targetScope"], "groupIds": item["targetGroupIds"]},
            "authorName": item.get("authorName", ""),
            "source": item.get("source", ""),
            "emailOptIn": item.get("emailOptIn", False),
            "expiresAt": item.get("expiresAt"),
        }, correlation_id=correlation_id)
