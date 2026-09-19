"""Identity mention-suggest client (NFR-FO-REL-1, J1).

Calls Identity's GET /members endpoint to get @mention autocomplete candidates.
1.5s timeout, fail-soft to empty list — posting never blocks on this.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import quote

import requests

logger = logging.getLogger(__name__)

_TIMEOUT_MS = int(os.environ.get("MENTION_TIMEOUT_MS", "1500"))
_TIMEOUT_S = _TIMEOUT_MS / 1000.0


class MentionClient:
    """Lightweight HTTP client for Identity's member lookup."""

    def __init__(self, base_url: str | None = None):
        raw = (base_url or os.environ.get("API_BASE_URL", "")).rstrip("/")
        if raw and not raw.startswith("https://"):
            raise ValueError(
                f"API_BASE_URL must use the https:// scheme — got: {raw!r}. "
                "file:// and other schemes are not permitted."
            )
        self._base_url = raw

    def suggest(self, q: str, group_id: str, bearer_token: str | None,
                claim_headers: dict | None = None) -> list[dict]:
        """Return mention candidates for the given prefix + group.

        Fail-soft: on timeout/error returns empty list (post still succeeds).
        `claim_headers` forward the caller's fresh claims to member-profiles'
        browseDirectory (this is the one internal call gated on the caller's own
        member_group_ids), so scoping stays fresh on the private path.
        """
        if not self._base_url or not q:
            return []
        url = f"{self._base_url}/members?q={quote(q, safe='')}&groupId={quote(group_id, safe='')}&limit=10"
        try:
            headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
            headers.update(claim_headers or {})
            resp = requests.get(
                url,
                headers=headers,
                timeout=_TIMEOUT_S,
            )
            resp.raise_for_status()
            return resp.json().get("items", [])
        except (requests.exceptions.RequestException, ValueError) as exc:
            logger.warning("mentionSuggest failed (fail-soft): %s", exc)
            return []

    def validate_mentions(
        self, user_ids: list[str], group_id: str, bearer_token: str | None,
        claim_headers: dict | None = None
    ) -> list[str]:
        """Validate mentioned user IDs against group access.

        Returns only the IDs that are valid group members/leaders/CLs.
        On failure, returns empty (fail-soft — post proceeds without mentions).
        """
        if not user_ids or not self._base_url:
            return []
        # For validation, we fetch group members and check intersection
        # At community scale, the group member list is bounded
        url = f"{self._base_url}/members?groupId={quote(group_id, safe='')}&limit=200"
        try:
            headers = {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
            headers.update(claim_headers or {})
            resp = requests.get(
                url,
                headers=headers,
                timeout=_TIMEOUT_S,
            )
            resp.raise_for_status()
            data = resp.json()
            valid_ids = {m.get("id") or m.get("userId", "") for m in data.get("items", [])}
            return [uid for uid in user_ids if uid in valid_ids]
        except (requests.exceptions.RequestException, ValueError) as exc:
            logger.warning("mention validation failed (fail-soft): %s", exc)
            return []
