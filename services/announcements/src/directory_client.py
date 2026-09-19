"""DirectoryClient — create-time author/group name denormalization (NFR-AN-REL-1).

The panel meta line shows the author's display name and the target group name(s)
(BR-8). JWT claims carry no display names, so we resolve them once AT CREATE via
the shared API Gateway (Members `GET /members/{id}`, Groups `GET /groups/{id}`),
forwarding the caller's own bearer token (no service credential minted — the
downstream authZ applies unchanged). Each call is bounded at 1.5s and FAILS
CLOSED: on any failure we return None and the caller stores email/id / raw group
id, so authoring never blocks on the directory (RESILIENCY-10). Panel READS never
call this — names are already denormalized on the item.
"""
from __future__ import annotations

import json
import os
from urllib import error as urlerror
from urllib import request as urlrequest

from _conventions.logger import get_logger, log

_logger = get_logger("announcements.directory")

_DEFAULT_TIMEOUT_SECONDS = 1.5  # tuned value (Events lesson: 300ms too tight for NAT->APIGW->Lambda)


class DirectoryClient:
    def __init__(self, base_url: str | None = None, timeout: float | None = None, opener=None):
        self.base_url = (base_url or os.environ.get("API_BASE_URL", "")).rstrip("/")
        env_timeout = os.environ.get("DIRECTORY_TIMEOUT_MS")
        self.timeout = timeout if timeout is not None else (
            (int(env_timeout) / 1000.0) if env_timeout else _DEFAULT_TIMEOUT_SECONDS)
        self._opener = opener or urlrequest.urlopen

    def _get(self, path: str, *, bearer_token: str | None,
             claim_headers: dict | None = None) -> dict | None:
        if not self.base_url or not self.base_url.startswith("https://"):
            return None  # only https:// same-account API GW permitted (SECURITY-01/07, S310)
        req = urlrequest.Request(f"{self.base_url}{path}", method="GET")  # noqa: S310 — scheme validated
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")
        for hk, hv in (claim_headers or {}).items():
            req.add_header(hk, hv)
        try:
            with self._opener(req, timeout=self.timeout) as resp:  # noqa: S310 — scheme validated
                body = resp.read()
                return json.loads(body) if body else None
        except (urlerror.URLError, TimeoutError, ValueError, OSError) as err:
            log(_logger, 30, "directory lookup failed (degrading fail-closed)", path=path, error=str(err))
            return None

    def member_name(self, member_id: str, *, bearer_token: str | None = None,
                    claim_headers: dict | None = None) -> str | None:
        data = self._get(f"/members/{member_id}", bearer_token=bearer_token,
                         claim_headers=claim_headers)
        if not data:
            return None
        first, last = data.get("firstName") or "", data.get("lastName") or ""
        name = f"{first} {last}".strip()
        return name or data.get("email") or None

    def group_name(self, group_id: str, *, bearer_token: str | None = None,
                   claim_headers: dict | None = None) -> str | None:
        data = self._get(f"/groups/{group_id}", bearer_token=bearer_token,
                         claim_headers=claim_headers)
        if not data:
            return None
        return data.get("name") or None
