"""FanOutClient — parallel, per-call-timeout cross-service reads (BR-9, NFR-MP-PERF-2/3).

This is the unit's defining resiliency pattern: `getOwnProfile`/`getMember` need a
current-quarter rollup from Contributions and basic activity counts from
Events/Forums/Certifications; `memberActivity` needs a fuller version of the same.
Each downstream call is issued in parallel (ThreadPoolExecutor) with its own bounded
timeout, and any failure (timeout, 5xx, connection error) is caught individually and
returns None rather than raising — a slow/unavailable dependency degrades only its
own section of the response, never the whole request (RESILIENCY-10).

A lightweight per-warm-container short-circuit (not a distributed circuit breaker)
skips a downstream service for a short cool-down window after repeated consecutive
failures, avoiding wasted timeout budget during a known outage. State resets on
cold start — acceptable since it is a latency optimization, not a correctness
mechanism (the per-call try/except already guarantees correctness on its own).

Calls forward the calling principal's own bearer token (same-account, same shared
API Gateway) so the downstream service's own in-service authZ applies unchanged —
no service-to-service credential is minted here (Infra Design Q2).
"""
from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib import error as urlerror
from urllib import request as urlrequest

from _conventions.logger import get_logger, log

_logger = get_logger("member-profiles.fan_out")

# Per-call fan-out budget. The 300ms placeholder was set while downstreams were
# MOCKS; the design (nfr-requirements/tech-stack-decisions.md) explicitly deferred
# the "final value set against measured downstream p95s once those services are
# real". Against the real Contributions /contributions/me (several sequential
# DynamoDB reads: memberships + rollup + lifetime + submissions + pillars, behind
# API Gateway with possible Lambda cold start) 300ms timed out MOST of the time,
# so the profile's contribution score, tier-by-group and contributions count came
# back empty intermittently. 2.5s comfortably covers warm p95 plus cold-start
# headroom; the parallel fan-out means this bounds total added latency (not the
# sum), and the short-circuit still skips a genuinely-down dependency after 3 fails.
_DEFAULT_TIMEOUT_SECONDS = 2.5  # per-call budget (tuned against real downstream latency)
_SHORT_CIRCUIT_THRESHOLD = 3     # consecutive failures before skipping
_SHORT_CIRCUIT_COOLDOWN_SECONDS = 30

# Per-warm-container failure state (resets on cold start — intentional).
_failure_state: dict[str, dict] = {}


def _short_circuited(service: str) -> bool:
    state = _failure_state.get(service)
    if not state:
        return False
    if state["consecutive"] < _SHORT_CIRCUIT_THRESHOLD:
        return False
    return (time.monotonic() - state["last_failure"]) < _SHORT_CIRCUIT_COOLDOWN_SECONDS


def _record_result(service: str, ok: bool) -> None:
    state = _failure_state.setdefault(service, {"consecutive": 0, "last_failure": 0.0})
    if ok:
        state["consecutive"] = 0
    else:
        state["consecutive"] += 1
        state["last_failure"] = time.monotonic()


class FanOutClient:
    """Issues parallel, timeout-bounded GET calls to sibling services through the
    shared API Gateway. `base_url` defaults to the same-account API endpoint."""

    def __init__(self, base_url: str | None = None, timeout: float = _DEFAULT_TIMEOUT_SECONDS,
                 opener=None):
        self.base_url = (base_url or os.environ.get("API_BASE_URL", "")).rstrip("/")
        self.timeout = timeout
        self._opener = opener or urlrequest.urlopen

    def _get(self, service: str, path: str, *, bearer_token: str | None,
             claim_headers: dict | None = None) -> dict | None:
        """A single GET call, individually fault-isolated. Returns None on ANY
        failure (timeout, HTTP error, connection error, bad JSON) — never raises.

        `claim_headers` (X-Claims-*) propagate the CALLER's fresh claims to the
        private API so the downstream builds its principal from them (the private
        API has no authorizer). Sent alongside the JWT during rollout; the JWT is
        dropped once the private authorizer is removed."""
        if _short_circuited(service):
            return None
        if not self.base_url or not self.base_url.startswith("https://"):
            # Only https:// same-account API Gateway endpoints are permitted
            # (SECURITY-01/07) — reject anything else (e.g. file://, custom
            # schemes) before ever constructing a request (S310).
            return None
        req = urlrequest.Request(f"{self.base_url}{path}", method="GET")  # noqa: S310 — scheme validated above
        if bearer_token:
            req.add_header("Authorization", f"Bearer {bearer_token}")
        for hk, hv in (claim_headers or {}).items():
            req.add_header(hk, hv)
        try:
            with self._opener(req, timeout=self.timeout) as resp:  # noqa: S310 — scheme validated above
                body = resp.read()
                _record_result(service, ok=True)
                return json.loads(body) if body else None
        except (urlerror.URLError, TimeoutError, ValueError, OSError) as err:
            _record_result(service, ok=False)
            log(_logger, 30, "fan-out call failed (degrading gracefully)",
                service=service, path=path, error=str(err))
            return None

    def fan_out(self, calls: dict[str, str], *, bearer_token: str | None = None,
                claim_headers: dict | None = None) -> dict[str, dict | None]:
        """`calls` = {service_name: path}. Issues all calls in parallel; returns
        {service_name: response_or_None}. Bounded total latency = slowest single
        call, not the sum (NFR-MP-PERF-2). `claim_headers` forward the caller's
        fresh claims to each internal call (see _get)."""
        if not calls:
            return {}
        with ThreadPoolExecutor(max_workers=len(calls)) as pool:
            futures = {
                svc: pool.submit(self._get, svc, path, bearer_token=bearer_token,
                                 claim_headers=claim_headers)
                for svc, path in calls.items()
            }
            return {svc: f.result() for svc, f in futures.items()}
