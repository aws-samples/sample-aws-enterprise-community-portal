"""Presenter / organizer designation and the completion-time awards (US-2.18).

BR-P3 is the rule that matters here and it is counter-intuitive enough to be
worth stating plainly: **only designees holding the Member role earn.**
Administrators, Community Leaders and User Group Leaders may be designated —
they often are, since they frequently present — but they are not point-eligible,
because earning points is exclusively a Member activity (US-6.17).

Change request 2026-08-06 (Q2-A / Q3-A):

* EXTERNAL presenters — people who are not portal users — arrive as plain names
  in `externalPresenters` and are stored as presenter rows with `external=True`
  and `pointsEligible=False`, always. Organizers cannot be external (the request
  is explicit: organizers are portal users).
* The designee's role now comes from a REAL server-side lookup at designation
  time (`DirectoryClient`), not from a default. The previous wiring defaulted
  every designee to Member, which made every designee — leaders included —
  points-eligible: BR-P3 existed only on paper. FAIL-CLOSED: if the lookup
  cannot verify the role, the designation is stored but marked NOT eligible with
  reason "role unverified" — a missed award is recoverable by re-designating, a
  wrong award is not revocable.

`ineligibleReason` exists so the authoring UI can state the exclusion at
designation time rather than leaving a leader to discover it after the event
(mockup gap G9).
"""
from __future__ import annotations

from _conventions.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from models import (
    POINT_ELIGIBLE_ROLES,
    STATUS_COMPLETED,
    can_manage,
    can_view,
    designation_public,
    listing,
    now_iso,
)

PRESENTER = "presenter"
ORGANIZER = "organizer"

MAX_DESIGNEES_PER_KIND = 25
MAX_EXTERNAL_NAME_LEN = 120

ROLE_UNVERIFIED_REASON = ("Role could not be verified — not points-eligible. "
                          "Re-designate to retry.")
EXTERNAL_REASON = "External presenters do not earn points."


class DesignationService:
    """`directory` resolves a userId to {"role", "displayName"} (or None) at
    designation time. It is injected so tests control it and so this service
    carries no Identity dependency of its own."""

    def __init__(self, repo, events, contributions, directory=None):
        self._repo = repo
        self._events = events
        self._contrib = contributions
        self._directory = directory
        # Per-request memo (Context is built per invocation): a recurring create
        # designates the same people on every occurrence, and 104 occurrences
        # must not mean 104 role lookups per designee.
        self._resolve_cache: dict[str, dict] = {}

    # ------------------------------------------------------------------ writes

    def set_from_input(self, event: dict, body: dict, *, principal,
                       bearer_token: str | None = None,
                       claim_headers: dict | None = None) -> dict | None:
        """Designations supplied inline on create. Returns the resulting counts
        so the caller can refresh its in-memory event dict — the counts are
        written to the STORED row by `set_designation_counts`, and without this
        the create response would report the pre-designation zeros (caught by
        the live deploy smoke, 2026-08-06)."""
        presenters = body.get("presenters") or []
        organizers = body.get("organizers") or []
        externals = body.get("externalPresenters") or []
        if not presenters and not organizers and not externals:
            return None
        return self._replace(event, presenters=presenters, organizers=organizers,
                             externals=externals, principal=principal,
                             bearer_token=bearer_token, claim_headers=claim_headers)

    def set(self, event_id: str, body: dict, *, principal,
            bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        event = self._repo.get_event(event_id)
        if event is None or not can_view(event, principal):
            raise NotFoundError(message="Event not found.")
        if not can_manage(event, principal):
            raise ForbiddenError(message="You cannot manage this event.")
        if event.get("status") == STATUS_COMPLETED:
            # After completion the awards have already been published; changing
            # designations then would imply retroactive awards this service
            # cannot revoke.
            raise ConflictError(
                message="Designations cannot be changed after an event is completed.")
        self._replace(event, presenters=body.get("presenters") or [],
                      organizers=body.get("organizers") or [],
                      externals=body.get("externalPresenters") or [],
                      principal=principal, bearer_token=bearer_token,
                      claim_headers=claim_headers)
        return self.list_for(event_id, principal=principal,
                             bearer_token=bearer_token, claim_headers=claim_headers)

    @staticmethod
    def _validate_ids(user_ids: list, kind: str) -> list[str]:
        if len(user_ids) > MAX_DESIGNEES_PER_KIND:
            raise ValidationError(f"At most {MAX_DESIGNEES_PER_KIND} {kind}s per event.")
        out: list[str] = []
        for uid in user_ids:
            uid = str(uid or "").strip()
            if not uid:
                raise ValidationError(f"{kind} ids must be non-empty.")
            if uid not in out:
                out.append(uid)
        return out

    @staticmethod
    def _validate_external_names(names: list) -> list[str]:
        if len(names) > MAX_DESIGNEES_PER_KIND:
            raise ValidationError(
                f"At most {MAX_DESIGNEES_PER_KIND} external presenters per event.")
        out: list[str] = []
        for name in names:
            name = str(name or "").strip()
            if not name:
                raise ValidationError("External presenter names must be non-empty.")
            if len(name) > MAX_EXTERNAL_NAME_LEN:
                raise ValidationError(
                    f"External presenter names are capped at {MAX_EXTERNAL_NAME_LEN} characters.")
            if name not in out:
                out.append(name)
        return out

    def _resolve(self, user_id: str, *, bearer_token: str | None,
                 claim_headers: dict | None = None) -> dict:
        """Role + display name for a portal designee. FAIL-CLOSED for points."""
        if user_id in self._resolve_cache:
            return self._resolve_cache[user_id]
        looked_up = self._directory.lookup(user_id, bearer_token=bearer_token,
                                           claim_headers=claim_headers) \
            if self._directory else None
        if looked_up is None:
            info = {"role": None, "displayName": user_id,
                    "eligible": False, "reason": ROLE_UNVERIFIED_REASON}
        else:
            role = looked_up["role"]
            eligible = role in POINT_ELIGIBLE_ROLES
            info = {"role": role, "displayName": looked_up.get("displayName") or user_id,
                    "eligible": eligible,
                    "reason": None if eligible else
                    f"{role}s do not earn points — earning is a Member activity."}
        self._resolve_cache[user_id] = info
        return info

    def _replace(self, event: dict, *, presenters: list, organizers: list,
                 externals: list, principal, bearer_token: str | None = None,
                 claim_headers: dict | None = None) -> dict:
        presenters = self._validate_ids(presenters, PRESENTER)
        organizers = self._validate_ids(organizers, ORGANIZER)
        externals = self._validate_external_names(externals)

        for kind, user_ids in ((PRESENTER, presenters), (ORGANIZER, organizers)):
            self._repo.clear_designations(event["id"], kind)
            for user_id in user_ids:
                info = self._resolve(user_id, bearer_token=bearer_token,
                                     claim_headers=claim_headers)
                self._repo.put_designation({
                    "eventId": event["id"], "userId": user_id, "kind": kind,
                    "displayName": info["displayName"], "external": False,
                    "roleAtDesignation": info["role"],
                    "pointsEligible": info["eligible"],
                    "ineligibleReason": info["reason"],
                    "designatedBy": principal.user_id, "designatedAt": now_iso(),
                })
            if kind == PRESENTER:
                # External presenters live under the presenter kind. Their row id
                # is derived from the list position; identity across writes does
                # not matter because _replace clears and rewrites the whole kind.
                for i, name in enumerate(externals):
                    self._repo.put_designation({
                        "eventId": event["id"], "userId": f"ext-{i + 1}", "kind": PRESENTER,
                        "displayName": name, "external": True,
                        "roleAtDesignation": None,
                        "pointsEligible": False,
                        "ineligibleReason": EXTERNAL_REASON,
                        "designatedBy": principal.user_id, "designatedAt": now_iso(),
                    })
        counts = {"presenterCount": len(presenters) + len(externals),
                  "organizerCount": len(organizers)}
        self._repo.set_designation_counts(
            event["id"], presenters=counts["presenterCount"],
            organizers=counts["organizerCount"])
        return counts

    # ------------------------------------------------------------------- reads

    def list_for(self, event_id: str, *, principal,
                 bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        event = self._repo.get_event(event_id)
        if event is None or not can_view(event, principal):
            raise NotFoundError(message="Event not found.")
        rows = self._repo.list_designations(event_id)
        if self._directory and bearer_token:
            rows = self._refresh_unresolved(event_id, rows, bearer_token=bearer_token,
                                            claim_headers=claim_headers)
        return listing(rows, designation_public)

    def _refresh_unresolved(self, event_id: str, rows: list[dict], *,
                            bearer_token: str, claim_headers: dict | None = None) -> list[dict]:
        """Re-resolve portal designees whose displayName is still their userId.

        This happens when the original designation write failed the directory
        lookup (network timeout, stub profile created before UserProvisioned).
        The name is frozen in the row at designation time; this is the only
        place it can be healed without requiring the organiser to re-designate.

        Only non-external rows are candidates: external presenters have a real
        human-supplied name, not a UUID.  Only rows where displayName == userId
        are retried: a row that already has a real name is never touched.
        """
        refreshed = []
        for row in rows:
            if (not row.get("external")
                    and row.get("displayName") == row.get("userId")):
                looked_up = self._directory.lookup(
                    row["userId"], bearer_token=bearer_token, claim_headers=claim_headers)
                if looked_up and looked_up.get("displayName") != row["userId"]:
                    # Got a real name — patch the stored row and return the
                    # updated copy so the response reflects the fix immediately.
                    updated = {**row,
                               "displayName": looked_up["displayName"],
                               "roleAtDesignation": looked_up.get("role") or row.get("roleAtDesignation")}
                    # Heal eligibility too: if the original failed closed, the
                    # role is now known so we can set the correct value.
                    if row.get("roleAtDesignation") is None and looked_up.get("role"):
                        role = looked_up["role"]
                        eligible = role in POINT_ELIGIBLE_ROLES
                        updated["roleAtDesignation"] = role
                        updated["pointsEligible"] = eligible
                        updated["ineligibleReason"] = (
                            None if eligible else
                            f"{role}s do not earn points — earning is a Member activity.")
                    self._repo.put_designation(
                        {k: v for k, v in updated.items()
                         if k not in ("pk", "sk")})
                    refreshed.append(updated)
                    continue
            refreshed.append(row)
        return refreshed

    # ------------------------------------------------------------------ awards

    def award_on_completion(self, event: dict, *, correlation_id: str | None = None,
                            bearer_token: str | None = None,
                            claim_headers: dict | None = None) -> int:
        """Publish delivery/organize awards when an event completes (BR-P4).

        Called from BOTH completion routes — manual completion and the automatic
        transition triggered by applied attendance — so a presenter earns
        regardless of how the event reached Completed (US-2.18 explicitly).

        Each event carries a stable idempotency key so a consumer retry cannot
        double-award (BR-P6). External designees never appear here: they are
        stored with pointsEligible=False by construction.
        """
        points = self._contrib.points_for(event.get("type"), bearer_token=bearer_token,
                                          claim_headers=claim_headers)
        delivery_points = points.get("delivery")
        batch: list[tuple[str, dict]] = []
        awarded = 0
        for row in self._repo.list_designations(event["id"]):
            if not row.get("pointsEligible"):
                continue
            event_type = "EventDelivered" if row.get("kind") == PRESENTER else "EventOrganized"
            batch.append((event_type, {
                "idempotencyKey": f"{event['id']}#{row['userId']}#{row['kind']}",
                "eventId": event["id"], "userId": row["userId"],
                "groupId": event.get("groupId"), "eventType": event.get("type"),
                # eventDate → quarter attribution in Contributions (Unit 7).
                "eventDate": event.get("startsAt"),
                "points": delivery_points,
            }))
            awarded += 1
        if batch:
            self._events.publish_many(batch, correlation_id=correlation_id)
        return awarded
