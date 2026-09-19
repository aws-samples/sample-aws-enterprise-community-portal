"""Event lifecycle, listing and calendar (US-2.1/2.3/2.4/2.5/2.9/2.13/2.14/2.19).

Authorization ordering matters and is deliberate (P-SEC-1):
  1. role check from the permission matrix
  2. load the event, then VISIBILITY -> 404 (not 403), so existence is not
     disclosed across scope boundaries (BR-A8)
  3. manage check for mutations (BR-A4/A5)

An event owns a time SPAN: `startsAt` (the GSI1 sort key) and `endsAt`. A
single-instant meeting and a multi-day hackathon are the same shape — there is
no separate "duration" concept and no recurring-series concept. The span is
capped (MAX_EVENT_SPAN_DAYS) so a typo cannot create an open-ended event.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from _conventions.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from _conventions.validation import require_enum, require_int, require_str
from models import (
    ALLOWED_TRANSITIONS,
    COMMUNITY,
    COUNTED_STATUSES,
    DELIVERY_MODES,
    BULK_PAGE_SIZE,
    EVENT_TYPES,
    MAX_EVENT_SPAN_DAYS,
    MAX_STAT_GROUPS,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_UPCOMING,
    STATUSES,
    can_manage,
    can_view,
    current_quarter,
    event_public,
    listing,
    new_id,
    now_iso,
    quarter_end_iso,
    quarter_of_iso,
    quarter_start_iso,
    trailing_quarters_asc,
    visible_scopes,
)


def _parse_iso(value: str, field: str) -> datetime:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        raise ValidationError(f"{field} must be an ISO-8601 timestamp.") from None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _overlaps_window(event: dict, window_from: str | None, window_to: str | None) -> bool:
    """True if the event's [startsAt, endsAt] span touches the [from, to] window.
    Compared on the date (first 10 chars) — ISO date strings sort chronologically,
    and `to` is an inclusive calendar day, so a whole-day comparison is correct."""
    start_day = (event.get("startsAt") or "")[:10]
    end_day = (event.get("endsAt") or event.get("startsAt") or "")[:10]
    if window_to and start_day and start_day > window_to[:10]:
        return False
    if window_from and end_day and end_day < window_from[:10]:
        return False
    return True


class EventService:

    def __init__(self, repo, events, contributions, designations,
                 library=None):
        self._repo = repo
        self._events = events
        self._contrib = contributions
        self._designations = designations
        self._library = library

    # ------------------------------------------------------------- authz hooks

    def _load_viewable(self, event_id: str, principal) -> dict:
        event = self._repo.get_event(event_id)
        if event is None or not can_view(event, principal):
            # Same response for "absent" and "not yours" (BR-A8).
            raise NotFoundError(message="Event not found.")
        return event

    def _load_manageable(self, event_id: str, principal) -> dict:
        event = self._load_viewable(event_id, principal)
        if not can_manage(event, principal):
            raise ForbiddenError(message="You cannot manage this event.")
        return event

    @staticmethod
    def _require_creator_role(principal, group_id: str | None) -> None:
        """BR-A2/A3. A UGL may create only for their led group — community-wide
        (`group_id is None`) is a Community-Leader-only capability."""
        if principal.role == "CommunityLeader":
            return
        if principal.role == "UserGroupLeader":
            if group_id and group_id == principal.led_group_id:
                return
            raise ForbiddenError(
                message="User Group Leaders can only create events for the group they lead.")
        raise ForbiddenError(message="You cannot create events.")

    # ------------------------------------------------------------- validation

    def _validate_input(self, body: dict, *, require_start: bool,
                         allow_past_start: bool = False) -> dict:
        title = require_str(body.get("title"), "title", max_len=200)
        description = require_str(body.get("description", ""), "description",
                                  max_len=5000, min_len=0)
        event_type = require_enum(body.get("type"), "type", set(EVENT_TYPES))
        mode = require_enum(body.get("deliveryMode"), "deliveryMode", set(DELIVERY_MODES))
        location = require_str(body.get("location", ""), "location", max_len=500, min_len=0)
        # Location is FREE TEXT for every delivery mode: a join link, a street
        # address, or simply a room name. A Virtual/Hybrid event legitimately
        # names a physical room (e.g. a hybrid session run from "Boardroom 3B"),
        # so requiring an https:// URL there was wrong.
        #
        # The one surviving constraint is scheme security (BR-V3): an explicit
        # http:// URL would carry a private community event's join link in
        # cleartext, so it is rejected rather than silently upgraded. Anything
        # that is not an http:// URL is accepted as typed.
        if location.strip().lower().startswith("http://"):
            raise ValidationError(
                "A join link must use https://. Free text (for example a room name) is also fine.")

        out = {
            "title": title, "description": description, "type": event_type,
            "deliveryMode": mode, "location": location,
            "announceOnCreate": bool(body.get("announceOnCreate", False)),
            "announceByEmail": bool(body.get("announceByEmail", False)),
            "teamsMeetingId": body.get("teamsMeetingId") or None,
        }
        # An event runs from startsAt to endsAt. Both are required together: a
        # partial edit that touches neither leaves the stored span untouched, but
        # anything that sets a start must also set the end (the form always sends
        # both). A single-instant meeting is just a short span.
        if require_start or body.get("startsAt") is not None:
            starts_at = _parse_iso(body.get("startsAt"), "startsAt")
            if not allow_past_start and starts_at <= datetime.now(timezone.utc):
                raise ValidationError("startsAt must be in the future.")
            ends_at = _parse_iso(body.get("endsAt"), "endsAt")
            if ends_at <= starts_at:
                raise ValidationError("endsAt must be after startsAt.")
            if ends_at - starts_at > timedelta(days=MAX_EVENT_SPAN_DAYS):
                raise ValidationError(
                    f"An event cannot span more than {MAX_EVENT_SPAN_DAYS} days.")
            out["startsAt"] = starts_at.isoformat()
            out["endsAt"] = ends_at.isoformat()
        return out

    # ----------------------------------------------------------------- create

    def create(self, body: dict, *, principal, correlation_id: str | None = None,
               bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        group_id = body.get("groupId") or None
        self._require_creator_role(principal, group_id)
        fields = self._validate_input(body, require_start=True)

        event = {
            "id": new_id("ev"), "groupId": group_id, "status": STATUS_UPCOMING,
            "createdBy": principal.user_id, "createdByRole": principal.role,
            "createdAt": now_iso(), "updatedAt": now_iso(),
            "rsvpYesCount": 0, "rsvpNoCount": 0, "attendedCount": 0,
            "presenterCount": 0, "organizerCount": 0, "icsSequence": 0,
            **fields,
        }
        self._repo.put_event(event)
        self._repo.register_scope(group_id)

        counts = self._designations.set_from_input(event, body, principal=principal,
                                                   bearer_token=bearer_token,
                                                   claim_headers=claim_headers)
        if counts:
            event.update(counts)  # response must match the stored row's counts

        # The announcement intent travels ON the event; Announcements (Unit 9)
        # creates it when that service is real. No synchronous call, so event
        # creation never depends on another service being up (BR-X1).
        self._events.publish("EventCreated", {
            "eventId": event["id"], "title": event["title"], "groupId": group_id,
            "type": event["type"], "startsAt": event["startsAt"],
            "announce": event["announceOnCreate"], "announceByEmail": event["announceByEmail"],
            "createdBy": principal.user_id,
        }, correlation_id=correlation_id)
        return event_public(event, principal=principal)

    # ------------------------------------------------------------------- read

    def get(self, event_id: str, *, principal, bearer_token: str | None = None,
            claim_headers: dict | None = None) -> dict:
        event = self._load_viewable(event_id, principal)
        points = self._contrib.points_for(event["type"], bearer_token=bearer_token,
                                          claim_headers=claim_headers)
        my_rsvp = self._repo.get_rsvp(event_id, principal.user_id) or {}
        return event_public(event, principal=principal, points=points, my_rsvp=my_rsvp)

    def list(self, *, principal, filters: dict, limit: int, cursor: str | None,
             bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        if principal.role == "Administrator":
            # Administrators have no event permissions at all — not even read
            # (BR-A1). The permission matrix has zero event entries for them.
            raise ForbiddenError(message="Administrators do not participate in events.")

        # Count-only fast path for the Member-Profiles activity summary fan-out
        # (/events?memberId=X&countOnly=true). It wants the number of events the
        # member ATTENDED — derived from that member's RSVP rows (attended flag),
        # NOT the number of events visible to them. Returning {"count": N} is what
        # the fan-out reads; without this branch the list fell through to a normal
        # page with no `count`, so "Events attended" always showed 0 (the bug).
        if str(filters.get("countOnly", "")).lower() == "true":
            target = filters.get("memberId") or principal.user_id
            attended = sum(1 for r in self._repo.list_user_rsvps(target) if r.get("attended"))
            return {"items": [], "count": attended}

        statuses = [filters["status"]] if filters.get("status") else list(STATUSES)
        for status in statuses:
            require_enum(status, "status", set(STATUSES))

        predicate = self._build_predicate(filters)
        if principal.role == "CommunityLeader":
            rows, next_cursor = self._repo.query_all_scopes_page(
                statuses=statuses, limit=limit, cursor=cursor,
                date_from=filters.get("from"), date_to=filters.get("to"),
                predicate=predicate, known_scopes=self._repo.list_scopes())
        else:
            rows, next_cursor = self._repo.query_scope_page(
                visible_scopes(principal), statuses=statuses, limit=limit, cursor=cursor,
                date_from=filters.get("from"), date_to=filters.get("to"),
                predicate=predicate)

        # One cached points read serves the whole page (P-REL-2).
        points_by_type: dict[str, dict] = {}
        for row in rows:
            event_type = row.get("type")
            if event_type not in points_by_type:
                points_by_type[event_type] = self._contrib.points_for(
                    event_type, bearer_token=bearer_token, claim_headers=claim_headers)
        # Per-caller RSVP state for the whole page in ONE query (same pattern as
        # the cached points read): without it the member-facing card cannot tell
        # it already RSVP'd, so it keeps offering the RSVP button and a member can
        # fire the same RSVP repeatedly (US-2.6). The single GET already returns
        # myRsvp; the list did not, and that gap is the reported bug.
        my_rsvps = {r["eventId"]: r for r in self._repo.list_user_rsvps(principal.user_id)
                    if r.get("eventId") and "response" in r}
        return listing(
            rows,
            lambda row: event_public(row, principal=principal,
                                     points=points_by_type.get(row.get("type")),
                                     my_rsvp=my_rsvps.get(row.get("id"))),
            cursor=next_cursor)

    # ------------------------------------------------- stats: events by type

    def stats_by_type(self, filters: dict, *, principal) -> dict:
        """Events per quarter, broken down by event type (US-7.2).

        Counting rule is deliberately IDENTICAL to the dashboard's "Group Events"
        stat card, so the two can never disagree:

        * the group the caller leads only — community-wide events belong to no
          single group and are not folded in (BR-S1);
        * the quarter the event's own date (`startsAt`) falls in;
        * every status EXCEPT Cancelled, i.e. Upcoming and Completed both count
          (a cancelled event did not and will not happen).

        Scope is fail-closed: a UGL always gets their led group whatever the
        query string says; a Community Leader may name a group; nobody else may
        call this.
        """
        if principal.role == "UserGroupLeader":
            if not principal.led_group_id:
                raise ForbiddenError(message="You do not lead a group.")
            scope = principal.led_group_id
        elif principal.role == "CommunityLeader":
            # No groupId means the community-wide scope, which is a real scope of
            # its own rather than "everything".
            scope = filters.get("groupId") or COMMUNITY
        else:
            raise ForbiddenError(message="Only leaders can view group statistics.")

        quarters = require_int(int(filters.get("quarters") or 4), "quarters",
                               minimum=1, maximum=12)
        keys = trailing_quarters_asc(quarters)
        date_from, date_to = quarter_start_iso(keys[0]), quarter_end_iso(keys[-1])
        # One narrow query per counted status. Cancelled is excluded by simply
        # never reading its partition, rather than filtering after the fact.
        rows = []
        for status in COUNTED_STATUSES:
            rows += self._repo.scan_scope_status_range(
                scope, status, date_from=date_from, date_to=date_to)

        counts: dict[str, dict[str, int]] = {q: {} for q in keys}
        for row in rows:
            stamp = row.get("gsi1sk") or ""
            event_type = row.get("type")
            if not stamp or not event_type:
                continue
            quarter = quarter_of_iso(stamp)
            if quarter in counts:
                counts[quarter][event_type] = counts[quarter].get(event_type, 0) + 1

        # Only types that actually occurred are returned, in canonical order, so
        # the chart renders 2-4 series instead of 8 mostly-empty ones.
        present = [t for t in EVENT_TYPES if any(c.get(t) for c in counts.values())]
        return {
            "groupId": None if scope == COMMUNITY else scope,
            "quarters": keys,
            "types": present,
            "items": [{"quarter": q, "total": sum(counts[q].values()),
                       "counts": counts[q]} for q in keys],
            "count": len(keys),
        }

    def stats_by_group(self, filters: dict, *, principal) -> dict:
        """Events per USER GROUP for ONE quarter (US-7.1, CL dashboard).

        The counting rule is the same one `stats_by_type` and the dashboard's
        "Group Events" card use — the event's own date, every status except
        Cancelled — so a Community Leader's per-group bar and that group's own
        leader see the same number.

        COMMUNITY-WIDE EVENTS GET THEIR OWN ROW. They belong to no single group
        (BR-S1), so folding them into one would be wrong and dropping them would
        leave the bars summing to less than the quarter's event count with no
        explanation.

        This service holds no group registry — it only learns about groups when
        one is soft-deleted — so the ids come from the caller, which already has
        them from /groups. That is safe because only a Community Leader may call
        this and a CL may read every group; the count is capped so a hand-built
        query string cannot turn one request into an unbounded fan-out.
        """
        if principal.role != "CommunityLeader":
            raise ForbiddenError(
                message="Only Community Leaders can view cross-group statistics.")

        quarter = filters.get("quarter") or current_quarter()
        raw = filters.get("groupIds") or ""
        group_ids, seen = [], set()
        for gid in (g.strip() for g in raw.split(",")):
            # De-duplicated: a repeated id would otherwise produce two bars for
            # one group and inflate the total.
            if gid and gid not in seen:
                seen.add(gid)
                group_ids.append(gid)
        if len(group_ids) > MAX_STAT_GROUPS:
            raise ValidationError(
                message=f"Too many groups requested (max {MAX_STAT_GROUPS}).")

        date_from, date_to = quarter_start_iso(quarter), quarter_end_iso(quarter)

        def count_for(scope: str) -> int:
            total = 0
            for status in COUNTED_STATUSES:
                total += len(self._repo.scan_scope_status_range(
                    scope, status, date_from=date_from, date_to=date_to))
            return total

        items = [{"groupId": gid, "events": count_for(gid)} for gid in group_ids]
        # Largest first — the chart is a ranked comparison.
        items.sort(key=lambda r: -r["events"])
        community = count_for(COMMUNITY)
        return {
            "quarter": quarter,
            "items": items,
            "count": len(items),
            # Reported separately so the caller can render it as its own bar and
            # state the arithmetic instead of leaving a gap.
            "communityWide": community,
            "total": community + sum(r["events"] for r in items),
        }

    @staticmethod
    def _build_predicate(filters: dict):
        """Post-filters applied INSIDE the page loop, so a selective filter still
        returns a full page rather than a nearly empty one (P-SCALE-2)."""
        q = (filters.get("q") or "").strip().lower()
        event_type = filters.get("type")
        mode = filters.get("deliveryMode")
        group_id = filters.get("groupId")
        if not any([q, event_type, mode, group_id]):
            return None

        def predicate(row: dict) -> bool:
            if event_type and row.get("type") != event_type:
                return False
            if mode and row.get("deliveryMode") != mode:
                return False
            if group_id and (row.get("groupId") or "") != group_id:
                return False
            if q:
                haystack = " ".join(str(row.get(f) or "") for f in
                                    ("title", "description", "type", "location")).lower()
                if q not in haystack:
                    return False
            return True
        return predicate

    def calendar(self, *, principal, filters: dict, bearer_token: str | None = None,
                 claim_headers: dict | None = None) -> dict:
        """Calendar is the same scoped query with a date window and no paging —
        a month never exceeds a page (BR-S5).

        The listing query bounds on `startsAt` (the GSI1 sort key), so a
        multi-day event that STARTED before the visible window but continues into
        it would be missed. We widen the lower bound by the maximum span so those
        events are fetched, then keep only the ones whose span actually overlaps
        the requested window."""
        cal_filters = dict(filters)
        cal_filters["status"] = filters.get("status") or STATUS_UPCOMING
        window_from = filters.get("from")
        window_to = filters.get("to")
        if window_from:
            widened = _parse_iso(window_from, "from") - timedelta(days=MAX_EVENT_SPAN_DAYS)
            cal_filters["from"] = widened.isoformat()

        result = self.list(principal=principal, filters=cal_filters, limit=200,
                           cursor=None, bearer_token=bearer_token, claim_headers=claim_headers)
        if window_from or window_to:
            result["items"] = [e for e in result["items"]
                               if _overlaps_window(e, window_from, window_to)]
            result["count"] = len(result["items"])
        return result

    # ----------------------------------------------------------------- mutate

    def edit(self, event_id: str, body: dict, *, principal,
             correlation_id: str | None = None) -> dict:
        event = self._load_manageable(event_id, principal)
        if event.get("status") != STATUS_UPCOMING:
            raise ConflictError(
                message="Only upcoming events can be edited.")
        fields = self._validate_input(body, require_start=bool(body.get("startsAt")),
                                       allow_past_start=True)

        updated = {**event, **fields, "updatedAt": now_iso(),
                   "icsSequence": int(event.get("icsSequence") or 0) + 1}
        self._repo.put_event(updated)

        self._events.publish("EventUpdated", {
            "eventId": event_id, "title": updated["title"],
            "startsAt": updated.get("startsAt"), "icsSequence": updated["icsSequence"],
            "notifyRsvps": True,
        }, correlation_id=correlation_id)
        return event_public(updated, principal=principal)

    def cancel(self, event_id: str, *, principal, correlation_id: str | None = None) -> None:
        event = self._load_manageable(event_id, principal)
        self._transition(event, STATUS_CANCELLED)
        event["status"] = STATUS_CANCELLED
        event["cancelledAt"] = now_iso()
        event["updatedAt"] = event["cancelledAt"]
        event["icsSequence"] = int(event.get("icsSequence") or 0) + 1
        self._repo.put_event(event)
        self._events.publish("EventCancelled", {
            "eventId": event_id, "title": event.get("title"),
            "groupId": event.get("groupId"), "notifyRsvps": True,
            "icsSequence": event["icsSequence"],
        }, correlation_id=correlation_id)

    def complete(self, event_id: str, *, principal, correlation_id: str | None = None,
                 bearer_token: str | None = None, claim_headers: dict | None = None) -> dict:
        event = self._load_manageable(event_id, principal)
        # US-2.19: the creator may manually mark an event Completed WITHOUT
        # recording attendance (BR-L2 only requires the date to have passed).
        # complete_internal enforces the past-date rule + the legal transition.
        return self.complete_internal(event, correlation_id=correlation_id,
                                      bearer_token=bearer_token, principal=principal,
                                      claim_headers=claim_headers)

    def complete_internal(self, event: dict, *, correlation_id: str | None = None,
                          bearer_token: str | None = None, principal=None,
                          claim_headers: dict | None = None) -> dict:
        """Shared by manual completion and the automatic transition that any
        applied attendance triggers (BR-L3)."""
        self._transition(event, STATUS_COMPLETED)
        # A spanning event is not over until it ENDS, so completion keys on endsAt
        # (falling back to startsAt for robustness on any row without an end).
        ends_at = event.get("endsAt") or event.get("startsAt")
        if ends_at and _parse_iso(ends_at, "endsAt") > datetime.now(timezone.utc):
            raise ValidationError("Only events whose date has passed can be completed.")

        # US-2.19 / BR-LIB-V2: description is mandatory before completion.
        # The Library auto-promotion (Path 1) copies the event description onto
        # every promoted material resource — an empty description would produce
        # unsearchable Library entries, so we gate it here.
        if not (event.get("description") or "").strip():
            raise ValidationError(
                "Event description is required before marking an event as completed.")

        event["status"] = STATUS_COMPLETED
        event["completedAt"] = now_iso()
        event["updatedAt"] = event["completedAt"]
        self._repo.put_event(event)

        # Path 1: auto-promote all clean materials to the Content Library.
        if self._library is not None:
            self._library.promote_event_materials(event)

        self._designations.award_on_completion(
            event, correlation_id=correlation_id, bearer_token=bearer_token,
            claim_headers=claim_headers)
        self._events.publish("EventCompleted", {
            "eventId": event["id"], "title": event.get("title"),
            "groupId": event.get("groupId"), "type": event.get("type"),
            "attendedCount": int(event.get("attendedCount") or 0),
        }, correlation_id=correlation_id)
        return event_public(event, principal=principal)

    @staticmethod
    def _transition(event: dict, target: str) -> None:
        """BR-L1 — the only legal transitions are Upcoming -> Completed and
        Upcoming -> Cancelled. Everything else, including any transition out of a
        terminal state, is a 409."""
        current = event.get("status")
        if target not in ALLOWED_TRANSITIONS.get(current, set()):
            raise ConflictError(
                message=f"An event that is {current} cannot become {target}.")

    def cancel_group_events(self, group_id: str, *, correlation_id: str | None = None) -> int:
        """BR-X3 — consumed `GroupSoftDeleted`. Only UPCOMING events are
        cancelled; completed ones are history and already-cancelled ones are
        left alone, which also makes the handler naturally idempotent."""
        cancelled = 0
        rows, cursor = self._repo.query_scope_page(
            [group_id], statuses=[STATUS_UPCOMING], limit=BULK_PAGE_SIZE)
        while True:
            for event in rows:
                event["status"] = STATUS_CANCELLED
                event["cancelledAt"] = now_iso()
                event["updatedAt"] = event["cancelledAt"]
                self._repo.put_event(event)
                self._events.publish("EventCancelled", {
                    "eventId": event["id"], "title": event.get("title"),
                    "groupId": group_id, "reason": "group-deleted", "notifyRsvps": True,
                }, correlation_id=correlation_id)
                cancelled += 1
            if not cursor:
                break
            rows, cursor = self._repo.query_scope_page(
                [group_id], statuses=[STATUS_UPCOMING], limit=BULK_PAGE_SIZE, cursor=cursor)
        return cancelled
