"""Claims: submit, my-claims, withdraw, and the public collection read (US-5.4/5.5).

Submission is the unit's only write that depends on another service: membership
is validated read-time against Identity with the CALLER'S OWN token (D3), and
Identity being unreachable fails the submission CLOSED (503) — a claim credited
to an unverified group would corrupt verification routing and points attribution.
"""
from __future__ import annotations

from _conventions.errors import AppError, ConflictError, NotFoundError, ValidationError
from _conventions.validation import require, require_str
from models import (
    ALL_STATUSES,
    EVIDENCE_EXTENSIONS,
    ROLE_MEMBER,
    ROLE_UGL,
    SCAN_CLEAN,
    SCAN_NONE,
    SCAN_PENDING,
    SCAN_QUARANTINED,
    STATUS_APPROVED,
    STATUS_PENDING,
    STATUS_WITHDRAWN,
    add_months,
    new_id,
    now_iso,
    owner_claim,
    parse_iso_date,
    public_claim,
    today_iso,
)
from scan_reconcile import reconcile_evidence


class NoGroupError(AppError):
    """422 with a distinct code so the UI can render the join-a-group prompt."""
    def __init__(self):
        super().__init__(code="NO_GROUP_MEMBERSHIP",
                         message="You must belong to at least one user group to submit a claim.",
                         status=422)


class ClaimService:
    def __init__(self, repo, storage, identity, events, uploads):
        self._repo = repo
        self._storage = storage
        self._identity = identity
        self._events = events
        self._uploads = uploads

    # ------------------------------------------------------------------ submit

    def submit(self, body: dict, *, principal, bearer_token: str | None,
               correlation_id: str | None = None) -> dict:
        cert_id = require_str(body.get("certId"), "certId", max_len=100)

        definition = self._repo.get_definition(cert_id)
        if not definition or not definition.get("active"):
            # BR-C1 — deactivated certs are hidden from submission AND rejected
            # server-side; UI hiding is not enforcement.
            raise ConflictError(message="This certification is not available for claims.")

        group_id = self._resolve_credited_group(body, principal, bearer_token)

        date_earned = self._validate_date_earned(body, definition)
        evidence = self._validate_evidence(body, principal)
        notes = None
        if body.get("notes"):
            notes = require_str(body["notes"], "notes", max_len=1000)

        claim = {
            "id": new_id("clm"),
            "certId": cert_id,
            "certName": definition["name"],
            "certCategory": definition.get("category"),
            "memberId": principal.user_id,
            # Denormalised at submission so queue rows render without per-row
            # identity lookups (the anti-pattern removed from Settings).
            "memberName": getattr(principal, "name", "") or None,
            "creditedGroupId": group_id,
            "creditedGroupName": body.get("creditedGroupName") or None,
            "status": STATUS_PENDING,
            # Points eligibility is frozen at submission (change request Q3=B):
            # only Members earn points. A UGL may claim and hold the badge, but
            # their approved claim awards zero. Reading role here (not at
            # approval) avoids a role-change race and a cross-service lookup.
            "pointsEligible": principal.role == ROLE_MEMBER,
            "notes": notes,
            "dateEarned": date_earned,
            "submittedAt": now_iso(),
            **evidence,
        }
        # create_claim's slot conditional put IS the duplicate rule (BR-C2):
        # concurrent submits cannot double-claim; no query-then-write window.
        self._repo.create_claim(claim)
        if evidence.get("evidenceFileKey"):
            self._repo.update_filekey_pointer(evidence["evidenceFileKey"], ownerId=claim["id"])
            # Converge now if the verdict already landed (closes the two-writer
            # window); the scan consumer and watchdog are the async backstops.
            outcome = reconcile_evidence(self._repo, claim["id"])
            if outcome in ("cleaned", "quarantined"):
                claim["scanStatus"] = self._repo.get_claim(claim["id"]).get("scanStatus")
        # No event on submission: the leader queue is a query, not a
        # notification (Option 2A), and nothing else consumes it.
        return owner_claim(claim)

    def _resolve_credited_group(self, body: dict, principal, bearer_token: str | None) -> str:
        """Which group a claim is credited to (drives routing + points).

        - Members credit a group they BELONG to (BR-C3): membership comes from
          principal.member_group_ids, which the edge claims authorizer refreshes
          from the database on every request (fresh-claims-at-the-edge).
        - UGLs credit the group they LEAD (change request 2026-08-07, Q1=A) —
          leadership, not membership, is the credit basis. Resolved JWT-first
          then Identity, and fail CLOSED if unresolvable: a claim credited to an
          unverified group would corrupt verification routing.
        """
        if principal.role == ROLE_UGL:
            led = getattr(principal, "led_group_id", None)
            if not led:
                led = self._identity.led_group_id(principal.user_id, bearer_token=bearer_token)
            if not led:
                raise AppError(code="DEPENDENCY_UNAVAILABLE",
                               message="Your led group could not be determined. Please try again.",
                               status=503)
            return led

        group_id = require_str(body.get("creditedGroupId"), "creditedGroupId", max_len=100)
        groups = getattr(principal, "member_group_ids", []) or []
        if not groups:
            raise NoGroupError()
        require(group_id in groups, "creditedGroupId",
                "you can only credit a group you belong to")
        return group_id

    def _validate_date_earned(self, body: dict, definition: dict) -> str | None:
        months = definition.get("expiryPeriodMonths")
        raw = body.get("dateEarned")
        # BR-C5′ (Certification Ledger enh., DR-6): earned date is now required
        # for EVERY claim (the certificate's real date), not only expiring certs —
        # it is the ledger's "Certification Date" and the charts' earned-quarter
        # bucket. The already-expired guard (BR-C6) still applies to expiring certs.
        require(bool(raw), "dateEarned", "required")
        earned = parse_iso_date(raw)
        today = parse_iso_date(today_iso(), "today")
        require(earned <= today, "dateEarned", "must not be in the future")
        if months and add_months(earned, int(months)).isoformat() <= today.isoformat():
            # BR-C6 (clarification C4=A): never enters a queue; the member
            # learns immediately.
            raise AppError(code="ALREADY_EXPIRED",
                           message="This certification has already expired.",
                           status=422)
        return earned.isoformat()

    def _validate_evidence(self, body: dict, principal) -> dict:
        url = body.get("evidenceUrl")
        file_key = body.get("evidenceFileKey")
        require(bool(url) != bool(file_key), "evidence",
                "provide exactly one of evidenceUrl or evidenceFileKey")
        if url:
            url = require_str(url, "evidenceUrl", max_len=2000)
            require(url.startswith(("https://", "http://")), "evidenceUrl",
                    "must be an http(s) link")
            return {"evidenceUrl": url, "scanStatus": SCAN_NONE}
        pointer = self._repo.get_filekey_pointer(file_key)
        require(pointer is not None and pointer.get("kind") == "evidence"
                and pointer.get("grantedTo") == principal.user_id,
                "evidenceFileKey", "unknown upload key")
        # Verdict BEFORE existence: a quarantined object was already deleted by
        # the consumer, and telling the member "not uploaded" for a file the
        # scanner rejected would send them re-uploading the same malware.
        verdict = pointer.get("scanStatus", SCAN_PENDING)
        if verdict == SCAN_QUARANTINED:
            raise ValidationError(message="Validation failed.", details=[
                {"field": "evidenceFileKey",
                 "message": "file failed the malware scan — please upload a different file"}])
        if not self._storage.object_exists(file_key):
            # Granted-but-never-uploaded must not become a claim: it would sit
            # in "awaiting scan" forever and the watchdog would cry wolf.
            raise ValidationError(message="Validation failed.", details=[
                {"field": "evidenceFileKey", "message": "file has not been uploaded"}])
        # Verdict-before-claim race: if GuardDuty already cleared the file, the
        # claim is born reviewable (the consumer will not fire again for it).
        return {"evidenceFileKey": file_key,
                "evidenceFileName": pointer.get("fileName"),
                "scanStatus": SCAN_CLEAN if verdict == SCAN_CLEAN else SCAN_PENDING}

    # ---------------------------------------------------------------- reads

    def my_claims(self, *, principal, limit: int = 20, cursor: str | None = None) -> dict:
        claims, next_cursor = self._repo.list_member_claims_page(
            principal.user_id, limit=limit, cursor=cursor)
        items = [self._with_badge(owner_claim(c)) for c in claims]
        result: dict = {"items": items, "count": len(items)}
        if next_cursor:
            result["cursor"] = next_cursor
        return result

    def list_claims(self, filters: dict, *, principal) -> dict:
        """The collection route member-profiles' deployed fan-out calls.
        Privacy by projection (BR-P1): non-owners get Approved-only badge data;
        the owner's full view lives on /claims/me."""
        member_id = filters.get("memberId")
        cert_id = filters.get("certId")
        status = filters.get("status")
        if status:
            require(status in ALL_STATUSES, "status", f"must be one of {sorted(ALL_STATUSES)}")
        count_only = str(filters.get("countOnly", "")).lower() == "true"
        require(bool(member_id) or bool(cert_id), "memberId",
                "provide memberId or certId")

        if member_id:
            claims = self._repo.list_member_claims(member_id)
            is_owner = member_id == principal.user_id
            if not is_owner:
                claims = [c for c in claims if c.get("status") == STATUS_APPROVED]
            if status:
                claims = [c for c in claims if c.get("status") == status]
            claims = self._filter_decided_range(claims, filters)
            if count_only:
                return {"items": [], "count": len(claims)}
            serialize = owner_claim if is_owner else public_claim
            # Badges order: date earned, newest first (US-5.9; anchor dateEarned
            # else decidedAt).
            claims.sort(key=lambda c: c.get("dateEarned") or c.get("decidedAt") or "",
                        reverse=True)
            items = [self._with_badge(serialize(c)) for c in claims]
            return {"items": items, "count": len(items)}

        # certId path (directory cert filter): holders only, always public shape.
        slots = self._repo.list_cert_slots(cert_id)
        holder_slots = [s for s in slots if s.get("status") == STATUS_APPROVED]
        if status and status != STATUS_APPROVED:
            holder_slots = []
        if count_only:
            return {"items": [], "count": len(holder_slots)}
        claims = [self._repo.get_claim(s["claimId"]) for s in holder_slots]
        claims = [c for c in claims if c and c.get("status") == STATUS_APPROVED]
        claims = self._filter_decided_range(claims, filters)
        items = [self._with_badge(public_claim(c)) for c in claims]
        return {"items": items, "count": len(items)}

    @staticmethod
    def _filter_decided_range(claims: list[dict], filters: dict) -> list[dict]:
        date_from, date_to = filters.get("from"), filters.get("to")
        if date_from:
            claims = [c for c in claims if (c.get("decidedAt") or "") >= date_from]
        if date_to:
            claims = [c for c in claims if (c.get("decidedAt") or "") <= date_to]
        return claims

    def _with_badge(self, row: dict) -> dict:
        """Join the definition's CURRENT badge image/name into claim rows —
        renaming a cert renames the badge everywhere (US-5.2 reading). The
        certName denormalised at submission is only the fallback for a deleted
        definition; setdefault here would freeze the old name forever."""
        definition = self._repo.get_definition(row.get("certId", ""))
        if definition:
            if definition.get("name"):
                row["certName"] = definition["name"]
            if definition.get("badgeImageUrl"):
                row["badgeImageUrl"] = definition["badgeImageUrl"]
        return row

    # --------------------------------------------------------------- withdraw

    def withdraw(self, claim_id: str, *, principal) -> None:
        claim = self._repo.get_claim(claim_id)
        if not claim or claim.get("memberId") != principal.user_id:
            # 404-not-403 on foreign claims (BR-A5): don't confirm existence.
            raise NotFoundError()
        if claim.get("status") != STATUS_PENDING:
            raise ConflictError(message="Only a pending claim can be withdrawn.")
        # No rejection reason, no event (US-5.5/US-8.15 — the member did it
        # themselves); slot deleted -> resubmission allowed (BR-W2).
        self._repo.transition_to_terminal(
            claim, new_status=STATUS_WITHDRAWN, expected_status=STATUS_PENDING,
            extra_sets={"withdrawnAt": now_iso()})

    # ----------------------------------------------------------- upload grant

    def grant_evidence_upload(self, body: dict, *, principal) -> dict:
        return self._uploads.grant(body, principal=principal, kind="evidence",
                                   extensions=EVIDENCE_EXTENSIONS)
