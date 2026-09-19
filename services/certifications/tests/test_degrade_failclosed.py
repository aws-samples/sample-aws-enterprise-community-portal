"""Mandatory suite 3 (NFR-CT-MAINT-1): fail-closed + degrade paths.

Identity down -> submission 503 while every read stays 200 (NFR-CT-REL-1);
consumer idempotency on replay; publish failure never fails a committed write;
concurrent-sweep exactly-once (mark-before-emit).
"""
from __future__ import annotations

from conftest import FakePrincipal, call, make_definition, submit_claim


def test_member_submission_is_identity_independent(ctx, cl, member, aws):
    """Fresh-claims-at-the-edge: a member's group membership rides in the
    authorizer-injected claims (principal.member_group_ids), so submission no
    longer makes a live Identity call and succeeds even if Identity is down.
    Fail-closed on membership now lives at the edge authorizer (missing CLAIMS
    item -> Deny), not on this hot path."""
    make_definition(ctx, cl)
    ctx.fake_identity.unreachable = True
    definition_id = ctx.definitions.catalog(principal=member)["items"][0]["id"]
    status, _ = call(ctx, "POST", "/certifications/claims", principal=member,
                     body={"certId": definition_id, "creditedGroupId": "g-serverless",
                           "evidenceUrl": "https://e.test/x", "dateEarned": "2026-06-01"})
    assert status == 201


def test_ugl_led_fallback_fails_submission_closed_503(ctx, cl, aws):
    """The one remaining live Identity dependency on the submit path is the UGL
    led-group fallback (JWT led absent). It stays fail-closed: Identity down and
    no JWT led -> 503, never a guessed credit group (NFR-CT-REL-1)."""
    definition = make_definition(ctx, cl)
    ctx.fake_identity.unreachable = True
    ugl_no_led = FakePrincipal("u-ugl", "UserGroupLeader", led_group_id=None)
    status, body = call(ctx, "POST", "/certifications/claims", principal=ugl_no_led,
                        body={"certId": definition["id"], "creditedGroupId": "g-serverless",
                              "evidenceUrl": "https://e.test/x", "dateEarned": "2026-06-01"})
    assert status == 503
    assert body["code"] == "DEPENDENCY_UNAVAILABLE"


def test_identity_down_reads_still_200(ctx, cl, member, aws):
    definition = make_definition(ctx, cl)
    claim = submit_claim(ctx, member, definition["id"])
    ctx.fake_identity.unreachable = True
    for method, path, qs in [
        ("GET", "/certifications", None),
        ("GET", "/certifications/claims/me", None),
        ("GET", "/certifications/claims", {"memberId": member.user_id}),
    ]:
        status, _ = call(ctx, method, path, principal=member, qs=qs)
        assert status == 200, path
    # CL queue is Identity-independent too (scope comes from role).
    status, body = call(ctx, "GET", "/certifications/verifications", principal=cl)
    assert status == 200 and body["count"] == 1
    assert claim["id"] == body["items"][0]["id"]


def test_no_group_membership_is_422_prompt(ctx, cl, aws):
    from conftest import FakePrincipal
    definition = make_definition(ctx, cl)
    loner = FakePrincipal("u-loner", "Member", member_group_ids=[])
    ctx.fake_identity.groups["u-loner"] = []
    status, body = call(ctx, "POST", "/certifications/claims", principal=loner,
                        body={"certId": definition["id"], "creditedGroupId": "g-x",
                              "evidenceUrl": "https://e.test/x", "dateEarned": "2026-06-01"})
    assert status == 422
    assert body["code"] == "NO_GROUP_MEMBERSHIP"


def test_credited_group_must_be_callers_current_group(ctx, cl, member, aws):
    definition = make_definition(ctx, cl)
    status, _ = call(ctx, "POST", "/certifications/claims", principal=member,
                     body={"certId": definition["id"], "creditedGroupId": "g-security",
                           "evidenceUrl": "https://e.test/x", "dateEarned": "2026-06-01"})
    assert status == 400  # not in the member's read-time group set


def test_membership_consumer_replay_is_idempotent(ctx, cl, member, aws):
    definition = make_definition(ctx, cl)
    submit_claim(ctx, member, definition["id"])
    envelope = {"id": "evt-1", "type": "MemberLeftGroup", "version": 1,
                "source": "identity-access", "time": "2026-08-06T00:00:00Z",
                "data": {"memberId": member.user_id, "groupId": "g-serverless",
                         "at": "2026-08-06T00:00:00Z"}}
    first = ctx.membership_consumer.handle(envelope)
    assert first["rejected"] == 1
    replay = ctx.membership_consumer.handle(envelope)
    assert replay == {"duplicate": True}
    # Only ONE CertificationRejected published across both deliveries.
    rejected = [e for e in ctx.events.published if e["type"] == "CertificationRejected"]
    assert len(rejected) == 1


def test_publish_failure_never_fails_the_committed_write(ctx, cl, member, aws):
    """Post-commit best-effort (BR-E1): a broken bus loses the event, not the
    decision."""

    class ExplodingClient:
        def put_events(self, **kwargs):
            raise RuntimeError("bus down")

    from providers import EventPublisher
    ctx.events = EventPublisher(client=ExplodingClient(), bus="arn:fake",
                                metrics=ctx.fake_metrics)
    ctx.verifications._events = ctx.events
    definition = make_definition(ctx, cl)
    claim = submit_claim(ctx, member, definition["id"])
    approved = ctx.verifications.decide(claim["id"], {"decision": "approve"},
                                        principal=cl, bearer_token=None)
    assert approved["status"] == "Approved"                     # write committed
    assert ctx.repo.get_claim(claim["id"])["status"] == "Approved"
    assert ctx.fake_metrics.of("EventPublishFailure")           # and it alarmed


def test_concurrent_sweep_cannot_double_emit_notice(ctx, cl, member, aws):
    """Mark-before-emit (BR-X2): the second sweep loses the conditional mark."""
    definition = make_definition(ctx, cl, expiryPeriodMonths=36)
    claim = submit_claim(ctx, member, definition["id"], dateEarned="2026-06-01")
    ctx.verifications.decide(claim["id"], {"decision": "approve"},
                             principal=cl, bearer_token=None)
    stored = ctx.repo.get_claim(claim["id"])
    # Inside the T-14 window relative to this simulated 'now'.
    near_expiry = stored["expiresAt"] + "T00:00:00+00:00"
    import datetime as dt
    now = (dt.datetime.fromisoformat(near_expiry) - dt.timedelta(days=7)).isoformat()
    first = ctx.expiry.sweep(now=now)
    second = ctx.expiry.sweep(now=now)
    assert first["noticed"] == 1
    assert second["noticed"] == 0
    notices = [e for e in ctx.events.published
               if e["type"] == "CertificationExpiringSoon"]
    assert len(notices) == 1


def test_scan_verdict_replay_is_idempotent(ctx, cl, member, aws):
    key = "certifications/evidence/u-mem-1/123-abc.pdf"
    ctx.repo.put_filekey_pointer(key, {"kind": "evidence", "grantedTo": "u-mem-1",
                                       "fileName": "cert.pdf", "scanStatus": "PendingScan",
                                       "grantedAt": "2026-08-06T00:00:00Z"})
    envelope = {"id": "scan-1", "detail-type": "GuardDuty Malware Protection Object Scan Result",
                "detail": {"s3ObjectDetails": {"objectKey": key},
                           "scanResultDetails": {"scanResultStatus": "NO_THREATS_FOUND"}}}
    first = ctx.scan_consumer.handle(envelope)
    assert first["verdict"] == "Clean"
    replay = ctx.scan_consumer.handle(envelope)
    assert replay == {"duplicate": True}
