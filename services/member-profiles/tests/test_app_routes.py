"""API-layer tests — route matching, authz (401/403), and the EventBridge
consumption branch, exercised through app.dispatch()."""
import json

from app import CONSUMED_EVENT_TYPES, Context, dispatch


def _event(method, path, *, claims=None, body=None, qs=None):
    return {
        "httpMethod": method,
        "path": path,
        "headers": {"Authorization": "Bearer test-token"},
        "requestContext": {"authorizer": {"claims": claims or {}}},
        "body": json.dumps(body) if body is not None else None,
        "queryStringParameters": qs,
    }


def _member_claims(sub="u1", role="Member", member_group_ids=""):
    """Cognito claims as the pre-token-generation trigger stamps them —
    `member_group_ids` is a COMMA-SEPARATED STRING, not a list."""
    return {"sub": sub, "role": role, "member_group_ids": member_group_ids}


def _cl_claims(sub="u-cl"):
    """A Community Leader, who is NOT group-scoped on the directory.

    Used by the directory route tests below because they assert paging and
    validation mechanics, not visibility. With Member claims they would be
    asserting the scoping rule by accident: a Member with no groups correctly
    sees an empty directory, so every count would be 0."""
    return {"sub": sub, "role": "CommunityLeader"}


def test_get_own_profile_requires_auth(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    resp = dispatch({"httpMethod": "GET", "path": "/members/me", "headers": {},
                     "requestContext": {"authorizer": {"claims": {}}}}, ctx)
    assert resp["statusCode"] == 401


def test_get_own_profile_success(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    resp = dispatch(_event("GET", "/members/me", claims=_member_claims()), ctx)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["id"] == "u1"


def test_update_own_profile(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    resp = dispatch(_event("PUT", "/members/me", claims=_member_claims(), body={"city": "Seattle"}), ctx)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["city"] == "Seattle"


def test_update_own_profile_400_body_carries_details(aws, fan_out, events):
    """FR-1 regression pin: a validation failure must surface `details` in the
    HTTP body so the SPA can show "bio: length must be 1-2000" instead of a bare
    "Validation failed.". This is the exact line that was dropped."""
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    resp = dispatch(_event("PUT", "/members/me", claims=_member_claims(), body={"bio": "x" * 2001}), ctx)
    assert resp["statusCode"] == 400
    body = json.loads(resp["body"])
    assert body["details"] == [{"field": "bio", "message": "length must be 1-2000"}]


def test_get_member_403_for_administrator(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    resp = dispatch(_event("GET", "/members/u1", claims=_member_claims(sub="admin", role="Administrator")), ctx)
    assert resp["statusCode"] == 403


def test_get_member_404_for_missing(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    resp = dispatch(_event("GET", "/members/nope", claims=_member_claims()), ctx)
    assert resp["statusCode"] == 404


def test_browse_directory(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    # browseDirectory is served only by OpenSearch now (no DynamoDB-scan branch),
    # so a no-limit GET /members pages OpenSearch with the default size — inject a
    # stub holding the indexed doc.
    ctx.repo._os_client = lambda: _FakeOsClient([
        {"id": "u1", "firstName": "A", "lastName": "B", "role": "Member",
         "status": "active", "groups": [], "groupIds": [], "firstNameNorm": "a"}])
    resp = dispatch(_event("GET", "/members", claims=_cl_claims(), qs={}), ctx)
    assert resp["statusCode"] == 200
    assert json.loads(resp["body"])["count"] == 1


def test_member_activity_403_for_member_self(aws, fan_out, events):
    """BR-13."""
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    resp = dispatch(_event("GET", "/members/u1/activity", claims=_member_claims(), qs={}), ctx)
    assert resp["statusCode"] == 403


def test_member_activity_200_for_community_leader(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    ctx.repo.put_profile({"id": "u1", "firstName": "A", "lastName": "B",
                         "role": "Member", "status": "active", "groups": []})
    resp = dispatch(_event("GET", "/members/u1/activity",
                          claims=_member_claims(sub="cl1", role="CommunityLeader"), qs={}), ctx)
    assert resp["statusCode"] == 200


def test_unknown_route_404(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    resp = dispatch(_event("GET", "/nope", claims=_member_claims()), ctx)
    assert resp["statusCode"] == 404


def test_eventbridge_branch_consumes_identity_events(aws, fan_out, events):
    """Verifies the dispatch() branch for the 6 consumed event types (Infra
    Design Q3) routes to the EventConsumer rather than the HTTP route matcher."""
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    assert "UserProvisioned" in CONSUMED_EVENT_TYPES
    eb_event = {"detail-type": "UserProvisioned",
                "detail": {"id": "evt-1", "type": "UserProvisioned",
                          "data": {"userId": "u9", "email": "u9@x.com", "role": "Member"}}}
    resp = dispatch(eb_event, ctx)
    assert resp["statusCode"] == 200
    assert ctx.repo.get_profile("u9") is not None


# --- browseDirectory pagination params (D-P1/D-P4, 2026-08-03) ---

class _FakeOsClient:
    """Minimal OpenSearch stub that serves items from an in-memory list."""

    def __init__(self, items):
        self._items = items

    def search(self, index, body):  # noqa: ANN001
        import base64, json as _json  # noqa: E401, PLC0415
        size = body.get("size", 25)
        search_after = body.get("search_after")
        # Simple offset: use the last id in search_after as the exclusive start
        start = 0
        if search_after:
            last_id = search_after[-1] if search_after else None
            for idx, item in enumerate(self._items):
                if item["id"] == last_id:
                    start = idx + 1
                    break
        page = self._items[start: start + size]
        hits = []
        for item in page:
            hits.append({"_source": item, "sort": [item.get("firstNameNorm", ""), item["id"]]})
        return {"hits": {"hits": hits}}


def _paging_ctx(aws, fan_out, events, n=5):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    items = []
    for i in range(n):
        profile = {"id": f"u{i:03d}", "firstName": f"F{i:03d}", "lastName": "L",
                   "role": "Member", "status": "active", "groups": []}
        ctx.repo.put_profile(profile)
        doc = dict(profile)
        doc["groupIds"] = []
        doc["firstNameNorm"] = f"f{i:03d}"
        doc["roleSortOrder"] = 2
        doc["awsProjectSort"] = 0
        items.append(doc)
    # Inject a fake OpenSearch client
    ctx.repo._os_client = lambda: _FakeOsClient(items)
    return ctx


def test_browse_directory_paged(aws, fan_out, events):
    ctx = _paging_ctx(aws, fan_out, events)
    resp = dispatch(_event("GET", "/members", claims=_cl_claims(), qs={"limit": "2"}), ctx)
    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert body["count"] == 2
    assert body["cursor"]
    resp2 = dispatch(_event("GET", "/members", claims=_cl_claims(),
                            qs={"limit": "2", "cursor": body["cursor"]}), ctx)
    body2 = json.loads(resp2["body"])
    assert body2["count"] == 2
    assert {i["id"] for i in body2["items"]}.isdisjoint({i["id"] for i in body["items"]})


def test_browse_directory_invalid_limit_400(aws, fan_out, events):
    ctx = _paging_ctx(aws, fan_out, events, n=1)
    for bad in ("abc", "0", "-5", "9999"):
        resp = dispatch(_event("GET", "/members", claims=_cl_claims(), qs={"limit": bad}), ctx)
        assert resp["statusCode"] == 400, bad
        assert json.loads(resp["body"])["code"] == "VALIDATION_ERROR"


def test_browse_directory_invalid_cursor_400(aws, fan_out, events):
    ctx = _paging_ctx(aws, fan_out, events, n=1)
    resp = dispatch(_event("GET", "/members", claims=_cl_claims(),
                           qs={"limit": "2", "cursor": "garbage!!"}), ctx)
    assert resp["statusCode"] == 400
    assert json.loads(resp["body"])["code"] == "VALIDATION_ERROR"


def test_browse_directory_scopes_a_member_to_their_groups(aws, fan_out, events):
    """End-to-end through dispatch: the router must forward the whole Principal,
    not just `principal.role`. Passing only the role is precisely what left this
    endpoint community-wide for every caller, and a service-level test cannot
    catch a router that drops the claims.
    """
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    profiles = [
        {"id": "m-g1", "firstName": "Ana", "lastName": "One", "role": "Member",
         "status": "active", "groups": [{"groupId": "g-1"}]},
        {"id": "m-g2", "firstName": "Ben", "lastName": "Two", "role": "Member",
         "status": "active", "groups": [{"groupId": "g-2"}]},
    ]
    docs = []
    for p in profiles:
        ctx.repo.put_profile(p)
        doc = dict(p)
        doc["groupIds"] = [g["groupId"] for g in p["groups"]]
        doc["firstNameNorm"] = p["firstName"].lower()
        doc["roleSortOrder"] = 2
        doc["awsProjectSort"] = 0
        docs.append(doc)

    class _ScopedOs:
        def search(self, index, body):  # noqa: ANN001
            filters = (body.get("query", {}).get("bool", {}) or {}).get("filter", []) or []
            rows = docs
            for f in filters:
                if "terms" in f and "groupIds.keyword" in f["terms"]:
                    allowed = set(f["terms"]["groupIds.keyword"])
                    rows = [d for d in rows if allowed & set(d["groupIds"])]
            return {"hits": {"hits": [
                {"_source": d, "sort": [d["firstNameNorm"], d["id"]]} for d in rows]}}

    ctx.repo._os_client = lambda: _ScopedOs()

    resp = dispatch(_event("GET", "/members",
                           claims=_member_claims(sub="caller", member_group_ids="g-1"),
                           qs={"limit": "25"}), ctx)

    assert resp["statusCode"] == 200
    body = json.loads(resp["body"])
    assert [i["id"] for i in body["items"]] == ["m-g1"]


def test_browse_directory_403_when_member_names_a_foreign_group(aws, fan_out, events):
    ctx = Context(table=aws.table, idempotency_table="member-profiles-idem-test",
                  fan_out=fan_out, events=events)
    resp = dispatch(_event("GET", "/members",
                           claims=_member_claims(sub="caller", member_group_ids="g-1"),
                           qs={"limit": "25", "groupId": "g-2"}), ctx)
    assert resp["statusCode"] == 403
    assert json.loads(resp["body"])["code"] == "FORBIDDEN"
