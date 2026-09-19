"""DirectoryService tests — US-3.4/3.5: pagination, filters, semantic-search
delegation with graceful keyword fallback (BR-6/6b, D3).

Every test now passes an explicit principal, because `browse` is group-scoped for
the Member role (2026-08-27) and the parameter is deliberately mandatory. Tests
that are about something OTHER than scoping use `CL` — a Community Leader is
unscoped, so those assertions keep their original meaning. Tests that need the
certification filter to apply (a CL has it stripped, BR-6) use `UGL`, which is
both non-CL and unscoped.
"""
import pytest
from directory_service import DirectoryService


class FakePrincipal:
    """Mirrors the fields of _conventions.authz.Principal that browse() reads."""

    def __init__(self, user_id, role, led_group_id=None, member_group_ids=None):
        self.user_id = user_id
        self.role = role
        self.account_type = "cognito"
        self.led_group_id = led_group_id
        self.member_group_ids = member_group_ids or []


CL = FakePrincipal("u-cl", "CommunityLeader")
UGL = FakePrincipal("u-ugl", "UserGroupLeader", led_group_id="g-1")


@pytest.fixture()
def member_in_g1():
    return FakePrincipal("u-mem", "Member", member_group_ids=["g-1"])


@pytest.fixture()
def member_no_groups():
    return FakePrincipal("u-loner", "Member", member_group_ids=[])


class _SettingsCache:
    def __init__(self, enabled):
        self._enabled = enabled

    def semantic_search_enabled(self):
        return self._enabled


def _seed(repo):
    repo.put_profile({"id": "u1", "firstName": "Alex", "lastName": "Morgan", "email": "alex@x.com",
                      "role": "Member", "status": "active", "skills": ["Lambda"], "groups": []})
    repo.put_profile({"id": "u2", "firstName": "Jordan", "lastName": "Lee", "email": "jordan@x.com",
                      "role": "CommunityLeader", "status": "active", "skills": [], "groups": []})


class _FullOs:
    """OpenSearch stub over a fixed doc list. Honours the multi_match `q`, the
    role/group/id filters, the default firstName sort, and search_after cursor
    paging — enough to exercise browse() now that OpenSearch is the ONLY path.
    """

    def __init__(self, docs):
        self._docs = docs
        self.last_query = None

    def _matching(self, body):
        self.last_query = body.get("query")
        bq = (body.get("query", {}) or {}).get("bool", {}) or {}
        out = list(self._docs)
        for m in bq.get("must", []) or []:
            mm = m.get("multi_match")
            if not mm:
                continue
            q = (mm.get("query") or "").lower()
            fields = mm.get("fields", [])

            def _hay(d):
                parts = []
                for f in fields:
                    v = d.get(f)
                    if isinstance(v, list):
                        parts.append(" ".join(map(str, v)))
                    elif v is not None:
                        parts.append(str(v))
                return " ".join(parts).lower()

            out = [d for d in out if q in _hay(d)]
        for f in bq.get("filter", []) or []:
            term = f.get("term", {})
            terms = f.get("terms", {})
            if "role.keyword" in term:
                out = [d for d in out if d.get("role") == term["role.keyword"]]
            if "groupIds.keyword" in term:
                out = [d for d in out if term["groupIds.keyword"] in set(d.get("groupIds", []))]
            if "groupIds.keyword" in terms:
                allowed = set(terms["groupIds.keyword"])
                out = [d for d in out if allowed & set(d.get("groupIds", []))]
            if "id.keyword" in terms:
                ids = set(terms["id.keyword"])
                out = [d for d in out if d.get("id") in ids]
        out.sort(key=lambda d: (d.get("firstNameNorm", ""), d.get("id", "")))
        return out

    def search(self, index, body):  # noqa: ANN001
        rows = self._matching(body)
        size = body.get("size", 26)
        search_after = body.get("search_after")
        start = 0
        if search_after:
            last_id = search_after[-1]
            for i, d in enumerate(rows):
                if d["id"] == last_id:
                    start = i + 1
                    break
        page = rows[start: start + size]
        return {"hits": {"hits": [
            {"_source": d, "sort": [d.get("firstNameNorm", ""), d["id"]]} for d in page]}}

    def count(self, index, body):  # noqa: ANN001
        return {"count": len(self._matching(body))}


def _svc(repo, fan_out, settings_enabled=False):
    """DirectoryService wired to a _FullOs stub built from whatever profiles have
    been seeded into `repo` — browse() is now always OpenSearch-backed."""
    docs = _os_docs(repo, repo.all_profiles())
    os_stub = _FullOs(docs)
    repo._os_client = lambda: os_stub
    return DirectoryService(repo, fan_out, _SettingsCache(enabled=settings_enabled)), os_stub


def test_browse_no_filters_returns_all(repo, fan_out):
    _seed(repo)
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=CL)
    assert out["count"] == 2


def test_browse_by_role(repo, fan_out):
    _seed(repo)
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=CL, role="Member")
    assert out["count"] == 1
    assert out["items"][0]["id"] == "u1"


def test_browse_keyword_search_via_opensearch(repo, fan_out):
    # keyword search is served by OpenSearch (multi_match over name/email/skills/…)
    _seed(repo)
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=CL, q="lambda")
    assert out["count"] == 1
    assert out["items"][0]["id"] == "u1"
    assert fan_out.calls == []  # no Search fan-out — semantic search removed


def test_browse_semantic_search_removed_no_fan_out(repo, fan_out):
    """Semantic search fan-out replaced by OpenSearch; browse() never calls
    the Search service regardless of the EnableSemanticSearch flag."""
    _seed(repo)
    svc, _ = _svc(repo, fan_out, settings_enabled=True)
    out = svc.browse(principal=CL, q="alex")
    assert out["count"] == 1
    assert out["items"][0]["id"] == "u1"
    # No Search service fan-out call
    assert not any(k == "search" for call in fan_out.calls for k in call)


def test_community_leader_directory_omits_cert_filter(repo, fan_out):
    """BR-6 — CL-facing directory ignores the certId filter param."""
    _seed(repo)
    fan_out.responses = {"certifications": {"items": [{"memberId": "u1"}]}}
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=CL, cert_id="cert-x")
    assert out["count"] == 2  # cert filter ignored for CL — no fan-out call made
    assert fan_out.calls == []


def test_member_directory_applies_cert_filter(repo, fan_out):
    _seed(repo)
    fan_out.responses = {"certifications": {"items": [{"memberId": "u1"}]}}
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=UGL, cert_id="cert-x")
    assert out["count"] == 1
    assert out["items"][0]["id"] == "u1"


def test_deactivated_members_remain_searchable_with_status(repo, fan_out):
    """US-3.5 — deactivated members remain in results (inactive status surfaced)."""
    repo.put_profile({"id": "u3", "firstName": "Ravi", "lastName": "Shah", "email": "r@x.com",
                      "role": "Member", "status": "inactive", "skills": [], "groups": []})
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=CL)
    ravi = next(i for i in out["items"] if i["id"] == "u3")
    assert ravi["status"] == "inactive"


def test_pagination_limit(repo, fan_out):
    _seed(repo)
    # Inject a fake OpenSearch client so the paged path works in tests
    items = [{"id": "u1", "firstName": "Alex", "lastName": "Morgan", "email": "alex@x.com",
               "role": "Member", "status": "active", "groups": [], "groupIds": [],
               "firstNameNorm": "alex"},
             {"id": "u2", "firstName": "Jordan", "lastName": "Lee", "email": "jordan@x.com",
               "role": "CommunityLeader", "status": "active", "groups": [], "groupIds": [],
               "firstNameNorm": "jordan"}]

    class _FakeOs:
        def search(self, index, body):  # noqa: ANN001
            size = body.get("size", 25)
            page = items[:size]
            return {"hits": {"hits": [{"_source": i, "sort": [i["firstNameNorm"], i["id"]]} for i in page]}}

    repo._os_client = lambda: _FakeOs()
    svc = DirectoryService(repo, fan_out, _SettingsCache(enabled=False))
    out = svc.browse(principal=CL, limit=1)
    assert len(out["items"]) == 1


# --- Cursor pagination through the service (D-P1..D-P4, 2026-08-03) ---

def _seed_many(repo, n):
    items = []
    for i in range(n):
        profile = {"id": f"u{i:03d}", "firstName": f"F{i:03d}", "lastName": "L",
                   "email": f"u{i:03d}@x.com", "role": "Member", "status": "active",
                   "skills": [], "groups": []}
        repo.put_profile(profile)
        doc = dict(profile)
        doc["groupIds"] = []
        doc["firstNameNorm"] = f"f{i:03d}"
        doc["roleSortOrder"] = 2
        doc["awsProjectSort"] = 0
        items.append(doc)
    return items


class _FakeOsClientFromList:
    """OpenSearch stub that serves a fixed list with search_after cursor pagination."""

    def __init__(self, items: list, id_filter: set | None = None):
        self._items = [i for i in items if id_filter is None or i["id"] in id_filter]

    def search(self, index, body):  # noqa: ANN001
        import base64, json as _json  # noqa: E401, PLC0415
        size = body.get("size", 25)
        search_after = body.get("search_after")
        # Apply id filter from body query if present
        query = body.get("query", {})
        filters = query.get("bool", {}).get("filter", [])
        id_filter = None
        for f in filters:
            if "terms" in f:
                # Support both "id" and "id.keyword" field names
                ids = f["terms"].get("id") or f["terms"].get("id.keyword")
                if ids:
                    id_filter = set(ids)
        items = [i for i in self._items if id_filter is None or i["id"] in id_filter]
        # Resume after search_after
        start = 0
        if search_after:
            last_id = search_after[-1]
            for idx, item in enumerate(items):
                if item["id"] == last_id:
                    start = idx + 1
                    break
        page = items[start: start + size]
        return {"hits": {"hits": [
            {"_source": i, "sort": [i.get("firstNameNorm", ""), i["id"]]}
            for i in page
        ]}}


def test_browse_paged_returns_cursor_then_final_page(repo, fan_out):
    all_items = _seed_many(repo, 5)
    repo._os_client = lambda: _FakeOsClientFromList(all_items)
    svc = DirectoryService(repo, fan_out, _SettingsCache(enabled=False))
    page1 = svc.browse(principal=CL, limit=3)
    assert page1["count"] == 3
    assert page1.get("cursor")
    page2 = svc.browse(principal=CL, limit=3, cursor=page1["cursor"])
    assert page2["count"] == 2
    assert "cursor" not in page2
    ids = {i["id"] for i in page1["items"]} | {i["id"] for i in page2["items"]}
    assert len(ids) == 5


def test_browse_paged_with_cert_filter_fills_page(repo, fan_out):
    """certId filter intersects holder IDs into OpenSearch terms filter."""
    all_items = _seed_many(repo, 6)
    holders = [{"memberId": f"u{i:03d}"} for i in (0, 2, 4)]
    fan_out.responses = {"certifications": {"items": holders}}
    repo._os_client = lambda: _FakeOsClientFromList(all_items)
    svc = DirectoryService(repo, fan_out, _SettingsCache(enabled=False))
    out = svc.browse(principal=UGL, cert_id="cert-x", limit=2)
    assert out["count"] == 2
    assert all(i["id"] in {"u000", "u002", "u004"} for i in out["items"])
    assert len(fan_out.calls) == 1


def test_browse_paged_cert_and_keyword_filter_intersect(repo, fan_out):
    """cert filter (via id_filter) intersects correctly in OpenSearch query."""
    all_items = _seed_many(repo, 6)
    fan_out.responses = {
        "certifications": {"items": [{"memberId": "u002"}, {"memberId": "u005"}]},
    }
    repo._os_client = lambda: _FakeOsClientFromList(all_items)
    svc = DirectoryService(repo, fan_out, _SettingsCache(enabled=False))
    out = svc.browse(principal=UGL, cert_id="cert-x", limit=10)
    assert {i["id"] for i in out["items"]} == {"u002", "u005"}


def test_browse_no_limit_returns_first_page(repo, fan_out):
    """No limit -> first page via OpenSearch (default 25), with no cursor when the
    result fits on one page. There is no unpaged DynamoDB-scan path anymore."""
    _seed_many(repo, 4)
    svc, _ = _svc(repo, fan_out)
    out = svc.browse(principal=CL)
    assert out["count"] == 4
    assert "cursor" not in out


# --- Group scoping for the Member role (2026-08-27) ---------------------------
#
# `GET /members` used to return every member in the community to any authenticated
# caller, and that was documented as intentional in both app.py and the SPA. It no
# longer is: a Member sees only members of the groups they belong to. Community
# Leaders and User Group Leaders are deliberately UNCHANGED.

def _seed_grouped(repo):
    """Three members: one in g-1, one in g-2, one in both."""
    repo.put_profile({"id": "in-g1", "firstName": "Ana", "lastName": "One",
                      "email": "ana@x.com", "role": "Member", "status": "active",
                      "skills": [], "groups": [{"groupId": "g-1"}]})
    repo.put_profile({"id": "in-g2", "firstName": "Ben", "lastName": "Two",
                      "email": "ben@x.com", "role": "Member", "status": "active",
                      "skills": [], "groups": [{"groupId": "g-2"}]})
    repo.put_profile({"id": "in-both", "firstName": "Cara", "lastName": "Both",
                      "email": "cara@x.com", "role": "Member", "status": "active",
                      "skills": [], "groups": [{"groupId": "g-1"}, {"groupId": "g-2"}]})


def _os_docs(repo, profiles):
    """Mirror profiles into the shape the OpenSearch index holds — `groups[]`
    flattened to `groupIds[]`, which is what the scope filter matches on."""
    docs = []
    for p in profiles:
        doc = dict(p)
        doc["groupIds"] = [g["groupId"] for g in p.get("groups", [])]
        doc["firstNameNorm"] = p["firstName"].lower()
        doc["roleSortOrder"] = 2
        doc["awsProjectSort"] = 0
        docs.append(doc)
    return docs


class _ScopeAwareOs:
    """OpenSearch stub that honours the `terms` filter on groupIds.keyword.

    It has to: the whole point of the change is that the scope is pushed INTO the
    query, so a stub that ignored filters would pass whether or not the filter was
    ever built. Also records the last query so a test can assert the filter's shape
    directly rather than only its effect.
    """

    def __init__(self, docs):
        self._docs = docs
        self.last_query = None

    def _matching(self, body):
        self.last_query = body.get("query")
        filters = (body.get("query", {}).get("bool", {}) or {}).get("filter", []) or []
        out = list(self._docs)
        for f in filters:
            if "terms" in f and "groupIds.keyword" in f["terms"]:
                allowed = set(f["terms"]["groupIds.keyword"])
                out = [d for d in out if allowed & set(d.get("groupIds", []))]
            if "term" in f and "groupIds.keyword" in f["term"]:
                wanted = f["term"]["groupIds.keyword"]
                out = [d for d in out if wanted in set(d.get("groupIds", []))]
            if "term" in f and "role.keyword" in f["term"]:
                out = [d for d in out if d.get("role") == f["term"]["role.keyword"]]
        return out

    def search(self, index, body):  # noqa: ANN001
        hits = self._matching(body)[: body.get("size", 25)]
        return {"hits": {"hits": [
            {"_source": d, "sort": [d.get("firstNameNorm", ""), d["id"]]} for d in hits]}}

    def count(self, index, body):  # noqa: ANN001
        return {"count": len(self._matching(body))}


def _scoped_svc(repo, fan_out):
    _seed_grouped(repo)
    docs = _os_docs(repo, repo.all_profiles())
    os_stub = _ScopeAwareOs(docs)
    repo._os_client = lambda: os_stub
    return DirectoryService(repo, fan_out, _SettingsCache(enabled=False)), os_stub


def test_member_sees_only_their_own_groups(repo, fan_out, member_in_g1):
    """The regression, directly: `in-g2` shares no group with the caller and must
    be absent, while `in-both` overlaps on g-1 and must be present."""
    svc, _ = _scoped_svc(repo, fan_out)

    out = svc.browse(principal=member_in_g1, limit=25)

    assert {i["id"] for i in out["items"]} == {"in-g1", "in-both"}


def test_member_with_no_groups_sees_an_empty_directory(repo, fan_out, member_no_groups):
    """Product decision: empty, NOT the whole community. This is the case where a
    fail-open default would be most damaging — the least-privileged caller."""
    svc, os_stub = _scoped_svc(repo, fan_out)

    out = svc.browse(principal=member_no_groups, limit=25)

    assert out["items"] == []
    assert out["count"] == 0
    # Short-circuited before OpenSearch: no query should have been issued at all.
    assert os_stub.last_query is None


def test_member_naming_a_group_they_are_not_in_is_refused(repo, fan_out, member_in_g1):
    """403 rather than a silent empty page, which would read as "that group has no
    members"."""
    from _conventions.errors import ForbiddenError

    svc, _ = _scoped_svc(repo, fan_out)

    with pytest.raises(ForbiddenError):
        svc.browse(principal=member_in_g1, group_id="g-2", limit=25)


def test_member_may_filter_within_their_own_group(repo, fan_out):
    svc, _ = _scoped_svc(repo, fan_out)
    both = FakePrincipal("u-both", "Member", member_group_ids=["g-1", "g-2"])

    out = svc.browse(principal=both, group_id="g-2", limit=25)

    assert {i["id"] for i in out["items"]} == {"in-g2", "in-both"}


def test_scope_is_pushed_into_the_query_not_applied_afterwards(repo, fan_out, member_in_g1):
    """Post-filtering a returned page would yield short pages and a count that no
    longer matches the cursor walk, so the filter must be in the query body."""
    svc, os_stub = _scoped_svc(repo, fan_out)

    svc.browse(principal=member_in_g1, limit=25)

    filters = os_stub.last_query["bool"]["filter"]
    terms = [f["terms"]["groupIds.keyword"] for f in filters if "terms" in f
             and "groupIds.keyword" in f["terms"]]
    assert terms == [["g-1"]]


def test_community_leader_is_not_scoped(repo, fan_out):
    svc, _ = _scoped_svc(repo, fan_out)
    out = svc.browse(principal=CL, limit=25)
    assert {i["id"] for i in out["items"]} == {"in-g1", "in-g2", "in-both"}


def test_user_group_leader_is_not_scoped(repo, fan_out):
    """Explicitly unchanged (user decision): narrowing a UGL to their led group
    would break the leader flows that look members up before adding them."""
    svc, _ = _scoped_svc(repo, fan_out)
    out = svc.browse(principal=UGL, limit=25)
    assert {i["id"] for i in out["items"]} == {"in-g1", "in-g2", "in-both"}


def test_count_and_search_agree_under_scoping(repo, fan_out, member_in_g1):
    """`count_members` and `search_members` share `_member_query`. If the new
    group_ids filter reached only one of them, the CSV-export progress bar would
    stall short of 100% or overshoot."""
    svc, _ = _scoped_svc(repo, fan_out)
    scope = ["g-1"]

    rows, _cursor = repo.search_members(group_ids=scope, limit=50)
    total = repo.count_members(group_ids=scope)

    assert total == len(rows) == 2


def test_no_limit_default_page_is_scoped_for_members(repo, fan_out, member_in_g1):
    """A Member who omits `limit` still gets the scoped first page (default 25)
    via OpenSearch — scope is pushed INTO the query, never a post-filter, and
    there is no unpaged scan path that could bypass it."""
    svc, _ = _scoped_svc(repo, fan_out)

    out = svc.browse(principal=member_in_g1)

    assert {i["id"] for i in out["items"]} == {"in-g1", "in-both"}
