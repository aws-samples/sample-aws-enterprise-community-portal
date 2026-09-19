"""Unit tests for the OpenSearch-backed library search path:

  * _library_query      — the bool query builder (mirrors the DynamoDB predicate)
  * search_opensearch    — body shape, sort, search_after cursor round-trip
  * LibraryService.search backend selection — OpenSearch when endpoint set,
    else fail-soft to the DynamoDB GSI1 walk (query_page)
"""
import base64
import json
from unittest.mock import MagicMock

import pytest

# SRC is placed on sys.path by tests/conftest.py before this module is imported.
from library_repository import LibraryRepository, _library_query
from library_service import LibraryService

# ---------------------------------------------------------------- query builder

class TestQueryBuilder:

    def test_keyword_only_multi_match_no_filters(self):
        q = _library_query(q="serverless")
        assert q["bool"]["filter"] == []
        must = q["bool"]["must"]
        assert must[0]["multi_match"]["query"] == "serverless"
        assert must[0]["multi_match"]["fields"] == ["title", "description"]

    def test_no_args_is_match_all(self):
        q = _library_query()
        assert q["bool"]["must"] == [{"match_all": {}}]
        assert q["bool"]["filter"] == []

    def test_filters_use_keyword_terms(self):
        q = _library_query(fmt="Slides", source="curator-direct", topic="serverless")
        filters = q["bool"]["filter"]
        assert {"term": {"format.keyword": "Slides"}} in filters
        assert {"term": {"source.keyword": "curator-direct"}} in filters
        assert {"term": {"topics.keyword": "serverless"}} in filters
        # no keyword -> match_all still present
        assert q["bool"]["must"] == [{"match_all": {}}]


# ---------------------------------------------------------------- search_opensearch

def _hit(resource_id, added_at):
    return {
        "_source": {"id": resource_id, "title": f"T{resource_id}",
                    "format": "Doc", "source": "curator-direct",
                    "addedAt": added_at, "topics": []},
        "sort": [added_at, resource_id],
    }


class TestSearchOpenSearch:

    def _repo_with_client(self, hits):
        repo = LibraryRepository(MagicMock())
        client = MagicMock()
        client.search.return_value = {"hits": {"hits": hits}}
        repo._os_client = MagicMock(return_value=client)
        return repo, client

    def test_returns_none_when_no_endpoint(self):
        repo = LibraryRepository(MagicMock())
        repo._os_client = MagicMock(return_value=None)
        items, cursor = repo.search_opensearch(q="x", limit=10, cursor=None)
        assert items == []
        assert cursor is None

    def test_body_shape_sort_and_size(self):
        repo, client = self._repo_with_client([_hit("lib-1", "2026-08-01")])
        repo.search_opensearch(q="aws", fmt="Doc", limit=10, cursor=None)
        body = client.search.call_args.kwargs["body"]
        assert body["size"] == 11  # limit + 1
        assert body["sort"] == [{"addedAt": "desc"}, {"id.keyword": "asc"}]
        assert client.search.call_args.kwargs["index"] == "library"

    def test_no_next_cursor_when_page_not_full(self):
        repo, _ = self._repo_with_client([_hit("lib-1", "2026-08-01")])
        items, cursor = repo.search_opensearch(q="aws", limit=10, cursor=None)
        assert len(items) == 1
        assert cursor is None

    def test_next_cursor_when_extra_hit_present(self):
        # limit=1, return 2 hits -> a next page exists, extra hit trimmed
        hits = [_hit("lib-1", "2026-08-02"), _hit("lib-2", "2026-08-01")]
        repo, _ = self._repo_with_client(hits)
        items, cursor = repo.search_opensearch(q="aws", limit=1, cursor=None)
        assert len(items) == 1
        assert items[0]["id"] == "lib-1"
        assert cursor is not None
        # cursor decodes to the last returned hit's sort values
        decoded = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        assert decoded == ["2026-08-02", "lib-1"]

    def test_cursor_is_passed_as_search_after(self):
        repo, client = self._repo_with_client([_hit("lib-1", "2026-08-01")])
        cursor = base64.urlsafe_b64encode(json.dumps(["2026-08-05", "lib-9"]).encode()).decode()
        repo.search_opensearch(q="aws", limit=10, cursor=cursor)
        body = client.search.call_args.kwargs["body"]
        assert body["search_after"] == ["2026-08-05", "lib-9"]

    def test_bad_cursor_raises_validation_error(self):
        from _conventions.errors import ValidationError
        repo, _ = self._repo_with_client([])
        with pytest.raises(ValidationError):
            repo.search_opensearch(q="aws", limit=10, cursor="!!!not-base64!!!")


# ---------------------------------------------------------------- backend selection

def _member_principal():
    p = MagicMock()
    p.role = "Member"
    p.user_id = "u-1"
    return p


def _svc():
    repo = MagicMock()
    storage = MagicMock()
    storage.presign_get.return_value = "https://s3/presigned"
    svc = LibraryService(repo, MagicMock(), storage)
    return svc, repo


class TestBackendSelection:

    def test_uses_opensearch_when_endpoint_set(self, monkeypatch):
        monkeypatch.setenv("OPENSEARCH_ENDPOINT", "https://abc.aoss.us-east-1.on.aws")
        svc, repo = _svc()
        repo.search_opensearch.return_value = ([], None)
        svc.search(principal=_member_principal(), filters={"q": "aws"}, limit=10, cursor=None)
        repo.search_opensearch.assert_called_once()
        repo.query_page.assert_not_called()

    def test_falls_back_to_dynamodb_when_endpoint_unset(self, monkeypatch):
        monkeypatch.delenv("OPENSEARCH_ENDPOINT", raising=False)
        svc, repo = _svc()
        repo.query_page.return_value = ([], None)
        svc.search(principal=_member_principal(), filters={"q": "aws"}, limit=10, cursor=None)
        repo.query_page.assert_called_once()
        repo.search_opensearch.assert_not_called()

    def test_opensearch_filters_forwarded(self, monkeypatch):
        monkeypatch.setenv("OPENSEARCH_ENDPOINT", "https://abc.aoss.us-east-1.on.aws")
        svc, repo = _svc()
        repo.search_opensearch.return_value = ([], None)
        svc.search(principal=_member_principal(),
                   filters={"q": "aws", "format": "Slides", "source": "curator-direct",
                            "topic": "Serverless"},
                   limit=5, cursor=None)
        kwargs = repo.search_opensearch.call_args.kwargs
        assert kwargs["q"] == "aws"
        assert kwargs["fmt"] == "Slides"
        assert kwargs["source"] == "curator-direct"
        # topic is lowercased by the service before the term filter
        assert kwargs["topic"] == "serverless"
        assert kwargs["limit"] == 5
