"""Unit tests for the Content Library OpenSearch stream indexer.

Mirrors the member-profiles indexer's contract:
  * RESOURCE#*/META items are indexed; everything else is skipped
  * REMOVE deletes the document
  * search-visibility rule (Clean OR Link) decides index-vs-delete on a write,
    matching the sparse GSI1 key in library_repository.put_resource
  * indexing is keyed by resource id, so re-processing a record is idempotent
"""
from unittest.mock import MagicMock, patch

# SRC is placed on sys.path by tests/conftest.py before this module is imported.
import library_indexer
import pytest

# ---------------------------------------------------------------- helpers

def _record(event_name, resource_id, new_image=None):
    rec = {
        "eventName": event_name,
        "dynamodb": {
            "Keys": {"pk": {"S": f"RESOURCE#{resource_id}"}, "sk": {"S": "META"}},
        },
    }
    if new_image is not None:
        rec["dynamodb"]["NewImage"] = new_image
    return rec


def _clean_image(resource_id="lib-1"):
    return {
        "pk": {"S": f"RESOURCE#{resource_id}"},
        "sk": {"S": "META"},
        "id": {"S": resource_id},
        "title": {"S": "Serverless Guide"},
        "description": {"S": "A deep dive"},
        "format": {"S": "Doc"},
        "source": {"S": "curator-direct"},
        "topics": {"L": [{"S": "serverless"}, {"S": "aws"}]},
        "scanState": {"S": "Clean"},
        "addedAt": {"S": "2026-08-01T00:00:00+00:00"},
        "gsi1pk": {"S": "COMMUNITY"},
        "gsi1sk": {"S": "2026-08-01T00:00:00+00:00#lib-1"},
    }


@pytest.fixture()
def mock_client():
    client = MagicMock()
    with patch.object(library_indexer, "_get_client", return_value=client):
        yield client


# ---------------------------------------------------------------- tests

class TestIndexing:

    def test_clean_resource_is_indexed(self, mock_client):
        library_indexer.handler({"Records": [_record("INSERT", "lib-1", _clean_image())]}, None)
        mock_client.index.assert_called_once()
        kwargs = mock_client.index.call_args.kwargs
        assert kwargs["index"] == "library"
        assert kwargs["id"] == "lib-1"
        body = kwargs["body"]
        assert body["title"] == "Serverless Guide"
        assert body["topics"] == ["serverless", "aws"]
        # DynamoDB key / GSI-projection fields must be stripped.
        for stripped in ("pk", "sk", "gsi1pk", "gsi1sk"):
            assert stripped not in body

    def test_link_resource_without_clean_state_is_indexed(self, mock_client):
        img = {
            "pk": {"S": "RESOURCE#lib-2"}, "sk": {"S": "META"},
            "id": {"S": "lib-2"}, "title": {"S": "Blog"}, "description": {"S": "d"},
            "format": {"S": "Link"}, "url": {"S": "https://blog.example.com"},
            "addedAt": {"S": "2026-08-02T00:00:00+00:00"},
        }
        library_indexer.handler({"Records": [_record("INSERT", "lib-2", img)]}, None)
        mock_client.index.assert_called_once()
        mock_client.delete.assert_not_called()

    def test_pending_scan_non_link_is_deleted_not_indexed(self, mock_client):
        img = {
            "pk": {"S": "RESOURCE#lib-3"}, "sk": {"S": "META"},
            "id": {"S": "lib-3"}, "title": {"S": "Slides"}, "description": {"S": "d"},
            "format": {"S": "Slides"}, "scanState": {"S": "PendingScan"},
            "s3Key": {"S": "library/lib-3/x.pptx"},
            "addedAt": {"S": "2026-08-03T00:00:00+00:00"},
        }
        library_indexer.handler({"Records": [_record("INSERT", "lib-3", img)]}, None)
        mock_client.index.assert_not_called()
        mock_client.delete.assert_called_once()
        assert mock_client.delete.call_args.kwargs["id"] == "lib-3"

    def test_quarantined_non_link_is_deleted(self, mock_client):
        img = {
            "pk": {"S": "RESOURCE#lib-4"}, "sk": {"S": "META"},
            "id": {"S": "lib-4"}, "title": {"S": "Bad"}, "description": {"S": "d"},
            "format": {"S": "PDF"}, "scanState": {"S": "Quarantined"},
            "addedAt": {"S": "2026-08-04T00:00:00+00:00"},
        }
        library_indexer.handler({"Records": [_record("INSERT", "lib-4", img)]}, None)
        mock_client.index.assert_not_called()
        mock_client.delete.assert_called_once()

    def test_remove_deletes_document(self, mock_client):
        library_indexer.handler({"Records": [_record("REMOVE", "lib-1")]}, None)
        mock_client.delete.assert_called_once()
        assert mock_client.delete.call_args.kwargs["id"] == "lib-1"
        mock_client.index.assert_not_called()

    def test_non_resource_items_skipped(self, mock_client):
        rec = {
            "eventName": "INSERT",
            "dynamodb": {"Keys": {"pk": {"S": "TAGS#ALL"}, "sk": {"S": "META"}},
                         "NewImage": {"pk": {"S": "TAGS#ALL"}, "sk": {"S": "META"}}},
        }
        library_indexer.handler({"Records": [rec]}, None)
        mock_client.index.assert_not_called()
        mock_client.delete.assert_not_called()

    def test_reprocessing_same_record_is_idempotent(self, mock_client):
        rec = _record("INSERT", "lib-1", _clean_image())
        library_indexer.handler({"Records": [rec, rec]}, None)
        # Both index calls target the same id — a re-run overwrites, never dupes.
        assert mock_client.index.call_count == 2
        ids = {c.kwargs["id"] for c in mock_client.index.call_args_list}
        assert ids == {"lib-1"}

    def test_missing_new_image_skipped(self, mock_client):
        library_indexer.handler({"Records": [_record("MODIFY", "lib-1", None)]}, None)
        mock_client.index.assert_not_called()
        mock_client.delete.assert_not_called()


class TestDeserialize:

    def test_types_and_stripping(self):
        img = {
            "pk": {"S": "RESOURCE#x"}, "sk": {"S": "META"},
            "gsi2pk": {"S": "MAT#m1"}, "gsi2sk": {"S": "x"},
            "id": {"S": "x"},
            "topics": {"L": [{"S": "a"}, {"S": "b"}]},
            "views": {"N": "42"},
            "flagged": {"BOOL": True},
            "note": {"NULL": True},
        }
        out = library_indexer._deserialize(img)
        assert out["id"] == "x"
        assert out["topics"] == ["a", "b"]
        assert out["views"] == 42
        assert out["flagged"] is True
        assert out["note"] is None
        for stripped in ("pk", "sk", "gsi2pk", "gsi2sk"):
            assert stripped not in out
