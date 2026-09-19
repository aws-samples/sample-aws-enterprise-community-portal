"""DynamoDB stream processor — indexes Content Library resources into OpenSearch.

Triggered by the library-${Stage} DynamoDB stream on every resource write.
Only RESOURCE#.../META items are processed; the TAGS#ALL singleton and any
other item types are ignored.

Search-visibility mirrors the DynamoDB GSI1 sparse-key rule in
`library_repository.put_resource`: a resource is searchable only when it has
scanned Clean or is a Link. This indexer applies the SAME rule:

  * searchable (Clean / Link) -> upsert the document
  * not-yet/ no-longer searchable (PendingScan / Quarantined non-link)
        -> delete any existing document

so a Pending->Clean transition indexes the resource and a Clean->Quarantined
transition removes it, keeping the index in step with what the DynamoDB search
path would have returned.

Sort field written per document:
  addedAt   str  ISO-8601 — newest-first sort (addedAt.keyword desc, id.keyword asc)
"""
from __future__ import annotations

import os
from decimal import Decimal

from _conventions.logger import get_logger

_logger = get_logger("events.library-indexer")

# Index name on the shared portal-search collection. Members use "members";
# the Content Library uses "library". No stage suffix (the collection itself is
# per-stage: portal-search-${Stage}).
OPENSEARCH_INDEX = "library"

_SCAN_CLEAN = "Clean"

# Lazily constructed OpenSearch client. opensearchpy/requests_aws4auth are
# imported inside _get_client (not at module top) so this module stays
# importable for unit tests that patch _get_client without the packages present;
# in Lambda they are vendored into the zip.
_os_client = None


def _get_client():  # noqa: ANN201
    global _os_client  # noqa: PLW0603
    if _os_client is None:
        import boto3  # noqa: PLC0415
        from opensearchpy import OpenSearch, RequestsHttpConnection  # noqa: PLC0415
        from requests_aws4auth import AWS4Auth  # noqa: PLC0415

        endpoint = os.environ["OPENSEARCH_ENDPOINT"]
        region = os.environ.get("AWS_REGION", "us-east-1")
        creds = boto3.Session().get_credentials().get_frozen_credentials()
        auth = AWS4Auth(creds.access_key, creds.secret_key, region, "aoss",
                        session_token=creds.token)
        host = endpoint.replace("https://", "").rstrip("/")
        _os_client = OpenSearch(
            hosts=[{"host": host, "port": 443}],
            http_auth=auth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            timeout=60,
        )
    return _os_client


def _is_searchable(doc: dict) -> bool:
    """Same rule as the sparse GSI1 key in library_repository.put_resource:
    a resource is searchable when it scanned Clean or is a Link."""
    is_link = doc.get("format") == "Link" or bool(doc.get("url"))
    return doc.get("scanState", _SCAN_CLEAN) == _SCAN_CLEAN or is_link


def handler(event: dict, context) -> None:  # noqa: ANN001
    client = _get_client()
    indexed = deleted = skipped = 0

    for record in event.get("Records", []):
        dynamodb = record.get("dynamodb", {})
        keys = dynamodb.get("Keys", {})
        pk = keys.get("pk", {}).get("S", "")
        sk = keys.get("sk", {}).get("S", "")

        if not pk.startswith("RESOURCE#") or sk != "META":
            skipped += 1
            continue

        resource_id = pk[len("RESOURCE#"):]
        event_name = record.get("eventName", "")

        if event_name == "REMOVE":
            _delete(client, resource_id)
            deleted += 1
            continue

        new_image = dynamodb.get("NewImage")
        if not new_image:
            skipped += 1
            continue

        doc = _deserialize(new_image)
        if _is_searchable(doc):
            try:
                client.index(index=OPENSEARCH_INDEX, id=resource_id, body=doc)
                indexed += 1
            except Exception:  # noqa: BLE001
                _logger.exception("Failed to index library resource in OpenSearch",
                                  extra={"resourceId": resource_id})
                raise
        else:
            # PendingScan / Quarantined non-link — must not be searchable.
            _delete(client, resource_id)
            deleted += 1

    _logger.info("Library stream batch processed",
                 extra={"indexed": indexed, "deleted": deleted, "skipped": skipped})


def _delete(client, resource_id: str) -> None:  # noqa: ANN001
    try:
        client.delete(index=OPENSEARCH_INDEX, id=resource_id, ignore=[404])
    except Exception:  # noqa: BLE001
        _logger.exception("Failed to delete library resource from OpenSearch",
                          extra={"resourceId": resource_id})
        raise


def _deserialize(image: dict) -> dict:
    """Convert DynamoDB typed JSON to a plain dict for OpenSearch.

    Strips DynamoDB key / GSI-projection fields.
    """
    out: dict = {}
    for k, v in image.items():
        out[k] = _deser_val(v)

    for key in ("pk", "sk", "gsi1pk", "gsi1sk", "gsi2pk", "gsi2sk",
                "gsi3pk", "gsi3sk", "ttl"):
        out.pop(key, None)

    return out


def _deser_val(v: dict):  # noqa: ANN201
    if "S" in v:
        return v["S"]
    if "N" in v:
        n = Decimal(v["N"])
        return int(n) if n == n.to_integral_value() else float(n)
    if "BOOL" in v:
        return v["BOOL"]
    if "NULL" in v:
        return None
    if "SS" in v:
        return list(v["SS"])
    if "NS" in v:
        return [float(x) for x in v["NS"]]
    if "L" in v:
        return [_deser_val(i) for i in v["L"]]
    if "M" in v:
        return {k: _deser_val(i) for k, i in v["M"].items()}
    return None
