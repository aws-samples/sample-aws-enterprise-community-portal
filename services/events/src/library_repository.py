"""DynamoDB access layer for the Content Library (library-${Stage} table).

Key design (single table, one item collection per resource):

  RESOURCE#<id>   / META                     -> LibraryResource item
      GSI1: COMMUNITY / <addedAt>#<id>        -> newest-first search (SPARSE: Clean only)
      GSI2: MAT#<materialId> / <id>           -> auto-removal lookup (SPARSE: Path 1 only)
      GSI3: CON#<contributionId> / <id>       -> idempotency (SPARSE: Path 2 only)

  TAGS#ALL        / META                     -> TagRegistry singleton (all distinct tags)

GSI1 is the hot search path. GSI2 and GSI3 are low-volume write-time lookups.
"""
from __future__ import annotations

import base64
import json
import os
from decimal import Decimal

from boto3.dynamodb.conditions import Key

# OpenSearch index name — must match library_indexer.OPENSEARCH_INDEX.
OPENSEARCH_INDEX = "library"


# ------------------------------------------------------------------ cursors

def _encode_cursor(key: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(key, default=str).encode()).decode()


def _decode_cursor(cursor: str) -> dict:
    try:
        return json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except Exception:
        from _conventions.errors import ValidationError
        raise ValidationError("Invalid pagination cursor.") from None


def _decimal_default(obj):
    if isinstance(obj, Decimal):
        return int(obj) if obj == obj.to_integral_value() else float(obj)
    raise TypeError


# ---------------------------------------------------------------- OpenSearch

def _library_query(*, q: str | None = None, fmt: str | None = None,
                   source: str | None = None, topic: str | None = None) -> dict:
    """The OpenSearch `bool` query for a Content Library search.

    Mirrors the DynamoDB `predicate` in `LibraryService.search`:
      * q      -> full-text over title + description (was substring on both)
      * fmt    -> exact `format` (was row["format"] == fmt)
      * source -> exact `source` (was row["source"] == source)
      * topic  -> membership in `topics` (was topic in row["topics"])

    All filter clauses are exact (`.keyword`) term matches, not scored. The whole
    index is already search-visible (Clean / Link only — the indexer applies the
    same sparse rule the GSI1 key did), so no scanState clause is needed.
    """
    filters: list[dict] = []
    if fmt:
        filters.append({"term": {"format.keyword": fmt}})
    if source:
        filters.append({"term": {"source.keyword": source}})
    if topic:
        # topics are stored lowercase-normalised at write time, so an exact
        # term on the already-lowercased needle matches.
        filters.append({"term": {"topics.keyword": topic}})

    must: list[dict] = []
    if q:
        must.append({
            "multi_match": {
                "query": q,
                "fields": ["title", "description"],
                "type": "phrase_prefix",
            }
        })

    return {"bool": {"must": must if must else [{"match_all": {}}], "filter": filters}}


# ------------------------------------------------------------------ repo

class LibraryRepository:
    """Single-table DynamoDB access for the Content Library."""

    def __init__(self, table):
        self._t = table

    # ---------------------------------------------------------------- writes

    def put_resource(self, resource: dict) -> None:
        """Write (or overwrite) a LibraryResource item.

        Maintains sparse GSI keys:
          GSI1: present only when scanState is Clean (or resource is a link)
          GSI2: present only when materialId is set (Path 1)
          GSI3: present only when contributionId is set (Path 2)
        """
        item = {k: v for k, v in resource.items()
                if v is not None and k not in ("pk", "sk", "gsi1pk", "gsi1sk",
                                                "gsi2pk", "gsi2sk", "gsi3pk", "gsi3sk")}
        item["pk"] = f"RESOURCE#{resource['id']}"
        item["sk"] = "META"

        # GSI1 — search index (Clean resources only)
        scan_state = resource.get("scanState", "Clean")
        is_link = resource.get("format") == "Link" or resource.get("url")
        if scan_state == "Clean" or is_link:
            item["gsi1pk"] = "COMMUNITY"
            item["gsi1sk"] = f"{resource['addedAt']}#{resource['id']}"
        else:
            item.pop("gsi1pk", None)
            item.pop("gsi1sk", None)

        # GSI2 — materialId lookup (Path 1 auto-removal)
        if resource.get("materialId"):
            item["gsi2pk"] = f"MAT#{resource['materialId']}"
            item["gsi2sk"] = resource["id"]

        # GSI3 — contributionId idempotency (Path 2)
        if resource.get("contributionId"):
            item["gsi3pk"] = f"CON#{resource['contributionId']}"
            item["gsi3sk"] = resource["id"]

        self._t.put_item(Item=item)

    def update_scan_state(self, resource_id: str, scan_state: str) -> None:
        """Update scanState and maintain GSI1 sparse key accordingly."""
        resource = self.get_resource(resource_id)
        if resource is None:
            return
        resource["scanState"] = scan_state
        self.put_resource(resource)

    def delete_resource(self, resource_id: str) -> None:
        self._t.delete_item(Key={
            "pk": f"RESOURCE#{resource_id}",
            "sk": "META",
        })

    def delete_by_material_id(self, material_id: str) -> None:
        """Auto-removal (BR-LIB-P5): delete Library resource for a given materialId."""
        resp = self._t.query(
            IndexName="GSI2",
            KeyConditionExpression=Key("gsi2pk").eq(f"MAT#{material_id}"),
        )
        for item in resp.get("Items", []):
            resource_id = item.get("id") or item.get("gsi2sk")
            if resource_id:
                self.delete_resource(resource_id)

    # ----------------------------------------------------------------- reads

    def get_resource(self, resource_id: str) -> dict | None:
        resp = self._t.get_item(Key={
            "pk": f"RESOURCE#{resource_id}",
            "sk": "META",
        })
        return resp.get("Item")

    def get_by_contribution_id(self, contribution_id: str) -> dict | None:
        """Idempotency check for Path 2 consumer."""
        resp = self._t.query(
            IndexName="GSI3",
            KeyConditionExpression=Key("gsi3pk").eq(f"CON#{contribution_id}"),
            Limit=1,
        )
        items = resp.get("Items", [])
        return items[0] if items else None

    def get_by_material_id(self, material_id: str) -> dict | None:
        """Idempotency check for Path 1 (event material / external upload).
        Rides the sparse GSI2 (MAT#<materialId>)."""
        resp = self._t.query(
            IndexName="GSI2",
            KeyConditionExpression=Key("gsi2pk").eq(f"MAT#{material_id}"),
            Limit=1,
        )
        items = resp.get("Items", [])
        return items[0] if items else None

    def query_page(self, *, limit: int, cursor: str | None,
                   predicate=None) -> tuple[list[dict], str | None]:
        """Search: GSI1 partition walk, newest first.

        All items in GSI1 are Clean (or links) — no post-scan filter needed
        for scan state. The predicate filters keyword/format/source/topic.
        """
        start_key: dict | None = None
        if cursor:
            start_key = _decode_cursor(cursor)

        matched: list[dict] = []
        exclusive = start_key

        while True:
            kwargs: dict = {
                "IndexName": "GSI1",
                "KeyConditionExpression": Key("gsi1pk").eq("COMMUNITY"),
                "ScanIndexForward": False,
                "Limit": limit + 1,
            }
            if exclusive:
                kwargs["ExclusiveStartKey"] = exclusive

            resp = self._t.query(**kwargs)
            for row in resp.get("Items", []):
                if predicate is None or predicate(row):
                    matched.append(row)
                if len(matched) > limit:
                    page = matched[:limit]
                    last = page[-1]
                    next_cursor = _encode_cursor({
                        "pk": last["pk"],
                        "sk": last["sk"],
                        "gsi1pk": last.get("gsi1pk", "COMMUNITY"),
                        "gsi1sk": last.get("gsi1sk", ""),
                    })
                    return page, next_cursor

            exclusive = resp.get("LastEvaluatedKey")
            if not exclusive:
                break

        return matched[:limit], None

    # ---------------------------------------------------- OpenSearch search

    def search_opensearch(self, *, q: str | None = None, fmt: str | None = None,
                          source: str | None = None, topic: str | None = None,
                          limit: int = 25,
                          cursor: str | None = None) -> tuple[list[dict], str | None]:
        """Query the OpenSearch 'library' index, newest first.

        Returns (items, next_cursor). next_cursor is an opaque base64 string
        encoding the `search_after` values of the last hit — stable across
        concurrent writes, the same cursor scheme member-profiles uses. Returns
        ([], None) when OpenSearch is not configured, so the service can fall
        back to the DynamoDB GSI1 walk.
        """
        client = self._os_client()
        if client is None:
            return [], None

        body: dict = {
            "query": _library_query(q=q, fmt=fmt, source=source, topic=topic),
            # newest-first; id tiebreaker keeps the sort total (stable search_after).
            # addedAt is an ISO-8601 timestamp: OpenSearch dynamic mapping detects
            # it as a `date` field, which has NO `.keyword` sub-field, so we sort
            # on `addedAt` itself (a date sorts chronologically). id is a plain
            # string and does get an `id.keyword` sub-field for the tiebreaker.
            "sort": [{"addedAt": "desc"}, {"id.keyword": "asc"}],
            "size": limit + 1,  # one extra hit reveals whether a next page exists
        }

        if cursor:
            from _conventions.errors import ValidationError  # noqa: PLC0415
            try:
                body["search_after"] = json.loads(
                    base64.urlsafe_b64decode(cursor.encode()))
            except (ValueError, TypeError, json.JSONDecodeError):
                raise ValidationError("Invalid pagination cursor.") from None

        resp = client.search(index=OPENSEARCH_INDEX, body=body)
        hits = resp.get("hits", {}).get("hits", [])

        next_cursor: str | None = None
        if len(hits) > limit:
            hits = hits[:limit]
            last_sort = hits[-1].get("sort", [])
            next_cursor = base64.urlsafe_b64encode(
                json.dumps(last_sort).encode()).decode()

        items = [h["_source"] for h in hits]
        return items, next_cursor

    def reindex_all(self) -> int:
        """Bulk-index every search-visible RESOURCE#*/META item into OpenSearch.

        Backfill / reconciliation entry point. Applies the same search-visibility
        rule as the stream indexer (Clean or Link) so the index matches what the
        DynamoDB search path would have returned. Returns the count indexed.
        Returns 0 when OpenSearch is not configured.
        """
        client = self._os_client()
        if client is None:
            return 0

        from boto3.dynamodb.conditions import Attr  # noqa: PLC0415
        items, kwargs = [], {}
        while True:
            resp = self._t.scan(FilterExpression=Attr("sk").eq("META")
                                 & Attr("pk").begins_with("RESOURCE#"), **kwargs)
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break

        bulk_lines: list[str] = []
        indexed = 0
        for item in items:
            scan_state = item.get("scanState", "Clean")
            is_link = item.get("format") == "Link" or bool(item.get("url"))
            if scan_state != "Clean" and not is_link:
                continue   # not search-visible — skip (matches sparse GSI1 rule)
            doc = {k: v for k, v in item.items()
                   if k not in ("pk", "sk", "gsi1pk", "gsi1sk", "gsi2pk",
                                "gsi2sk", "gsi3pk", "gsi3sk", "ttl")}
            bulk_lines.append(json.dumps(
                {"index": {"_index": OPENSEARCH_INDEX, "_id": item.get("id", "")}}))
            bulk_lines.append(json.dumps(doc, default=_decimal_default))
            indexed += 1

        if bulk_lines:
            client.bulk(body="\n".join(bulk_lines) + "\n")
        return indexed

    def _os_client(self):  # noqa: ANN201
        """Lazy OpenSearch client — returns None if endpoint not configured.

        Same construction as member-profiles (aoss AWS4Auth, port 443). The None
        return is the fail-soft gate: when OPENSEARCH_ENDPOINT is unset the
        service reverts to the DynamoDB GSI1 walk.
        """
        endpoint = os.environ.get("OPENSEARCH_ENDPOINT", "")
        if not endpoint:
            return None
        try:
            import boto3 as _boto3  # noqa: PLC0415
            from opensearchpy import OpenSearch, RequestsHttpConnection  # noqa: PLC0415
            from requests_aws4auth import AWS4Auth  # noqa: PLC0415
        except ImportError:
            return None
        region = os.environ.get("AWS_REGION", "us-east-1")
        creds = _boto3.Session().get_credentials().get_frozen_credentials()
        auth = AWS4Auth(creds.access_key, creds.secret_key, region, "aoss",
                        session_token=creds.token)
        host = endpoint.replace("https://", "").rstrip("/")
        return OpenSearch(
            hosts=[{"host": host, "port": 443}],
            http_auth=auth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            timeout=60,
        )

    # --------------------------------------------------------------- tags

    def get_all_tags(self) -> set[str]:
        """Fetch the TAGS#ALL singleton item. Returns empty set if absent."""
        resp = self._t.get_item(Key={"pk": "TAGS#ALL", "sk": "META"})
        item = resp.get("Item")
        if not item:
            return set()
        return set(item.get("tags") or [])

    def add_tags(self, new_tags: list[str]) -> None:
        """Add tags to the TAGS#ALL singleton. No-op on empty list."""
        if not new_tags:
            return
        tag_set = set(t.strip().lower() for t in new_tags if t.strip())
        if not tag_set:
            return
        self._t.update_item(
            Key={"pk": "TAGS#ALL", "sk": "META"},
            UpdateExpression="ADD #tags :vals",
            ExpressionAttributeNames={"#tags": "tags"},
            ExpressionAttributeValues={":vals": tag_set},
        )
