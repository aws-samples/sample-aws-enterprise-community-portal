"""Single-table DynamoDB access for Identity & Access (NFR-IA-SCALE-1).

Key design (see nfr-design/logical-components.md):
  USER#<id>            / PROFILE                 -> user
      GSI1  EMAIL#<email> / USER                 -> email lookup
      GSI2  ROLE#<role>   / USER#<id>            -> role/status listing
  GROUP#<id>           / META                     -> group
  GROUP#<id>           / MEMBERCOUNT              -> current member counter
  GROUP#<id>           / MEMBER#<memberId>        -> current-membership projection
  GROUP#<id>           / JOINREQ#<at>#<id>        -> join request
  MEMBER#<id>          / MEVENT#<at>#<id>         -> membership event
      GSI3  GROUP#<groupId> / MEVENT#<at>         -> per-group membership history
  OTP#<challengeId>    / CHALLENGE  (TTL=ttl)     -> otp challenge
  EXPORT#<jobId>       / JOB        (TTL=ttl)     -> async CSV export job

Current membership is a materialised projection of the append-only event log
(2026-08-05, 13k+ member groups). Membership was previously derived by folding
the group's ENTIRE event history on every read, so one page of a 13,000-member
list read 13,000+ event items and `list_groups` did that once per group. The
projection is written inside `append_membership_event` — the single method every
membership mutation in this service already goes through — so it cannot drift
from the event log, which remains the source of truth
(`derive_members_from_events` rebuilds the projection from it).

All expressions are parameterized (SECURITY-05). No string-built queries.
"""
from __future__ import annotations

import base64
import json
import os

from _conventions.errors import ValidationError
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError
from models import (
    GROUP_ACTIVE,
    MEVENT_END,
    MEVENT_START,
    ROLE_ADMIN,
    ROLE_COMMUNITY_LEADER,
    ROLE_MEMBER,
    ROLE_UGL,
    epoch,
    member_search_key,
)

# Fixed partition-walk order for the paged admin user list (D-U1) — ROLES is a
# set, so an explicit order keeps cursors stable across requests.
ROLE_PAGE_ORDER = [ROLE_ADMIN, ROLE_COMMUNITY_LEADER, ROLE_UGL, ROLE_MEMBER]

# Shared OpenSearch index — owned by member-profiles, partially updated by identity-access.
# identity-access writes identity fields only (partial update / doc_as_upsert).
# member-profiles writes the full document including bio, skills, groupIds.
OPENSEARCH_INDEX = "members"

# Role sort order for the admin table (0 = top when ascending).
_ROLE_SORT_ORDER: dict[str, int] = {
    "Administrator": 0,
    "CommunityLeader": 1,
    "UserGroupLeader": 2,
    "Member": 3,
}


def _user_to_search_doc(user: dict) -> dict:
    """Convert a DynamoDB user record to an OpenSearch document.

    Strips DynamoDB projection keys, adds roleSortOrder and normalised name
    fields for deterministic sort. Mirrors what indexer.py does for stream events.
    """
    doc = {k: v for k, v in user.items()
           if k not in ("pk", "sk", "gsi1pk", "gsi1sk", "gsi2pk", "gsi2sk",
                        "gsi3pk", "gsi3sk", "ttl")}
    doc["roleSortOrder"] = _ROLE_SORT_ORDER.get(doc.get("role", ""), 99)
    # Normalise status to lowercase — identity-access stores "Active"/"Inactive"
    # but the merged index and frontend use "active"/"inactive".
    if doc.get("status"):
        doc["status"] = doc["status"].lower()
    return doc


def _user_query(*, q: str | None = None, role: str | None = None,
                status: str | None = None, group_ids: set[str] | None = None) -> dict:
    """The OpenSearch `bool` query for an admin user listing.

    Shared by `search_users` (which fetches the rows) and `count_users` (which
    supplies the denominator for the CSV-export progress bar). They MUST build
    the query identically — if the count and the row walk disagree, the progress
    percentage is wrong and can stall short of 100% or run past it.
    """
    # Filter clauses — always exact-match, never scored.
    filters: list[dict] = []
    if role:
        filters.append({"term": {"role.keyword": role}})
    if status:
        # status is normalised to lowercase in the index regardless of
        # what identity-access stores ("Active" → "active").
        filters.append({"term": {"status.keyword": status.lower()}})
    if group_ids is not None:
        # group_ids is a set of user IDs that belong to the requested group —
        # resolved upstream in the service layer. Filter to those users only.
        filters.append({"terms": {"id.keyword": list(group_ids)}})

    # Full-text clause — phrase_prefix matches partial words (e.g. "smi" → "Smith").
    must: list[dict] = []
    if q:
        must.append({
            "multi_match": {
                "query": q,
                "fields": ["firstName", "lastName", "email", "professionalRole"],
                "type": "phrase_prefix",
            }
        })

    return {"bool": {"must": must if must else [{"match_all": {}}], "filter": filters}}


def encode_user_cursor(item: dict) -> str:
    """Opaque cursor: role partition + last returned user id (D-U1)."""
    key = {"role": item["role"], "id": item["id"]}
    return base64.urlsafe_b64encode(json.dumps(key).encode()).decode()


def decode_user_cursor(cursor: str) -> dict:
    """Decode a client-supplied cursor; malformed input is a 400, never a 500."""
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        if not isinstance(key, dict) or set(key) != {"role", "id"} \
                or key["role"] not in ROLE_PAGE_ORDER or not isinstance(key["id"], str):
            raise ValueError("bad cursor shape")
        return key
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValidationError("Invalid pagination cursor.") from None


def encode_member_cursor(member_id: str, *, leaders_done: bool = True) -> str:
    """Opaque cursor for the paged group member list.

    Two fields, both needed: `m` is the last id returned and `ld` records which
    block the walk stopped in. The member screen lists the group's LEADERS first
    (leadership is not membership, so a leader may have no projection item) and
    then the members in id order. A single-field cursor cannot tell "stopped
    inside the leader block" from "stopped inside the member block", and
    resuming in the wrong one silently skips every member whose id sorts below
    the last leader's id."""
    return base64.urlsafe_b64encode(
        json.dumps({"m": member_id, "ld": leaders_done}).encode()).decode()


def decode_member_cursor(cursor: str) -> tuple[str, bool]:
    """Decode a client-supplied member cursor -> (last_id, leaders_done).
    Malformed input is a 400, never a 500. The pre-2026-08-05 single-field
    `{"m": id}` form is still accepted and means "leaders already emitted"."""
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        if not isinstance(key, dict) or not set(key) <= {"m", "ld"} \
                or not isinstance(key.get("m"), str):
            raise ValueError("bad cursor shape")
        leaders_done = key.get("ld", True)
        if not isinstance(leaders_done, bool):
            raise ValueError("bad cursor shape")
        return key["m"], leaders_done
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValidationError("Invalid pagination cursor.") from None


def encode_history_cursor(at: str, member_id: str, event_id: str) -> str:
    """Opaque cursor for the paged membership history. All three parts are
    required to rebuild the GSI3 ExclusiveStartKey (index keys + table keys)."""
    return base64.urlsafe_b64encode(
        json.dumps({"at": at, "m": member_id, "id": event_id}).encode()).decode()


def decode_history_cursor(cursor: str) -> dict:
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        if not isinstance(key, dict) or set(key) != {"at", "m", "id"} \
                or not all(isinstance(key[k], str) for k in ("at", "m", "id")):
            raise ValueError("bad cursor shape")
        return key
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValidationError("Invalid pagination cursor.") from None


def encode_group_cursor(item: dict) -> str:
    """Opaque cursor for the paged group list. The page is a Query on GSI4, so
    resuming needs the full LastEvaluatedKey shape — the base table key (pk/sk)
    AND the index key (gsi4pk/gsi4sk) — carried on the last returned META row."""
    return base64.urlsafe_b64encode(
        json.dumps({k: item[k] for k in ("pk", "sk", "gsi4pk", "gsi4sk") if k in item}
                   ).encode()).decode()


_GROUP_CURSOR_KEYS = {"pk", "sk", "gsi4pk", "gsi4sk"}


def decode_group_cursor(cursor: str) -> dict:
    try:
        key = json.loads(base64.urlsafe_b64decode(cursor.encode()))
        if not isinstance(key, dict) or not key \
                or not set(key) <= _GROUP_CURSOR_KEYS \
                or not all(isinstance(v, str) for v in key.values()):
            raise ValueError("bad cursor shape")
        return key
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValidationError("Invalid pagination cursor.") from None


class IdentityRepository:
    def __init__(self, table):
        self._t = table

    # ---------- Users ----------
    def put_user(self, user: dict) -> dict:
        item = dict(user)
        item["pk"] = f"USER#{user['id']}"
        item["sk"] = "PROFILE"
        item["gsi1pk"] = f"EMAIL#{user['email'].lower()}"
        item["gsi1sk"] = "USER"
        item["gsi2pk"] = f"ROLE#{user['role']}"
        item["gsi2sk"] = f"USER#{user['id']}"
        self._t.put_item(Item=item)
        # Claims projection (fresh-claims-at-the-edge): put_user is the single
        # funnel for user create / edit / role change / JIT, so mirroring role +
        # ledGroupId onto the CLAIMS item here keeps it current from ONE place.
        # First write also creates the item (memberGroupIds filled by membership
        # events). The edge authorizer reads this item instead of the stale JWT.
        self._sync_claims_identity(user["id"], user.get("role", ROLE_MEMBER),
                                   user.get("ledGroupId"))
        return user

    # ---------- Claims projection (fresh-claims-at-the-edge) ----------
    @staticmethod
    def _claims_key(user_id: str) -> dict:
        return {"pk": f"MEMBER#{user_id}", "sk": "CLAIMS"}

    def _sync_claims_identity(self, user_id: str, role: str,
                              led_group_id: str | None) -> None:
        """Mirror role + ledGroupId onto the CLAIMS item (called from put_user).
        `role` and `version` are DynamoDB reserved words, so aliased. ledGroupId
        is REMOVEd when the user is not a leader, so a demoted UGL's stale led
        group cannot linger in the claim the edge trusts."""
        sets = ["#r = :r"]
        values = {":r": role, ":one": 1}
        expr_remove = ""
        if led_group_id:
            sets.append("ledGroupId = :l")
            values[":l"] = led_group_id
        else:
            expr_remove = " REMOVE ledGroupId"
        expr = "SET " + ", ".join(sets) + " ADD #v :one" + expr_remove
        self._t.update_item(
            Key=self._claims_key(user_id),
            UpdateExpression=expr,
            ExpressionAttributeNames={"#r": "role", "#v": "version"},
            ExpressionAttributeValues=values,
        )

    def get_member_claims(self, user_id: str) -> dict | None:
        """Read the materialized claims for the edge authorizer. Returns None
        when absent (caller fails closed). memberGroupIds is a String Set in
        storage; returned as a sorted list ([] when absent)."""
        item = self._t.get_item(Key=self._claims_key(user_id)).get("Item")
        if not item:
            return None
        groups = item.get("memberGroupIds")
        return {
            "role": item.get("role", ROLE_MEMBER),
            "ledGroupId": item.get("ledGroupId") or None,
            "memberGroupIds": sorted(groups) if groups else [],
            "version": int(item.get("version", 0)),
        }

    def rebuild_member_claims(self, user: dict) -> dict:
        """Recompute and overwrite a user's CLAIMS item from source of truth
        (user record + folded membership events). Used by the one-time backfill
        and as the drift-repair path. Idempotent. Only members carry
        memberGroupIds (mirrors token_claims_handler)."""
        user_id = user["id"]
        role = user.get("role", ROLE_MEMBER)
        item = {**self._claims_key(user_id), "role": role, "version": 1}
        led = user.get("ledGroupId") or None
        if led:
            item["ledGroupId"] = led
        if role == ROLE_MEMBER:
            groups = self.current_groups_for_member(user_id)
            if groups:
                item["memberGroupIds"] = set(groups)
        self._t.put_item(Item=item)
        return item

    def get_user(self, user_id: str) -> dict | None:
        resp = self._t.get_item(Key={"pk": f"USER#{user_id}", "sk": "PROFILE"})
        return resp.get("Item")

    def get_user_by_email(self, email: str) -> dict | None:
        resp = self._t.query(
            IndexName="GSI1",
            KeyConditionExpression=Key("gsi1pk").eq(f"EMAIL#{email.lower()}") & Key("gsi1sk").eq("USER"),
            Limit=1,
        )
        items = resp.get("Items", [])
        return items[0] if items else None

    def list_users(self) -> list[dict]:
        # GSI2 partitions users by role; gather every role (bounded set).
        from models import ROLES
        all_items: list[dict] = []
        for role in ROLES:
            kwargs: dict = {}
            while True:
                resp = self._t.query(
                    IndexName="GSI2",
                    KeyConditionExpression=Key("gsi2pk").eq(f"ROLE#{role}"),
                    **kwargs,
                )
                all_items.extend(resp.get("Items", []))
                if "LastEvaluatedKey" in resp:
                    kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                else:
                    break
        return all_items

    def list_users_page(self, *, role: str | None = None, status: str | None = None,
                        keyword: str | None = None, id_filter: set[str] | None = None,
                        limit: int = 25, cursor: str | None = None) -> tuple[list[dict], str | None]:
        """One page of the admin user list (D-U1/D-U2). GSI2 Query per role
        partition, walked in ROLE_PAGE_ORDER when no role filter; post-filters
        (status/keyword/id_filter) applied inside a fetch-until-full loop so a
        page never comes back short while more matches exist. Returns
        (rows, next_cursor); next_cursor is None on the last page."""
        kw = keyword.lower() if keyword else None

        def _matches(i: dict) -> bool:
            if status and i.get("status") != status:
                return False
            if id_filter is not None and i.get("id") not in id_filter:
                return False
            if kw:
                haystack = " ".join([
                    i.get("firstName") or "", i.get("lastName") or "",
                    i.get("email") or "", i.get("professionalRole") or "",
                ]).lower()
                if kw not in haystack:
                    return False
            return True

        roles = [role] if role else ROLE_PAGE_ORDER
        start_key: dict | None = None
        if cursor:
            decoded = decode_user_cursor(cursor)
            if role and decoded["role"] != role:
                raise ValidationError("Cursor does not match the requested role filter.")
            if not role:
                roles = ROLE_PAGE_ORDER[ROLE_PAGE_ORDER.index(decoded["role"]):]
            # Resume AFTER the last returned row (all key attrs derivable, D-U1).
            start_key = {"gsi2pk": f"ROLE#{decoded['role']}", "gsi2sk": f"USER#{decoded['id']}",
                         "pk": f"USER#{decoded['id']}", "sk": "PROFILE"}

        matched: list[dict] = []
        for r in roles:
            kwargs: dict = {}
            if start_key is not None:
                kwargs["ExclusiveStartKey"] = start_key
                start_key = None  # applies only to the cursor's own partition
            while True:
                resp = self._t.query(
                    IndexName="GSI2",
                    KeyConditionExpression=Key("gsi2pk").eq(f"ROLE#{r}"),
                    **kwargs,
                )
                matched.extend(i for i in resp.get("Items", []) if _matches(i))
                if len(matched) > limit:
                    page = matched[:limit]
                    return page, encode_user_cursor(page[-1])
                if "LastEvaluatedKey" in resp:
                    kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
                else:
                    break  # partition exhausted — move to the next role (or finish)
        return matched, None

    # ---------- OpenSearch user search & reindex ----------

    def search_users(
        self,
        *,
        q: str | None = None,
        role: str | None = None,
        status: str | None = None,
        group_ids: set[str] | None = None,
        limit: int = 50,
        sort: str = "name",
        sort_dir: str = "asc",
        cursor: str | None = None,
    ) -> tuple[list[dict], str | None]:
        """Query the shared OpenSearch 'members' index for admin user search.

        Returns (items, next_cursor). next_cursor is an opaque base64 string
        encoding the OpenSearch search_after values of the last returned hit —
        stable across concurrent writes. Returns ([], None) if OpenSearch is
        not configured.
        """
        client = self._os_client()
        if client is None:
            return [], None

        # Sort specification.
        # All string fields use .keyword sub-fields for sorting — OpenSearch
        # auto-creates these for every string value; they are not analysed and
        # support sorting, unlike the parent text field.
        _dir = "asc" if sort_dir == "asc" else "desc"
        if sort == "email":
            sort_spec = [{"email.keyword": _dir}, {"id.keyword": "asc"}]
        elif sort == "role":
            sort_spec = [{"roleSortOrder": _dir}, {"id.keyword": "asc"}]
        elif sort == "status":
            sort_spec = [{"status.keyword": _dir}, {"id.keyword": "asc"}]
        else:  # default: name
            sort_spec = [{"lastName.keyword": _dir}, {"firstName.keyword": _dir}, {"id.keyword": "asc"}]

        body: dict = {
            "query": _user_query(q=q, role=role, status=status, group_ids=group_ids),
            "sort": sort_spec,
            "size": limit,
        }

        # Resume from cursor (search_after pagination — stable across concurrent writes).
        if cursor:
            try:
                body["search_after"] = json.loads(
                    base64.urlsafe_b64decode(cursor.encode())
                )
            except (ValueError, TypeError, json.JSONDecodeError):
                raise ValidationError("Invalid pagination cursor.") from None

        resp = client.search(index=OPENSEARCH_INDEX, body=body)
        hits = resp.get("hits", {}).get("hits", [])
        items = [h["_source"] for h in hits]

        next_cursor: str | None = None
        if len(hits) == limit:
            last_sort = hits[-1].get("sort", [])
            next_cursor = base64.urlsafe_b64encode(
                json.dumps(last_sort).encode()
            ).decode()

        return items, next_cursor

    def count_users(self, *, q: str | None = None, role: str | None = None,
                    status: str | None = None,
                    group_ids: set[str] | None = None) -> int | None:
        """Exact count of users matching the same filters `search_users` would.

        Supplies the denominator for the CSV-export progress bar. Uses the
        OpenSearch `_count` API, which returns a total without materialising
        hits — so it stays cheap at 25k+ users, unlike counting via DynamoDB
        (which would mean walking the whole table a second time).

        Returns None when OpenSearch is not configured, so callers can fall back
        to an indeterminate progress display rather than reporting a fake total.
        """
        client = self._os_client()
        if client is None:
            return None
        resp = client.count(
            index=OPENSEARCH_INDEX,
            body={"query": _user_query(q=q, role=role, status=status, group_ids=group_ids)},
        )
        return int(resp.get("count", 0))

    def reindex_all_users(self) -> int:
        """Bulk partial-update every user's identity fields into the shared
        OpenSearch 'members' index.

        Uses update (not index) so member-profiles fields (bio, skills,
        groupIds) are never overwritten. doc_as_upsert creates the document
        if it doesn't exist.

        Used by the nightly reconciliation schedule and the on-demand
        POST /admin/reindex-users endpoint.

        Returns the count of documents updated.
        """
        client = self._os_client()
        if client is None:
            return 0

        all_users = self.list_users()
        if not all_users:
            return 0

        # Identity fields owned by identity-access in the merged index.
        _identity_fields = frozenset({
            "id", "firstName", "lastName", "email",
            "role", "status", "roleSortOrder",
            "city", "country", "professionalRole", "awsProject", "timeZone",
        })

        # Bulk update: alternating action + partial doc lines.
        bulk_lines: list[str] = []
        for user in all_users:
            user_id = user.get("id", "")
            full_doc = _user_to_search_doc(user)
            identity_doc = {k: v for k, v in full_doc.items() if k in _identity_fields}
            action = json.dumps({"update": {"_index": OPENSEARCH_INDEX, "_id": user_id}})
            doc_line = json.dumps({"doc": identity_doc, "doc_as_upsert": True})
            bulk_lines.append(action)
            bulk_lines.append(doc_line)

        bulk_body = "\n".join(bulk_lines) + "\n"
        client.bulk(body=bulk_body)
        return len(all_users)

    def _os_client(self):  # noqa: ANN201
        """Lazy OpenSearch client — returns None if endpoint not configured."""
        endpoint = os.environ.get("OPENSEARCH_ENDPOINT", "")
        if not endpoint:
            return None
        # Import lazily so the module loads cleanly in environments without the
        # opensearch-py package installed (e.g. unit tests that mock DynamoDB only).
        try:
            import boto3  # noqa: PLC0415
            from opensearchpy import OpenSearch, RequestsHttpConnection  # noqa: PLC0415
            from requests_aws4auth import AWS4Auth  # noqa: PLC0415
        except ImportError:
            return None

        # Credentials are re-fetched each call so a refreshed STS token is used
        # (Lambda execution role credentials rotate). The OpenSearch client is
        # NOT cached here — it is stateless and lightweight to construct.
        region = os.environ.get("AWS_REGION", "us-east-1")
        creds = boto3.Session().get_credentials().get_frozen_credentials()
        auth = AWS4Auth(
            creds.access_key,
            creds.secret_key,
            region,
            "aoss",
            session_token=creds.token,
        )
        host = endpoint.replace("https://", "").rstrip("/")
        return OpenSearch(
            hosts=[{"host": host, "port": 443}],
            http_auth=auth,
            use_ssl=True,
            verify_certs=True,
            connection_class=RequestsHttpConnection,
            timeout=60,   # OpenSearch Serverless cold-start can take 10-30s
        )

    # ---------- Groups ----------
    def put_group(self, group: dict) -> dict:
        item = dict(group)
        item["pk"] = f"GROUP#{group['id']}"
        item["sk"] = "META"
        # GSI4: place every group META row under a single partition so the group
        # catalogue is a Query, not a full-table Scan (perf fix — the identity
        # table also holds ~30k users + memberships, so a Scan reads all of them).
        # Set here (a full put_item) so ALL 7 write paths — create/edit/delete/
        # restore/assign_leader/_reassign_leader/_release_leadership — are covered
        # by this one choke point; a soft-deleted row keeps gsi4* and is filtered
        # by `status` on read, so it still appears when include_deleted=True.
        item["gsi4pk"] = "GROUP"
        item["gsi4sk"] = group["id"]
        self._t.put_item(Item=item)
        return group

    def get_group(self, group_id: str) -> dict | None:
        resp = self._t.get_item(Key={"pk": f"GROUP#{group_id}", "sk": "META"})
        return resp.get("Item")

    def list_groups(self, include_deleted: bool = False) -> list[dict]:
        groups, _ = self.list_groups_with_counts(include_deleted=include_deleted)
        return groups

    def list_groups_with_counts(self, include_deleted: bool = False) -> tuple[list[dict], dict[str, int]]:
        """Groups plus their member counts.

        Groups are a small curated catalogue but they live in a table dominated
        by ~30k users + memberships, so listing them via a Scan cost O(table).
        GSI4 places every group META row under one partition (gsi4pk="GROUP"),
        so this is a Query whose cost is O(#groups). Member counts live on the
        separate GROUP#<id>/MEMBERCOUNT items and are read per returned group
        (a handful of GetItems) — the (groups, counts) contract is unchanged."""
        groups: list[dict] = []
        kwargs: dict = {"IndexName": "GSI4",
                        "KeyConditionExpression": Key("gsi4pk").eq("GROUP")}
        while True:
            resp = self._t.query(**kwargs)
            groups.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break
        if not include_deleted:
            groups = [g for g in groups if g.get("status", GROUP_ACTIVE) == GROUP_ACTIVE]
        counts = {g["id"]: self.group_member_count(g["id"]) for g in groups}
        return groups, counts

    def list_groups_page(self, *, include_deleted: bool = False, limit: int = 25,
                         cursor: str | None = None) -> tuple[list[dict], str | None]:
        """One page of group META rows (2026-08-08, high-volume CL "All Groups"
        table). Queries GSI4 (gsi4pk="GROUP") ordered by gsi4sk (=group id)
        instead of scanning the whole table. Fetch-until-full with the status
        filter applied in-loop so a page never comes back short while more
        matches exist. Returns (groups, next_cursor); member counts + leaders are
        resolved per page by the service, bounding that work to page size."""
        groups: list[dict] = []
        kwargs: dict = {"IndexName": "GSI4",
                        "KeyConditionExpression": Key("gsi4pk").eq("GROUP")}
        if cursor:
            kwargs["ExclusiveStartKey"] = decode_group_cursor(cursor)
        while True:
            resp = self._t.query(**kwargs)
            for g in resp.get("Items", []):
                if include_deleted or g.get("status", GROUP_ACTIVE) == GROUP_ACTIVE:
                    groups.append(g)
                    if len(groups) > limit:
                        page = groups[:limit]
                        return page, encode_group_cursor(page[-1])
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break
        return groups, None

    def delete_group(self, group_id: str) -> None:
        self._t.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": "META"})

    # ---------- Join requests ----------
    def put_join_request(self, jr: dict) -> dict:
        item = dict(jr)
        item["pk"] = f"GROUP#{jr['groupId']}"
        item["sk"] = f"JOINREQ#{jr['requestedAt']}#{jr['id']}"
        self._t.put_item(Item=item)
        return jr

    def list_join_requests(self, group_id: str, status: str | None = None) -> list[dict]:
        """Every join request for a group, oldest first. Paginated: a single
        Query page caps at 1 MB and silently truncated the list on a group with
        a long request history (fixed 2026-08-05 alongside the member list)."""
        items: list[dict] = []
        kwargs: dict = {}
        while True:
            resp = self._t.query(
                KeyConditionExpression=Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("JOINREQ#"),
                **kwargs,
            )
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break
        if status:
            items = [j for j in items if j.get("status") == status]
        return sorted(items, key=lambda j: j.get("requestedAt", ""))

    def find_pending_request(self, group_id: str, member_id: str) -> dict | None:
        for jr in self.list_join_requests(group_id, status="Pending"):
            if jr.get("memberId") == member_id:
                return jr
        return None

    # ---------- Membership events (append-only, US-1.34) ----------
    def append_membership_event(self, event: dict) -> dict:
        """Append an event AND apply it to the current-membership projection.

        Both happen here on purpose: group_service, user_service, the seed job
        and the tests all mutate membership through this one method, so keeping
        the projection here means there is exactly one place it can be forgotten
        rather than four."""
        item = dict(event)
        item["pk"] = f"MEMBER#{event['memberId']}"
        item["sk"] = f"MEVENT#{event['at']}#{event['id']}"
        item["gsi3pk"] = f"GROUP#{event['groupId']}"
        item["gsi3sk"] = f"MEVENT#{event['at']}"
        self._t.put_item(Item=item)
        gid = event["groupId"]
        if event["type"] in MEVENT_START:
            self.put_group_member(gid, event["memberId"], joined_at=event.get("at"))
            # Claims projection: add the group to the member's live set. ADD on a
            # String Set is idempotent and race-free (no read-modify-write), and
            # creates the CLAIMS item if a membership event somehow precedes the
            # user's first put_user. #v = version (reserved word).
            self._t.update_item(
                Key=self._claims_key(event["memberId"]),
                UpdateExpression="ADD memberGroupIds :g, #v :one",
                ExpressionAttributeNames={"#v": "version"},
                ExpressionAttributeValues={":g": {gid}, ":one": 1},
            )
        elif event["type"] in MEVENT_END:
            self.delete_group_member(gid, event["memberId"])
            # DELETE from the Set; removing the last element deletes the
            # attribute entirely (matches the "absent == no groups" read contract).
            self._t.update_item(
                Key=self._claims_key(event["memberId"]),
                UpdateExpression="DELETE memberGroupIds :g ADD #v :one",
                ExpressionAttributeNames={"#v": "version"},
                ExpressionAttributeValues={":g": {gid}, ":one": 1},
            )
        return event

    # ---------- Current-membership projection (2026-08-05, 13k+ scale) ----------
    def put_group_member(self, group_id: str, member_id: str, *,
                         joined_at: str | None = None) -> bool:
        """Record `member_id` as a current member of `group_id`. Returns True if
        this was a new membership (so the counter moved). The conditional put is
        what makes the counter exact instead of best-effort: a repeated join
        event cannot double-count."""
        user = self.get_user(member_id) or {}
        item = {
            "pk": f"GROUP#{group_id}", "sk": f"MEMBER#{member_id}",
            "groupId": group_id, "memberId": member_id,
            "joinedAt": joined_at or "",
            "searchKey": member_search_key(user),
        }
        try:
            self._t.put_item(Item=item, ConditionExpression=Attr("pk").not_exists())
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            # Already a member — refresh the row (searchKey/joinedAt) without
            # touching the counter.
            self._t.put_item(Item={**item, "joinedAt": joined_at
                                   or (self.get_group_member(group_id, member_id) or {}).get("joinedAt", "")})
            return False
        self._bump_member_count(group_id, 1)
        return True

    def delete_group_member(self, group_id: str, member_id: str) -> bool:
        """Drop a current membership. Returns True if a row was actually removed,
        so an end event for a non-member cannot drive the counter negative."""
        try:
            self._t.delete_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{member_id}"},
                                ConditionExpression=Attr("pk").exists())
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
                raise
            return False
        self._bump_member_count(group_id, -1)
        return True

    def get_group_member(self, group_id: str, member_id: str) -> dict | None:
        resp = self._t.get_item(Key={"pk": f"GROUP#{group_id}", "sk": f"MEMBER#{member_id}"})
        return resp.get("Item")

    def refresh_member_search_keys(self, member_id: str, group_ids) -> None:
        """Re-denormalise the search haystack after a profile edit (M5)."""
        user = self.get_user(member_id) or {}
        key = member_search_key(user)
        for gid in group_ids:
            self._t.update_item(
                Key={"pk": f"GROUP#{gid}", "sk": f"MEMBER#{member_id}"},
                UpdateExpression="SET searchKey = :k",
                ConditionExpression=Attr("pk").exists(),
                ExpressionAttributeValues={":k": key},
            )

    def _bump_member_count(self, group_id: str, delta: int) -> None:
        """Counter lives on its own item, NOT on the group META row: put_group()
        does a full put_item, so a counter stored there would be clobbered by any
        read-modify-write of the group (edit, assign leader, restore)."""
        self._t.update_item(
            Key={"pk": f"GROUP#{group_id}", "sk": "MEMBERCOUNT"},
            UpdateExpression="ADD memberCount :d",
            ExpressionAttributeValues={":d": delta},
        )

    # ---------------- community roster counts (US-7.1, nightly) ----------------

    def put_community_counts(self, counts: dict) -> None:
        """Store the nightly community roster snapshot as ONE item.

        Recomputed from scratch each night rather than incremented, so it cannot
        drift from the roster — including after an out-of-band write. The whole
        point of the snapshot is that the dashboard reads a single item instead of
        counting 13,000 users on every page load.
        """
        item = {"pk": "COMMUNITY", "sk": "COUNTS"}
        item.update(counts)
        self._t.put_item(Item=item)

    def get_community_counts(self) -> dict:
        resp = self._t.get_item(Key={"pk": "COMMUNITY", "sk": "COUNTS"})
        item = resp.get("Item") or {}
        return {k: v for k, v in item.items() if k not in ("pk", "sk")}

    # ---------------- per-group member stats (US-7.1, nightly) ----------------

    def put_group_member_stats(self, stats: dict) -> None:
        """Store the nightly per-group member breakdown as ONE item.

        A SEPARATE item from COUNTS rather than more attributes on it, for two
        reasons that both bite in production:

        * the two are written by two independent nightly jobs, so sharing an item
          would make them read-modify-write the same row — the later writer would
          silently drop the earlier one's fields;
        * a job failing must not take the other's data with it. The roster card
          and this chart degrade independently, which is what lets the dashboard
          show one as stale while the other is current.

        Same reason it is recomputed rather than incremented: it cannot drift from
        the membership event log, including after an out-of-band write.
        """
        item = {"pk": "COMMUNITY", "sk": "GROUPSTATS"}
        item.update(stats)
        self._t.put_item(Item=item)

    def get_group_member_stats(self) -> dict:
        resp = self._t.get_item(Key={"pk": "COMMUNITY", "sk": "GROUPSTATS"})
        item = resp.get("Item") or {}
        return {k: v for k, v in item.items() if k not in ("pk", "sk")}

    def group_member_count(self, group_id: str) -> int:
        resp = self._t.get_item(Key={"pk": f"GROUP#{group_id}", "sk": "MEMBERCOUNT"})
        return int((resp.get("Item") or {}).get("memberCount", 0))

    def set_group_member_count(self, group_id: str, count: int) -> None:
        """Absolute set — used by the backfill/repair path only."""
        self._t.put_item(Item={"pk": f"GROUP#{group_id}", "sk": "MEMBERCOUNT",
                               "memberCount": count})

    def count_group_members(self, group_id: str, *, leader_ids=None,
                            keyword: str | None = None) -> int | None:
        """Denominator for the group-member export's progress bar.

        Returns None when a keyword filter is in play. The projection keeps a
        counter for the whole group but not for a filtered subset, and counting
        the subset would mean walking the very rows the export is about to walk —
        paying for the listing twice. An indeterminate bar is the honest answer;
        `_public` already renders `percent: None` that way.

        Leaders are included because the listing emits them as a first block:
        leadership is not membership, so a leader may have no projection row and
        would otherwise be missing from the denominator. Only leaders who are NOT
        current members are added — counting a leader who is also a member twice
        would leave the bar stalled short of 100%. Leaders are a handful per
        group, so the per-leader check is cheap.
        """
        if keyword:
            return None
        total = self.group_member_count(group_id)
        for leader_id in (leader_ids or ()):
            if group_id not in self.current_groups_for_member(leader_id):
                total += 1
        return total

    def group_members_page(self, group_id: str, *, limit: int,
                           after_member_id: str | None = None,
                           keyword: str | None = None) -> tuple[list[dict], bool]:
        """One page of the current-membership projection, ordered by member id.

        Returns (rows, has_more). `keyword` is pushed down as a DynamoDB
        `contains()` FilterExpression against the denormalised searchKey, so
        non-matching members are discarded server-side instead of costing one
        profile read each. Fetches limit+1 to decide `has_more` without a second
        request."""
        cond = Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("MEMBER#")
        rows: list[dict] = []
        kwargs: dict = {}
        if after_member_id:
            kwargs["ExclusiveStartKey"] = {"pk": f"GROUP#{group_id}",
                                           "sk": f"MEMBER#{after_member_id}"}
        if keyword:
            kwargs["FilterExpression"] = Attr("searchKey").contains(keyword)
        while len(rows) <= limit:
            resp = self._t.query(KeyConditionExpression=cond, **kwargs)
            rows.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break
        return rows[:limit], len(rows) > limit

    def member_events(self, member_id: str) -> list[dict]:
        resp = self._t.query(
            KeyConditionExpression=Key("pk").eq(f"MEMBER#{member_id}") & Key("sk").begins_with("MEVENT#"),
        )
        return resp.get("Items", [])

    def group_events(self, group_id: str) -> list[dict]:
        """Every membership event for a group (GSI3 partition). Paginated: a
        13k-member group's event history exceeds DynamoDB's 1 MB page, and a
        single-page read silently truncated the derived member set (fixed
        2026-08-05 alongside the paged member list)."""
        items: list[dict] = []
        kwargs: dict = {}
        while True:
            resp = self._t.query(
                IndexName="GSI3",
                KeyConditionExpression=Key("gsi3pk").eq(f"GROUP#{group_id}") & Key("gsi3sk").begins_with("MEVENT#"),
                **kwargs,
            )
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                return items

    def group_events_upto(self, group_id: str, *, before: str) -> list[dict]:
        """A group's membership events up to `before` (an ISO bound), as minimal
        `{memberId, type}` rows.

        Aggregation-only read for the per-group member breakdown (US-7.1). Two
        things keep it cheap enough for a dashboard load:

        * the bound is a SORT-KEY condition, so events after the window are never
          read — asking for an old quarter costs less, not more;
        * `ProjectionExpression` fetches only what the fold needs, so a large
          group transfers a fraction of its history.

        Paginated for the same reason `group_events` is: a big group's history
        exceeds DynamoDB's 1 MB page, and a single-page read would silently
        undercount.
        """
        items: list[dict] = []
        kwargs: dict = {}
        while True:
            resp = self._t.query(
                IndexName="GSI3",
                KeyConditionExpression=(Key("gsi3pk").eq(f"GROUP#{group_id}")
                                        & Key("gsi3sk").between("MEVENT#", f"MEVENT#{before}")),
                ProjectionExpression="memberId, #t",
                ExpressionAttributeNames={"#t": "type"},
                **kwargs,
            )
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                return items

    def group_events_page(self, group_id: str, *, limit: int,
                          cursor: str | None = None) -> tuple[list[dict], str | None]:
        """One page of a group's membership history, NEWEST FIRST (GSI3 read
        backwards). The unpaged path folds every event and resolves a display
        name per row, which is the same 13k problem as the member list."""
        kwargs: dict = {}
        if cursor:
            key = decode_history_cursor(cursor)
            kwargs["ExclusiveStartKey"] = {
                "gsi3pk": f"GROUP#{group_id}", "gsi3sk": f"MEVENT#{key['at']}",
                "pk": f"MEMBER#{key['m']}", "sk": f"MEVENT#{key['at']}#{key['id']}",
            }
        resp = self._t.query(
            IndexName="GSI3",
            KeyConditionExpression=Key("gsi3pk").eq(f"GROUP#{group_id}") & Key("gsi3sk").begins_with("MEVENT#"),
            ScanIndexForward=False,
            Limit=limit,
            **kwargs,
        )
        items = resp.get("Items", [])
        next_cursor = None
        if "LastEvaluatedKey" in resp and items:
            last = items[-1]
            next_cursor = encode_history_cursor(last.get("at", ""), last.get("memberId", ""),
                                                last.get("id", ""))
        return items, next_cursor

    def all_membership_events(self) -> list[dict]:
        items, kwargs = [], {}
        while True:
            resp = self._t.scan(FilterExpression=Key("sk").begins_with("MEVENT#"), **kwargs)
            items.extend(resp.get("Items", []))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                break
        return items

    # ---------- Derived / projected membership (BR-M1) ----------
    def current_groups_for_member(self, member_id: str) -> set[str]:
        """Active group ids: latest start event per group with no later end event."""
        events = sorted(self.member_events(member_id), key=lambda e: e.get("at", ""))
        state: dict[str, bool] = {}
        for e in events:
            gid = e["groupId"]
            if e["type"] in MEVENT_START:
                state[gid] = True
            elif e["type"] in MEVENT_END:
                state[gid] = False
        return {gid for gid, active in state.items() if active}

    def current_members_of_group(self, group_id: str) -> set[str]:
        """Read the projection (one partition Query), not the event history.
        Folding the history here cost 13,000+ item reads per call on a large
        group and `list_groups` did it once per group."""
        members: set[str] = set()
        kwargs: dict = {}
        while True:
            resp = self._t.query(
                KeyConditionExpression=Key("pk").eq(f"GROUP#{group_id}") & Key("sk").begins_with("MEMBER#"),
                ProjectionExpression="memberId",
                **kwargs,
            )
            members.update(i["memberId"] for i in resp.get("Items", []) if i.get("memberId"))
            if "LastEvaluatedKey" in resp:
                kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
            else:
                return members

    def derive_members_from_events(self, group_id: str) -> dict[str, str]:
        """Rebuild current membership from the append-only log — the source of
        truth. Used by the backfill/repair tool, not by request handling.
        Returns {memberId: joinedAt}."""
        events = sorted(self.group_events(group_id), key=lambda e: e.get("at", ""))
        state: dict[str, str | None] = {}
        for e in events:
            mid = e["memberId"]
            if e["type"] in MEVENT_START:
                state[mid] = e.get("at", "")
            elif e["type"] in MEVENT_END:
                state[mid] = None
        return {mid: at for mid, at in state.items() if at is not None}

    # ---------- OTP challenges (TTL) ----------
    def put_otp(self, challenge: dict) -> dict:
        item = dict(challenge)
        item["pk"] = f"OTP#{challenge['challengeId']}"
        item["sk"] = "CHALLENGE"
        self._t.put_item(Item=item)
        return challenge

    def get_otp(self, challenge_id: str) -> dict | None:
        resp = self._t.get_item(Key={"pk": f"OTP#{challenge_id}", "sk": "CHALLENGE"})
        item = resp.get("Item")
        if item and int(item.get("expiresAt", 0)) < epoch():
            return None
        return item

    def update_otp_attempts(self, challenge_id: str, attempts: int) -> None:
        self._t.update_item(
            Key={"pk": f"OTP#{challenge_id}", "sk": "CHALLENGE"},
            UpdateExpression="SET attempts = :a",
            ExpressionAttributeValues={":a": attempts},
        )

    def increment_otp_attempts(self, challenge_id: str, max_attempts: int) -> bool:
        """Atomically increment the attempt counter. Returns True if the increment
        succeeded (below limit); False if the limit was reached OR the challenge
        doesn't exist (race-safe). Closes the TOCTOU brute-force window — two
        concurrent requests cannot both pass the same count (2026-08-13 security fix)."""
        from botocore.exceptions import ClientError
        try:
            self._t.update_item(
                Key={"pk": f"OTP#{challenge_id}", "sk": "CHALLENGE"},
                UpdateExpression="ADD attempts :one",
                ConditionExpression="attribute_exists(pk) AND attempts < :max_val",
                ExpressionAttributeValues={":one": 1, ":max_val": max_attempts},
            )
            return True
        except ClientError as err:
            if err.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def delete_otp(self, challenge_id: str) -> None:
        self._t.delete_item(Key={"pk": f"OTP#{challenge_id}", "sk": "CHALLENGE"})

    # ---------- CSV export jobs (TTL) ----------
    # Short-lived job records for the async Admin > Users CSV export. Same
    # dual-expiry belt-and-braces as OTP challenges above: `ttl` lets DynamoDB
    # reclaim the row, and `expiresAt` is re-checked in application code because
    # TTL deletion is asynchronous and can lag by hours.

    def put_export_job(self, job: dict) -> dict:
        item = dict(job)
        item["pk"] = f"EXPORT#{job['jobId']}"
        item["sk"] = "JOB"
        self._t.put_item(Item=item)
        return job

    def get_export_job(self, job_id: str) -> dict | None:
        resp = self._t.get_item(Key={"pk": f"EXPORT#{job_id}", "sk": "JOB"})
        item = resp.get("Item")
        if item and int(item.get("expiresAt", 0)) < epoch():
            return None
        return item

    def acquire_export_lock(self, actor: str, job_id: str, *, ttl_seconds: int) -> bool:
        """Atomically claim the one in-flight export slot for `actor`.

        Returns False if that admin already has an export running. A conditional
        write rather than a read-then-write so two rapid clicks cannot both pass,
        and rather than a GSI scan of active jobs (settings' approach) because a
        single-item condition is both cheaper and race-free.

        Self-healing: the condition also succeeds once the existing lock is past
        `expiresAt`, so a worker that dies without releasing blocks retries for
        at most `ttl_seconds` instead of forever. `ttl` lets DynamoDB reclaim the
        row eventually; correctness relies on `expiresAt`, not on TTL timing.
        """
        now = epoch()
        try:
            self._t.put_item(
                Item={"pk": f"EXPORTLOCK#{actor}", "sk": "LOCK", "jobId": job_id,
                      "expiresAt": now + ttl_seconds, "ttl": now + ttl_seconds},
                ConditionExpression="attribute_not_exists(pk) OR expiresAt < :now",
                ExpressionAttributeValues={":now": now},
            )
            return True
        except ClientError as err:
            if err.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return False
            raise

    def release_export_lock(self, actor: str) -> None:
        self._t.delete_item(Key={"pk": f"EXPORTLOCK#{actor}", "sk": "LOCK"})

    def update_export_job(self, job_id: str, fields: dict) -> None:
        """Targeted attribute update.

        Deliberately an UpdateExpression rather than the read-merge-put that
        settings' `update_job_run` uses: the worker writes `progress` repeatedly
        while the API may be reading the same row, and a full-item put would
        race and could resurrect stale attributes.
        """
        if not fields:
            return
        names = {f"#f{i}": k for i, k in enumerate(fields)}
        values = {f":v{i}": v for i, v in enumerate(fields.values())}
        sets = ", ".join(f"{n} = {v}" for n, v in zip(names, values, strict=True))
        self._t.update_item(
            Key={"pk": f"EXPORT#{job_id}", "sk": "JOB"},
            UpdateExpression=f"SET {sets}",
            ExpressionAttributeNames=names,
            ExpressionAttributeValues=values,
        )
