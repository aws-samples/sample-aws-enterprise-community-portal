"""DirectoryService — browseDirectory (US-3.4/3.5) backed by OpenSearch.

Keyword search, role/group/cert filters, and all column sorts are handled by
OpenSearch, which is the ONLY read path. `browse()` always issues a single paged
query (limit defaults to 25); there is no DynamoDB-scan branch — omitting the
limit returns the first page, never a full-table scan. (An earlier "no limit =
unpaged CSV export scan" branch was removed: it was dead code, because the CSV
export walks all pages through its own `search_members` loop in export_worker,
not this method — see F1 perf fix.)

Cert filter still requires a fan-out to Certifications (to get the set of
holder IDs) but that result is pushed as a terms filter into the OpenSearch
query rather than post-filtered in-process.
"""
from __future__ import annotations

from _conventions.errors import ForbiddenError
from models import directory_row_public, listing
from shoutout_service import can_send_shoutout

ROLE_MEMBER = "Member"
ROLE_CL = "CommunityLeader"


def _row_serializer(principal):
    """directory_row_public bound to this caller, so each row carries whether the
    caller may shout that person out.

    The row previously carried no verdict and the SPA offered the button whenever
    the ROW's role was "Member" — which ignored self and ignored a UGL's group
    scope, so the button appeared and then failed. Pure in-memory per row: no
    extra I/O, which matters on a 13k-member directory.
    """
    return lambda item: directory_row_public(
        item, can_shoutout=can_send_shoutout(principal, item))


def member_scope(principal) -> list[str] | None:
    """Groups whose members this caller may see. None means UNSCOPED.

    Only the Member role is scoped (product decision 2026-08-27). Community
    Leaders are community-wide operators and User Group Leaders keep the
    directory-wide view they already had — narrowing a UGL to their led group
    would break the leader workflows that look members up before adding them to
    anything.

    An EMPTY LIST is not the same as None. [] means "this caller may see nobody",
    which is the deliberate answer for a Member who belongs to no groups: they
    get an empty directory, not the whole community. Returning None there would
    invert the rule and expose everything to exactly the least-privileged caller.
    """
    if getattr(principal, "role", None) != ROLE_MEMBER:
        return None
    return list(principal.member_group_ids or [])


class DirectoryService:
    def __init__(self, repo, fan_out, settings_cache):
        self._repo = repo
        self._fan_out = fan_out
        self._settings = settings_cache

    def browse(
        self,
        *,
        principal,
        q: str | None = None,
        role: str | None = None,
        group_id: str | None = None,
        cert_id: str | None = None,
        limit: int | None = None,
        cursor: str | None = None,
        sort: str = "firstName",
        sort_dir: str = "asc",
        bearer_token: str | None = None,
        claim_headers: dict | None = None,
    ) -> dict:
        """Directory listing, group-scoped for the Member role.

        `principal` REPLACED `principal_role` and is REQUIRED (2026-08-27). The
        listing used to take only the caller's role string, use it for exactly one
        thing (dropping the cert filter for Community Leaders) and return every
        member in the community to anybody authenticated — which was documented as
        intentional here and in the SPA. It no longer is: a Member sees only
        members of their own groups.

        The parameter is mandatory and has no default on purpose. An optional
        `principal=None` would make "forgot to pass it" indistinguishable from
        "no scoping needed", and the failure would be silent and in the
        permissive direction.
        """
        principal_role = getattr(principal, "role", None)
        # BR-6: Community-Leader-facing directory omits the certification filter.
        if principal_role == ROLE_CL:
            cert_id = None

        # Group scope for the caller. `scope is None` => unscoped (CL/UGL/Admin).
        scope = member_scope(principal)
        if scope is not None:
            if not scope:
                # No groups, so nobody is visible. Returned before any query runs:
                # OpenSearch would answer this correctly via an empty `terms`, but
                # there is no reason to pay for the round-trip, and the cert
                # fan-out below would be a wasted call too.
                return listing([], directory_row_public)
            if group_id and group_id not in scope:
                # An explicitly requested group the caller is not in. 403 rather
                # than a silent empty page: the group catalogue is already public
                # to every member (that is what makes joining possible), so
                # nothing is disclosed by saying no clearly, and a silent empty
                # result would read as "that group has no members".
                raise ForbiddenError(
                    message="You can only view members of a group you belong to.")

        # Certification holder filter: fan-out to Certifications once per request,
        # result intersected into the OpenSearch id_filter / in-process filter.
        holder_ids: set[str] | None = None
        if cert_id:
            result = self._fan_out.fan_out(
                {"certifications": f"/certifications/claims?certId={cert_id}&status=Approved"},
                bearer_token=bearer_token, claim_headers=claim_headers,
            )
            holder_ids = {
                c.get("memberId")
                for c in (result.get("certifications") or {}).get("items", [])
            }

        # Always served by OpenSearch — one paged query. There is no DynamoDB
        # scan path: the interactive listing is a single page (default 25), and
        # the CSV export walks ALL pages via its own `search_members` loop in
        # export_worker (not this method). `limit` defaults to 25 so a caller
        # that omits it gets the first page, never a full-table scan.
        items_raw, next_cursor = self._repo.search_members(
            q=q,
            role=role,
            group_id=group_id,
            # Scope pushed INTO the query, not applied to the page that comes
            # back. Post-filtering a page of 25 would return short pages (or an
            # empty one with a cursor) whenever the caller's groups were sparse in
            # the sort order, and the count would no longer match the cursor walk.
            group_ids=scope,
            id_filter=holder_ids,
            sort=sort,
            sort_dir=sort_dir,
            limit=limit or 25,
            cursor=cursor,
        )
        return listing(items_raw, _row_serializer(principal), cursor=next_cursor)

    def reindex_members(self) -> dict:
        """Full DynamoDB → OpenSearch reconciliation.

        Called by the nightly schedule (source=scheduled-reindex) and the
        on-demand POST /members/reindex endpoint.
        """
        indexed = self._repo.reindex_all_members()
        return {"indexed": indexed}
