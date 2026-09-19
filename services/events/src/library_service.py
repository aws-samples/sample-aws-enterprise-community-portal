"""Content Library — business logic for all three entry paths, search, and curation.

Entry paths (US-2.22–2.24):
  Path 1 — Event completion auto-promotes all Clean materials (BR-LIB-P1/P2/P3)
  Path 2 — ContributionApproved EventBridge consumer with addToLibrary=True (BR-LIB-P7)
  Path 3 — Curator direct add via POST /library (BR-LIB-P13)

Search is search-first (BR-LIB-S1) and community-wide (no group scoping).
All file resources go through the GuardDuty scan gate before becoming downloadable.
Tags are stored lowercase-normalized; TAGS#ALL singleton maintained on every write.
"""
from __future__ import annotations

import os

from _conventions.errors import ForbiddenError, NotFoundError, ValidationError
from _conventions.validation import require_enum, require_str
from models import (CONTENT_TYPES, SCAN_CLEAN, SCAN_PENDING, SCAN_QUARANTINED,
                    content_type_for, new_id, now_iso)

# Re-export content types so the Library uses the same enum as event materials (Q5 decision).
LIBRARY_CONTENT_TYPES = CONTENT_TYPES   # Slides, PDF, Doc, Recording, Link
LIBRARY_SOURCES = ("event-material", "member-contribution", "curator-direct")

LIBRARY_DOWNLOAD_URL_SECONDS = 3600   # 1 hour
LIBRARY_UPLOAD_URL_SECONDS = 900      # 15 min

_CURATOR_ROLES = ("CommunityLeader", "UserGroupLeader")


def _normalize_tags(raw: list) -> list[str]:
    seen, out = set(), []
    for t in (raw or []):
        normalized = str(t).strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out[:20]   # BR-LIB-V4 max 20 tags


class LibraryService:

    def __init__(self, repo, events_repo, storage, events_publisher=None):
        """
        repo          — LibraryRepository (library table)
        events_repo   — EventRepository   (events table, for list_materials)
        storage       — S3Storage
        events_publisher — EventPublisher (optional; for future events)
        """
        self._repo = repo
        self._events_repo = events_repo
        self._storage = storage
        self._events = events_publisher

    # ------------------------------------------------------------------ authz

    def _assert_curator(self, principal) -> None:
        """BR-LIB-A3: only CL/UGL may write to the Library."""
        if principal.role not in _CURATOR_ROLES:
            raise ForbiddenError(message="Only Community Leaders and User Group Leaders "
                                         "can manage the Content Library.")

    # -------------------------------------------------- Path 1: auto-promote

    def promote_event_materials(self, event: dict) -> int:
        """Promote all Clean materials for a just-completed event (BR-LIB-P2).

        Called by EventService.complete_internal after the event is written.
        Returns the number of resources created.
        """
        promoted = 0
        for mat in self._events_repo.list_materials(event["id"]):
            if self._qualifies_for_library(mat):
                self._create_from_material(mat, event)
                promoted += 1
        # External-upload files that already scanned Clean before completion
        # (the reverse ordering the scan-time trigger can't catch).
        for link in self._events_repo.list_upload_links(event["id"]):
            if (link.get("uploaded") and not link.get("revoked")
                    and link.get("scanState") == SCAN_CLEAN):
                self.promote_external_upload(link, event)
                promoted += 1
        return promoted

    def promote_single_material(self, material: dict, event: dict) -> None:
        """Promote one material that just passed scanning on an already-completed
        event (BR-LIB-P1 Trigger B). Idempotent — no-op if already promoted."""
        if not self._qualifies_for_library(material):
            return
        if self._repo.get_by_material_id(material["id"]):
            return   # already in Library
        self._create_from_material(material, event)

    def promote_external_upload(self, link: dict, event: dict) -> None:
        """Promote an external-upload (upload-link) file to the Content Library.

        External uploads are NOT Material rows, so they are modeled here as a
        material-like resource keyed by the upload-link id (for GSI2
        idempotency). The caller gates this on a Clean scan verdict + Completed
        event, mirroring the material scan gate. Idempotent."""
        if not link.get("uploaded") or link.get("revoked"):
            return
        s3_key = link.get("s3Key") or ""
        name = link.get("fileName") or (s3_key.rsplit("/", 1)[-1] if s3_key else "")
        if not name:
            return
        material_like = {
            "id":          link["id"],   # UL id → GSI2 materialId for idempotency
            "name":        name,
            "contentType": content_type_for(name),
            "s3Key":       s3_key,
            "kind":        "file",
            "uploaded":    True,
            "scanState":   SCAN_CLEAN,
        }
        self.promote_single_material(material_like, event)

    def remove_by_material_id(self, material_id: str) -> None:
        """Auto-remove Library resource when its source material is deleted (BR-LIB-P5)."""
        self._repo.delete_by_material_id(material_id)

    @staticmethod
    def _qualifies_for_library(material: dict) -> bool:
        """A material qualifies when it is Clean and either a link or uploaded."""
        scan = material.get("scanState", SCAN_CLEAN)
        if scan != SCAN_CLEAN:
            return False
        kind = material.get("kind", "file")
        if kind == "link":
            return True
        return bool(material.get("uploaded"))

    def _create_from_material(self, material: dict, event: dict) -> None:
        resource_id = new_id("lib")
        resource = {
            "id":              resource_id,
            "title":           material.get("name", ""),
            "description":     event.get("description", ""),
            "format":          material.get("contentType", "Doc"),
            "topics":          [],
            "source":          "event-material",
            "scope":           "COMMUNITY",
            "url":             material.get("link") or material.get("url"),
            "s3Key":           material.get("s3Key"),
            "scanState":       SCAN_CLEAN,
            "submittedBy":     event.get("createdBy", ""),
            "submittedByName": event.get("createdByName", event.get("createdBy", "")),
            "addedBy":         "system",
            "addedAt":         now_iso(),
            "eventId":         event.get("id"),
            "eventTitle":      event.get("title"),
            "materialId":      material.get("id"),
            "contributionId":  None,
        }
        self._repo.put_resource(resource)
        # No tags on Path 1 — topics[] is empty

    # ------------------------------------ Path 1: scan-gate update for files

    def update_scan_state(self, resource_id: str, scan_state: str) -> None:
        """Called by MalwareScanConsumer for library/ prefix objects (BR-LIB-P4)."""
        self._repo.update_scan_state(resource_id, scan_state)

    # --------------------------------------- Path 2: contribution opt-in

    def add_from_contribution(self, payload: dict) -> None:
        """Create a Library resource from a ContributionApproved event (BR-LIB-P7).

        payload keys (from EventBridge detail):
          contributionId, memberId, memberName, approverId, approverName,
          addToLibrary, libraryTitle, libraryDescription, libraryFormat,
          libraryTopics, libraryUrl, libraryS3Key
        """
        if not payload.get("addToLibrary"):
            return

        contribution_id = payload.get("contributionId") or payload.get("submissionId")
        if not contribution_id:
            return

        # BR-LIB-P12 idempotency: redelivered event must not create a duplicate.
        if self._repo.get_by_contribution_id(contribution_id):
            return

        title = require_str(payload.get("libraryTitle") or "", "libraryTitle", max_len=200)
        description = require_str(payload.get("libraryDescription") or "",
                                   "libraryDescription", max_len=5000, min_len=1)
        fmt = require_enum(payload.get("libraryFormat") or "",
                           "libraryFormat", set(LIBRARY_CONTENT_TYPES))
        topics = _normalize_tags(payload.get("libraryTopics") or [])
        url = payload.get("libraryUrl")
        s3_key = payload.get("libraryS3Key")

        if fmt == "Link":
            if not url or not str(url).startswith("https://"):
                raise ValidationError("A Link resource requires an https:// URL.")

        resource = {
            "id":              new_id("lib"),
            "title":           title,
            "description":     description,
            "format":          fmt,
            "topics":          topics,
            "source":          "member-contribution",
            "scope":           "COMMUNITY",
            "url":             url,
            "s3Key":           s3_key,
            "scanState":       SCAN_CLEAN if fmt == "Link" else SCAN_PENDING,
            "submittedBy":     payload.get("memberId", ""),
            "submittedByName": payload.get("memberName", ""),
            "addedBy":         payload.get("approverId", ""),
            "addedAt":         now_iso(),
            "eventId":         None,
            "eventTitle":      None,
            "materialId":      None,
            "contributionId":  contribution_id,
        }
        self._repo.put_resource(resource)
        self._repo.add_tags(topics)

    # ------------------------------------------ Path 3: curator direct add

    def add(self, body: dict, *, principal) -> dict:
        """Curator direct add (US-2.23 / BR-LIB-P13)."""
        self._assert_curator(principal)
        self._validate_resource_fields(body)

        fmt = body["format"]
        topics = _normalize_tags(body.get("topics") or [])
        resource_id = new_id("lib")

        s3_key = None
        presigned_upload_url = None
        if fmt != "Link":
            file_name = body.get("fileName") or body.get("title", "file")
            s3_key = f"library/{resource_id}/{file_name}"
            presigned_upload_url = self._storage.presign_put(
                s3_key, expires_in=LIBRARY_UPLOAD_URL_SECONDS,
                content_length=body.get("sizeBytes"))

        resource = {
            "id":              resource_id,
            "title":           body["title"],
            "description":     body["description"],
            "format":          fmt,
            "topics":          topics,
            "source":          "curator-direct",
            "scope":           "COMMUNITY",
            "url":             body.get("url"),
            "s3Key":           s3_key,
            "scanState":       SCAN_CLEAN if fmt == "Link" else SCAN_PENDING,
            "submittedBy":     principal.user_id,
            "submittedByName": getattr(principal, "name", principal.user_id),
            "addedBy":         principal.user_id,
            "addedAt":         now_iso(),
            "eventId":         None,
            "eventTitle":      None,
            "materialId":      None,
            "contributionId":  None,
        }
        self._repo.put_resource(resource)
        self._repo.add_tags(topics)

        out = self.resource_public(resource)
        if presigned_upload_url:
            out["presignedUploadUrl"] = presigned_upload_url
        return out

    # ----------------------------------------------------------------- search

    def search(self, *, principal, filters: dict, limit: int,
               cursor: str | None) -> dict:
        """Search-first community-wide search (US-2.20 / BR-LIB-S1..S10)."""
        if principal.role == "Administrator":
            raise ForbiddenError(message="Administrators do not have access to the Content Library.")

        q = (filters.get("q") or "").strip()
        fmt = filters.get("format")
        topic = (filters.get("topic") or "").strip().lower()
        source = filters.get("source")

        # BR-LIB-S1 search-first: at least one of q/format/topic/source required.
        if not q and not fmt and not topic and not source:
            return {"items": [], "count": 0}

        if fmt:
            require_enum(fmt, "format", set(LIBRARY_CONTENT_TYPES))
        if source:
            require_enum(source, "source", set(LIBRARY_SOURCES))
        if not 1 <= limit <= 50:
            raise ValidationError("limit must be between 1 and 50.")

        rows, next_cursor = self._search_rows(
            q=q or None, fmt=fmt, source=source, topic=topic or None,
            limit=limit, cursor=cursor)

        out = []
        for mat in rows:
            url = None
            if (mat.get("format") != "Link"
                    and mat.get("s3Key")
                    and mat.get("scanState") == SCAN_CLEAN):
                url = self._storage.presign_get(
                    mat["s3Key"], expires_in=LIBRARY_DOWNLOAD_URL_SECONDS)
            out.append(self.resource_public(mat, download_url=url))

        result: dict = {"items": out, "count": len(out)}
        if next_cursor:
            result["cursor"] = next_cursor
        return result

    def _search_rows(self, *, q, fmt, source, topic, limit,
                     cursor) -> tuple[list[dict], str | None]:
        """Pick the search backend.

        When OPENSEARCH_ENDPOINT is set (the deployed state — the shared
        portal-search collection is always on for members too) the query goes to
        OpenSearch, which does the filtering/sort/pagination server-side and
        avoids the O(N) GSI1 partition walk that made this path ~6 s at 5k+
        resources.

        When the endpoint is unset (local runs, or a stage where OpenSearch is
        not wired) it fails soft to the original DynamoDB GSI1 walk + Python
        predicate, so search still works — just at the old cost. The gate is the
        endpoint variable, NOT the semantic-search feature flag: OpenSearch
        backs the directory unconditionally, and the Content Library rides the
        same collection.
        """
        if os.environ.get("OPENSEARCH_ENDPOINT"):
            return self._repo.search_opensearch(
                q=q, fmt=fmt, source=source, topic=topic,
                limit=limit, cursor=cursor)

        needle = q.lower() if q else None

        def predicate(row: dict) -> bool:
            if fmt and row.get("format") != fmt:
                return False
            if source and row.get("source") != source:
                return False
            if topic and topic not in (row.get("topics") or []):
                return False
            if needle:
                haystack = (
                    (row.get("title") or "") + " " + (row.get("description") or "")
                ).lower()
                if needle not in haystack:
                    return False
            return True

        return self._repo.query_page(limit=limit, cursor=cursor, predicate=predicate)

    # --------------------------------------------------------------- tags

    def get_tags(self, *, principal, prefix: str = "") -> dict:
        """Return distinct tags matching prefix (US-2.26 / BR-LIB-T1..T3)."""
        if principal.role == "Administrator":
            raise ForbiddenError(message="Administrators do not have access to the Content Library.")

        all_tags = self._repo.get_all_tags()
        prefix = prefix.strip().lower()
        if prefix:
            matches = sorted(t for t in all_tags if t.startswith(prefix))
        else:
            matches = sorted(all_tags)[:100]
        return {"tags": matches}

    # --------------------------------------------------------------- curation

    def edit(self, resource_id: str, body: dict, *, principal) -> dict:
        """Edit editable fields of a Library resource (US-2.25 / BR-LIB-C1)."""
        self._assert_curator(principal)
        existing = self._repo.get_resource(resource_id)
        if existing is None:
            raise NotFoundError(message="Library resource not found.")

        # Build updated item, keeping immutable fields intact.
        updated = {k: v for k, v in existing.items()
                   if k not in ("pk", "sk", "gsi1pk", "gsi1sk",
                                "gsi2pk", "gsi2sk", "gsi3pk", "gsi3sk")}

        if "title" in body:
            updated["title"] = require_str(body["title"], "title", max_len=200)
        if "description" in body:
            updated["description"] = require_str(body["description"], "description",
                                                  max_len=5000, min_len=1)
        if "format" in body:
            updated["format"] = require_enum(
                body["format"], "format", set(LIBRARY_CONTENT_TYPES))
        if "topics" in body:
            updated["topics"] = _normalize_tags(body["topics"])
        if "url" in body:
            url = body["url"]
            if url and not str(url).startswith("https://"):
                raise ValidationError("URL must start with https://.")
            updated["url"] = url

        updated["updatedAt"] = now_iso()
        self._repo.put_resource(updated)
        self._repo.add_tags(updated.get("topics") or [])
        return self.resource_public(updated)

    def remove(self, resource_id: str, *, principal) -> None:
        """Delete a Library resource (US-2.25 / BR-LIB-C3).
        S3 object is NOT deleted — it may still be referenced elsewhere.
        """
        self._assert_curator(principal)
        existing = self._repo.get_resource(resource_id)
        if existing is None:
            raise NotFoundError(message="Library resource not found.")
        self._repo.delete_resource(resource_id)
        # TAGS#ALL not updated immediately (lazy — BR-LIB-T4)

    # ------------------------------------------------------------- validation

    def _validate_resource_fields(self, body: dict) -> None:
        """Shared validation for Path 3 add and edit."""
        require_str(body.get("title") or "", "title", max_len=200)
        require_str(body.get("description") or "", "description",
                    max_len=5000, min_len=1)
        require_enum(body.get("format") or "", "format", set(LIBRARY_CONTENT_TYPES))
        if body.get("format") == "Link":
            url = body.get("url") or ""
            if not url.startswith("https://"):
                raise ValidationError("A Link resource requires an https:// URL.")

    # ---------------------------------------------------------- serialization

    @staticmethod
    def resource_public(resource: dict, download_url: str | None = None) -> dict:
        """Serialize a LibraryResource item to the public API shape."""
        out: dict = {
            "id":              resource.get("id"),
            "title":           resource.get("title", ""),
            "description":     resource.get("description", ""),
            "format":          resource.get("format"),
            "topics":          list(resource.get("topics") or []),
            "source":          resource.get("source"),
            "submittedBy":     resource.get("submittedBy"),
            "submittedByName": resource.get("submittedByName"),
            "addedBy":         resource.get("addedBy"),
            "addedAt":         resource.get("addedAt"),
        }
        # Source-specific attribution fields
        if resource.get("source") == "event-material":
            out["eventId"]    = resource.get("eventId")
            out["eventTitle"] = resource.get("eventTitle")

        # Download / open-link
        if download_url:
            out["downloadUrl"] = download_url
        elif resource.get("url"):
            out["url"] = resource["url"]

        # Scan state (links are always Clean, no need to surface it)
        if resource.get("format") != "Link":
            out["scanState"] = resource.get("scanState", SCAN_PENDING)

        return out
