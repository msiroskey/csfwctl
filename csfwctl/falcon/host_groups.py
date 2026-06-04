"""Host-group sub-client (read-only surface for Phase 2).

csfwctl reads host groups to verify policy assignments. Creating host
groups is supported via ``apply --create-groups``; that codepath lands
in Phase 5 alongside the applier.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from csfwctl.falcon.client import FalconAPIError

if TYPE_CHECKING:
    from csfwctl.falcon.client import FalconClient


class HostGroupsAPI:
    """Host-group read wrapper plus the minimum write surface for apply."""

    _MAX_PAGE_SIZE = 500
    """CrowdStrike caps ``limit`` on ``query_host_groups`` at 500.

    Passing a higher value returns ``HTTP 400 "N is an invalid page size,
    must be between 1 and 500"``. The rule-groups endpoint allows 5 000,
    so this is a host-group-specific cap.
    """

    def __init__(self, client: FalconClient) -> None:
        self._client = client

    def _svc(self) -> Any:
        return self._client._host_group_service()  # noqa: SLF001

    def query(self, *, filter: str | None = None, limit: int | None = None) -> list[str]:
        """Return host-group IDs matching ``filter`` (FQL).

        When ``limit`` is omitted, paginates through every result page
        and concatenates the ids. The host-groups endpoint caps a
        single page at 500 (it returns HTTP 400 for anything larger);
        without pagination a tenant with more than 500 groups would be
        silently truncated, and the unfiltered fallback in
        :meth:`find_by_name` would miss the very record it is trying to
        locate.

        When ``limit`` is supplied, a single page is fetched.  The
        caller is responsible for keeping it within ``1..500``.
        """
        if limit is not None:
            return self._query_page(filter=filter, limit=limit, offset=0)

        all_ids: list[str] = []
        offset = 0
        while True:
            page_ids, total = self._query_page_with_total(
                filter=filter, limit=self._MAX_PAGE_SIZE, offset=offset
            )
            if not page_ids:
                break
            all_ids.extend(page_ids)
            if total > 0 and len(all_ids) >= total:
                break
            # A short page (fewer results than the requested limit) is
            # the last page. This is the termination condition when the
            # API does not return a ``meta.pagination.total`` count.
            if len(page_ids) < self._MAX_PAGE_SIZE:
                break
            offset += len(page_ids)
        return all_ids

    def _query_page(self, *, filter: str | None, limit: int, offset: int) -> list[str]:
        ids, _ = self._query_page_with_total(filter=filter, limit=limit, offset=offset)
        return ids

    def _query_page_with_total(
        self, *, filter: str | None, limit: int, offset: int
    ) -> tuple[list[str], int]:
        """Fetch one page of ids and the reported ``total`` count."""
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        if filter is not None:
            params["filter"] = filter
        result = self._client.call(
            "host_groups.query",
            lambda: self._svc().query_host_groups(parameters=params),
        )
        body = result.get("body") or {}
        ids = [str(r) for r in body.get("resources") or []]
        meta = body.get("meta") or {}
        pagination = meta.get("pagination") or {}
        try:
            total = int(pagination.get("total") or 0)
        except (TypeError, ValueError):
            total = 0
        return ids, total

    def get(self, ids: list[str]) -> list[dict[str, Any]]:
        """Return full host-group detail records."""
        if not ids:
            return []
        result = self._client.call(
            "host_groups.get",
            lambda: self._svc().get_host_groups(ids=ids),
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def list_all(self, *, filter: str | None = None) -> list[dict[str, Any]]:
        """Convenience: query + get."""
        ids = self.query(filter=filter)
        return self.get(ids) if ids else []

    def find_by_name(self, name: str) -> dict[str, Any] | None:
        """Find a host group by exact display name; return ``None`` if absent.

        Tries the FQL ``name:'X'`` filter first (cheap), then falls back
        to enumerating all host groups and matching client-side if the
        filter returns no results. The fallback exists because some
        CrowdStrike tenants have been observed returning an empty
        resource list for the name filter even when an exact-match group
        exists — the applier then issues ``create`` and the server
        rejects it with ``409 Duplicate group name``. Matching against
        the unfiltered list is slower but is the only way to make the
        lookup reliable.
        """
        ids = self.query(filter=f"name:'{name}'")
        if ids:
            results = self.get(ids)
            # The server can return more than one result when ``name``
            # is treated as a substring/prefix match; pick the exact
            # match if present, otherwise the first.
            for r in results:
                if str(r.get("name", "")) == name:
                    return r
            if results:
                return results[0]
        for record in self.list_all():
            if str(record.get("name", "")) == name:
                return record
        return None

    def create(self, name: str, *, description: str = "") -> dict[str, Any]:
        """Create an empty static host group. Used by ``apply --create-groups``.

        Idempotent: if CrowdStrike rejects the create with
        ``409 Duplicate group name``, the group already exists. Falls
        back to a thorough name lookup and returns the existing record
        so the applier can thread its id into the policy payload
        instead of aborting the apply.
        """
        try:
            result = self._client.call(
                "host_groups.create",
                lambda: self._svc().create_host_groups(
                    body={
                        "resources": [
                            {
                                "group_type": "static",
                                "name": name,
                                "description": description,
                            }
                        ]
                    }
                ),
            )
        except FalconAPIError as exc:
            if _is_duplicate_name_error(exc):
                existing = self.find_by_name(name)
                if existing is not None:
                    return existing
            raise
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return dict(resources[0]) if resources else {}

    def create_dynamic(self, name: str, *, fql: str, description: str = "") -> dict[str, Any]:
        """Create a dynamic host group with an FQL membership filter.

        The CrowdStrike API field is ``assignment_rule`` for the FQL filter.
        Pending real-tenant confirmation of the exact payload shape; see
        ``docs/architecture.md``.

        Idempotent on duplicate-name 409 — see :meth:`create`.
        """
        try:
            result = self._client.call(
                "host_groups.create_dynamic",
                lambda: self._svc().create_host_groups(
                    body={
                        "resources": [
                            {
                                "group_type": "dynamic",
                                "name": name,
                                "description": description,
                                "assignment_rule": fql,
                            }
                        ]
                    }
                ),
            )
        except FalconAPIError as exc:
            if _is_duplicate_name_error(exc):
                existing = self.find_by_name(name)
                if existing is not None:
                    return existing
            raise
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return dict(resources[0]) if resources else {}

    def update_fql(self, group_id: str, fql: str) -> dict[str, Any]:
        """Update an existing dynamic group's FQL assignment rule."""
        result = self._client.call(
            "host_groups.update_fql",
            lambda: self._svc().update_host_groups(
                body={
                    "resources": [
                        {
                            "id": group_id,
                            "assignment_rule": fql,
                        }
                    ]
                }
            ),
        )
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return dict(resources[0]) if resources else {}


def _is_duplicate_name_error(exc: FalconAPIError) -> bool:
    """Return ``True`` when a FalconAPIError represents a duplicate-name 409.

    The duplicate-name 409 body has the shape
    ``{"errors": [{"code": 409, "message": "Duplicate group name X."}]}``.
    Match on status + message substring to avoid mistaking other 409s
    (e.g. concurrency conflicts) for the same condition.
    """
    if exc.status != 409:
        return False
    body = exc.body
    if isinstance(body, dict):
        for err in body.get("errors") or []:
            if isinstance(err, dict) and "Duplicate group name" in str(err.get("message", "")):
                return True
    return False


__all__ = ["HostGroupsAPI"]
