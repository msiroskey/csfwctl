"""Host-group sub-client (read-only surface for Phase 2).

csfwctl reads host groups to verify policy assignments. Creating host
groups is supported via ``apply --create-groups``; that codepath lands
in Phase 5 alongside the applier.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from csfwctl.falcon.client import FalconClient


class HostGroupsAPI:
    """Host-group read wrapper plus the minimum write surface for apply."""

    def __init__(self, client: FalconClient) -> None:
        self._client = client

    def _svc(self) -> Any:
        return self._client._host_group_service()  # noqa: SLF001

    def query(self, *, filter: str | None = None, limit: int | None = None) -> list[str]:
        """Return host-group IDs matching ``filter`` (FQL)."""
        params: dict[str, Any] = {}
        if filter is not None:
            params["filter"] = filter
        if limit is not None:
            params["limit"] = limit
        result = self._client.call(
            "host_groups.query",
            lambda: self._svc().query_host_groups(parameters=params),
        )
        body = result.get("body") or {}
        return [str(r) for r in body.get("resources") or []]

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
        """Find a host group by exact display name; return ``None`` if absent."""
        ids = self.query(filter=f"name:'{name}'")
        if not ids:
            return None
        results = self.get(ids)
        return results[0] if results else None

    def create(self, name: str, *, description: str = "") -> dict[str, Any]:
        """Create an empty static host group. Used by ``apply --create-groups``."""
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
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return dict(resources[0]) if resources else {}

    def create_dynamic(self, name: str, *, fql: str, description: str = "") -> dict[str, Any]:
        """Create a dynamic host group with an FQL membership filter.

        The CrowdStrike API field is ``assignment_rule`` for the FQL filter.
        Pending real-tenant confirmation of the exact payload shape; see
        ``docs/architecture.md``.
        """
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


__all__ = ["HostGroupsAPI"]
