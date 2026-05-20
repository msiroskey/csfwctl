"""Firewall network-location sub-client.

FalconPy names these "network locations" in its ``FirewallManagement``
service. See :doc:`/docs/architecture` for the Phase 2 location API
spike findings, especially the handling of the system-managed ``any``
location.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from csfwctl.falcon.client import FalconClient

ANY_LOCATION_NAME = "any"
"""Reserved csfwctl-side name for the system-managed default location.

The CrowdStrike-side default location is auto-managed by the tenant.
The loader treats ``any`` as a sentinel reference; this sub-client
filters it out of write paths.
"""


class LocationsAPI:
    """Network-location CRUD wrapper."""

    def __init__(self, client: FalconClient) -> None:
        self._client = client

    def _svc(self) -> Any:
        return self._client._firewall_management_service()  # noqa: SLF001

    def query(self, *, filter: str | None = None, limit: int | None = None) -> list[str]:
        """Return network-location IDs matching ``filter`` (FQL)."""
        params: dict[str, Any] = {}
        if filter is not None:
            params["filter"] = filter
        if limit is not None:
            params["limit"] = limit
        result = self._client.call(
            "network_locations.query",
            lambda: self._svc().query_network_locations(parameters=params),
        )
        body = result.get("body") or {}
        return [str(r) for r in body.get("resources") or []]

    def get_details(self, ids: list[str]) -> list[dict[str, Any]]:
        """Return fully-populated location records (addresses, DNS, etc.)."""
        if not ids:
            return []
        result = self._client.call(
            "network_locations.get_details",
            lambda: self._svc().get_network_locations_details(ids=ids),
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def list_all(self, *, filter: str | None = None) -> list[dict[str, Any]]:
        """Convenience: query + get_details."""
        ids = self.query(filter=filter)
        return self.get_details(ids) if ids else []

    def upsert(self, locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Create or update one or more locations in a single call."""
        result = self._client.call(
            "network_locations.upsert",
            lambda: self._svc().upsert_network_locations(body={"resources": locations}),
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def delete(self, ids: list[str]) -> None:
        """Delete the listed network-location IDs."""
        if not ids:
            return
        self._client.call(
            "network_locations.delete",
            lambda: self._svc().delete_network_locations(ids=ids),
        )


__all__ = ["ANY_LOCATION_NAME", "LocationsAPI"]
