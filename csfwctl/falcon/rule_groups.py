"""Firewall rule-group sub-client.

Wraps FalconPy's ``FirewallManagement`` rule-group endpoints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from csfwctl.falcon.client import FalconClient


class RuleGroupsAPI:
    """Rule-group CRUD wrapper."""

    def __init__(self, client: FalconClient) -> None:
        self._client = client

    def _svc(self) -> Any:
        return self._client._firewall_management_service()  # noqa: SLF001

    def query(self, *, filter: str | None = None, limit: int | None = None) -> list[str]:
        """Return rule-group IDs matching ``filter`` (FQL)."""
        params: dict[str, Any] = {}
        if filter is not None:
            params["filter"] = filter
        if limit is not None:
            params["limit"] = limit
        result = self._client.call(
            "firewall_rule_groups.query",
            lambda: self._svc().query_rule_groups(parameters=params),
        )
        body = result.get("body") or {}
        return [str(r) for r in body.get("resources") or []]

    def get(self, ids: list[str]) -> list[dict[str, Any]]:
        """Return full rule-group detail records for the given IDs."""
        if not ids:
            return []
        result = self._client.call(
            "firewall_rule_groups.get",
            lambda: self._svc().get_rule_groups(ids=ids),
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def list_all(self, *, filter: str | None = None) -> list[dict[str, Any]]:
        """Convenience: query + get."""
        ids = self.query(filter=filter)
        return self.get(ids) if ids else []

    def create(self, rule_group: dict[str, Any]) -> dict[str, Any]:
        """Create a rule group. FalconPy's endpoint accepts one at a time."""
        result = self._client.call(
            "firewall_rule_groups.create",
            lambda: self._svc().create_rule_group(body=rule_group),
        )
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return dict(resources[0]) if resources else {}

    def update(self, rule_group: dict[str, Any]) -> dict[str, Any]:
        """Update a rule group."""
        result = self._client.call(
            "firewall_rule_groups.update",
            lambda: self._svc().update_rule_group(body=rule_group),
        )
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return dict(resources[0]) if resources else {}

    def delete(self, ids: list[str]) -> None:
        """Delete the listed rule-group IDs."""
        if not ids:
            return
        self._client.call(
            "firewall_rule_groups.delete",
            lambda: self._svc().delete_rule_groups(ids=ids),
        )


__all__ = ["RuleGroupsAPI"]
