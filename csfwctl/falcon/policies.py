"""Firewall-policy sub-client.

Thin wrappers around FalconPy's ``FirewallPolicies`` service. Each
method funnels through :meth:`FalconClient.call` so retry and logging
happen in exactly one place.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from csfwctl.falcon.client import FalconClient


class PoliciesAPI:
    """Wrapper exposing policy CRUD + precedence + action endpoints."""

    def __init__(self, client: FalconClient) -> None:
        self._client = client

    def _svc(self) -> Any:
        return self._client._firewall_policies_service()  # noqa: SLF001

    def query(self, *, filter: str | None = None, limit: int | None = None) -> list[str]:
        """Return policy IDs matching ``filter`` (FQL)."""
        params: dict[str, Any] = {}
        if filter is not None:
            params["filter"] = filter
        if limit is not None:
            params["limit"] = limit
        result = self._client.call(
            "firewall_policies.query",
            lambda: self._svc().query_policies(parameters=params),
        )
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return [str(r) for r in resources]

    def get(self, ids: list[str]) -> list[dict[str, Any]]:
        """Return full detail records for the given policy IDs."""
        if not ids:
            return []
        result = self._client.call(
            "firewall_policies.get",
            lambda: self._svc().get_policies(ids=ids),
        )
        body = result.get("body") or {}
        resources = body.get("resources") or []
        return list(resources)

    def list_all(self, *, filter: str | None = None) -> list[dict[str, Any]]:
        """Convenience: query + get in one call."""
        ids = self.query(filter=filter)
        return self.get(ids) if ids else []

    def create(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Create one or more policies; returns the created resources."""
        result = self._client.call(
            "firewall_policies.create",
            lambda: self._svc().create_policies(body={"resources": policies}),
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def update(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Update one or more policies; returns the updated resources."""
        result = self._client.call(
            "firewall_policies.update",
            lambda: self._svc().update_policies(body={"resources": policies}),
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def delete(self, ids: list[str]) -> None:
        """Delete the listed policy IDs."""
        if not ids:
            return
        self._client.call(
            "firewall_policies.delete",
            lambda: self._svc().delete_policies(ids=ids),
        )

    def get_policy_containers(self, ids: list[str]) -> list[dict[str, Any]]:
        """Return firewall policy container entities for the given policy IDs.

        The ``getFirewallPolicies`` endpoint does not include rule group
        assignments; those live in the policy container returned here.
        Each container carries ``policy_id`` and ``rule_group_ids``.
        """
        if not ids:
            return []
        result = self._client.call(
            "firewall_management.get_policy_containers",
            lambda: self._client._firewall_management_service().get_policy_containers(ids=ids),  # noqa: SLF001
        )
        body = result.get("body") or {}
        return list(body.get("resources") or [])

    def set_precedence(self, ids_in_order: list[str], *, platform_name: str) -> None:
        """Reorder policies for a platform.

        ``ids_in_order`` is the desired ordering from highest precedence
        to lowest. ``platform_name`` is ``Windows`` or ``Mac`` (the
        CrowdStrike-side spelling).
        """
        self._client.call(
            "firewall_policies.set_precedence",
            lambda: self._svc().set_policies_precedence(
                body={"ids": ids_in_order, "platform_name": platform_name}
            ),
        )

    def perform_action(self, action_name: str, ids: list[str], value: str) -> None:
        """Run an action against policies (``add-host-group``, etc.)."""
        self._client.call(
            "firewall_policies.perform_action",
            lambda: self._svc().perform_action(
                action_name=action_name,
                body={"ids": ids, "action_parameters": [{"name": "filter", "value": value}]},
            ),
        )


__all__ = ["PoliciesAPI"]
