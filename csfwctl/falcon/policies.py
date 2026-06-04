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

    def update_policy_container(
        self,
        *,
        policy_id: str,
        platform_id: str,
        rule_group_ids: list[str],
        tracking: str | None = None,
        default_inbound: str | None = None,
        default_outbound: str | None = None,
        enforce: bool | None = None,
        local_logging: bool | None = None,
        test_mode: bool | None = None,
        is_default_policy: bool | None = None,
    ) -> dict[str, Any]:
        """Update the policy container for one firewall policy.

        ``update_policies`` (PATCH) only accepts ``id``/``name``/
        ``description`` — rule-group assignments, enforcement mode,
        default inbound/outbound traffic, and local-logging all live
        on the **policy container**, which is updated through a
        separate endpoint (``PUT /fwmgr/entities/policies/v1``). Without
        this call, ``apply`` reports success but rule groups and
        settings never land on the policy.

        ``platform_id`` is the lowercase platform id
        (``"windows"`` / ``"mac"`` / ``"linux"``), NOT the
        Title-Case ``platform_name`` that ``create_policies`` accepts.
        """
        body: dict[str, Any] = {
            "policy_id": policy_id,
            "platform_id": platform_id,
            "rule_group_ids": rule_group_ids,
        }
        if tracking is not None:
            body["tracking"] = tracking
        if default_inbound is not None:
            body["default_inbound"] = default_inbound
        if default_outbound is not None:
            body["default_outbound"] = default_outbound
        if enforce is not None:
            body["enforce"] = enforce
        if local_logging is not None:
            body["local_logging"] = local_logging
        if test_mode is not None:
            body["test_mode"] = test_mode
        if is_default_policy is not None:
            body["is_default_policy"] = is_default_policy
        result = self._client.call(
            "firewall_management.update_policy_container",
            lambda: self._client._firewall_management_service().update_policy_container(  # noqa: SLF001
                body=body
            ),
        )
        resp_body = result.get("body") or {}
        resources = resp_body.get("resources") or []
        return dict(resources[0]) if resources else {}

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

    def perform_action(
        self,
        action_name: str,
        ids: list[str],
        action_parameters: list[dict[str, str]] | None = None,
    ) -> None:
        """Run an action against policies.

        ``action_name`` is one of ``add-host-group`` / ``remove-host-group`` /
        ``add-rule-group`` / ``remove-rule-group`` / ``enable`` / ``disable``.
        ``action_parameters`` is passed through verbatim — its expected
        shape depends on the action:

        - ``add-host-group`` / ``remove-host-group``:
          ``[{"name": "group_id", "value": "<host_group_id>"}]``
        - ``add-rule-group`` / ``remove-rule-group``:
          ``[{"name": "rule_group_id", "value": "<rule_group_id>"}]``
        - ``enable`` / ``disable``: ``None`` (no parameters required).
        """
        body: dict[str, Any] = {"ids": ids}
        if action_parameters:
            body["action_parameters"] = action_parameters
        self._client.call(
            "firewall_policies.perform_action",
            lambda: self._svc().perform_action(action_name=action_name, body=body),
        )

    def enable(self, policy_ids: list[str]) -> None:
        """Enable the listed policies via ``perform_action``."""
        if not policy_ids:
            return
        self.perform_action("enable", policy_ids)

    def disable(self, policy_ids: list[str]) -> None:
        """Disable the listed policies via ``perform_action``."""
        if not policy_ids:
            return
        self.perform_action("disable", policy_ids)

    def add_host_group(self, policy_id: str, host_group_id: str) -> None:
        """Attach a host group to a policy via ``perform_action``."""
        self.perform_action(
            "add-host-group",
            [policy_id],
            [{"name": "group_id", "value": host_group_id}],
        )

    def remove_host_group(self, policy_id: str, host_group_id: str) -> None:
        """Detach a host group from a policy via ``perform_action``."""
        self.perform_action(
            "remove-host-group",
            [policy_id],
            [{"name": "group_id", "value": host_group_id}],
        )


__all__ = ["PoliciesAPI"]
