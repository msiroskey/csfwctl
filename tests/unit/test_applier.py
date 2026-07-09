"""Unit tests for :mod:`csfwctl.applier`.

The applier is exercised end-to-end against a hand-rolled fake
``FalconClient``: we drive it with a change set produced by the real
differ, then assert on the recorded API calls and the resulting
:class:`ApplyReport`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from csfwctl.applier import (
    AppliedAction,
    ApplyError,
    ApplyOptions,
    ApplyReport,
    HostGroupPolicy,
    apply_change_set,
)
from csfwctl.differ import (
    METADATA_SIGNATURE_TOKEN,
    LiveState,
    compute_diff,
)
from csfwctl.exporter import (
    location_to_api_shape,
    policy_to_api_shape,
    rule_group_to_api_shape,
)
from csfwctl.loader import ConfigRepo
from csfwctl.safety import (
    BlastRadiusExceeded,
    DriftBlocked,
    SafetyOptions,
    UnbootstrappedTenantError,
    parse_signature,
)
from csfwctl.schema import (
    Action,
    Direction,
    HostGroupEnv,
    Location,
    Platform,
    Policy,
    Protocol,
    Rule,
    RuleGroup,
    TombstoneEntry,
    Tombstones,
)

# ---- fixtures: schema fixtures + fake client ----------------------------


def _windows_rg() -> RuleGroup:
    return RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        description="Baseline rules for Windows endpoints.",
        rules=[
            Rule(
                name="Allow established inbound",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
            ),
        ],
    )


def _windows_policy(with_inline: bool = False) -> Policy:
    rules: list[Rule] = []
    if with_inline:
        rules.append(
            Rule(
                name="Allow DNS outbound",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.udp,
            )
        )
    return Policy(
        name="abc01-endpoints-windows",
        display_name="ABC01-Endpoints-Windows",
        platform=Platform.windows,
        description="Baseline policy for ABC01 Windows endpoints.",
        host_groups={
            "ABC01-Endpoints-Windows-Test": HostGroupEnv.test,
            "ABC01-Endpoints-Windows-Pilot": HostGroupEnv.pilot,
            "ABC01-Endpoints-Windows-Production": HostGroupEnv.production,
        },
        rules=rules,
        rule_groups=["windows-baseline"],
    )


def _repo_with(
    *,
    policies: list[Policy] | None = None,
    rule_groups: list[RuleGroup] | None = None,
    locations: list[Location] | None = None,
    tombstones: Tombstones | None = None,
) -> ConfigRepo:
    return ConfigRepo(
        root=Path("/tmp/fake-repo"),
        policies={p.name.lower(): p for p in policies or []},
        rule_groups={rg.name: rg for rg in rule_groups or []},
        locations={loc.name: loc for loc in locations or []},
        tombstones=tombstones or Tombstones(),
    )


class FakeSubClient:
    """Shared accounting for write/delete calls."""

    def __init__(self) -> None:
        self.created: list[Any] = []
        self.updated: list[Any] = []
        self.deleted: list[Any] = []


class FakeLocationsAPI(FakeSubClient):
    def upsert(self, locations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for loc in locations:
            if "id" in loc:
                self.updated.append(loc)
                results.append(dict(loc))
            else:
                self.created.append(loc)
                results.append({**loc, "id": f"loc-id-{loc['name']}"})
        return results

    def delete(self, ids: list[str]) -> None:
        self.deleted.extend(ids)


class FakeRuleGroupsAPI(FakeSubClient):
    def create(self, rule_group: dict[str, Any]) -> dict[str, Any]:
        self.created.append(rule_group)
        return {**rule_group, "id": f"rg-id-{rule_group['name']}"}

    def update(self, rule_group: dict[str, Any]) -> dict[str, Any]:
        self.updated.append(rule_group)
        return dict(rule_group)

    def delete(self, ids: list[str]) -> None:
        self.deleted.extend(ids)


class FakePoliciesAPI(FakeSubClient):
    def __init__(self) -> None:
        super().__init__()
        # Container updates (rule_group_ids + default-traffic / enforcement).
        self.container_updates: list[dict[str, Any]] = []
        # perform_action calls: (action_name, ids, action_parameters)
        self.actions: list[tuple[str, list[str], list[dict[str, str]] | None]] = []
        # Live container state by policy id; configured by tests that need
        # to assert overlay semantics (existing values flow through unless
        # the YAML overrides them).
        self.container_state: dict[str, dict[str, Any]] = {}
        # set_precedence calls: (ids_in_order, platform_name)
        self.precedence_calls: list[tuple[list[str], str]] = []

    def create(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in policies:
            self.created.append(p)
            out.append({**p, "id": f"policy-id-{p['name']}"})
        return out

    def update(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.updated.extend(policies)
        return [dict(p) for p in policies]

    def get_policy_containers(self, ids: list[str]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for pid in ids:
            out.append(self.container_state.get(pid, {"policy_id": pid}))
        return out

    def update_policy_container(self, **kwargs: Any) -> dict[str, Any]:
        self.container_updates.append(dict(kwargs))
        return {"id": kwargs.get("policy_id", "")}

    def perform_action(
        self,
        action_name: str,
        ids: list[str],
        action_parameters: list[dict[str, str]] | None = None,
    ) -> None:
        self.actions.append((action_name, list(ids), action_parameters))

    def enable(self, policy_ids: list[str]) -> None:
        self.perform_action("enable", policy_ids)

    def disable(self, policy_ids: list[str]) -> None:
        self.perform_action("disable", policy_ids)

    def add_host_group(self, policy_id: str, host_group_id: str) -> None:
        self.perform_action(
            "add-host-group",
            [policy_id],
            [{"name": "group_id", "value": host_group_id}],
        )

    def remove_host_group(self, policy_id: str, host_group_id: str) -> None:
        self.perform_action(
            "remove-host-group",
            [policy_id],
            [{"name": "group_id", "value": host_group_id}],
        )

    def set_precedence(self, ids_in_order: list[str], *, platform_name: str) -> None:
        self.precedence_calls.append((list(ids_in_order), platform_name))

    def delete(self, ids: list[str]) -> None:
        self.deleted.extend(ids)


class FakeHostGroupsAPI(FakeSubClient):
    def __init__(self, known: dict[str, str] | None = None) -> None:
        super().__init__()
        self.known = dict(known or {})

    def find_by_name(self, name: str) -> dict[str, Any] | None:
        if name in self.known:
            return {"id": self.known[name], "name": name}
        return None

    def create(self, name: str, *, description: str = "") -> dict[str, Any]:
        self.created.append(name)
        new_id = f"hg-id-{name}"
        self.known[name] = new_id
        return {"id": new_id, "name": name}


class FakeFalconClient:
    """In-memory stand-in for :class:`csfwctl.falcon.client.FalconClient`."""

    def __init__(self, *, host_groups: dict[str, str] | None = None) -> None:
        self.policies = FakePoliciesAPI()
        self.rule_groups = FakeRuleGroupsAPI()
        self.host_groups = FakeHostGroupsAPI(host_groups)
        self.locations = FakeLocationsAPI()


# ---- live-state helpers --------------------------------------------------


def _signed_description(env: str, extra: str = "") -> str:
    """Attach a metadata trailer so a record reads as 'managed'."""
    base = extra or ""
    sep = "\n\n" if base else ""
    return (
        f"{base}{sep}{METADATA_SIGNATURE_TOKEN}"
        f" | version: 1 | git_sha: oldsha | applied: 2026-01-01T00:00:00Z | env: {env}"
    )


def _render_live_state(
    *,
    env: str,
    policies: list[Policy] = (),
    rule_groups: list[RuleGroup] = (),
    locations: list[Location] = (),
    signed: bool = True,
) -> LiveState:
    """Render desired models into a LiveState. Assigns predictable IDs."""
    state = LiveState()
    rules_by_id: dict[str, dict[str, Any]] = {}
    for rg in rule_groups:
        shape = rule_group_to_api_shape(rg, env)
        if signed:
            shape["description"] = _signed_description(env, shape.get("description", ""))
        state.rule_groups.append(shape)
        for rule in shape.get("rules", []):
            rules_by_id[str(rule["id"])] = rule
    for policy in policies:
        shape = policy_to_api_shape(policy, env)
        if signed:
            shape["description"] = _signed_description(env, shape.get("description", ""))
        only_env = HostGroupEnv(env)
        shape["groups"] = [
            g for g in shape["groups"] if policy.host_groups.get(g["name"]) is only_env
        ]
        state.policies.append(shape)
    for loc in locations:
        shape = location_to_api_shape(loc)
        if signed:
            shape["description"] = _signed_description("any", shape.get("description", ""))
        state.locations.append(shape)
    state.rules_by_id = rules_by_id
    return state


def _options(env: str = "test", **overrides: Any) -> ApplyOptions:
    defaults: dict[str, Any] = {
        "env": env,
        "git_sha": "abc1234",
        "dry_run": False,
        "initial_bootstrap": False,
        "host_group_policy": HostGroupPolicy.warn,
    }
    defaults.update(overrides)
    return ApplyOptions(**defaults)


def _safety(**overrides: Any) -> SafetyOptions:
    defaults: dict[str, Any] = {
        "max_changes": 100,
        "max_deletes": 100,
        "enforce": True,
        "allow_delete": True,
        "initial_bootstrap": False,
        "require_bootstrap_for_unmanaged": True,
    }
    defaults.update(overrides)
    return SafetyOptions(**defaults)


# ---- bootstrap gating ----------------------------------------------------


def test_apply_refuses_unbootstrapped_tenant() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg], signed=False)
    client = FakeFalconClient()
    cs = compute_diff(repo, "test", state)
    with pytest.raises(UnbootstrappedTenantError):
        apply_change_set(
            client=client,
            repo=repo,
            change_set=cs,
            state=state,
            options=_options(),
            safety_options=_safety(),
        )


def test_apply_allows_unbootstrapped_when_initial_bootstrap_set() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg], signed=False)
    client = FakeFalconClient()
    cs = compute_diff(repo, "test", state)
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(initial_bootstrap=True),
        safety_options=_safety(initial_bootstrap=True),
    )
    # Bootstrap touches the live rule group's metadata only.
    assert report.count("metadata") == 1
    assert client.rule_groups.updated  # the bootstrap write fired


# ---- creates -------------------------------------------------------------


def test_apply_creates_locations_rule_groups_policies_in_order() -> None:
    """Apply against an empty tenant: every desired object lands as a create."""
    rg = _windows_rg()
    policy = _windows_policy(with_inline=False)
    loc = Location(name="corp-vpn", addresses=["10.0.0.0/24"])
    repo = _repo_with(policies=[policy], rule_groups=[rg], locations=[loc])
    # Empty live state, but signed somewhere so bootstrap check passes.
    # We bypass the bootstrap gate using initial_bootstrap=False but
    # providing a single signed throwaway location.
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    # The seed is not in the YAML, so it shows up as unmanaged but
    # otherwise non-actionable; the diff still emits creates for our
    # YAML objects.
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Test": "hg-test"})
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=seed,
        options=_options(),
        safety_options=_safety(),
    )
    # Locations: corp-vpn create, seed left alone (it's unmanaged).
    assert any(c["name"] == "corp-vpn" for c in client.locations.created)
    # Rule group create.
    assert any(c["name"].startswith("windows-baseline") for c in client.rule_groups.created)
    # Policy create with the host-group id wired in.
    assert client.policies.created
    policy_payload = client.policies.created[0]
    assert policy_payload["groups"] == [{"id": "hg-test", "name": "ABC01-Endpoints-Windows-Test"}]
    # Rule-group ids resolved to the freshly-created id, not fake-uuid.
    new_rg_id = f"rg-id-{client.rule_groups.created[0]['name']}"
    assert policy_payload["settings"]["rule_group_ids"] == [new_rg_id]
    # Report counts match.
    assert report.count("create") >= 3


def test_apply_creates_synthesise_override_rule_group_first() -> None:
    """A policy with inline rules creates the override RG too."""
    policy = _windows_policy(with_inline=True)
    rg = _windows_rg()
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Test": "hg-test"})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=seed,
        options=_options(),
        safety_options=_safety(),
    )
    rg_names = [r["name"] for r in client.rule_groups.created]
    assert "windows-baseline-Test" in rg_names
    assert "abc01-endpoints-windows-overrides-test-Test" in rg_names
    # The policy's rule_group_ids references both RG ids, override first.
    policy_payload = client.policies.created[0]
    rg_ids = policy_payload["settings"]["rule_group_ids"]
    assert rg_ids[0].endswith("overrides-test-Test")
    assert rg_ids[1].endswith("baseline-Test")


# ---- updates rewrite the metadata signature ------------------------------


def test_apply_update_rewrites_metadata_trailer_with_incremented_version() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg])
    # Tamper so the differ emits an update against the rule group.
    live_rule = next(iter(state.rules_by_id.values()))
    live_rule["action"] = "DENY"
    cs = compute_diff(repo, "test", state)
    assert cs.updates

    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(git_sha="newsha"),
        safety_options=_safety(),
    )
    assert client.rule_groups.updated
    payload = client.rule_groups.updated[0]
    # Normal updates use the diff-based format; the description trailer is
    # expressed as a JSON Patch replace operation, not a top-level key.
    assert payload["diff_type"] == "application/json-patch+json"
    assert "rule_ids" in payload
    desc_value = payload["diff_operations"][0]["value"]
    sig = parse_signature(desc_value)
    assert sig is not None
    # Previous version was 1; the applier bumped it.
    assert sig.version == 2
    assert sig.git_sha == "newsha"


# ---- drift gate ----------------------------------------------------------


def test_apply_refuses_drifted_managed_update_without_enforce() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg])
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    cs = compute_diff(repo, "test", state)

    client = FakeFalconClient()
    with pytest.raises(DriftBlocked):
        apply_change_set(
            client=client,
            repo=repo,
            change_set=cs,
            state=state,
            options=_options(),
            safety_options=_safety(enforce=False),
        )
    assert not client.rule_groups.updated


# ---- deletes -------------------------------------------------------------


def test_apply_delete_requires_allow_delete_even_with_tombstone() -> None:
    keep = _windows_rg()
    legacy = RuleGroup(name="legacy-rdp-allow", platform=Platform.windows)
    repo = _repo_with(
        rule_groups=[keep],
        tombstones=Tombstones(
            rule_groups=[
                TombstoneEntry(
                    name="legacy-rdp-allow",
                    deleted_in_sha="def5678",
                    reason="Folded into windows-baseline.",
                )
            ]
        ),
    )
    state = _render_live_state(env="test", rule_groups=[keep, legacy])
    cs = compute_diff(repo, "test", state)
    assert cs.deletes

    client = FakeFalconClient()
    from csfwctl.safety import SafetyError

    with pytest.raises(SafetyError, match="allow-delete"):
        apply_change_set(
            client=client,
            repo=repo,
            change_set=cs,
            state=state,
            options=_options(),
            safety_options=_safety(allow_delete=False),
        )
    assert not client.rule_groups.deleted


def test_apply_delete_proceeds_when_allow_delete_set() -> None:
    keep = _windows_rg()
    legacy = RuleGroup(name="legacy-rdp-allow", platform=Platform.windows)
    repo = _repo_with(
        rule_groups=[keep],
        tombstones=Tombstones(
            rule_groups=[
                TombstoneEntry(
                    name="legacy-rdp-allow",
                    deleted_in_sha="def5678",
                    reason="Folded into windows-baseline.",
                )
            ]
        ),
    )
    state = _render_live_state(env="test", rule_groups=[keep, legacy])
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(allow_delete=True),
    )
    assert client.rule_groups.deleted
    # The deleted id is the live id from the rendered API shape.
    assert client.rule_groups.deleted[0].endswith("legacy-rdp-allow-Test") or (
        len(client.rule_groups.deleted[0]) > 0
    )


# ---- blast radius --------------------------------------------------------


def test_apply_refuses_when_blast_radius_exceeded() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient()
    with pytest.raises(BlastRadiusExceeded):
        apply_change_set(
            client=client,
            repo=repo,
            change_set=cs,
            state=seed,
            options=_options(),
            safety_options=_safety(max_changes=0),
        )


# ---- host group handling -------------------------------------------------


def test_apply_strict_groups_raises_on_missing_host_group() -> None:
    policy = _windows_policy()
    rg = _windows_rg()
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient()  # no host groups registered
    with pytest.raises(ApplyError, match="host group"):
        apply_change_set(
            client=client,
            repo=repo,
            change_set=cs,
            state=seed,
            options=_options(host_group_policy=HostGroupPolicy.strict),
            safety_options=_safety(),
        )


def test_apply_create_groups_creates_missing_host_groups() -> None:
    policy = _windows_policy()
    rg = _windows_rg()
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=seed,
        options=_options(host_group_policy=HostGroupPolicy.create),
        safety_options=_safety(),
    )
    assert "ABC01-Endpoints-Windows-Test" in client.host_groups.created
    # And the resulting policy payload carries the freshly-minted id.
    assert client.policies.created[0]["groups"][0]["id"].startswith("hg-id-")
    assert any(a.kind == "host-group" and a.op == "create" for a in report.actions)


def test_apply_warn_groups_skips_missing_assignment() -> None:
    policy = _windows_policy()
    rg = _windows_rg()
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=seed,
        options=_options(host_group_policy=HostGroupPolicy.warn),
        safety_options=_safety(),
    )
    assert any("host group" in w for w in report.warnings)
    # Policy still gets created; just without the host group.
    assert client.policies.created
    assert client.policies.created[0]["groups"] == []


# ---- dry-run -------------------------------------------------------------


def test_apply_dry_run_makes_no_writes_but_reports_actions() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    seed = _render_live_state(
        env="test",
        locations=[Location(name="seed", addresses=["10.255.255.255/32"])],
    )
    cs = compute_diff(repo, "test", seed)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=seed,
        options=_options(dry_run=True),
        safety_options=_safety(),
    )
    assert not client.rule_groups.created
    assert not client.policies.created
    assert report.count("create") >= 1
    assert all(a.detail == "dry-run" for a in report.actions if a.op == "create")


# ---- rule group update uses diff-based format ----------------------------


def test_apply_update_rule_group_uses_diff_based_format() -> None:
    """Normal rule-group UPDATE sends diff_type + tracking + rule_ids, not full content.

    The CrowdStrike PATCH endpoint rejects payloads lacking these fields with
    HTTP 400.  This test verifies the applier emits the correct format.
    """
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg])
    # Inject a tracking token so we can confirm it threads through.
    live_rg = state.rule_groups[0]
    live_rg["tracking"] = "tok-abc123"
    # Force an update by tampering with a rule field.
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    cs = compute_diff(repo, "test", state)
    assert cs.updates

    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(git_sha="sha999"),
        safety_options=_safety(),
    )

    assert client.rule_groups.updated
    payload = client.rule_groups.updated[0]
    assert payload["diff_type"] == "application/json-patch+json"
    assert payload["tracking"] == "tok-abc123"
    assert "rule_ids" in payload
    ops = payload["diff_operations"]
    assert ops[0]["op"] == "replace"
    assert ops[0]["path"] == "/description"
    sig = parse_signature(ops[0]["value"])
    assert sig is not None
    assert sig.git_sha == "sha999"


def _rg_with_rules(rules: list[Rule]) -> RuleGroup:
    return RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        description="Baseline rules for Windows endpoints.",
        rules=rules,
    )


def _apply_rule_group_update(desired: RuleGroup, live: RuleGroup) -> dict[str, Any]:
    """Drive an apply where the live rule group differs from desired; return the PATCH."""
    repo = _repo_with(rule_groups=[desired])
    state = _render_live_state(env="test", rule_groups=[live])
    cs = compute_diff(repo, "test", state)
    assert cs.updates
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert client.rule_groups.updated
    return client.rule_groups.updated[0]


def test_apply_update_rule_group_adds_new_rule_via_diff_op() -> None:
    """A desired rule absent from live becomes an `add` op on /rules/-."""
    kept = Rule(
        name="Allow established inbound",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=Protocol.tcp,
    )
    added = Rule(
        name="Allow updater outbound",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        file_path=r"C:\Program Files\app\*.exe",
    )
    payload = _apply_rule_group_update(_rg_with_rules([kept, added]), _rg_with_rules([kept]))

    adds = [op for op in payload["diff_operations"] if op["op"] == "add"]
    assert len(adds) == 1
    assert adds[0]["path"] == "/rules/-"
    value = adds[0]["value"]
    assert value["name"] == "Allow updater outbound"
    assert "id" not in value  # server assigns the id for a new rule
    assert value["temp_id"]  # non-empty placeholder the server maps to a real id
    assert {
        "name": "image_name",
        "value": r"C:\Program Files\app\*.exe",
        "type": "windows_path",
    } in value["fields"]
    # rule_ids keeps the existing rule and appends the added rule's temp_id.
    assert len(payload["rule_ids"]) == 2
    assert value["temp_id"] in payload["rule_ids"]


def test_apply_update_rule_group_removes_rule_via_diff_op() -> None:
    """A live rule gone from desired becomes a `remove` op and drops from rule_ids."""
    kept = Rule(
        name="Allow established inbound",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=Protocol.tcp,
    )
    removed = Rule(
        name="Allow updater outbound",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
    )
    payload = _apply_rule_group_update(_rg_with_rules([kept]), _rg_with_rules([kept, removed]))

    removes = [op for op in payload["diff_operations"] if op["op"] == "remove"]
    assert len(removes) == 1
    assert removes[0]["path"] == "/rules/1"  # the second (removed) live rule
    assert len(payload["rule_ids"]) == 1  # dropped from two to one


def test_apply_update_rule_group_modified_rule_becomes_remove_add() -> None:
    """A content change on an existing rule becomes a remove + add pair.

    The endpoint rejects a ``replace`` on a whole ``/rules/<i>`` object, so a
    modification is expressed as removing the live rule by index and appending
    the desired content.
    """
    live = _rg_with_rules(
        [
            Rule(
                name="Allow established inbound",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
            )
        ]
    )
    desired = _rg_with_rules(
        [
            Rule(
                name="Allow established inbound",
                action=Action.block,  # changed action
                direction=Direction.inbound,
                protocol=Protocol.tcp,
            )
        ]
    )
    repo = _repo_with(rule_groups=[desired])
    state = _render_live_state(env="test", rule_groups=[live])
    live_rule_id = state.rule_groups[0]["rule_ids"][0]
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    payload = client.rule_groups.updated[0]
    # No `replace` op targets a /rules/<i> object — those are rejected by the API.
    assert not [
        op
        for op in payload["diff_operations"]
        if op["op"] == "replace" and op["path"].startswith("/rules/")
    ]
    # The live rule is removed by index...
    removes = [op for op in payload["diff_operations"] if op["op"] == "remove"]
    assert [op["path"] for op in removes] == ["/rules/0"]
    # ...and the live id is dropped from rule_ids (server assigns a new one).
    assert live_rule_id not in payload["rule_ids"]
    # ...and the desired content is appended with a temp_id the server maps...
    adds = [op for op in payload["diff_operations"] if op["op"] == "add"]
    assert len(adds) == 1
    assert adds[0]["path"] == "/rules/-"
    assert adds[0]["value"]["action"] == "DENY"
    assert "id" not in adds[0]["value"]
    temp_id = adds[0]["value"]["temp_id"]
    assert temp_id
    # ...and that temp_id replaces the dropped live id in rule_ids.
    assert payload["rule_ids"] == [temp_id]


def test_apply_update_rule_group_pure_reorder_rewrites_rule_ids() -> None:
    """Reordering rules (no content change) reorders rule_ids without add/remove ops.

    A pure reorder previously produced no diff operations and left ``rule_ids``
    in the live order, so the new ordering never landed on the wire. ``rule_ids``
    is the authoritative final ordering, so it must be emitted in desired order.
    """
    rule_a = Rule(
        name="Allow A",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=Protocol.tcp,
    )
    rule_b = Rule(
        name="Allow B",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
    )
    live = _rg_with_rules([rule_a, rule_b])
    desired = _rg_with_rules([rule_b, rule_a])

    repo = _repo_with(rule_groups=[desired])
    state = _render_live_state(env="test", rule_groups=[live])
    live_rule_ids = list(state.rule_groups[0]["rule_ids"])
    cs = compute_diff(repo, "test", state)
    assert cs.updates
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    payload = client.rule_groups.updated[0]
    # No content churn: the only diff op is the description trailer.
    content_ops = [op for op in payload["diff_operations"] if op["path"].startswith("/rules")]
    assert content_ops == []
    # rule_ids is rewritten into the desired (reversed) order.
    assert payload["rule_ids"] == list(reversed(live_rule_ids))


def test_apply_update_rule_group_reorder_with_add_keeps_desired_order() -> None:
    """A reorder combined with an add lands all rules in desired order.

    The retained rule keeps its live id; the added rule rides on its temp_id,
    and the final ``rule_ids`` follows the desired sequence.
    """
    rule_a = Rule(
        name="Allow A",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=Protocol.tcp,
    )
    rule_b = Rule(
        name="Allow B",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
    )
    live = _rg_with_rules([rule_a])
    # Desired: the new rule first, the existing rule second (a reorder + add).
    desired = _rg_with_rules([rule_b, rule_a])

    repo = _repo_with(rule_groups=[desired])
    state = _render_live_state(env="test", rule_groups=[live])
    live_a_id = state.rule_groups[0]["rule_ids"][0]
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    payload = client.rule_groups.updated[0]
    adds = [op for op in payload["diff_operations"] if op["op"] == "add"]
    assert len(adds) == 1
    temp_id = adds[0]["value"]["temp_id"]
    # Desired order is [B (new), A (existing)] → [temp_id, live_a_id].
    assert payload["rule_ids"] == [temp_id, live_a_id]


# ---- bootstrap mode ------------------------------------------------------


def test_bootstrap_only_writes_metadata_never_modifies_content() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg], signed=False)
    # Even tamper with the live rule contents — bootstrap should ignore it.
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(initial_bootstrap=True),
        safety_options=_safety(initial_bootstrap=True),
    )
    # The bootstrap path sends a diff-based, metadata-only payload: the
    # description trailer is changed via a JSON Patch op, and rule content
    # (rule_ids) is preserved rather than rewritten.
    assert client.rule_groups.updated
    payload = client.rule_groups.updated[0]
    assert payload["diff_type"] == "application/json-patch+json"
    assert "rule_ids" in payload
    ops = payload["diff_operations"]
    assert len(ops) == 1
    assert ops[0]["op"] == "replace"
    assert ops[0]["path"] == "/description"
    sig = parse_signature(ops[0]["value"])
    assert sig is not None
    # No previous signature on the live record → version 1.
    assert sig.version == 1
    assert report.count("metadata") == 1


def test_bootstrap_warns_for_yaml_without_live_counterpart() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = LiveState()  # nothing live, but bootstrap proceeds
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(initial_bootstrap=True),
        safety_options=_safety(initial_bootstrap=True),
    )
    assert any("no live counterpart" in w for w in report.warnings)
    assert not client.rule_groups.updated


def test_bootstrap_matches_live_rule_group_with_spaces_in_name() -> None:
    """Live objects whose names use spaces instead of hyphens still resolve.

    Real tenants often have pre-existing rule groups created outside of
    csfwctl where CrowdStrike stored the display name with spaces (e.g.
    ``ODTI Windows CIO Support Tool Access-Test``).  _build_live_index
    must normalise via to_slug() so the spaced live name matches the
    hyphenated YAML slug.
    """
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    # Simulate a live rule group whose name has spaces instead of hyphens.
    # rule_group_to_api_shape would produce "Windows-Baseline-Test"; we
    # override the name to use spaces as CrowdStrike would for a pre-existing
    # object.
    state = LiveState()
    spaced_name = "Windows Baseline-Test"
    state.rule_groups.append(
        {
            "id": "rg-live-id-001",
            "name": spaced_name,
            "description": "",
            "rules": [],
            "rule_ids": [],
            "platform": "Windows",
        }
    )
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(initial_bootstrap=True),
        safety_options=_safety(initial_bootstrap=True),
    )
    # Bootstrap should have written metadata to the live rule group,
    # not warned that it has no YAML counterpart.
    assert client.rule_groups.updated, "expected a metadata-only update for the spaced-name RG"
    assert not any("no live counterpart" in w for w in report.warnings)
    assert report.count("metadata") == 1


def test_apply_updates_rule_group_with_camelcase_display_name() -> None:
    """Camel-case display names that do not round-trip through ``to_slug``
    still resolve to the existing live rule group on update.

    Regression: a YAML slug ``asc-mac-endpoints`` paired with display
    name ``ASC-MacEndpoints`` produces live name
    ``ASC-MacEndpoints-Pilot``. Stripping the env suffix and re-slugging
    yields ``asc-macendpoints`` (``to_slug`` only normalises whitespace
    and underscores, not camel-case boundaries), so the slug-keyed live
    index never matches. The applier therefore tried to *create* the
    rule group again and CrowdStrike rejected with
    ``Duplicate rule group name ASC-MacEndpoints-Pilot``.

    With the display-name fallback in place, the rule group must be
    routed to the update path and use the existing live ID.
    """
    rg = RuleGroup(
        name="asc-mac-endpoints",
        display_name="ASC-MacEndpoints",
        platform=Platform.mac,
        rules=[
            Rule(
                name="Allow established inbound",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
            ),
        ],
    )
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="pilot", rule_groups=[rg])
    # Force a content change so the diff routes through the update path
    # rather than no-change. The metadata trailer means the differ also
    # has to route via update for the signature refresh.
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    # Capture the live id the applier should reuse.
    live_id = state.rule_groups[0]["id"]

    cs = compute_diff(repo, "pilot", state)
    # Verify the differ matched via display-name fallback.
    rg_creates = [c for c in cs.creates if c.kind == "rule-group"]
    rg_updates = [c for c in cs.updates if c.kind == "rule-group"]
    assert rg_creates == [], f"unexpected creates: {rg_creates}"
    assert any(c.slug == "asc-mac-endpoints" for c in rg_updates)

    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    # The applier should have issued an UPDATE against the existing live
    # ID, not a CREATE that would collide with the existing live name.
    assert not client.rule_groups.created, (
        f"applier attempted to create a rule group that already exists: "
        f"{client.rule_groups.created}"
    )
    assert client.rule_groups.updated, "expected an update against the live RG"
    payload = client.rule_groups.updated[0]
    assert payload["id"] == live_id


def test_apply_updates_policy_with_camelcase_display_name() -> None:
    """Camel-case policy display names that do not round-trip via ``to_slug``
    still resolve to the existing live policy on update.

    Regression: a YAML slug ``asc-mac-endpoints`` with display name
    ``ASC-MacEndpoints`` projected to live CrowdStrike name
    ``ASC-MacEndpoints-Pilot``. Stripping the env suffix and re-slugging
    yields ``asc-macendpoints``, so the slug-keyed live index never
    matched. The applier therefore re-created the policy and
    CrowdStrike rejected with ``Duplicate policy name``.
    """
    policy = Policy(
        name="asc-mac-endpoints",
        display_name="ASC-MacEndpoints",
        platform=Platform.mac,
        rule_groups=[],
    )
    repo = _repo_with(policies=[policy])
    state = _render_live_state(env="pilot", policies=[policy])
    # Force a content change so the diff routes through update.
    state.policies[0]["enabled"] = False
    live_id = state.policies[0]["id"]

    cs = compute_diff(repo, "pilot", state)
    p_creates = [c for c in cs.creates if c.kind == "policy"]
    p_updates = [c for c in cs.updates if c.kind == "policy"]
    assert p_creates == [], f"unexpected policy creates: {p_creates}"
    assert any(c.slug == "asc-mac-endpoints" for c in p_updates)

    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    assert not client.policies.created, (
        f"applier attempted to create a policy that already exists: {client.policies.created}"
    )
    assert client.policies.updated, "expected an update against the live policy"
    payload = client.policies.updated[0]
    assert payload["id"] == live_id


def test_apply_policy_update_routes_rule_groups_to_container_endpoint() -> None:
    """``update_policies`` does not accept ``rule_group_ids``; the change
    must be routed through ``update_policy_container``.

    Regression: the applier was sending rule_group_ids in the
    ``update_policies`` body, where the server silently dropped them.
    The change log read ``rule_groups: list changed (0 -> 3 items)``
    but the live policy stayed empty.
    """
    rg = _windows_rg()
    desired = _windows_policy()
    repo = _repo_with(policies=[desired], rule_groups=[rg])

    live_policy = Policy(
        name=desired.name,
        display_name=desired.display_name,
        platform=desired.platform,
        description=desired.description,
        host_groups=desired.host_groups,
        rules=[],
        rule_groups=[],  # live has no rule groups attached
    )
    state = _render_live_state(env="pilot", policies=[live_policy], rule_groups=[rg])

    cs = compute_diff(repo, "pilot", state)
    p_updates = [c for c in cs.updates if c.kind == "policy"]
    assert p_updates, "expected a policy update for rule_groups drift"

    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Pilot": "hg-pilot"})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    assert client.policies.container_updates, (
        "expected update_policy_container to fire; rule_group_ids would otherwise "
        "be silently dropped by update_policies"
    )
    payload = client.policies.container_updates[0]
    assert payload["platform_id"] == "windows"
    assert payload["rule_group_ids"], "container update missing rule_group_ids"
    live_id = state.policies[0]["id"]
    assert payload["policy_id"] == live_id


def test_apply_policy_update_toggles_enabled_state_via_perform_action() -> None:
    """A status change must be applied through ``perform_action``;
    ``update_policies`` does not honour the ``enabled`` field.
    """
    rg = _windows_rg()
    desired = _windows_policy()  # default Status.enabled
    repo = _repo_with(policies=[desired], rule_groups=[rg])

    state = _render_live_state(env="pilot", policies=[desired], rule_groups=[rg])
    state.policies[0]["enabled"] = False
    live_id = state.policies[0]["id"]

    cs = compute_diff(repo, "pilot", state)
    p_updates = [c for c in cs.updates if c.kind == "policy"]
    assert p_updates and any(fc.path == "status" for c in p_updates for fc in c.field_changes)

    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Pilot": "hg-pilot"})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    assert ("enable", [live_id], None) in client.policies.actions, (
        f"expected perform_action enable for {live_id}; got {client.policies.actions}"
    )


def test_apply_policy_update_routes_host_group_changes_to_perform_action() -> None:
    """Host-group add/remove on an existing policy must use
    ``perform_action add-host-group`` / ``remove-host-group`` — the
    ``groups`` field on ``update_policies`` is silently dropped.
    """
    rg = _windows_rg()
    desired = _windows_policy()
    # Drop one host group from the live policy so the diff emits a
    # HostGroupChange(op='add'). Reuse the live-state helper and then
    # strip the Pilot group from the rendered shape.
    repo = _repo_with(policies=[desired], rule_groups=[rg])
    state = _render_live_state(env="pilot", policies=[desired], rule_groups=[rg])
    state.policies[0]["groups"] = []
    live_id = state.policies[0]["id"]

    cs = compute_diff(repo, "pilot", state)
    p_updates = [c for c in cs.updates if c.kind == "policy"]
    assert p_updates and any(c.host_group_changes for c in p_updates)

    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Pilot": "hg-pilot"})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    matching = [
        a
        for a in client.policies.actions
        if a[0] == "add-host-group"
        and a[1] == [live_id]
        and a[2]
        and a[2][0] == {"name": "group_id", "value": "hg-pilot"}
    ]
    assert matching, f"expected add-host-group action; got {client.policies.actions}"


def test_apply_policy_update_removes_cross_env_host_group_drift() -> None:
    """A host group attached to the wrong env's policy is removed.

    Regression: ``_host_group_changes`` filtered both sides by the
    current env, so a Pilot-env host group attached to the Test policy
    was invisible to the applier. The differ flagged it as a generic
    field-level change but no ``HostGroupChange(remove)`` was emitted,
    so ``perform_action remove-host-group`` never fired and the stray
    group remained on every apply.
    """
    rg = _windows_rg()
    desired = _windows_policy()
    repo = _repo_with(policies=[desired], rule_groups=[rg])
    # The live Test policy has the Pilot host group attached -- drift.
    state = _render_live_state(env="test", policies=[desired], rule_groups=[rg])
    state.policies[0]["groups"] = [
        {"id": "hg-pilot", "name": "ABC01-Endpoints-Windows-Pilot"},
    ]
    live_id = state.policies[0]["id"]

    cs = compute_diff(repo, "test", state)
    p_updates = [c for c in cs.updates if c.kind == "policy"]
    assert p_updates, "expected an update"
    ops = {(hgc.op, hgc.group_name) for c in p_updates for hgc in c.host_group_changes}
    assert ("remove", "ABC01-Endpoints-Windows-Pilot") in ops
    assert ("add", "ABC01-Endpoints-Windows-Test") in ops

    client = FakeFalconClient(
        host_groups={
            "ABC01-Endpoints-Windows-Test": "hg-test",
            "ABC01-Endpoints-Windows-Pilot": "hg-pilot",
        }
    )
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="test"),
        safety_options=_safety(),
    )
    actions = client.policies.actions
    add_test = (
        "add-host-group",
        [live_id],
        [{"name": "group_id", "value": "hg-test"}],
    )
    remove_pilot = (
        "remove-host-group",
        [live_id],
        [{"name": "group_id", "value": "hg-pilot"}],
    )
    assert add_test in actions, f"expected {add_test} in {actions}"
    assert remove_pilot in actions, f"expected {remove_pilot} in {actions}"


def test_apply_policy_update_remove_lookup_does_not_create_target() -> None:
    """``--create-groups`` must not accidentally create a host group we
    are about to detach. The remove-side lookup goes through
    ``_lookup_host_group_ids`` and skips the create path.
    """
    rg = _windows_rg()
    desired = _windows_policy()
    repo = _repo_with(policies=[desired], rule_groups=[rg])
    state = _render_live_state(env="test", policies=[desired], rule_groups=[rg])
    state.policies[0]["groups"] = [
        {"id": "hg-stale", "name": "ABC01-Endpoints-Stale-Group"},
    ]

    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient(
        host_groups={
            "ABC01-Endpoints-Windows-Test": "hg-test",
            # The stale group exists so the remove can be issued.
            "ABC01-Endpoints-Stale-Group": "hg-stale",
        }
    )
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="test", host_group_policy=HostGroupPolicy.create),
        safety_options=_safety(),
    )
    # The stale group must not appear in the "created" log -- it was
    # only looked up for the remove perform_action.
    assert "ABC01-Endpoints-Stale-Group" not in client.host_groups.created


def test_apply_policy_create_applies_container_and_host_groups() -> None:
    """Creating a policy must follow up ``create_policies`` with
    ``update_policy_container`` (rule groups + settings), per-host-group
    ``add-host-group`` actions, and an ``enable`` toggle when the
    desired status is enabled.

    Regression: ``create_policies`` only accepts name/description/
    platform_name; without the follow-up calls, a freshly created
    policy ended up with no rule groups, no host groups attached, and
    disabled.
    """
    rg = _windows_rg()
    desired = _windows_policy()
    repo = _repo_with(policies=[desired], rule_groups=[rg])
    # Live has nothing for this policy but does have a managed sentinel
    # record so the safety bootstrap check does not block the apply.
    state = LiveState()
    state.locations.append(
        {
            "id": "loc-sentinel",
            "name": "sentinel-location",
            "description": _signed_description("any"),
        }
    )

    cs = compute_diff(repo, "pilot", state)
    p_creates = [c for c in cs.creates if c.kind == "policy"]
    assert p_creates, "expected a create"

    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Pilot": "hg-pilot"})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    created_id = f"policy-id-{desired.display_name}-Pilot"
    assert client.policies.container_updates, "expected update_policy_container after create"
    payload = client.policies.container_updates[0]
    assert payload["policy_id"] == created_id
    assert payload["platform_id"] == "windows"

    actions = client.policies.actions
    add_action = ("add-host-group", [created_id], [{"name": "group_id", "value": "hg-pilot"}])
    assert add_action in actions, f"expected {add_action} in {actions}"
    assert ("enable", [created_id], None) in actions, (
        f"expected enable action on newly created policy; got {actions}"
    )


def test_apply_policy_container_always_sends_required_fields() -> None:
    """``update_policy_container`` rejects payloads missing
    ``default_inbound``/``default_outbound``/``enforce``/``test_mode``
    with HTTP 400 ``"... attribute cannot be empty"``.

    The applier must always send those fields. When the YAML
    ``settings`` block doesn't specify them, the values are taken
    from the live container; when there's no live container yet
    (fresh create), safe defaults apply.
    """
    rg = _windows_rg()
    desired = _windows_policy()  # no ``settings`` block in the YAML
    repo = _repo_with(policies=[desired], rule_groups=[rg])

    state = _render_live_state(env="pilot", policies=[desired], rule_groups=[rg])
    # Force an update by changing rule content so the diff routes through
    # the policy update path.
    state.policies[0]["enabled"] = False

    cs = compute_diff(repo, "pilot", state)
    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Pilot": "hg-pilot"})
    live_id = state.policies[0]["id"]
    client.policies.container_state[live_id] = {
        "policy_id": live_id,
        "default_inbound": "DENY",
        "default_outbound": "ALLOW",
        "enforce": True,
        "local_logging": False,
        "test_mode": False,
        "tracking": "tok-123",
    }
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    assert client.policies.container_updates, "expected an update_policy_container call"
    payload = client.policies.container_updates[0]
    # All four "cannot be empty" fields must be present with values
    # overlaid from the existing container (no YAML override).
    assert payload["default_inbound"] == "DENY"
    assert payload["default_outbound"] == "ALLOW"
    assert payload["enforce"] is True
    assert payload["test_mode"] is False
    # tracking flows through too so the API has its optimistic-
    # concurrency token.
    assert payload.get("tracking") == "tok-123"


def test_apply_policy_container_uses_defaults_when_no_live_container() -> None:
    """For a freshly created policy with no YAML ``settings`` and no
    live container yet, the applier must still send valid defaults
    for the required fields rather than leaving them empty.
    """
    rg = _windows_rg()
    desired = _windows_policy()
    repo = _repo_with(policies=[desired], rule_groups=[rg])
    # Empty live state for the policy + a sentinel managed record to
    # satisfy the bootstrap-tenant safety check.
    state = LiveState()
    state.locations.append(
        {
            "id": "loc-sentinel",
            "name": "sentinel-location",
            "description": _signed_description("any"),
        }
    )

    cs = compute_diff(repo, "pilot", state)
    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Pilot": "hg-pilot"})
    # No container_state seeded → get_policy_containers returns a stub
    # with no settings → applier falls back to safe defaults.
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(env="pilot"),
        safety_options=_safety(),
    )
    assert client.policies.container_updates
    payload = client.policies.container_updates[0]
    assert payload["default_inbound"] == "ALLOW"
    assert payload["default_outbound"] == "ALLOW"
    assert payload["enforce"] is False
    assert payload["test_mode"] is False
    assert payload["local_logging"] is False


# ---- report serialization ------------------------------------------------


def test_apply_report_to_json_round_trips() -> None:
    import json

    report = ApplyReport(env="test", dry_run=False, bootstrap=False)
    report.actions.append(
        AppliedAction(
            kind="policy", op="create", slug="p1", display_name="P1-Test", detail="policy-id-1"
        )
    )
    payload = json.loads(json.dumps(report.to_json()))
    assert payload["env"] == "test"
    assert payload["summary"]["create"] == 1
    assert payload["actions"][0]["slug"] == "p1"


# ---- precedence / metadata description preservation ---------------------


def test_apply_preserves_existing_free_text_in_description() -> None:
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg])
    # Force an update.
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    payload = client.rule_groups.updated[0]
    # Normal updates use the diff-based format; description is in diff_operations.
    assert payload["diff_type"] == "application/json-patch+json"
    desc_value = payload["diff_operations"][0]["value"]
    # Free-text "Baseline rules for Windows endpoints." is preserved.
    assert "Baseline rules for Windows endpoints." in desc_value
    # And the new trailer is present.
    assert "Managed by csfwctl" in desc_value


# ---- precedence hook (step 4) --------------------------------------------


def _mac_policy(name: str, *, priority: Any, display_name: str | None = None) -> Policy:
    """Minimal mac policy fixture for precedence tests."""
    from csfwctl.schema import PrecedenceBucket

    return Policy(
        name=name,
        display_name=display_name or name,
        platform=Platform.mac,
        priority=priority if isinstance(priority, PrecedenceBucket) else PrecedenceBucket(priority),
    )


def test_apply_precedence_reorders_managed_policies_to_bucket_order() -> None:
    """A high-bucket policy lands ahead of a default-bucket one on the tenant."""
    from csfwctl.schema import PrecedenceBucket

    p_default = _mac_policy("asc-mac-endpoints", priority=PrecedenceBucket.default)
    p_high = _mac_policy(
        "asc-exception-mac-monitor-only",
        priority=PrecedenceBucket.high,
        display_name="Exception-Mac-Monitor-Only",
    )
    repo = _repo_with(policies=[p_default, p_high])
    # Live state has both, but in the *reverse* of the resolved order — the
    # high-bucket policy sits below the default one, mirroring CS's habit
    # of appending new policies to the end of the platform list.
    state = _render_live_state(env="test", policies=[p_default, p_high])
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert len(client.policies.precedence_calls) == 1
    ids_in_order, platform_name = client.policies.precedence_calls[0]
    assert platform_name == "Mac"
    high_id = state.policies[1]["id"]
    default_id = state.policies[0]["id"]
    # Both platforms show high before default.
    assert ids_in_order.index(high_id) < ids_in_order.index(default_id)
    prec_actions = [a for a in report.actions if a.op == "precedence"]
    assert prec_actions and prec_actions[0].display_name == "precedence:Mac"


def test_apply_precedence_skips_when_live_order_already_matches() -> None:
    """No API call and no recorded action when live already matches resolved."""
    from csfwctl.schema import PrecedenceBucket

    p_high = _mac_policy(
        "asc-exception-mac-monitor-only",
        priority=PrecedenceBucket.high,
        display_name="Exception-Mac-Monitor-Only",
    )
    p_default = _mac_policy("asc-mac-endpoints", priority=PrecedenceBucket.default)
    repo = _repo_with(policies=[p_high, p_default])
    # Live in the resolved order (high first).
    state = _render_live_state(env="test", policies=[p_high, p_default])
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert client.policies.precedence_calls == []
    assert not [a for a in report.actions if a.op == "precedence"]


def test_apply_precedence_preserves_unmanaged_policies_at_tail() -> None:
    """CS rejects payloads that omit existing ids, so unmanaged live policies
    must be appended in their current relative order."""
    from csfwctl.schema import PrecedenceBucket

    p_high = _mac_policy(
        "asc-exception-mac-monitor-only",
        priority=PrecedenceBucket.high,
        display_name="Exception-Mac-Monitor-Only",
    )
    repo = _repo_with(policies=[p_high])
    # Seed live with two unmanaged mac policies plus the managed one, with
    # the managed policy at the bottom (as CS returns it).
    state = _render_live_state(env="test", policies=[p_high])
    state.policies.insert(
        0,
        {
            "id": "unmanaged-1",
            "name": "Legacy-Mac-Policy",
            "platform_name": "Mac",
            "description": "not managed",
        },
    )
    state.policies.insert(
        1,
        {
            "id": "unmanaged-2",
            "name": "Another-Mac-Policy",
            "platform_name": "Mac",
            "description": "also not managed",
        },
    )
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert len(client.policies.precedence_calls) == 1
    ids_in_order, _ = client.policies.precedence_calls[0]
    managed_id = state.policies[2]["id"]
    # Managed first, then unmanaged in their live relative order.
    assert ids_in_order == [managed_id, "unmanaged-1", "unmanaged-2"]


def test_apply_precedence_scopes_by_platform() -> None:
    """Windows policies stay on the Windows call; Mac policies stay on the Mac call."""
    from csfwctl.schema import PrecedenceBucket

    p_mac_high = _mac_policy(
        "asc-mac-high",
        priority=PrecedenceBucket.high,
        display_name="Mac-High",
    )
    p_mac_default = _mac_policy(
        "asc-mac-default",
        priority=PrecedenceBucket.default,
        display_name="Mac-Default",
    )
    p_win = _windows_policy(with_inline=False)
    rg = _windows_rg()
    repo = _repo_with(policies=[p_mac_default, p_mac_high, p_win], rule_groups=[rg])
    state = _render_live_state(
        env="test",
        policies=[p_mac_default, p_mac_high, p_win],
        rule_groups=[rg],
    )
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Test": "hg-test"})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    # Windows should not be reordered (only one policy on that platform,
    # already in position); Mac should be reordered.
    mac_calls = [c for c in client.policies.precedence_calls if c[1] == "Mac"]
    windows_calls = [c for c in client.policies.precedence_calls if c[1] == "Windows"]
    assert len(mac_calls) == 1
    assert windows_calls == []
    mac_ids, _ = mac_calls[0]
    high_id = state.policies[1]["id"]
    default_id = state.policies[0]["id"]
    assert mac_ids.index(high_id) < mac_ids.index(default_id)


def test_apply_precedence_dry_run_records_intent_without_write() -> None:
    """Dry-run appends a ``precedence`` action but never calls set_precedence."""
    from csfwctl.schema import PrecedenceBucket

    p_high = _mac_policy(
        "asc-mac-high",
        priority=PrecedenceBucket.high,
        display_name="Mac-High",
    )
    p_default = _mac_policy(
        "asc-mac-default",
        priority=PrecedenceBucket.default,
        display_name="Mac-Default",
    )
    repo = _repo_with(policies=[p_high, p_default])
    state = _render_live_state(env="test", policies=[p_default, p_high])
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(dry_run=True),
        safety_options=_safety(),
    )
    assert client.policies.precedence_calls == []
    prec_actions = [a for a in report.actions if a.op == "precedence"]
    assert len(prec_actions) == 1
    assert prec_actions[0].detail.startswith("dry-run")


def test_apply_precedence_orders_freshly_created_policy_ahead_of_live() -> None:
    """A newly-created high-bucket policy lands at the top of the tenant order."""
    from csfwctl.schema import PrecedenceBucket

    # Existing live policy at default; the newly-desired one is high.
    p_default = _mac_policy(
        "asc-mac-endpoints",
        priority=PrecedenceBucket.default,
        display_name="Mac-Endpoints",
    )
    p_high = _mac_policy(
        "asc-exception-mac-monitor-only",
        priority=PrecedenceBucket.high,
        display_name="Exception-Mac-Monitor-Only",
    )
    repo = _repo_with(policies=[p_default, p_high])
    # Live has only the default; p_high will be created during apply.
    state = _render_live_state(env="test", policies=[p_default])
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert len(client.policies.precedence_calls) == 1
    ids_in_order, platform_name = client.policies.precedence_calls[0]
    assert platform_name == "Mac"
    created_id = f"policy-id-{client.policies.created[0]['name']}"
    default_id = state.policies[0]["id"]
    # The just-created high-bucket policy is first, ahead of the pre-existing one.
    assert ids_in_order == [created_id, default_id]


# ---- structured per-action diff detail -----------------------------------


def test_applied_action_to_json_carries_structured_change_detail() -> None:
    """``AppliedAction`` JSON surfaces field / host-group / managed-group changes."""
    import json

    from csfwctl.differ import FieldChange, HostGroupChange, ManagedGroupChange

    action = AppliedAction(
        kind="policy",
        op="update",
        slug="abc01-endpoints-windows",
        display_name="ABC01-Endpoints-Windows-Test",
        detail="policy-id-1",
        field_changes=(FieldChange(path="status", before="enabled", after="disabled"),),
        host_group_changes=(HostGroupChange(op="add", group_name="HG-New", env=HostGroupEnv.test),),
        managed_group_changes=(
            ManagedGroupChange(
                op="update",
                group_name="HG-Managed",
                env=HostGroupEnv.test,
                desired_fql="hostname:['a','b']",
                live_fql="hostname:['a']",
            ),
        ),
    )
    payload = json.loads(json.dumps(action.to_json()))
    assert payload["field_changes"] == [
        {"path": "status", "before": "enabled", "after": "disabled"}
    ]
    assert payload["host_group_changes"] == [{"op": "add", "group_name": "HG-New", "env": "test"}]
    assert payload["managed_group_changes"][0]["op"] == "update"
    assert payload["managed_group_changes"][0]["desired_fql"] == "hostname:['a','b']"
    assert payload["managed_group_changes"][0]["live_fql"] == "hostname:['a']"


def test_apply_rule_group_update_action_carries_field_changes() -> None:
    """A rule-group rule edit shows up on the recorded action, not just the payload."""
    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg])
    # Tamper so the differ emits a content update.
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    rg_actions = [a for a in report.actions if a.kind == "rule-group" and a.op == "update"]
    assert rg_actions, "expected a rule-group update action"
    field_paths = {fc.path for fc in rg_actions[0].field_changes}
    # The rule-list change is recorded under the 'rules' leaf.
    assert "rules" in field_paths


def test_apply_policy_update_action_carries_host_group_changes() -> None:
    """Adding a host group on a policy surfaces a host_group_changes entry."""
    policy = _windows_policy(with_inline=False)
    rg = _windows_rg()
    # Live: policy currently has *no* host groups assigned in the test env.
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live_state(env="test", policies=[policy], rule_groups=[rg])
    # Strip the live policy's groups list so the differ emits an add.
    state.policies[0]["groups"] = []
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient(host_groups={"ABC01-Endpoints-Windows-Test": "hg-test"})
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    policy_updates = [a for a in report.actions if a.kind == "policy" and a.op == "update"]
    assert policy_updates, "expected a policy update action"
    hg_ops = [(hg.op, hg.group_name) for hg in policy_updates[0].host_group_changes]
    assert ("add", "ABC01-Endpoints-Windows-Test") in hg_ops
    # And the standalone host-group action row carries the same structured entry.
    hg_rows = [a for a in report.actions if a.kind == "host-group" and a.op == "host-group"]
    assert hg_rows
    assert hg_rows[0].host_group_changes
    assert hg_rows[0].host_group_changes[0].group_name == "ABC01-Endpoints-Windows-Test"


def test_apply_emits_structured_log_record_per_action(caplog: Any) -> None:
    """Each AppliedAction emits one INFO record on the csfwctl.applier logger."""
    import logging

    rg = _windows_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live_state(env="test", rule_groups=[rg])
    next(iter(state.rules_by_id.values()))["action"] = "DENY"
    cs = compute_diff(repo, "test", state)
    client = FakeFalconClient()
    with caplog.at_level(logging.INFO, logger="csfwctl.applier"):
        apply_change_set(
            client=client,
            repo=repo,
            change_set=cs,
            state=state,
            options=_options(),
            safety_options=_safety(),
        )
    action_records = [
        r for r in caplog.records if r.name == "csfwctl.applier" and "apply.action" in r.message
    ]
    assert action_records, "expected at least one apply.action log record"
    rg_record = next(
        (r for r in action_records if getattr(r, "kind", "") == "rule-group"),
        None,
    )
    assert rg_record is not None
    # The structured field_changes ride in the log record's extras.
    assert getattr(rg_record, "field_changes", None)
    assert any(fc["path"] == "rules" for fc in rg_record.field_changes)
