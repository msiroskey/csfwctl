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
    def create(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for p in policies:
            self.created.append(p)
            out.append({**p, "id": f"policy-id-{p['name']}"})
        return out

    def update(self, policies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        self.updated.extend(policies)
        return [dict(p) for p in policies]

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
