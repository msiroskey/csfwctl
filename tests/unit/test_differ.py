"""Unit tests for :mod:`csfwctl.differ`.

The differ consumes a loaded ``ConfigRepo`` and a hand-built
:class:`LiveState`; we lean on the exporter's ``*_to_api_shape`` helpers
to render desired models into the same shapes a real tenant would return.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from csfwctl.differ import (
    METADATA_SIGNATURE_TOKEN,
    ChangeSet,
    DiffOp,
    LiveState,
    ManagedStatus,
    build_desired_state,
    compute_diff,
    env_suffix,
    is_managed_description,
    project_policy_for_env,
    synthesise_override_rule_groups,
)
from csfwctl.exporter import (
    location_to_api_shape,
    policy_to_api_shape,
    rule_group_to_api_shape,
)
from csfwctl.loader import ConfigRepo, load_config_repo
from csfwctl.schema import (
    Action,
    Direction,
    Endpoint,
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

# ---- helpers --------------------------------------------------------------


def _baseline_rg() -> RuleGroup:
    return RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="Allow established inbound",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
            ),
        ],
    )


def _abc_policy(with_inline: bool = True) -> Policy:
    rules = (
        [
            Rule(
                name="Allow corp DNS outbound",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.udp,
                remote=Endpoint(addresses=["10.1.1.53"], ports=[53]),
            )
        ]
        if with_inline
        else []
    )
    return Policy(
        name="ABC01-Endpoints-Windows",
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
    policies: list[Policy] | None = None,
    rule_groups: list[RuleGroup] | None = None,
    locations: list[Location] | None = None,
    tombstones: Tombstones | None = None,
    root: Path | None = None,
) -> ConfigRepo:
    return ConfigRepo(
        root=root or Path("/tmp/fake"),
        policies={p.name.lower(): p for p in policies or []},
        rule_groups={rg.name: rg for rg in rule_groups or []},
        locations={loc.name: loc for loc in locations or []},
        tombstones=tombstones or Tombstones(),
    )


def _render_live(
    *,
    env: str,
    policies: list[Policy] = (),
    rule_groups: list[RuleGroup] = (),
    locations: list[Location] = (),
    description_for_managed: bool = True,
    extra_rule_groups_for_overrides: bool = True,
) -> LiveState:
    """Render desired models into API shapes for one env and bundle into LiveState.

    ``description_for_managed`` flips the metadata-signature trailer on
    every record so ``_classify_managed`` returns ``managed``. Set False
    to simulate live records that pre-date csfwctl's adoption.
    """
    state = LiveState()
    rules_by_id: dict[str, dict[str, Any]] = {}

    for rg in rule_groups:
        shape = rule_group_to_api_shape(rg, env)
        if description_for_managed:
            shape["description"] = (shape.get("description") or "") + (
                "\n" + METADATA_SIGNATURE_TOKEN + " | version: 1 | git_sha: abc123 | env: " + env
            )
        state.rule_groups.append(shape)
        for rule in shape.get("rules", []):
            rules_by_id[str(rule["id"])] = rule

    for policy in policies:
        shape = policy_to_api_shape(policy, env)
        if description_for_managed:
            shape["description"] = (shape.get("description") or "") + (
                "\n" + METADATA_SIGNATURE_TOKEN + " | version: 1 | git_sha: abc123 | env: " + env
            )
        # Filter groups to only this env's so live looks realistic.
        only_env = HostGroupEnv(env)
        shape["groups"] = [
            g for g in shape["groups"] if policy.host_groups.get(g["name"]) is only_env
        ]
        state.policies.append(shape)
        if policy.rules and extra_rule_groups_for_overrides:
            override_slug = f"{policy.name.lower()}-overrides-{env}"
            override_rg = RuleGroup(
                name=override_slug,
                platform=policy.platform,
                rules=list(policy.rules),
            )
            rg_shape = rule_group_to_api_shape(override_rg, env)
            # Override-RGs already carry env in slug; convention applies env suffix too.
            rg_shape["name"] = f"{override_slug}-{env.title()}"
            if description_for_managed:
                rg_shape["description"] = (rg_shape.get("description") or "") + (
                    "\n"
                    + METADATA_SIGNATURE_TOKEN
                    + " | version: 1 | git_sha: abc123 | env: "
                    + env
                )
            state.rule_groups.append(rg_shape)
            for rule in rg_shape.get("rules", []):
                rules_by_id[str(rule["id"])] = rule

    for loc in locations:
        shape = location_to_api_shape(loc)
        if description_for_managed:
            shape["description"] = (shape.get("description") or "") + (
                "\n" + METADATA_SIGNATURE_TOKEN + " | version: 1 | git_sha: abc123 | env: any"
            )
        state.locations.append(shape)

    state.rules_by_id = rules_by_id
    return state


# ---- managed-signature detection -----------------------------------------


def test_is_managed_description_detects_signature() -> None:
    assert is_managed_description("Baseline policy.\nManaged by csfwctl | version: 1") is True
    assert is_managed_description("Baseline policy.") is False
    assert is_managed_description("") is False
    assert is_managed_description(None) is False


# ---- env helpers ---------------------------------------------------------


def test_env_suffix_capitalizes() -> None:
    assert env_suffix("test") == "-Test"
    assert env_suffix("pilot") == "-Pilot"
    assert env_suffix("production") == "-Production"


# ---- override-RG synthesis ----------------------------------------------


def test_synthesise_override_rule_groups_only_for_inline_rules() -> None:
    inline_policy = _abc_policy(with_inline=True)
    no_inline_policy = Policy(
        name="Quiet-Policy",
        platform=Platform.windows,
        rule_groups=["windows-baseline"],
    )
    repo = _repo_with(
        policies=[inline_policy, no_inline_policy],
        rule_groups=[_baseline_rg()],
    )
    overrides = synthesise_override_rule_groups(repo, "test")
    assert set(overrides) == {"abc01-endpoints-windows-overrides-test"}
    rg = overrides["abc01-endpoints-windows-overrides-test"]
    assert rg.platform is Platform.windows
    assert [r.name for r in rg.rules] == ["Allow corp DNS outbound"]


def test_synthesise_override_rule_groups_empty_when_no_inline() -> None:
    policy = _abc_policy(with_inline=False)
    repo = _repo_with(policies=[policy], rule_groups=[_baseline_rg()])
    overrides = synthesise_override_rule_groups(repo, "pilot")
    assert overrides == {}


# ---- policy projection ---------------------------------------------------


def test_project_policy_for_env_filters_host_groups() -> None:
    policy = _abc_policy(with_inline=True)
    projected = project_policy_for_env(
        policy, "abc01-endpoints-windows", "test", override_present=True
    )
    assert set(projected.host_groups) == {"ABC01-Endpoints-Windows-Test"}
    # Override slug is prepended; inline rules are emptied.
    assert projected.rules == []
    assert projected.rule_groups[0] == "abc01-endpoints-windows-overrides-test"
    assert projected.rule_groups[1] == "windows-baseline"


def test_project_policy_for_env_no_inline_keeps_rule_groups() -> None:
    policy = _abc_policy(with_inline=False)
    projected = project_policy_for_env(
        policy, "abc01-endpoints-windows", "pilot", override_present=False
    )
    assert projected.rule_groups == ["windows-baseline"]
    assert projected.rules == []
    assert set(projected.host_groups) == {"ABC01-Endpoints-Windows-Pilot"}


# ---- desired-state builder -----------------------------------------------


def test_build_desired_state_includes_synthesised_overrides() -> None:
    repo = _repo_with(
        policies=[_abc_policy(with_inline=True)],
        rule_groups=[_baseline_rg()],
    )
    policies, rule_groups, locations = build_desired_state(repo, "test")
    assert set(rule_groups) == {"windows-baseline", "abc01-endpoints-windows-overrides-test"}
    assert set(policies) == {"abc01-endpoints-windows"}
    assert locations == {}


# ---- end-to-end diff: no changes ----------------------------------------


def test_compute_diff_no_changes_when_live_matches_desired() -> None:
    rg = _baseline_rg()
    policy = _abc_policy(with_inline=True)
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])

    cs = compute_diff(repo, "test", state)
    assert cs.has_changes is False
    assert cs.total_changes == 0
    # We should have a no-change entry per logical object (policy + base
    # RG + synthesised override RG).
    assert len(cs.no_changes) == 3
    assert all(c.op is DiffOp.no_change for c in cs.no_changes)


# ---- end-to-end diff: creates -------------------------------------------


def test_compute_diff_creates_when_live_is_empty() -> None:
    repo = _repo_with(
        policies=[_abc_policy(with_inline=False)],
        rule_groups=[_baseline_rg()],
        locations=[Location(name="corp-vpn", addresses=["10.100.0.0/16"])],
    )
    cs = compute_diff(repo, "test", LiveState())

    assert cs.has_changes is True
    kinds = sorted(c.kind for c in cs.creates)
    assert kinds == ["location", "policy", "rule-group"]
    assert all(c.managed is ManagedStatus.new for c in cs.creates)


# ---- end-to-end diff: updates -------------------------------------------


def test_compute_diff_update_detects_rule_changes() -> None:
    rg = _baseline_rg()
    # Live has the rule group, but rule action is different.
    state = _render_live(env="test", rule_groups=[rg])
    # Tamper with the live rule's action so the diff sees a change.
    live_rule = next(iter(state.rules_by_id.values()))
    live_rule["action"] = "DENY"

    repo = _repo_with(rule_groups=[rg])
    cs = compute_diff(repo, "test", state)
    assert len(cs.updates) == 1
    update = cs.updates[0]
    assert update.kind == "rule-group"
    assert update.slug == "windows-baseline"
    # The field diff lands somewhere under rules.
    assert any("rules" in fc.path for fc in update.field_changes)


def test_compute_diff_update_detects_host_group_change() -> None:
    policy = _abc_policy(with_inline=False)
    rg = _baseline_rg()
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])
    # Remove the host group entry from the live policy record.
    state.policies[0]["groups"] = []

    repo = _repo_with(policies=[policy], rule_groups=[rg])
    cs = compute_diff(repo, "test", state)
    update = next(c for c in cs.updates if c.kind == "policy")
    assert update.host_group_changes
    assert update.host_group_changes[0].op == "add"
    assert update.host_group_changes[0].group_name == "ABC01-Endpoints-Windows-Test"


# ---- end-to-end diff: deletes / tombstones ------------------------------


def test_compute_diff_delete_requires_matching_tombstone() -> None:
    rg = _baseline_rg()
    other_rg = RuleGroup(name="legacy-rdp-allow", platform=Platform.windows)
    repo = _repo_with(
        rule_groups=[rg],
        tombstones=Tombstones(
            rule_groups=[
                TombstoneEntry(
                    name="legacy-rdp-allow",
                    deleted_in_sha="def5678",
                    reason="Folded into baseline.",
                )
            ]
        ),
    )
    state = _render_live(env="test", rule_groups=[rg, other_rg])

    cs = compute_diff(repo, "test", state)
    assert any(c.slug == "legacy-rdp-allow" for c in cs.deletes)
    delete = next(c for c in cs.deletes if c.slug == "legacy-rdp-allow")
    assert delete.op is DiffOp.delete
    assert delete.reason == "tombstoned"


def test_compute_diff_unmanaged_when_live_only_and_no_tombstone() -> None:
    rg = _baseline_rg()
    unknown_rg = RuleGroup(name="random-extra", platform=Platform.windows)
    repo = _repo_with(rule_groups=[rg])
    state = _render_live(env="test", rule_groups=[rg, unknown_rg], description_for_managed=False)

    cs = compute_diff(repo, "test", state)
    assert cs.has_changes is False
    assert any(c.slug == "random-extra" for c in cs.unmanaged)
    extra = next(c for c in cs.unmanaged if c.slug == "random-extra")
    assert extra.managed is ManagedStatus.unmanaged


# ---- env filtering -------------------------------------------------------


def test_compute_diff_ignores_other_envs() -> None:
    """Live records for ``-Pilot`` must not influence a ``--env test`` run."""
    rg = _baseline_rg()
    repo = _repo_with(rule_groups=[rg])
    test_state = _render_live(env="test", rule_groups=[rg])
    pilot_state = _render_live(env="pilot", rule_groups=[rg])
    combined = LiveState(
        rule_groups=test_state.rule_groups + pilot_state.rule_groups,
        rules_by_id={**test_state.rules_by_id, **pilot_state.rules_by_id},
    )
    cs = compute_diff(repo, "test", combined)
    # No changes, because the Test live state matches desired.
    assert cs.has_changes is False


# ---- override-RG round trip ---------------------------------------------


def test_compute_diff_recognises_override_rule_groups_matching_live() -> None:
    """Inline policy rules round-trip when live carries the override-RG."""
    rg = _baseline_rg()
    policy = _abc_policy(with_inline=True)
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])

    cs = compute_diff(repo, "test", state)
    assert cs.has_changes is False
    # The override RG is reflected in the no-changes list.
    slugs = {c.slug for c in cs.no_changes if c.kind == "rule-group"}
    assert "abc01-endpoints-windows-overrides-test" in slugs


def test_compute_diff_warns_about_orphan_override_rule_group() -> None:
    """When live has an override-RG but desired policy lost its inline rules."""
    rg = _baseline_rg()
    policy_no_inline = _abc_policy(with_inline=False)
    policy_with_inline = _abc_policy(with_inline=True)
    repo = _repo_with(policies=[policy_no_inline], rule_groups=[rg])
    # Live still has the override-RG (from a previous apply).
    state = _render_live(env="test", policies=[policy_with_inline], rule_groups=[rg])

    cs = compute_diff(repo, "test", state)
    assert any("orphan override rule group" in w for w in cs.warnings)


# ---- JSON serialization -------------------------------------------------


def test_change_set_to_json_round_trips() -> None:
    import json

    rg = _baseline_rg()
    repo = _repo_with(rule_groups=[rg])
    state = _render_live(env="test", rule_groups=[rg])
    live_rule = next(iter(state.rules_by_id.values()))
    live_rule["action"] = "DENY"

    cs = compute_diff(repo, "test", state)
    payload = json.dumps(cs.to_json())
    parsed = json.loads(payload)
    assert parsed["env"] == "test"
    assert parsed["summary"]["updates"] == 1
    assert parsed["updates"][0]["kind"] == "rule-group"
    assert parsed["updates"][0]["op"] == "update"


# ---- unknown env --------------------------------------------------------


def test_compute_diff_rejects_unknown_env() -> None:
    repo = _repo_with(rule_groups=[_baseline_rg()])
    with pytest.raises(ValueError, match="unknown env"):
        compute_diff(repo, "qa", LiveState())


# ---- realistic fixture integration --------------------------------------


def test_compute_diff_against_realistic_repo_with_matching_live(
    realistic_repo_path: Path,
) -> None:
    """Round-trip the realistic fixture against its rendered live state."""
    repo = load_config_repo(realistic_repo_path)
    state = LiveState()
    rules_by_id: dict[str, dict[str, Any]] = {}

    # Render every policy/rule-group/location for env=test and stuff it
    # into LiveState.  Override-RGs get synthesised the same way the
    # helper above does — we replicate that inline here for clarity.
    for rg in repo.rule_groups.values():
        shape = rule_group_to_api_shape(rg, "test")
        shape["description"] = (shape.get("description") or "") + (
            "\n" + METADATA_SIGNATURE_TOKEN + " | env: test"
        )
        state.rule_groups.append(shape)
        for rule in shape.get("rules", []):
            rules_by_id[str(rule["id"])] = rule

    for slug, policy in repo.policies.items():
        shape = policy_to_api_shape(policy, "test")
        shape["description"] = (shape.get("description") or "") + (
            "\n" + METADATA_SIGNATURE_TOKEN + " | env: test"
        )
        shape["groups"] = [
            g for g in shape["groups"] if policy.host_groups.get(g["name"]) is HostGroupEnv.test
        ]
        state.policies.append(shape)
        if policy.rules:
            override_slug = f"{slug}-overrides-test"
            override_rg = RuleGroup(
                name=override_slug, platform=policy.platform, rules=list(policy.rules)
            )
            rg_shape = rule_group_to_api_shape(override_rg, "test")
            rg_shape["name"] = f"{override_slug}-Test"
            rg_shape["description"] = METADATA_SIGNATURE_TOKEN + " | env: test"
            state.rule_groups.append(rg_shape)
            for rule in rg_shape.get("rules", []):
                rules_by_id[str(rule["id"])] = rule

    for loc in repo.locations.values():
        shape = location_to_api_shape(loc)
        shape["description"] = (shape.get("description") or "") + (
            "\n" + METADATA_SIGNATURE_TOKEN + " | env: any"
        )
        state.locations.append(shape)

    state.rules_by_id = rules_by_id

    cs = compute_diff(repo, "test", state)
    assert cs.has_changes is False, [
        (c.kind, c.slug, [(fc.path, fc.before, fc.after) for fc in c.field_changes])
        for c in cs.updates
    ]


# ---- empty repo + empty live --------------------------------------------


def test_compute_diff_empty_repo_empty_live_is_clean() -> None:
    repo = _repo_with()
    cs = compute_diff(repo, "test", LiveState())
    assert cs.has_changes is False
    assert cs.no_changes == []
    assert cs.unmanaged == []


# ---- managed flag on updates ---------------------------------------------


def test_compute_diff_marks_updates_as_managed_when_signature_present() -> None:
    rg = _baseline_rg()
    state = _render_live(env="test", rule_groups=[rg])
    state.rules_by_id[next(iter(state.rules_by_id))]["action"] = "DENY"

    cs = compute_diff(_repo_with(rule_groups=[rg]), "test", state)
    assert cs.updates[0].managed is ManagedStatus.managed


def test_change_set_helpers() -> None:
    cs = ChangeSet(env="test")
    assert cs.has_changes is False
    assert cs.total_changes == 0
    assert cs.all_actionable() == []
