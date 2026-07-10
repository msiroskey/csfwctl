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
    compute_all_envs_diff,
    compute_diff,
    compute_precedence_diff,
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
    AddressFamily,
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
        name="quiet-policy",
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


def test_build_desired_state_drops_redundant_rule_group_address_family() -> None:
    """A YAML ``address_family`` matching inference is dropped on the desired side.

    ``rule_from_api`` only pins ``address_family`` on the live side when the
    wire value diverges from inference. Without the mirror step on the desired
    side, a YAML rule that pins ``address_family: ip4`` on an already-IPv4
    rule produced a spurious ``None -> 'ip4'`` field change against the
    canonicalised live rule.
    """
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="Allow updater outbound",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
                address_family=AddressFamily.ip4,  # redundant: inference already IP4
                remote=Endpoint(addresses=["10.0.0.0/8"]),
            ),
        ],
    )
    repo = _repo_with(rule_groups=[rg])
    _, rule_groups, _ = build_desired_state(repo, "test")
    assert rule_groups["windows-baseline"].rules[0].address_family is None


def test_build_desired_state_preserves_divergent_rule_group_address_family() -> None:
    """An ``address_family`` that diverges from inference is kept intact."""
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="App-based rule",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
                address_family=AddressFamily.ip4,  # no addresses → inference NONE
            ),
        ],
    )
    repo = _repo_with(rule_groups=[rg])
    _, rule_groups, _ = build_desired_state(repo, "test")
    assert rule_groups["windows-baseline"].rules[0].address_family is AddressFamily.ip4


def test_build_desired_state_canonicalises_inherited_policy_rules() -> None:
    """An inherited policy's inline rules are canonicalised in the override RG.

    Regression for the report: adding a new inherited policy surfaced the
    parent's redundantly-pinned ``address_family`` on every diff.
    """
    parent_rule = Rule(
        name="Allow updater outbound",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        address_family=AddressFamily.ip4,  # matches inference (IPv4 remote)
        remote=Endpoint(addresses=["10.0.0.0/8"]),
    )
    parent = Policy(
        name="parent-policy",
        platform=Platform.windows,
        rules=[parent_rule],
        host_groups={"Parent-HG-Test": HostGroupEnv.test},
    )
    child = Policy(
        name="child-policy",
        platform=Platform.windows,
        inherits="parent-policy",
        host_groups={"Child-HG-Test": HostGroupEnv.test},
    )
    repo = _repo_with(policies=[parent, child])
    _, rule_groups, _ = build_desired_state(repo, "test")
    for slug in ("parent-policy-overrides-test", "child-policy-overrides-test"):
        assert rule_groups[slug].rules[0].address_family is None


def test_compute_diff_no_change_when_yaml_pins_redundant_address_family() -> None:
    """End-to-end: redundant explicit ``address_family: ip4`` in YAML no
    longer trips ``compute_diff`` when the live wire matches inference.
    """
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="Allow updater outbound",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
                address_family=AddressFamily.ip4,
                remote=Endpoint(addresses=["10.0.0.0/8"]),
            ),
        ],
    )
    policy = Policy(
        name="abc01-endpoints-windows",
        display_name="ABC01-Endpoints-Windows",
        platform=Platform.windows,
        rule_groups=["windows-baseline"],
        host_groups={"ABC01-Endpoints-Windows-Test": HostGroupEnv.test},
    )
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])

    cs = compute_diff(repo, "test", state)
    assert cs.total_changes == 0, [
        (c.op, c.display_name, [(fc.path, fc.before, fc.after) for fc in c.field_changes])
        for c in cs.all_actionable()
    ]


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
    # The structured change keeps the whole ``rules`` list intact — the
    # applier consumes it to build the JSON-Patch payload.
    assert any("rules" in fc.path for fc in update.field_changes)


# ---- list-level diff granularity (display expansion) --------------------
#
# The structured ChangeSet keeps list values opaque (so the applier can
# turn the whole ``rules`` change into JSON-Patch ops). ``expand_field_change``
# is the display-time projection that breaks an opaque list change down
# into per-element / per-leaf entries for the human-readable diff output.


def test_expand_field_change_reports_only_changed_rule_field() -> None:
    """Adding a field to one rule reports just that leaf, not the whole list.

    Mirrors the real-world report where a single rule gained a
    ``file_path`` and the old opaque-list diff dumped every rule twice.
    """
    from csfwctl.differ import FieldChange, expand_field_change

    before = [
        {"name": "SSH", "action": "allow", "protocol": "tcp"},
        {"name": "Airdrop", "action": "allow", "protocol": "udp"},
        {"name": "Rapport", "action": "allow", "protocol": "tcp"},
    ]
    after = [
        {"name": "SSH", "action": "allow", "protocol": "tcp"},
        {
            "name": "Airdrop",
            "action": "allow",
            "protocol": "udp",
            "file_path": "/usr/libexec/sharingd",
        },
        {"name": "Rapport", "action": "allow", "protocol": "tcp"},
    ]
    leaves = expand_field_change(FieldChange(path="rules", before=before, after=after))
    assert [(c.path, c.before, c.after) for c in leaves] == [
        ("rules[Airdrop].file_path", None, "/usr/libexec/sharingd"),
    ]


def test_expand_field_change_reports_add_and_remove() -> None:
    """A removed rule and an added rule are reported as whole items by key."""
    from csfwctl.differ import FieldChange, expand_field_change

    before = [{"name": "Keep"}, {"name": "Drop"}]
    after = [{"name": "Keep"}, {"name": "New"}]
    leaves = expand_field_change(FieldChange(path="rules", before=before, after=after))
    by_path = {c.path: (c.before, c.after) for c in leaves}
    assert by_path == {
        "rules[Drop]": ({"name": "Drop"}, None),
        "rules[New]": (None, {"name": "New"}),
    }


def test_expand_field_change_reports_reorder_compactly() -> None:
    """A pure reorder surfaces as a single compact (order) entry."""
    from csfwctl.differ import FieldChange, expand_field_change

    before = [{"name": "A"}, {"name": "B"}, {"name": "C"}]
    after = [{"name": "B"}, {"name": "A"}, {"name": "C"}]
    leaves = expand_field_change(FieldChange(path="rules", before=before, after=after))
    assert [c.path for c in leaves] == ["rules (order)"]
    assert leaves[0].before == ["A", "B", "C"]
    assert leaves[0].after == ["B", "A", "C"]


def test_expand_field_change_scalar_list_uses_positional_paths() -> None:
    """Scalar lists (e.g. ports) diff positionally, surfacing the index."""
    from csfwctl.differ import FieldChange, expand_field_change

    leaves = expand_field_change(
        FieldChange(path="local.ports", before=[22, 80], after=[22, 80, 443])
    )
    assert [(c.path, c.before, c.after) for c in leaves] == [
        ("local.ports[2]", None, 443),
    ]


def test_expand_field_change_passthrough_for_scalars() -> None:
    """A non-list change is returned unchanged."""
    from csfwctl.differ import FieldChange, expand_field_change

    fc = FieldChange(path="status", before="enabled", after="disabled")
    assert expand_field_change(fc) == [fc]


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


def test_compute_diff_emits_remove_for_cross_env_host_group_drift() -> None:
    """A Pilot-env host group attached to the Test policy is drift.

    Regression: ``_host_group_changes`` previously filtered both sides
    by the current env, so a Pilot-named host group on the live Test
    policy was invisible and no ``HostGroupChange(remove)`` was
    emitted. The applier acts only on the ``HostGroupChange`` tuple,
    so the stray group was silently retained on every apply even
    though the change log reported ``host_groups.<group>: 'pilot' ->
    None`` via the field-level model diff.
    """
    policy = _abc_policy(with_inline=False)
    rg = _baseline_rg()
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])
    # Swap the (correct) Test host group for the Pilot one so the live
    # Test policy looks like it has cross-env drift: the Pilot group is
    # attached to a Test policy.
    state.policies[0]["groups"] = [
        {"id": "hg-pilot", "name": "ABC01-Endpoints-Windows-Pilot"},
    ]

    repo = _repo_with(policies=[policy], rule_groups=[rg])
    cs = compute_diff(repo, "test", state)
    update = next(c for c in cs.updates if c.kind == "policy")
    ops = {(hgc.op, hgc.group_name) for hgc in update.host_group_changes}
    # The Test group should be added, the stray Pilot group removed.
    assert ("add", "ABC01-Endpoints-Windows-Test") in ops, (
        f"missing add for the desired Test host group: {ops}"
    )
    assert ("remove", "ABC01-Endpoints-Windows-Pilot") in ops, (
        f"missing remove for the cross-env drift Pilot host group: {ops}"
    )


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


def test_compute_diff_matches_rule_group_by_display_name_when_slug_collapses() -> None:
    """Live RGs whose camelCase name does not round-trip via ``to_slug``
    are still matched against the desired YAML slug.

    Regression: a desired RG with YAML slug ``asc-mac-endpoints`` and
    display name ``ASC-MacEndpoints`` projects to live name
    ``ASC-MacEndpoints-Pilot``. Stripping the env suffix and re-slugging
    yields ``asc-macendpoints`` (``to_slug`` does not insert hyphens at
    camelCase boundaries), so a slug-only lookup misses the live record.
    The differ then emits a ``create`` and the rule-group create endpoint
    rejects it with ``Duplicate rule group name``.

    The fallback by full env-suffixed display name must produce
    ``no_change`` here, with the live record neither re-created nor
    flagged as unmanaged.
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
    state = _render_live(env="pilot", rule_groups=[rg])

    cs = compute_diff(repo, "pilot", state)
    rg_creates = [c for c in cs.creates if c.kind == "rule-group"]
    rg_unmanaged = [c for c in cs.unmanaged if c.kind == "rule-group"]
    rg_no_changes = [c for c in cs.no_changes if c.kind == "rule-group"]
    assert rg_creates == [], f"unexpected creates: {rg_creates}"
    assert rg_unmanaged == [], f"unexpected unmanaged: {rg_unmanaged}"
    assert any(c.slug == "asc-mac-endpoints" for c in rg_no_changes)


def test_compute_diff_does_not_drop_live_policy_with_unresolved_rule_group_ref() -> None:
    """A live policy that references an unfetched rule group must not vanish.

    Regression: ``policy_from_api`` raised ``ImporterError`` on a
    referenced rule-group ID that was not in the env-filtered fetched
    map, and ``_translate_live_state`` silently swallowed the exception.
    The whole live policy then disappeared from the diff and the next
    apply emitted a create, which CrowdStrike rejected with
    ``Duplicate policy name``.

    With ``tolerant_rule_group_refs=True`` in the differ's call site,
    the policy must remain visible (matched as ``no_change`` against the
    YAML policy), the unresolved reference logged via a warning rather
    than dropped silently, and no create emitted.
    """
    policy = _abc_policy(with_inline=False)
    repo = _repo_with(policies=[policy])
    state = _render_live(env="test", policies=[policy], extra_rule_groups_for_overrides=False)
    # Sabotage the live policy so it references an RG id that is not in
    # the env-filtered fetched state. Previously this crashed
    # ``policy_from_api`` and the whole policy disappeared.
    state.policies[0].setdefault("settings", {})["rule_group_ids"] = ["nonexistent-rg-id"]

    cs = compute_diff(repo, "test", state)
    policy_creates = [c for c in cs.creates if c.kind == "policy"]
    policy_no_changes = [c for c in cs.no_changes if c.kind == "policy"]
    policy_updates = [c for c in cs.updates if c.kind == "policy"]
    assert policy_creates == [], f"unexpected policy creates: {policy_creates}"
    assert any(c.slug == policy.name for c in (*policy_no_changes, *policy_updates))


def test_compute_diff_matches_policy_by_display_name_when_slug_collapses() -> None:
    """Policies with non-roundtripping camel-case display names match live.

    Mirror of the rule-group regression: a YAML slug
    ``asc-mac-endpoints`` paired with display name ``ASC-MacEndpoints``
    projects to CrowdStrike name ``ASC-MacEndpoints-Pilot``, which
    re-slugs to ``asc-macendpoints``. Without the display-name fallback
    the differ emits a phantom policy create and CrowdStrike rejects
    with ``Duplicate policy name``.
    """
    policy = Policy(
        name="asc-mac-endpoints",
        display_name="ASC-MacEndpoints",
        platform=Platform.mac,
        rule_groups=[],
    )
    repo = _repo_with(policies=[policy])
    state = _render_live(env="pilot", policies=[policy], extra_rule_groups_for_overrides=False)

    cs = compute_diff(repo, "pilot", state)
    policy_creates = [c for c in cs.creates if c.kind == "policy"]
    policy_unmanaged = [c for c in cs.unmanaged if c.kind == "policy"]
    policy_no_changes = [c for c in cs.no_changes if c.kind == "policy"]
    assert policy_creates == [], f"unexpected policy creates: {policy_creates}"
    assert policy_unmanaged == [], f"unexpected policy unmanaged: {policy_unmanaged}"
    assert any(c.slug == "asc-mac-endpoints" for c in policy_no_changes)


def test_compute_diff_does_not_report_phantom_rule_groups_slug_change() -> None:
    """A policy referencing a rule group whose display name collapses under
    ``to_slug`` must not diff its own ``rule_groups`` list against live.

    Regression: a YAML rule group ``asc-mac-endpoints`` with display name
    ``ASC-MacEndpoints`` projects to live name ``ASC-MacEndpoints-Pilot``,
    which ``policy_from_api`` re-slugs to ``asc-macendpoints`` when
    resolving the referencing policy's ``rule_group_ids``. The desired
    policy's ``rule_groups`` list carries ``asc-mac-endpoints`` from the
    YAML, so a naive comparison emitted a phantom
    ``rule_groups[0]: 'asc-macendpoints' -> 'asc-mac-endpoints'`` update
    against a policy that had not actually changed. The rule-group diff
    already reconciles the two via display-name fallback; the policy diff
    must consume that reconciliation as a live→desired slug alias before
    dumping and comparing the policy.
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
    policy = Policy(
        name="asc-mac-endpoints",
        display_name="ASC-Mac-Endpoints",
        platform=Platform.mac,
        rule_groups=[rg.name],
    )
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live(
        env="pilot",
        policies=[policy],
        rule_groups=[rg],
        extra_rule_groups_for_overrides=False,
    )
    # ``policy_to_api_shape`` derives its ``rule_group_ids`` from the
    # policy's slug reference (``asc-mac-endpoints``) while
    # ``rule_group_to_api_shape`` derives the rule group's id from its
    # display name (``ASC-MacEndpoints``). When the two diverge the fake
    # IDs no longer line up. Re-point the policy at the actual live rule
    # group id so ``policy_from_api`` can resolve the reference and the
    # test exercises the phantom-diff path we're guarding against.
    rg_live_id = state.rule_groups[0]["id"]
    state.policies[0]["settings"]["rule_group_ids"] = [rg_live_id]

    cs = compute_diff(repo, "pilot", state)
    policy_updates = [c for c in cs.updates if c.kind == "policy"]
    assert policy_updates == [], (
        f"unexpected policy updates (phantom rule_groups diff): {policy_updates}"
    )
    assert any(c.slug == policy.name for c in cs.no_changes if c.kind == "policy")


def test_compute_diff_does_not_report_phantom_priority_change() -> None:
    """A policy whose YAML sets a non-default ``priority`` bucket must not
    fire a phantom ``priority: 'default' -> '<bucket>'`` field change.

    Regression: ``policy_from_api`` hardcodes ``priority=default`` on
    every imported live record because the CrowdStrike firewall-policy
    API has no per-policy priority field — precedence is converged
    separately via ``set_precedence``. ``policy_to_api_shape`` likewise
    omits the field. Comparing ``priority`` as a policy body field
    therefore surfaced a phantom bucket transition on every apply of
    e.g. ``Exception-Mac: Monitor Only`` (``priority: high``), obscuring
    the actual change under review.
    """
    from csfwctl.schema import PrecedenceBucket

    policy = Policy(
        name="asc-exception-mac-monitor-only",
        display_name="ASC-Exception-Mac-Monitor-Only",
        platform=Platform.mac,
        priority=PrecedenceBucket.high,
        host_groups={"ASC-Exception-Mac-Monitor-Only-Test": HostGroupEnv.test},
        rule_groups=["asc-mac-endpoints"],
    )
    rg = RuleGroup(
        name="asc-mac-endpoints",
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
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live(
        env="test",
        policies=[policy],
        rule_groups=[rg],
        extra_rule_groups_for_overrides=False,
    )

    cs = compute_diff(repo, "test", state)
    policy_updates = [c for c in cs.updates if c.kind == "policy"]
    assert policy_updates == [], (
        f"unexpected policy updates (phantom priority diff): {policy_updates}"
    )
    assert any(c.slug == policy.name for c in cs.no_changes if c.kind == "policy")


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


# ---- multi-env aggregation ----------------------------------------------


def test_compute_all_envs_diff_runs_every_env() -> None:
    """One fetch, three change sets keyed by env in promotion order."""
    repo = _repo_with(
        policies=[_abc_policy(with_inline=False)],
        rule_groups=[_baseline_rg()],
    )
    multi = compute_all_envs_diff(repo, LiveState())
    assert list(multi.change_sets.keys()) == ["test", "pilot", "production"]
    # Empty live -> every env shows the same creates.
    assert all(cs.has_changes for cs in multi.change_sets.values())


def test_compute_all_envs_diff_no_env_drift_when_all_equal() -> None:
    """All envs equally behind (empty live) -> no ripple warning."""
    repo = _repo_with(
        policies=[_abc_policy(with_inline=False)],
        rule_groups=[_baseline_rg()],
        locations=[Location(name="corp-vpn", addresses=["10.100.0.0/16"])],
    )
    multi = compute_all_envs_diff(repo, LiveState())
    assert multi.has_changes is True
    assert multi.has_env_drift is False
    assert multi.env_drift_warnings == []


def test_compute_all_envs_diff_detects_downstream_ripple() -> None:
    """Test converged but pilot/production behind -> ripple warnings."""
    rg = _baseline_rg()
    policy = _abc_policy(with_inline=False)
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    # Live carries only the test-env records, so test is converged while
    # pilot and production still need the policy + rule group created.
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])

    multi = compute_all_envs_diff(repo, state)
    assert multi.change_sets["test"].has_changes is False
    assert multi.change_sets["pilot"].has_changes is True
    assert multi.change_sets["production"].has_changes is True
    assert multi.has_env_drift is True
    warnings = multi.env_drift_warnings
    assert len(warnings) == 2
    assert any(w.startswith("pilot:") for w in warnings)
    assert any(w.startswith("production:") for w in warnings)


def test_env_scoped_change_count_excludes_locations() -> None:
    """Tenant-global location changes don't count toward the ripple signal."""
    repo = _repo_with(
        locations=[Location(name="corp-vpn", addresses=["10.100.0.0/16"])],
    )
    cs = compute_diff(repo, "test", LiveState())
    # One location create, but it is excluded from the env-scoped count.
    assert cs.total_changes == 1
    assert cs.env_scoped_change_count == 0


def test_multi_env_diff_to_json_shape() -> None:
    import json

    rg = _baseline_rg()
    policy = _abc_policy(with_inline=False)
    repo = _repo_with(policies=[policy], rule_groups=[rg])
    state = _render_live(env="test", policies=[policy], rule_groups=[rg])

    multi = compute_all_envs_diff(repo, state)
    payload = json.loads(json.dumps(multi.to_json()))
    assert set(payload["summary"].keys()) == {"test", "pilot", "production"}
    assert payload["env_drift"] is True
    assert len(payload["env_drift_warnings"]) == 2
    assert set(payload["change_sets"].keys()) == {"test", "pilot", "production"}
    assert payload["change_sets"]["test"]["env"] == "test"
    assert payload["precedence_deltas"] == {}
    assert payload["precedence_warnings"] == []


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


# ---- family-id rule lookup (fetch_live_state) ----------------------------


def test_compute_diff_detects_update_when_rules_keyed_by_family_id() -> None:
    """Differ must not treat a rule group as 'new' when rule_ids are family IDs.

    CrowdStrike group GET records carry hex family IDs in rule_ids that differ
    from the numeric id on the rule detail records.  If rules_by_id is only
    keyed by numeric id, rule_group_from_api raises ImporterError and the group
    is silently dropped from the live state — causing a create instead of an
    update on every subsequent apply.  fetch_live_state now uses multi-strategy
    lookup (numeric id + value scan + positional fallback) to handle both forms.
    We simulate the mismatch here: rule_ids = ["family-abc"], rule record id = "42".
    """
    rg = _baseline_rg()
    shape = rule_group_to_api_shape(rg, "test")
    # Replace the shape's rule_ids with a fake family ID that won't match
    # the numeric id in the rule records.
    family_id = "838b17a58aab40e59c9a952299fd0b00"
    rule_record = shape["rules"][0]
    rule_record["id"] = "42"  # numeric id on the detail record
    shape["rule_ids"] = [family_id]

    # Build a LiveState that mirrors the fetch_live_state mismatch:
    # rules_by_id is keyed by family_id (multi-strategy would produce this),
    # not by the numeric "42".
    state = LiveState()
    state.rule_groups = [shape]
    state.rules_by_id = {family_id: rule_record}  # family-id key, as multi-strategy builds it

    cs = compute_diff(_repo_with(rule_groups=[rg]), "test", state)
    # Group is correctly detected as existing (no creates).
    assert not cs.creates, f"unexpected creates: {cs.creates}"


# ---- skip_unassigned_envs / tombstone_unassigned_envs --------------------


def _override_only_policy(
    *,
    envs: dict[str, HostGroupEnv] | None = None,
    skip: bool = True,
    tombstone: bool = False,
    managed_hosts: dict[HostGroupEnv, list[str]] | None = None,
) -> Policy:
    """Single-env override-style policy for the skip/tombstone tests."""
    return Policy(
        name="abc01-adhoc-override",
        display_name="ABC01-AdHoc-Override",
        platform=Platform.windows,
        host_groups=envs or {},
        managed_host_groups=managed_hosts or {},
        rules=[
            Rule(
                name="Allow local ssh",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
                remote=Endpoint(ports=[22]),
            )
        ],
        skip_unassigned_envs=skip,
        tombstone_unassigned_envs=tombstone,
    )


def test_build_desired_state_skips_unassigned_env() -> None:
    policy = _override_only_policy(envs={"ABC01-AdHoc-Test": HostGroupEnv.test})
    repo = _repo_with(policies=[policy])
    # Bound to test → present in test's desired state, plus its override RG.
    policies, rule_groups, _ = build_desired_state(repo, "test")
    assert "abc01-adhoc-override" in policies
    assert "abc01-adhoc-override-overrides-test" in rule_groups
    # Unassigned in pilot → dropped entirely.
    policies, rule_groups, _ = build_desired_state(repo, "pilot")
    assert "abc01-adhoc-override" not in policies
    assert "abc01-adhoc-override-overrides-pilot" not in rule_groups


def test_build_desired_state_managed_host_groups_count_as_assignment() -> None:
    policy = _override_only_policy(
        managed_hosts={HostGroupEnv.pilot: ["host-a", "host-b"]},
    )
    repo = _repo_with(policies=[policy])
    policies, _, _ = build_desired_state(repo, "pilot")
    assert "abc01-adhoc-override" in policies
    policies, _, _ = build_desired_state(repo, "production")
    assert "abc01-adhoc-override" not in policies


def test_build_desired_state_flag_off_still_generates_all_envs() -> None:
    policy = _override_only_policy(envs={"ABC01-AdHoc-Test": HostGroupEnv.test}, skip=False)
    repo = _repo_with(policies=[policy])
    for env in ("test", "pilot", "production"):
        policies, _, _ = build_desired_state(repo, env)
        assert "abc01-adhoc-override" in policies


def test_compute_diff_skipped_unassigned_env_reports_managed_live_as_unmanaged() -> None:
    """Skip alone (no tombstone): a stale managed object is preserved.

    The safety invariant is that deletes require an explicit tombstone.
    Without ``tombstone_unassigned_envs`` a lingering managed object in
    an unassigned env is reported as unmanaged (i.e. drift) so an
    operator has to notice it, not silently deleted.
    """
    policy = _override_only_policy(envs={"ABC01-AdHoc-Test": HostGroupEnv.test})
    repo = _repo_with(policies=[policy])
    # Pretend the object exists live in pilot even though it's unassigned there.
    pilot_policy = _override_only_policy(envs={"ABC01-AdHoc-Pilot": HostGroupEnv.pilot}, skip=False)
    live = _render_live(env="pilot", policies=[pilot_policy])
    cs = compute_diff(repo, "pilot", live)
    assert not cs.deletes
    assert any(u.slug == "abc01-adhoc-override" for u in cs.unmanaged)


def test_compute_diff_tombstone_flag_auto_deletes_managed_live() -> None:
    """With tombstone_unassigned_envs, the stale managed object is queued for delete."""
    policy = _override_only_policy(envs={"ABC01-AdHoc-Test": HostGroupEnv.test}, tombstone=True)
    repo = _repo_with(policies=[policy])
    pilot_policy = _override_only_policy(envs={"ABC01-AdHoc-Pilot": HostGroupEnv.pilot}, skip=False)
    live = _render_live(env="pilot", policies=[pilot_policy])
    cs = compute_diff(repo, "pilot", live)
    delete_slugs = {d.slug for d in cs.deletes}
    assert "abc01-adhoc-override" in delete_slugs
    # Its synthesised override rule group is auto-deleted too.
    assert "abc01-adhoc-override-overrides-pilot" in delete_slugs
    policy_delete = next(d for d in cs.deletes if d.slug == "abc01-adhoc-override")
    assert policy_delete.reason == "unassigned in env; tombstone_unassigned_envs=true"


def test_compute_diff_tombstone_flag_leaves_unmanaged_live_alone() -> None:
    """An unmanaged live object (no csfwctl signature) is never auto-deleted."""
    policy = _override_only_policy(envs={"ABC01-AdHoc-Test": HostGroupEnv.test}, tombstone=True)
    repo = _repo_with(policies=[policy])
    pilot_policy = _override_only_policy(envs={"ABC01-AdHoc-Pilot": HostGroupEnv.pilot}, skip=False)
    live = _render_live(env="pilot", policies=[pilot_policy], description_for_managed=False)
    cs = compute_diff(repo, "pilot", live)
    assert not any(d.slug == "abc01-adhoc-override" for d in cs.deletes)
    assert any(u.slug == "abc01-adhoc-override" for u in cs.unmanaged)


def test_compute_diff_skip_keeps_other_envs_creating_normally() -> None:
    """The flag is per-env; the assigned env still gets create+apply."""
    policy = _override_only_policy(envs={"ABC01-AdHoc-Test": HostGroupEnv.test}, tombstone=True)
    repo = _repo_with(policies=[policy])
    # Nothing live in test yet → create expected.
    cs = compute_diff(repo, "test", LiveState())
    slugs = {c.slug for c in cs.creates}
    assert "abc01-adhoc-override" in slugs
    assert "abc01-adhoc-override-overrides-test" in slugs


# ---- precedence preview --------------------------------------------------


def _mac_policy_with_priority(slug: str, display: str, bucket: Any) -> Policy:
    """Minimal mac policy assigned to Test — enough for precedence resolution."""
    from csfwctl.schema import PrecedenceBucket

    return Policy(
        name=slug,
        display_name=display,
        platform=Platform.mac,
        priority=bucket if isinstance(bucket, PrecedenceBucket) else PrecedenceBucket(bucket),
        host_groups={f"{display}-Test": HostGroupEnv.test},
    )


def test_compute_precedence_diff_flags_high_bucket_move_up() -> None:
    """A ``high`` policy sitting below defaults on the tenant surfaces as a move.

    Regression: `Exception-Mac: Monitor Only` (priority high) shipped
    below its `default`-bucket sibling in the tenant. Applying the
    resolver's precedence should lift it above; the diff-time preview
    must surface that transition so the operator knows the ordering
    call is coming.
    """
    from csfwctl.schema import PrecedenceBucket

    endpoints = _mac_policy_with_priority(
        "asc-mac-endpoints", "Asc-Mac-Endpoints", PrecedenceBucket.default
    )
    exception = _mac_policy_with_priority(
        "asc-exception-mac-monitor-only",
        "Asc-Exception-Mac-Monitor-Only",
        PrecedenceBucket.high,
    )
    repo = _repo_with(policies=[endpoints, exception])
    state = _render_live(env="test", policies=[endpoints, exception])
    # Simulate the tenant returning `default` ahead of `high` in
    # precedence.asc — that is exactly the pre-apply state.
    state.precedence_ids_by_platform = {
        "Mac": [state.policies[0]["id"], state.policies[1]["id"]],
    }

    deltas, warnings = compute_precedence_diff(repo, state)
    assert warnings == []
    assert Platform.mac in deltas
    delta = deltas[Platform.mac]
    move_by_slug = {m.slug: m for m in delta.moves}
    assert set(move_by_slug) == {"asc-exception-mac-monitor-only", "asc-mac-endpoints"}
    assert move_by_slug["asc-exception-mac-monitor-only"].live_ordinal == 1
    assert move_by_slug["asc-exception-mac-monitor-only"].resolved_ordinal == 0
    assert move_by_slug["asc-exception-mac-monitor-only"].delta == -1


def test_compute_precedence_diff_skips_platform_without_live_order() -> None:
    """Platforms whose ``precedence_ids_by_platform`` is empty are skipped.

    Unit tests that hand-build a LiveState do not populate the
    precedence field; the preview should stay quiet rather than emit
    'all resolved policies are new' noise.
    """
    from csfwctl.schema import PrecedenceBucket

    endpoints = _mac_policy_with_priority(
        "asc-mac-endpoints", "Asc-Mac-Endpoints", PrecedenceBucket.default
    )
    repo = _repo_with(policies=[endpoints])
    state = _render_live(env="test", policies=[endpoints])
    assert state.precedence_ids_by_platform == {}

    deltas, warnings = compute_precedence_diff(repo, state)
    assert deltas == {}
    assert warnings == []


def test_compute_all_envs_diff_populates_precedence_deltas() -> None:
    """The multi-env aggregate carries the computed precedence deltas."""
    from csfwctl.schema import PrecedenceBucket

    endpoints = _mac_policy_with_priority(
        "asc-mac-endpoints", "Asc-Mac-Endpoints", PrecedenceBucket.default
    )
    exception = _mac_policy_with_priority(
        "asc-exception-mac-monitor-only",
        "Asc-Exception-Mac-Monitor-Only",
        PrecedenceBucket.high,
    )
    repo = _repo_with(policies=[endpoints, exception])
    state = _render_live(env="test", policies=[endpoints, exception])
    state.precedence_ids_by_platform = {
        "Mac": [state.policies[0]["id"], state.policies[1]["id"]],
    }

    multi = compute_all_envs_diff(repo, state)
    assert multi.has_precedence_changes is True
    payload = multi.to_json()
    assert "mac" in payload["precedence_deltas"]
    move_slugs = [m["slug"] for m in payload["precedence_deltas"]["mac"]["moves"]]
    assert "asc-exception-mac-monitor-only" in move_slugs
