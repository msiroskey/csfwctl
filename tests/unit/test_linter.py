"""Tests for the Phase 7 linter module."""

from __future__ import annotations

from pathlib import Path

import pytest

from csfwctl.linter import (
    LINT_REGISTRY,
    BroadAllowLint,
    DeletedWithoutTombstoneLint,
    LintContext,
    LintFinding,
    OrphanRuleGroupLint,
    PolicyWithoutHostGroupsLint,
    PrecedenceCycleLint,
    Severity,
    has_errors,
    register_lint,
    run_lints,
)
from csfwctl.loader import load_config_repo
from csfwctl.schema import (
    Action,
    Direction,
    Endpoint,
    Platform,
    PrecedenceBucket,
    PrecedenceOverride,
    PrecedenceOverrides,
    Protocol,
    Rule,
    RuleGroup,
    Status,
    TombstoneEntry,
    Tombstones,
)
from csfwctl.schema.policy import Policy

# ---- helpers --------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def empty_repo(tmp_path: Path) -> Path:
    """A blank-but-valid config repo skeleton at ``tmp_path/repo``."""
    root = tmp_path / "repo"
    (root / "policies").mkdir(parents=True)
    (root / "rule_groups").mkdir()
    (root / "locations").mkdir()
    _write(
        root / "tombstones.yaml",
        "policies: []\nrule_groups: []\nlocations: []\n",
    )
    _write(root / "precedence.yaml", "overrides: []\n")
    return root


# ---- LintFinding / formatting --------------------------------------------


def test_lintfinding_format_and_json(tmp_path: Path) -> None:
    f = LintFinding(
        rule_id="orphan-rule-group",
        severity=Severity.warning,
        path=tmp_path / "rule_groups" / "rg.yaml",
        message="not used",
        field_path=None,
        line=None,
    )
    text = f.format()
    assert "rg.yaml" in text
    assert "[warning/orphan-rule-group]: not used" in text

    payload = f.to_json()
    assert payload["rule_id"] == "orphan-rule-group"
    assert payload["severity"] == "warning"
    assert payload["line"] is None


def test_lintfinding_format_with_line_and_field(tmp_path: Path) -> None:
    f = LintFinding(
        rule_id="broad-allow",
        severity=Severity.error,
        path=tmp_path / "x.yaml",
        message="boom",
        line=42,
        field_path="rules.allow-all",
    )
    text = f.format()
    assert ":42:" in text
    assert "rules.allow-all" in text


def test_has_errors() -> None:
    a = LintFinding(rule_id="r", severity=Severity.warning, path=Path("x"), message="m")
    b = LintFinding(rule_id="r", severity=Severity.error, path=Path("x"), message="m")
    assert not has_errors([a])
    assert has_errors([a, b])


# ---- realistic / minimal repos round-trip cleanly ------------------------


def test_realistic_repo_passes_with_no_findings(realistic_repo_path: Path) -> None:
    repo = load_config_repo(realistic_repo_path)
    findings = run_lints(repo)
    assert findings == [], [f.format() for f in findings]


def test_minimal_repo_passes_with_no_findings(minimal_repo_path: Path) -> None:
    repo = load_config_repo(minimal_repo_path)
    findings = run_lints(repo)
    assert findings == [], [f.format() for f in findings]


# ---- OrphanRuleGroupLint --------------------------------------------------


def test_orphan_rule_group_flagged(realistic_repo_copy: Path) -> None:
    """Add an unreferenced rule group to the realistic repo."""
    _write(
        realistic_repo_copy / "rule_groups" / "windows-orphan.yaml",
        "name: windows-orphan\nplatform: windows\nstatus: enabled\nrules: []\n",
    )

    repo = load_config_repo(realistic_repo_copy)
    findings = OrphanRuleGroupLint().check(LintContext(repo=repo))

    assert len(findings) == 1
    assert findings[0].rule_id == "orphan-rule-group"
    assert findings[0].severity is Severity.warning
    assert "windows-orphan" in findings[0].message
    assert findings[0].path.name == "windows-orphan.yaml"


def test_orphan_rule_group_skips_status_deleted(realistic_repo_copy: Path) -> None:
    """A ``status: deleted`` orphan is left for deleted-without-tombstone."""
    _write(
        realistic_repo_copy / "rule_groups" / "windows-orphan.yaml",
        "name: windows-orphan\nplatform: windows\nstatus: deleted\nrules: []\n",
    )
    repo = load_config_repo(realistic_repo_copy)
    findings = OrphanRuleGroupLint().check(LintContext(repo=repo))
    assert findings == []


def test_orphan_skips_rule_groups_referenced_only_by_deleted_policy(tmp_path: Path) -> None:
    """A rule group cited only by a deleted-status policy still counts as orphan."""
    from csfwctl.loader import ConfigRepo

    rg = RuleGroup(name="rg-only-used-by-dead", platform=Platform.windows, rules=[])
    dead = Policy(
        name="pol-x-windows",
        platform=Platform.windows,
        priority=PrecedenceBucket.default,
        status=Status.deleted,
        host_groups={"Pol-X-Test": "test"},
        rule_groups=["rg-only-used-by-dead"],
    )
    repo = ConfigRepo(
        root=tmp_path,
        policies={"pol-x-windows": dead},
        rule_groups={"rg-only-used-by-dead": rg},
    )
    findings = OrphanRuleGroupLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].rule_id == "orphan-rule-group"


# ---- PolicyWithoutHostGroupsLint -----------------------------------------


def test_policy_without_host_groups_flagged(empty_repo: Path) -> None:
    _write(
        empty_repo / "policies" / "abc01-policy.yaml",
        "name: abc01-policy\nplatform: windows\nstatus: enabled\nhost_groups: {}\n",
    )
    repo = load_config_repo(empty_repo)
    findings = PolicyWithoutHostGroupsLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].rule_id == "policy-without-host-groups"
    assert "abc01-policy" in findings[0].message
    assert findings[0].field_path == "host_groups"


def test_policy_with_host_groups_passes(empty_repo: Path) -> None:
    _write(
        empty_repo / "policies" / "abc01-policy.yaml",
        "name: abc01-policy\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Abc01-Hosts-Test: test\n",
    )
    repo = load_config_repo(empty_repo)
    findings = PolicyWithoutHostGroupsLint().check(LintContext(repo=repo))
    assert findings == []


def test_policy_without_host_groups_skips_deleted_status(tmp_path: Path) -> None:
    """A deleted-status policy without host_groups is not flagged."""
    from csfwctl.loader import ConfigRepo

    dead = Policy(
        name="abc01-policy",
        platform=Platform.windows,
        priority=PrecedenceBucket.default,
        status=Status.deleted,
        host_groups={},
    )
    repo = ConfigRepo(root=tmp_path, policies={"abc01-policy": dead})
    findings = PolicyWithoutHostGroupsLint().check(LintContext(repo=repo))
    assert findings == []


# ---- DeletedWithoutTombstoneLint -----------------------------------------


def test_deleted_policy_without_tombstone_flagged(empty_repo: Path) -> None:
    _write(
        empty_repo / "policies" / "abc01-policy.yaml",
        "name: abc01-policy\nplatform: windows\nstatus: deleted\n"
        "host_groups:\n  Abc01-Hosts-Test: test\n",
    )
    repo = load_config_repo(empty_repo)
    findings = DeletedWithoutTombstoneLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].rule_id == "deleted-without-tombstone"
    assert "abc01-policy" in findings[0].message
    assert "policy" in findings[0].message


def test_deleted_rule_group_with_tombstone_passes(tmp_path: Path) -> None:
    """A deleted rule group with a matching tombstone does not fire the lint.

    The loader rejects this combination at YAML level (a tombstone whose
    name is still present), so the in-memory ``ConfigRepo`` here mirrors
    the only state the lint actually has to defend against: a
    programmatic caller that hands it both. The lint must still get the
    answer right.
    """
    from csfwctl.loader import ConfigRepo

    rg = RuleGroup(name="rg-stale", platform=Platform.windows, status=Status.deleted, rules=[])
    tomb = Tombstones(
        rule_groups=[TombstoneEntry(name="rg-stale", deleted_in_sha="abc1234", reason="gone")]
    )
    repo = ConfigRepo(
        root=tmp_path,
        rule_groups={"rg-stale": rg},
        tombstones=tomb,
    )
    findings = DeletedWithoutTombstoneLint().check(LintContext(repo=repo))
    assert findings == []


def test_deleted_location_without_tombstone_flagged(empty_repo: Path) -> None:
    _write(
        empty_repo / "locations" / "stale-vpn.yaml",
        "name: stale-vpn\nstatus: deleted\naddresses: []\n",
    )
    repo = load_config_repo(empty_repo)
    findings = DeletedWithoutTombstoneLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert "stale-vpn" in findings[0].message
    assert "location" in findings[0].message


# ---- PrecedenceCycleLint -------------------------------------------------


def test_precedence_cycle_flagged(realistic_repo_copy: Path) -> None:
    """Two overrides forming a cycle on the same platform."""
    _write(
        realistic_repo_copy / "precedence.yaml",
        "overrides:\n"
        "  - before: research-lab-7-windows\n    after: abc01-endpoints-windows\n"
        "  - before: abc01-endpoints-windows\n    after: research-lab-7-windows\n",
    )
    repo = load_config_repo(realistic_repo_copy)
    findings = PrecedenceCycleLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].rule_id == "precedence-cycle"
    assert findings[0].path.name == "precedence.yaml"
    assert "cycle" in findings[0].message.lower()


def test_precedence_no_cycle_passes(realistic_repo_path: Path) -> None:
    repo = load_config_repo(realistic_repo_path)
    findings = PrecedenceCycleLint().check(LintContext(repo=repo))
    assert findings == []


# ---- BroadAllowLint -------------------------------------------------------


def test_broad_allow_world_open_remote_flagged(empty_repo: Path) -> None:
    _write(
        empty_repo / "policies" / "wide.yaml",
        "name: wide\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Wide-Open-Test: test\n"
        "rules:\n"
        "  - name: Allow from anywhere\n"
        "    enabled: true\n"
        "    action: allow\n"
        "    direction: inbound\n"
        "    protocol: tcp\n"
        "    remote:\n      addresses: ['0.0.0.0/0']\n"
        "    locations: [any]\n",
    )
    repo = load_config_repo(empty_repo)
    findings = BroadAllowLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].rule_id == "broad-allow"
    assert "0.0.0.0/0" in findings[0].message
    assert findings[0].field_path == "rules.Allow from anywhere"


def test_broad_allow_unconstrained_flagged_in_rule_group(empty_repo: Path) -> None:
    _write(
        empty_repo / "rule_groups" / "wide-rg.yaml",
        "name: wide-rg\nplatform: windows\nstatus: enabled\n"
        "rules:\n"
        "  - name: Allow everything\n"
        "    enabled: true\n"
        "    action: allow\n"
        "    direction: inbound\n"
        "    protocol: any\n"
        "    locations: [any]\n",
    )
    # Reference the orphan from a policy so we only get a broad-allow finding.
    _write(
        empty_repo / "policies" / "pol.yaml",
        "name: pol\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Pol-Test: test\n"
        "rule_groups:\n  - wide-rg\n",
    )
    repo = load_config_repo(empty_repo)
    findings = BroadAllowLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert "no local or remote" in findings[0].message
    assert findings[0].path.name == "wide-rg.yaml"


def test_broad_allow_constrained_state_passes(empty_repo: Path) -> None:
    """A state-qualified allow rule (e.g. established) is not flagged."""
    _write(
        empty_repo / "rule_groups" / "rg.yaml",
        "name: rg\nplatform: windows\nstatus: enabled\n"
        "rules:\n"
        "  - name: Allow established\n"
        "    enabled: true\n"
        "    action: allow\n"
        "    direction: inbound\n"
        "    protocol: tcp\n"
        "    state: established\n"
        "    locations: [any]\n",
    )
    _write(
        empty_repo / "policies" / "pol.yaml",
        "name: pol\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Pol-Test: test\n"
        "rule_groups:\n  - rg\n",
    )
    repo = load_config_repo(empty_repo)
    findings = BroadAllowLint().check(LintContext(repo=repo))
    assert findings == []


def test_broad_allow_block_actions_not_flagged(empty_repo: Path) -> None:
    """A wide-open block rule is fine — that's the safe direction."""
    _write(
        empty_repo / "rule_groups" / "rg.yaml",
        "name: rg\nplatform: windows\nstatus: enabled\n"
        "rules:\n"
        "  - name: Block all\n"
        "    enabled: true\n"
        "    action: block\n"
        "    direction: inbound\n"
        "    protocol: any\n"
        "    locations: [any]\n",
    )
    _write(
        empty_repo / "policies" / "pol.yaml",
        "name: pol\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Pol-Test: test\n"
        "rule_groups:\n  - rg\n",
    )
    repo = load_config_repo(empty_repo)
    findings = BroadAllowLint().check(LintContext(repo=repo))
    assert findings == []


def test_broad_allow_options_disable(empty_repo: Path) -> None:
    _write(
        empty_repo / "policies" / "wide.yaml",
        "name: wide\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Wide-Open-Test: test\n"
        "rules:\n"
        "  - name: Allow from anywhere\n"
        "    enabled: true\n"
        "    action: allow\n"
        "    direction: inbound\n"
        "    protocol: tcp\n"
        "    remote:\n      addresses: ['0.0.0.0/0']\n"
        "    locations: [any]\n",
    )
    repo = load_config_repo(empty_repo)
    ctx = LintContext(repo=repo, options={"broad-allow": {"disabled": True}})
    assert BroadAllowLint().check(ctx) == []


def test_broad_allow_skips_deleted_policy(tmp_path: Path) -> None:
    """A deleted-status policy's rules aren't held against it."""
    from csfwctl.loader import ConfigRepo

    rule = Rule(
        name="Allow from anywhere",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=Protocol.tcp,
        remote=Endpoint(addresses=["0.0.0.0/0"]),
    )
    dead = Policy(
        name="wide-open",
        platform=Platform.windows,
        priority=PrecedenceBucket.default,
        status=Status.deleted,
        host_groups={"Wide-Open-Test": "test"},
        rules=[rule],
    )
    repo = ConfigRepo(root=tmp_path, policies={"wide-open": dead})
    assert BroadAllowLint().check(LintContext(repo=repo)) == []


# ---- run_lints / registry / options --------------------------------------


def test_run_lints_combines_findings(realistic_repo_copy: Path) -> None:
    """An orphan plus a cycle: both fire from a single run."""
    _write(
        realistic_repo_copy / "rule_groups" / "windows-orphan.yaml",
        "name: windows-orphan\nplatform: windows\nstatus: enabled\nrules: []\n",
    )
    _write(
        realistic_repo_copy / "precedence.yaml",
        "overrides:\n"
        "  - before: research-lab-7-windows\n    after: abc01-endpoints-windows\n"
        "  - before: abc01-endpoints-windows\n    after: research-lab-7-windows\n",
    )

    repo = load_config_repo(realistic_repo_copy)
    findings = run_lints(repo)
    ids = sorted(f.rule_id for f in findings)
    assert ids == ["orphan-rule-group", "precedence-cycle"]


def test_run_lints_disabled_via_argument(realistic_repo_copy: Path) -> None:
    _write(
        realistic_repo_copy / "rule_groups" / "windows-orphan.yaml",
        "name: windows-orphan\nplatform: windows\nstatus: enabled\nrules: []\n",
    )
    repo = load_config_repo(realistic_repo_copy)
    findings = run_lints(repo, disabled={"orphan-rule-group"})
    assert all(f.rule_id != "orphan-rule-group" for f in findings)


def test_run_lints_disabled_via_csfwctl_toml(realistic_repo_copy: Path) -> None:
    _write(
        realistic_repo_copy / "rule_groups" / "windows-orphan.yaml",
        "name: windows-orphan\nplatform: windows\nstatus: enabled\nrules: []\n",
    )
    _write(
        realistic_repo_copy / "csfwctl.toml",
        "[lint]\ndisabled = ['orphan-rule-group']\n",
    )
    repo = load_config_repo(realistic_repo_copy)
    findings = run_lints(repo)
    assert all(f.rule_id != "orphan-rule-group" for f in findings)


def test_run_lints_passes_options_to_rules(empty_repo: Path) -> None:
    _write(
        empty_repo / "policies" / "wide.yaml",
        "name: wide\nplatform: windows\nstatus: enabled\n"
        "host_groups:\n  Wide-Open-Test: test\n"
        "rules:\n"
        "  - name: Allow from anywhere\n"
        "    enabled: true\n"
        "    action: allow\n"
        "    direction: inbound\n"
        "    protocol: tcp\n"
        "    remote:\n      addresses: ['0.0.0.0/0']\n"
        "    locations: [any]\n",
    )
    _write(
        empty_repo / "csfwctl.toml",
        "[lint.options.broad-allow]\ndisabled = true\n",
    )
    repo = load_config_repo(empty_repo)
    findings = run_lints(repo)
    assert all(f.rule_id != "broad-allow" for f in findings)


def test_register_lint_plugin(realistic_repo_path: Path) -> None:
    """A site-specific lint plugged in at runtime fires through run_lints."""

    class AlwaysWarn:
        rule_id = "test-always-warn"
        description = "test"
        default_severity = Severity.warning

        def check(self, ctx: LintContext) -> list[LintFinding]:
            return [
                LintFinding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    path=ctx.repo.root,
                    message="hi",
                )
            ]

    instance = AlwaysWarn()
    try:
        register_lint(instance)
        assert "test-always-warn" in LINT_REGISTRY
        repo = load_config_repo(realistic_repo_path)
        findings = run_lints(repo)
        assert any(f.rule_id == "test-always-warn" for f in findings)
    finally:
        LINT_REGISTRY.pop("test-always-warn", None)


def test_builtin_registry_contents() -> None:
    """Sanity-check the built-in rule set hasn't drifted unannounced."""
    assert set(LINT_REGISTRY) == {
        "precedence-cycle",
        "orphan-rule-group",
        "policy-without-host-groups",
        "deleted-without-tombstone",
        "broad-allow",
    }


# ---- in-memory model-driven sanity (no filesystem) -----------------------


def test_orphan_rule_group_in_memory(tmp_path: Path) -> None:
    """Build a ConfigRepo in memory and check the orphan lint fires."""
    from csfwctl.loader import ConfigRepo

    rg = RuleGroup(name="windows-orphan", platform=Platform.windows, rules=[])
    repo = ConfigRepo(root=tmp_path, rule_groups={"windows-orphan": rg})
    findings = OrphanRuleGroupLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].path == tmp_path / "rule_groups" / "windows-orphan.yaml"


def test_broad_allow_in_memory(tmp_path: Path) -> None:
    """Build a Policy with a wide-open rule and verify the lint flags it."""
    from csfwctl.loader import ConfigRepo

    rule = Rule(
        name="Allow all",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=Protocol.tcp,
        remote=Endpoint(addresses=["0.0.0.0/0"]),
    )
    policy = Policy(
        name="wide-open",
        platform=Platform.windows,
        priority=PrecedenceBucket.default,
        rules=[rule],
        host_groups={"Wide-Open-Test": "test"},
    )
    repo = ConfigRepo(root=tmp_path, policies={"wide-open": policy})
    findings = BroadAllowLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert "0.0.0.0/0" in findings[0].message


def test_in_memory_precedence_cycle(tmp_path: Path) -> None:
    """Verify the precedence-cycle lint without touching the loader."""
    from csfwctl.loader import ConfigRepo

    pol_a = Policy(
        name="alpha-windows",
        platform=Platform.windows,
        priority=PrecedenceBucket.default,
        host_groups={"Alpha-Test": "test"},
    )
    pol_b = Policy(
        name="beta-windows",
        platform=Platform.windows,
        priority=PrecedenceBucket.default,
        host_groups={"Beta-Test": "test"},
    )
    overrides = PrecedenceOverrides(
        overrides=[
            PrecedenceOverride(before="alpha-windows", after="beta-windows"),
            PrecedenceOverride(before="beta-windows", after="alpha-windows"),
        ]
    )
    repo = ConfigRepo(
        root=tmp_path,
        policies={"alpha-windows": pol_a, "beta-windows": pol_b},
        precedence_overrides=overrides,
    )
    findings = PrecedenceCycleLint().check(LintContext(repo=repo))
    assert len(findings) == 1
    assert findings[0].severity is Severity.warning
