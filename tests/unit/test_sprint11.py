"""Tests for Sprint 11: policy inheritance, policy settings, managed host groups."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from csfwctl.applier import (
    ApplyOptions,
    HostGroupPolicy,
    apply_change_set,
)
from csfwctl.differ import (
    LiveState,
    build_desired_state,
    compute_diff,
    project_policy_for_env,
)
from csfwctl.exporter import policy_from_api, policy_to_api_shape
from csfwctl.linter import (
    CrossPlatformInheritanceLint,
    InheritanceDepthLint,
    LintContext,
    OrphanInheritsLint,
    PolicyWithoutHostGroupsLint,
)
from csfwctl.loader import ConfigRepo
from csfwctl.resolver import (
    managed_host_group_cs_name,
    managed_host_group_fql,
    resolve_inheritance,
)
from csfwctl.safety import SafetyOptions
from csfwctl.schema import (
    Action,
    Direction,
    HostGroupEnv,
    Platform,
    Policy,
    Protocol,
    Rule,
    RuleGroup,
    Status,
)
from csfwctl.schema.policy_settings import (
    DefaultTrafficAction,
    EnforcementMode,
    PolicySettings,
)

# ---- helpers ----------------------------------------------------------------


def _rule(name: str = "r") -> Rule:
    return Rule(name=name, action=Action.allow, direction=Direction.outbound, protocol=Protocol.tcp)


def _policy(
    name: str = "abc01-windows",
    *,
    platform: Platform = Platform.windows,
    **kwargs: Any,
) -> Policy:
    return Policy(name=name, platform=platform, **kwargs)


def _rg(name: str = "baseline", platform: Platform = Platform.windows) -> RuleGroup:
    return RuleGroup(name=name, platform=platform, rules=[_rule()])


# ---- PolicySettings ---------------------------------------------------------


def test_policy_settings_defaults() -> None:
    ps = PolicySettings()
    assert ps.enforcement_mode is None
    assert ps.default_inbound is None
    assert ps.default_outbound is None


def test_policy_settings_enforce() -> None:
    ps = PolicySettings(enforcement_mode="enforce")
    assert ps.enforcement_mode is EnforcementMode.enforce


def test_policy_settings_monitor() -> None:
    ps = PolicySettings(enforcement_mode="monitor")
    assert ps.enforcement_mode is EnforcementMode.monitor


def test_policy_settings_local_logging() -> None:
    ps = PolicySettings(enforcement_mode="local_logging")
    assert ps.enforcement_mode is EnforcementMode.local_logging


def test_policy_settings_default_traffic() -> None:
    ps = PolicySettings(default_inbound="allow", default_outbound="deny")
    assert ps.default_inbound is DefaultTrafficAction.allow
    assert ps.default_outbound is DefaultTrafficAction.deny


def test_policy_settings_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        PolicySettings(enforcement_mode="enforce", unknown_field="x")  # type: ignore[call-arg]


# ---- Policy new fields ------------------------------------------------------


def test_policy_inherits_field() -> None:
    p = _policy(inherits="other-policy")
    assert p.inherits == "other-policy"


def test_policy_inherits_self_raises() -> None:
    with pytest.raises(ValidationError, match="cannot inherit from itself"):
        _policy("abc01-windows", inherits="abc01-windows")


def test_policy_append_flags_default_false() -> None:
    p = _policy()
    assert p.append_rule_groups is False
    assert p.append_rules is False


def test_policy_settings_field() -> None:
    p = _policy(settings=PolicySettings(enforcement_mode="monitor"))
    assert p.settings is not None
    assert p.settings.enforcement_mode is EnforcementMode.monitor


def test_policy_managed_host_groups_field() -> None:
    p = _policy(
        managed_host_groups={
            HostGroupEnv.test: ["machine-a", "machine-b"],
        }
    )
    assert p.managed_host_groups[HostGroupEnv.test] == ["machine-a", "machine-b"]


def test_policy_managed_host_groups_env_overlap_raises() -> None:
    with pytest.raises(ValidationError, match="test"):
        _policy(
            host_groups={"ABC01-Test": HostGroupEnv.test},
            managed_host_groups={HostGroupEnv.test: ["machine-a"]},
        )


def test_policy_managed_host_groups_different_envs_ok() -> None:
    p = _policy(
        host_groups={"ABC01-Pilot": HostGroupEnv.pilot},
        managed_host_groups={HostGroupEnv.test: ["machine-a"]},
    )
    assert HostGroupEnv.test in p.managed_host_groups
    assert HostGroupEnv.pilot in p.host_groups.values()


# ---- resolver helpers -------------------------------------------------------


def test_managed_host_group_cs_name_with_display_name() -> None:
    p = _policy(display_name="ABC01-Endpoints-Windows")
    assert managed_host_group_cs_name(p, "test") == "ABC01-Endpoints-Windows-Managed-Test"


def test_managed_host_group_cs_name_from_slug() -> None:
    p = _policy("abc01-endpoints-windows")
    name = managed_host_group_cs_name(p, "production")
    assert name == "Abc01-Endpoints-Windows-Managed-Production"


def test_managed_host_group_fql_single() -> None:
    assert managed_host_group_fql(["host-a"]) == "hostname:'host-a'"


def test_managed_host_group_fql_multiple() -> None:
    fql = managed_host_group_fql(["host-a", "host-b", "host-c"])
    assert fql == "hostname:'host-a' or hostname:'host-b' or hostname:'host-c'"


def test_managed_host_group_fql_empty() -> None:
    assert managed_host_group_fql([]) == ""


# ---- resolve_inheritance ----------------------------------------------------


def _make_repo(policies: list[Policy], *, tmp_path: Path) -> ConfigRepo:
    """Build a minimal in-memory-ish ConfigRepo for resolver tests."""
    repo = ConfigRepo.__new__(ConfigRepo)
    repo.root = tmp_path
    repo.policies = {p.name: p for p in policies}
    repo.rule_groups = {}
    repo.locations = {}
    repo.tombstones = type("T", (), {"policies": [], "rule_groups": [], "locations": []})()
    repo.precedence_overrides = type("P", (), {"overrides": []})()
    repo.tool_config = type(
        "TC",
        (),
        {
            "lint": type("L", (), {"disabled": [], "options": {}})(),
            "safety": None,
            "tool": None,
            "notifications": {},
        },
    )()
    return repo


def test_resolve_no_inheritance_returns_same(tmp_path: Path) -> None:
    p = _policy()
    repo = _make_repo([p], tmp_path=tmp_path)
    result = resolve_inheritance(p, repo)
    assert result is p


def test_resolve_orphan_returns_child(tmp_path: Path) -> None:
    p = _policy(inherits="nonexistent")
    repo = _make_repo([p], tmp_path=tmp_path)
    result = resolve_inheritance(p, repo)
    assert result is p


def test_resolve_scalar_fields_replaced_by_child(tmp_path: Path) -> None:
    parent = _policy(
        "parent-policy",
        priority="high",
        status=Status.enabled,
        description="Parent description",
    )
    child = _policy(
        "child-policy",
        inherits="parent-policy",
        status=Status.disabled,
    )
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert result.inherits is None
    assert result.status is Status.disabled  # child's value
    assert result.priority.value == "high"  # inherited from parent
    assert result.description == "Parent description"  # inherited from parent


def test_resolve_unset_field_inherits_parent_rule_groups(tmp_path: Path) -> None:
    parent = _policy("parent-policy", rule_groups=["baseline"])
    child = _policy("child-policy", inherits="parent-policy")
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert result.rule_groups == ["baseline"]


def test_resolve_child_explicitly_sets_rule_groups_replaces(tmp_path: Path) -> None:
    parent = _policy("parent-policy", rule_groups=["baseline"])
    child = _policy("child-policy", inherits="parent-policy", rule_groups=["override"])
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert result.rule_groups == ["override"]


def test_resolve_append_rule_groups(tmp_path: Path) -> None:
    parent = _policy("parent-policy", rule_groups=["baseline"])
    child = _policy(
        "child-policy",
        inherits="parent-policy",
        rule_groups=["extra"],
        append_rule_groups=True,
    )
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert result.rule_groups == ["baseline", "extra"]
    assert result.append_rule_groups is False  # cleared


def test_resolve_append_rules(tmp_path: Path) -> None:
    parent_rule = _rule("parent-rule")
    child_rule = _rule("child-rule")
    parent = _policy("parent-policy", rules=[parent_rule])
    child = _policy(
        "child-policy",
        inherits="parent-policy",
        rules=[child_rule],
        append_rules=True,
    )
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    rule_names = [r.name for r in result.rules]
    assert rule_names == ["parent-rule", "child-rule"]
    assert result.append_rules is False  # cleared


def test_resolve_replace_rules_default(tmp_path: Path) -> None:
    parent_rule = _rule("parent-rule")
    child_rule = _rule("child-rule")
    parent = _policy("parent-policy", rules=[parent_rule])
    child = _policy("child-policy", inherits="parent-policy", rules=[child_rule])
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert [r.name for r in result.rules] == ["child-rule"]


def test_resolve_settings_override(tmp_path: Path) -> None:
    parent = _policy("parent-policy")
    child = _policy(
        "child-policy",
        inherits="parent-policy",
        settings=PolicySettings(enforcement_mode="monitor"),
    )
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert result.settings is not None
    assert result.settings.enforcement_mode is EnforcementMode.monitor


def test_resolve_settings_inherited(tmp_path: Path) -> None:
    parent = _policy(
        "parent-policy",
        settings=PolicySettings(enforcement_mode="enforce", default_inbound="deny"),
    )
    child = _policy("child-policy", inherits="parent-policy")
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    assert result.settings is not None
    assert result.settings.enforcement_mode is EnforcementMode.enforce
    assert result.settings.default_inbound is DefaultTrafficAction.deny


def test_resolve_managed_host_groups_drops_inherited_overlap(tmp_path: Path) -> None:
    """Child's managed_host_groups for test env removes inherited host_groups for test."""
    parent = _policy(
        "parent-policy",
        host_groups={"ABC01-Test": HostGroupEnv.test, "ABC01-Pilot": HostGroupEnv.pilot},
    )
    child = _policy(
        "child-policy",
        inherits="parent-policy",
        managed_host_groups={HostGroupEnv.test: ["machine-foo"]},
    )
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    result = resolve_inheritance(child, repo)
    # test env must not appear in host_groups since managed_host_groups owns it
    assert HostGroupEnv.test not in result.host_groups.values()
    assert HostGroupEnv.pilot in result.host_groups.values()
    assert result.managed_host_groups.get(HostGroupEnv.test) == ["machine-foo"]


# ---- lint rules -------------------------------------------------------------


def _lint_repo(policies: list[Policy], *, tmp_path: Path) -> ConfigRepo:
    return _make_repo(policies, tmp_path=tmp_path)


def test_orphan_inherits_fires_on_missing_parent(tmp_path: Path) -> None:
    p = _policy(inherits="nonexistent-parent")
    repo = _lint_repo([p], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    findings = OrphanInheritsLint().check(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "orphan-inherits"
    assert findings[0].severity.value == "error"
    assert "nonexistent-parent" in findings[0].message


def test_orphan_inherits_no_finding_when_parent_exists(tmp_path: Path) -> None:
    parent = _policy("parent-policy")
    child = _policy("child-policy", inherits="parent-policy")
    repo = _lint_repo([parent, child], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    findings = OrphanInheritsLint().check(ctx)
    assert findings == []


def test_orphan_inherits_no_finding_no_inherits(tmp_path: Path) -> None:
    p = _policy()
    repo = _lint_repo([p], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    assert OrphanInheritsLint().check(ctx) == []


def test_inheritance_depth_fires_on_chain(tmp_path: Path) -> None:
    grandparent = _policy("grandparent-policy")
    parent = _policy("parent-policy", inherits="grandparent-policy")
    child = _policy("child-policy", inherits="parent-policy")
    repo = _lint_repo([grandparent, parent, child], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    findings = InheritanceDepthLint().check(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "inheritance-depth"
    assert "child-policy" in findings[0].message


def test_inheritance_depth_ok_for_depth_1(tmp_path: Path) -> None:
    parent = _policy("parent-policy")
    child = _policy("child-policy", inherits="parent-policy")
    repo = _lint_repo([parent, child], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    assert InheritanceDepthLint().check(ctx) == []


def test_cross_platform_inheritance_fires(tmp_path: Path) -> None:
    parent = _policy("parent-policy", platform=Platform.windows)
    child = Policy(name="child-policy", platform=Platform.mac, inherits="parent-policy")
    repo = _lint_repo([parent, child], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    findings = CrossPlatformInheritanceLint().check(ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "cross-platform-inheritance"


def test_cross_platform_inheritance_ok_same_platform(tmp_path: Path) -> None:
    parent = _policy("parent-policy")
    child = _policy("child-policy", inherits="parent-policy")
    repo = _lint_repo([parent, child], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    assert CrossPlatformInheritanceLint().check(ctx) == []


def test_policy_without_host_groups_allows_managed(tmp_path: Path) -> None:
    p = _policy(managed_host_groups={HostGroupEnv.test: ["machine-a"]})
    repo = _lint_repo([p], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    findings = PolicyWithoutHostGroupsLint().check(ctx)
    assert findings == []


def test_policy_without_host_groups_fires_when_both_empty(tmp_path: Path) -> None:
    p = _policy()
    repo = _lint_repo([p], tmp_path=tmp_path)
    ctx = LintContext(repo=repo)
    findings = PolicyWithoutHostGroupsLint().check(ctx)
    assert len(findings) == 1


# ---- exporter settings round-trip ------------------------------------------


def _base_policy_api_record(name: str = "ABC01-Windows-Test") -> dict[str, Any]:
    return {
        "id": "policy-uuid",
        "name": name,
        "platform_name": "Windows",
        "enabled": True,
        "description": "",
        "groups": [],
        "settings": {"rule_group_ids": []},
    }


def test_policy_to_api_shape_no_settings() -> None:
    p = _policy()
    shape = policy_to_api_shape(p, "test")
    assert "enforce" not in shape["settings"]
    assert "inbound" not in shape["settings"]


def test_policy_to_api_shape_enforce_mode() -> None:
    p = _policy(settings=PolicySettings(enforcement_mode="enforce"))
    shape = policy_to_api_shape(p, "test")
    assert shape["settings"]["enforce"] is True
    assert shape["settings"]["local_logging"] is False


def test_policy_to_api_shape_monitor_mode() -> None:
    p = _policy(settings=PolicySettings(enforcement_mode="monitor"))
    shape = policy_to_api_shape(p, "test")
    assert shape["settings"]["enforce"] is False
    assert shape["settings"]["local_logging"] is False


def test_policy_to_api_shape_local_logging() -> None:
    p = _policy(settings=PolicySettings(enforcement_mode="local_logging"))
    shape = policy_to_api_shape(p, "test")
    assert shape["settings"]["enforce"] is False
    assert shape["settings"]["local_logging"] is True


def test_policy_to_api_shape_default_traffic() -> None:
    p = _policy(settings=PolicySettings(default_inbound="deny", default_outbound="allow"))
    shape = policy_to_api_shape(p, "test")
    assert shape["settings"]["inbound"] == "DENY"
    assert shape["settings"]["outbound"] == "ALLOW"


def test_policy_from_api_reads_enforce_settings() -> None:
    record = _base_policy_api_record()
    record["settings"]["enforce"] = True
    record["settings"]["local_logging"] = False
    record["settings"]["inbound"] = "DENY"
    record["settings"]["outbound"] = "ALLOW"
    p = policy_from_api(record, rule_groups_by_id={})
    assert p.settings is not None
    assert p.settings.enforcement_mode is EnforcementMode.enforce
    assert p.settings.default_inbound is DefaultTrafficAction.deny
    assert p.settings.default_outbound is DefaultTrafficAction.allow


def test_policy_from_api_reads_monitor_mode() -> None:
    record = _base_policy_api_record()
    record["settings"]["enforce"] = False
    record["settings"]["local_logging"] = False
    p = policy_from_api(record, rule_groups_by_id={})
    assert p.settings is not None
    assert p.settings.enforcement_mode is EnforcementMode.monitor


def test_policy_from_api_no_settings_when_absent() -> None:
    record = _base_policy_api_record()
    p = policy_from_api(record, rule_groups_by_id={})
    assert p.settings is None


# ---- project_policy_for_env with managed_host_groups -----------------------


def test_project_adds_managed_group_to_host_groups() -> None:
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: ["machine-foo"]},
    )
    projected = project_policy_for_env(p, "abc01-endpoints", "test", override_present=False)
    assert "ABC01-Endpoints-Managed-Test" in projected.host_groups
    assert projected.host_groups["ABC01-Endpoints-Managed-Test"] is HostGroupEnv.test


def test_project_no_managed_group_when_env_not_covered() -> None:
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.pilot: ["machine-foo"]},
    )
    projected = project_policy_for_env(p, "abc01-endpoints", "test", override_present=False)
    assert not any("Managed" in k for k in projected.host_groups)


def test_project_no_managed_group_when_list_empty() -> None:
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: []},
    )
    projected = project_policy_for_env(p, "abc01-endpoints", "test", override_present=False)
    assert not any("Managed" in k for k in projected.host_groups)


def test_project_passes_settings_through() -> None:
    p = _policy(settings=PolicySettings(enforcement_mode="monitor"))
    projected = project_policy_for_env(p, "abc01-windows", "test", override_present=False)
    assert projected.settings is not None
    assert projected.settings.enforcement_mode is EnforcementMode.monitor


# ---- differ managed group changes ------------------------------------------


def _minimal_live_state() -> LiveState:
    return LiveState()


def test_diff_shows_managed_group_create(tmp_path: Path) -> None:
    """A new managed_host_groups entry should produce a create ManagedGroupChange."""
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        host_groups={},
        managed_host_groups={HostGroupEnv.test: ["machine-foo"]},
    )
    repo = _make_repo([p], tmp_path=tmp_path)
    state = _minimal_live_state()
    cs = compute_diff(repo, "test", state)
    assert len(cs.creates) == 1
    change = cs.creates[0]
    assert change.managed_group_changes
    mgc = change.managed_group_changes[0]
    assert mgc.op == "create"
    assert "machine-foo" in mgc.desired_fql


def test_diff_shows_managed_group_no_change_when_fql_matches(tmp_path: Path) -> None:
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: ["machine-foo"]},
    )
    expected_name = managed_host_group_cs_name(p, "test")
    expected_fql = managed_host_group_fql(["machine-foo"])
    # Build a live policy shape (without the managed group already assigned)
    live_state = LiveState(
        host_groups=[{"id": "hg-123", "name": expected_name, "assignment_rule": expected_fql}]
    )
    repo = _make_repo([p], tmp_path=tmp_path)
    cs = compute_diff(repo, "test", live_state)
    # Policy is a create (no live policy), but managed group is no-change
    assert cs.creates
    change = cs.creates[0]
    assert change.managed_group_changes
    mgc = change.managed_group_changes[0]
    assert mgc.op == "no-change"


def test_diff_shows_managed_group_update_when_fql_differs(tmp_path: Path) -> None:
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: ["machine-foo", "machine-bar"]},
    )
    expected_name = managed_host_group_cs_name(p, "test")
    old_fql = managed_host_group_fql(["machine-foo"])
    live_state = LiveState(
        host_groups=[{"id": "hg-123", "name": expected_name, "assignment_rule": old_fql}]
    )
    repo = _make_repo([p], tmp_path=tmp_path)
    cs = compute_diff(repo, "test", live_state)
    change = cs.creates[0]
    mgc = change.managed_group_changes[0]
    assert mgc.op == "update"
    assert "machine-bar" in mgc.desired_fql
    assert mgc.live_fql == old_fql


# ---- applier with managed host groups --------------------------------------


class _FakeSubClient:
    def __init__(self) -> None:
        self.created: list[Any] = []
        self.updated: list[Any] = []
        self.deleted: list[Any] = []


class _FakeLocationsAPI(_FakeSubClient):
    def upsert(self, locations: list[dict]) -> list[dict]:
        results = []
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


class _FakeRuleGroupsAPI(_FakeSubClient):
    def create(self, rg: dict) -> dict:
        self.created.append(rg)
        return {**rg, "id": f"rg-id-{rg['name']}"}

    def update(self, rg: dict) -> dict:
        self.updated.append(rg)
        return dict(rg)

    def delete(self, ids: list[str]) -> None:
        self.deleted.extend(ids)


class _FakePoliciesAPI(_FakeSubClient):
    def create(self, policies: list[dict]) -> list[dict]:
        out = []
        for p in policies:
            self.created.append(p)
            out.append({**p, "id": f"pol-id-{p['name']}"})
        return out

    def update(self, policies: list[dict]) -> list[dict]:
        self.updated.extend(policies)
        return [dict(p) for p in policies]

    def delete(self, ids: list[str]) -> None:
        self.deleted.extend(ids)


class _FakeHostGroupsAPI(_FakeSubClient):
    """Extended fake that supports create_dynamic and update_fql."""

    def __init__(self, known: dict[str, dict] | None = None) -> None:
        super().__init__()
        # known maps name → {id, assignment_rule, description}
        self._known: dict[str, dict] = dict(known or {})
        self.dynamic_created: list[dict] = []
        self.fql_updated: list[dict] = []

    def find_by_name(self, name: str) -> dict | None:
        return self._known.get(name)

    def create(self, name: str, *, description: str = "") -> dict:
        rec = {"id": f"hg-{name}", "name": name, "description": description}
        self.created.append(rec)
        self._known[name] = rec
        return rec

    def list_all(self, *, filter: str | None = None) -> list[dict]:
        return list(self._known.values())

    def create_dynamic(self, name: str, *, fql: str, description: str = "") -> dict:
        rec = {
            "id": f"dyn-hg-{name}",
            "name": name,
            "description": description,
            "assignment_rule": fql,
        }
        self.dynamic_created.append(rec)
        self._known[name] = rec
        return rec

    def update_fql(self, group_id: str, fql: str) -> dict:
        update = {"id": group_id, "assignment_rule": fql}
        self.fql_updated.append(update)
        for rec in self._known.values():
            if rec.get("id") == group_id:
                rec["assignment_rule"] = fql
        return update


class _FakeClient:
    def __init__(self, known_host_groups: dict[str, dict] | None = None) -> None:
        self.policies = _FakePoliciesAPI()
        self.rule_groups = _FakeRuleGroupsAPI()
        self.host_groups = _FakeHostGroupsAPI(known_host_groups)
        self.locations = _FakeLocationsAPI()


def _options(env: str = "test", **kw: Any) -> ApplyOptions:
    defaults: dict[str, Any] = {
        "env": env,
        "git_sha": "abc1234",
        "dry_run": False,
        "initial_bootstrap": False,
        "host_group_policy": HostGroupPolicy.warn,
    }
    defaults.update(kw)
    return ApplyOptions(**defaults)


def _safety(**kw: Any) -> SafetyOptions:
    defaults: dict[str, Any] = {
        "max_changes": 100,
        "max_deletes": 100,
        "enforce": True,
        "allow_delete": True,
        "initial_bootstrap": False,
        "require_bootstrap_for_unmanaged": True,
    }
    defaults.update(kw)
    return SafetyOptions(**defaults)


_SIGNED = (
    "Managed by csfwctl | version: 1 | git_sha: old | applied: 2026-01-01T00:00:00Z | env: test"
)


def _bootstrapped_live_state(**extra: Any) -> LiveState:
    """A live state with one signed dummy record so bootstrap check passes."""
    return LiveState(
        locations=[{"id": "loc-dummy", "name": "dummy-location", "description": _SIGNED}],
        **extra,
    )


def test_applier_creates_dynamic_host_group(tmp_path: Path) -> None:
    """Applier creates a dynamic group and assigns it to the policy."""
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: ["machine-foo"]},
    )
    repo = _make_repo([p], tmp_path=tmp_path)
    state = _bootstrapped_live_state()
    cs = compute_diff(repo, "test", state)
    client = _FakeClient()
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert len(client.host_groups.dynamic_created) == 1
    created = client.host_groups.dynamic_created[0]
    assert created["name"] == "ABC01-Endpoints-Managed-Test"
    assert "machine-foo" in created["assignment_rule"]
    # Policy payload should reference the managed group
    assert len(client.policies.created) == 1
    pol_groups = client.policies.created[0]["groups"]
    assert any(g["name"] == "ABC01-Endpoints-Managed-Test" for g in pol_groups)


def test_applier_updates_dynamic_host_group_fql(tmp_path: Path) -> None:
    """Applier updates FQL when hostnames change."""
    from csfwctl.differ import METADATA_SIGNATURE_TOKEN

    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: ["machine-foo", "machine-bar"]},
    )
    group_name = managed_host_group_cs_name(p, "test")
    old_fql = managed_host_group_fql(["machine-foo"])
    signed_desc = f"{METADATA_SIGNATURE_TOKEN} | version: 1 | git_sha: old | applied: 2026-01-01T00:00:00Z | env: test"

    existing_group = {
        "id": "existing-hg-id",
        "name": group_name,
        "assignment_rule": old_fql,
        "description": signed_desc,
    }
    # Build signed live policy so bootstrap check passes
    live_pol_shape = policy_to_api_shape(p, "test")
    live_pol_shape["description"] = signed_desc
    live_pol_shape["groups"] = [{"id": "existing-hg-id", "name": group_name}]

    state = LiveState(
        policies=[live_pol_shape],
        host_groups=[existing_group],
    )
    repo = _make_repo([p], tmp_path=tmp_path)
    cs = compute_diff(repo, "test", state)
    client = _FakeClient(known_host_groups={group_name: existing_group})
    apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(),
        safety_options=_safety(),
    )
    assert len(client.host_groups.fql_updated) == 1
    updated = client.host_groups.fql_updated[0]
    assert updated["id"] == "existing-hg-id"
    assert "machine-bar" in updated["assignment_rule"]


def test_applier_dry_run_does_not_create_group(tmp_path: Path) -> None:
    p = _policy(
        "abc01-endpoints",
        display_name="ABC01-Endpoints",
        managed_host_groups={HostGroupEnv.test: ["machine-foo"]},
    )
    repo = _make_repo([p], tmp_path=tmp_path)
    state = _bootstrapped_live_state()
    cs = compute_diff(repo, "test", state)
    client = _FakeClient()
    report = apply_change_set(
        client=client,
        repo=repo,
        change_set=cs,
        state=state,
        options=_options(dry_run=True),
        safety_options=_safety(),
    )
    assert len(client.host_groups.dynamic_created) == 0
    # But action still recorded
    assert any(a.op == "create" and a.kind == "host-group" for a in report.actions)


# ---- inheritance in build_desired_state ------------------------------------


def test_build_desired_state_materialises_inheritance(tmp_path: Path) -> None:
    parent = _policy(
        "parent-policy",
        rule_groups=["baseline"],
        host_groups={"ABC01-Test": HostGroupEnv.test},
    )
    child = _policy(
        "child-policy",
        inherits="parent-policy",
        settings=PolicySettings(enforcement_mode="monitor"),
    )
    repo = _make_repo([parent, child], tmp_path=tmp_path)
    # Add baseline rule group to repo so validation passes
    repo.rule_groups = {"baseline": _rg("baseline")}
    desired_policies, _, _ = build_desired_state(repo, "test")
    child_projected = desired_policies["child-policy"]
    assert child_projected.rule_groups == ["baseline"]
    assert child_projected.settings is not None
    assert child_projected.settings.enforcement_mode is EnforcementMode.monitor
