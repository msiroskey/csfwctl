"""Semantic linter — checks that span beyond per-file schema validation.

The loader already enforces per-document Pydantic validation and the
hard cross-reference rules (rule-group platform mismatch, location
references, tombstones not matching live YAML, precedence overrides
pointing at known policies). This module covers the softer concerns
described in ``csfwctl-project-plan.md`` section 9, phase 7:

- Rule groups defined but referenced by no policy.
- Policies with an empty ``host_groups`` map.
- Objects whose ``status`` is ``deleted`` but which carry no matching
  tombstone entry (and the inverse — tombstones whose name still has a
  YAML file are caught at load time).
- Precedence overrides that form a cycle when resolved.
- "Overly broad" allow rules — heuristic warnings on rules whose
  combination of fields lets nearly anything through.

Built-in rules implement the :class:`Lint` protocol and are registered in
:data:`LINT_REGISTRY`. Site-specific rules can call :func:`register_lint`
at import time to add their own without touching this module.

Findings carry a ``rule_id`` and a :class:`Severity` so the caller can
filter (``run_lints(disabled=...)``) and decide how to react. The
``validate`` command surfaces every finding; warnings do not fail the
command unless ``--strict`` is passed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from csfwctl.loader import (
    LOCATIONS_DIR,
    POLICIES_DIR,
    PRECEDENCE_FILE,
    RULE_GROUPS_DIR,
    TOMBSTONES_FILE,
    ConfigRepo,
)
from csfwctl.precedence_resolver import PrecedenceError, resolve_precedence
from csfwctl.schema import Action, Rule, Status


class Severity(StrEnum):
    """Lint finding severities.

    ``error`` finds fail ``validate`` even without ``--strict``.
    ``warning`` and ``info`` are surfaced but non-fatal by default.
    """

    error = "error"
    warning = "warning"
    info = "info"


@dataclass(frozen=True)
class LintFinding:
    """One result emitted by a :class:`Lint` rule.

    The shape mirrors :class:`csfwctl.loader.LoadError` so the
    ``validate`` renderer can format both kinds of records uniformly.
    """

    rule_id: str
    severity: Severity
    path: Path
    message: str
    line: int | None = None
    field_path: str | None = None

    def format(self) -> str:
        """Human-readable single line: ``file[:line[:field]] [sev/rule]: msg``."""
        loc_parts: list[str] = [str(self.path)]
        if self.line is not None:
            loc_parts.append(str(self.line))
        if self.field_path:
            loc_parts.append(self.field_path)
        return f"{':'.join(loc_parts)} [{self.severity.value}/{self.rule_id}]: {self.message}"

    def to_json(self) -> dict[str, Any]:
        """JSON-serializable representation for notifier/CI payloads."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "path": str(self.path),
            "message": self.message,
            "line": self.line,
            "field_path": self.field_path,
        }


@dataclass
class LintContext:
    """Per-run state handed to every lint rule.

    ``options`` carries arbitrary per-rule configuration. Rules look up
    their own settings under their ``rule_id`` so additions stay local.
    """

    repo: ConfigRepo
    options: dict[str, Any] = field(default_factory=dict)


@runtime_checkable
class Lint(Protocol):
    """Plug-in linter rule.

    Implementations are class instances (so they can carry per-rule
    state) and must expose a stable ``rule_id``, a one-line
    ``description``, a ``default_severity``, and a ``check`` method that
    returns zero or more findings.
    """

    rule_id: str
    description: str
    default_severity: Severity

    def check(self, ctx: LintContext) -> list[LintFinding]: ...


# ---- built-in rules -------------------------------------------------------


class OrphanRuleGroupLint:
    """Rule groups not referenced by any active policy.

    A rule group that no policy lists is dead weight: it will not be
    materialised in any environment and is a likely leftover from a
    refactor. Skipped if the rule group is tombstoned or its own
    ``status`` is ``deleted``.
    """

    rule_id = "orphan-rule-group"
    description = "rule group defined but not referenced by any policy"
    default_severity = Severity.warning

    def check(self, ctx: LintContext) -> list[LintFinding]:
        referenced: set[str] = set()
        for policy in ctx.repo.policies.values():
            if policy.status is Status.deleted:
                continue
            referenced.update(policy.rule_groups)

        findings: list[LintFinding] = []
        rg_dir = ctx.repo.root / RULE_GROUPS_DIR
        for slug, rg in sorted(ctx.repo.rule_groups.items()):
            # A deleted-status rule group is on its way out — covered by
            # ``deleted-without-tombstone``. The loader already rejects a
            # tombstone whose YAML file still exists, so no need to
            # double-check here.
            if rg.status is Status.deleted:
                continue
            if slug in referenced:
                continue
            findings.append(
                LintFinding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    path=rg_dir / f"{slug}.yaml",
                    message=(
                        f"rule group {slug!r} is not referenced by any policy; "
                        "remove it or add it to a policy's rule_groups list"
                    ),
                )
            )
        return findings


class PolicyWithoutHostGroupsLint:
    """Policies that bind to no host group in any environment.

    Such a policy cannot apply to anything once pushed. Usually the
    operator forgot to fill in ``host_groups:`` after copying a template.
    """

    rule_id = "policy-without-host-groups"
    description = "policy has no host_groups assignments"
    default_severity = Severity.warning

    def check(self, ctx: LintContext) -> list[LintFinding]:
        findings: list[LintFinding] = []
        policies_dir = ctx.repo.root / POLICIES_DIR
        for slug, policy in sorted(ctx.repo.policies.items()):
            if policy.status is Status.deleted:
                continue
            has_any_host_assignment = bool(policy.host_groups) or bool(
                policy.managed_host_groups
            )
            if not has_any_host_assignment:
                findings.append(
                    LintFinding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        path=policies_dir / f"{slug}.yaml",
                        field_path="host_groups",
                        message=(
                            f"policy {policy.name!r} has no host_groups or "
                            "managed_host_groups; it will not apply to any hosts "
                            "in any environment"
                        ),
                    )
                )
        return findings


class DeletedWithoutTombstoneLint:
    """``status: deleted`` objects that lack a tombstone entry.

    The applier refuses to delete an object without a matching tombstone
    plus ``--allow-delete``. Surfacing the missing tombstone at validate
    time means the operator catches it before they get near apply.
    """

    rule_id = "deleted-without-tombstone"
    description = "status: deleted object has no matching tombstone entry"
    default_severity = Severity.warning

    def check(self, ctx: LintContext) -> list[LintFinding]:
        findings: list[LintFinding] = []
        policies_dir = ctx.repo.root / POLICIES_DIR
        rg_dir = ctx.repo.root / RULE_GROUPS_DIR
        loc_dir = ctx.repo.root / LOCATIONS_DIR

        policy_tombs = {entry.name for entry in ctx.repo.tombstones.policies}
        rg_tombs = {entry.name for entry in ctx.repo.tombstones.rule_groups}
        loc_tombs = {entry.name for entry in ctx.repo.tombstones.locations}

        for slug, policy in sorted(ctx.repo.policies.items()):
            if policy.status is Status.deleted and slug not in policy_tombs:
                findings.append(
                    self._finding(
                        path=policies_dir / f"{slug}.yaml",
                        slug=slug,
                        kind="policy",
                    )
                )

        for slug, rg in sorted(ctx.repo.rule_groups.items()):
            if rg.status is Status.deleted and slug not in rg_tombs:
                findings.append(
                    self._finding(
                        path=rg_dir / f"{slug}.yaml",
                        slug=slug,
                        kind="rule group",
                    )
                )

        for slug, loc in sorted(ctx.repo.locations.items()):
            if loc.status is Status.deleted and slug not in loc_tombs:
                findings.append(
                    self._finding(
                        path=loc_dir / f"{slug}.yaml",
                        slug=slug,
                        kind="location",
                    )
                )

        return findings

    def _finding(self, *, path: Path, slug: str, kind: str) -> LintFinding:
        return LintFinding(
            rule_id=self.rule_id,
            severity=self.default_severity,
            path=path,
            field_path="status",
            message=(
                f"{kind} {slug!r} is marked status: deleted but has no "
                f"matching entry in {TOMBSTONES_FILE}; "
                "apply --allow-delete will refuse without one"
            ),
        )


class PrecedenceCycleLint:
    """Precedence overrides that resolve into a cycle.

    Detected by re-running :func:`resolve_precedence` and catching
    :class:`PrecedenceError`. A cycle eventually breaks ``apply``; the
    lint surfaces it at ``validate`` time so the operator notices first.
    """

    rule_id = "precedence-cycle"
    description = "precedence overrides form a cycle"
    default_severity = Severity.warning

    def check(self, ctx: LintContext) -> list[LintFinding]:
        try:
            resolve_precedence(ctx.repo)
        except PrecedenceError as exc:
            return [
                LintFinding(
                    rule_id=self.rule_id,
                    severity=self.default_severity,
                    path=ctx.repo.root / PRECEDENCE_FILE,
                    field_path="overrides",
                    message=str(exc),
                )
            ]
        return []


_WORLD_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})


class BroadAllowLint:
    """Heuristic warning for "overly broad" allow rules.

    Two patterns trip the rule:

    1. An ``action: allow`` rule whose ``remote.addresses`` (and not
       ``addresses_negated``) contains ``0.0.0.0/0`` or ``::/0``. That
       is "allow from the entire internet" by construction.
    2. An ``action: allow`` rule with no constraint on either endpoint
       (no addresses, no ports, no negation) and no connection-state
       qualifier — i.e., wide open in every dimension.

    Both are configurable on/off via ``options['broad-allow']``:

    .. code-block:: toml

        [lint.broad-allow]
        disabled = false           # set true to opt out entirely
        world_open = true          # flag 0.0.0.0/0 etc.
        unconstrained = true       # flag no-constraint allow rules
    """

    rule_id = "broad-allow"
    description = "allow rule has overly broad scope"
    default_severity = Severity.warning

    def check(self, ctx: LintContext) -> list[LintFinding]:
        opts = ctx.options.get(self.rule_id) or {}
        if opts.get("disabled"):
            return []
        check_world = opts.get("world_open", True)
        check_unconstrained = opts.get("unconstrained", True)

        findings: list[LintFinding] = []

        policies_dir = ctx.repo.root / POLICIES_DIR
        for slug, policy in sorted(ctx.repo.policies.items()):
            if policy.status is Status.deleted:
                continue
            for rule in policy.rules:
                reason = _broad_allow_reason(
                    rule, check_world=check_world, check_unconstrained=check_unconstrained
                )
                if reason is None:
                    continue
                findings.append(
                    LintFinding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        path=policies_dir / f"{slug}.yaml",
                        field_path=f"rules.{rule.name}",
                        message=f"allow rule {rule.name!r}: {reason}",
                    )
                )

        rg_dir = ctx.repo.root / RULE_GROUPS_DIR
        for slug, rg in sorted(ctx.repo.rule_groups.items()):
            if rg.status is Status.deleted:
                continue
            for rule in rg.rules:
                reason = _broad_allow_reason(
                    rule, check_world=check_world, check_unconstrained=check_unconstrained
                )
                if reason is None:
                    continue
                findings.append(
                    LintFinding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        path=rg_dir / f"{slug}.yaml",
                        field_path=f"rules.{rule.name}",
                        message=f"allow rule {rule.name!r}: {reason}",
                    )
                )

        return findings


def _broad_allow_reason(
    rule: Rule,
    *,
    check_world: bool,
    check_unconstrained: bool,
) -> str | None:
    """Return a human-readable reason this rule is broad, or ``None``."""
    if rule.action is not Action.allow:
        return None
    if rule.state is not None:
        # Connection-state qualifier (e.g., established) constrains the rule.
        return None

    if check_world:
        for endpoint, label in ((rule.remote, "remote"), (rule.local, "local")):
            if endpoint is None or endpoint.addresses_negated:
                continue
            for addr in endpoint.addresses:
                if addr in _WORLD_CIDRS:
                    return f"{label} address {addr} is world-open"

    if check_unconstrained:
        if _endpoint_unconstrained(rule.local) and _endpoint_unconstrained(rule.remote):
            return (
                "no local or remote address/port constraints "
                "(rule allows traffic in every dimension)"
            )

    return None


def _endpoint_unconstrained(endpoint: Any) -> bool:
    """An endpoint counts as unconstrained when no list filters traffic."""
    if endpoint is None:
        return True
    return not endpoint.addresses and not endpoint.ports


# ---- Sprint-11 rules ------------------------------------------------------


class OrphanInheritsLint:
    """Policy ``inherits`` references a slug that does not exist in the repo.

    An orphan parent means the inheritance resolver silently returns the
    raw child policy; the child would be applied without any parent fields
    merged in, likely producing an incomplete policy.
    """

    rule_id = "orphan-inherits"
    description = "policy inherits from a slug that does not exist"
    default_severity = Severity.error

    def check(self, ctx: LintContext) -> list[LintFinding]:
        findings: list[LintFinding] = []
        policies_dir = ctx.repo.root / POLICIES_DIR
        for slug, policy in sorted(ctx.repo.policies.items()):
            if policy.inherits is None:
                continue
            if policy.inherits not in ctx.repo.policies:
                findings.append(
                    LintFinding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        path=policies_dir / f"{slug}.yaml",
                        field_path="inherits",
                        message=(
                            f"policy {slug!r} inherits from {policy.inherits!r} "
                            "which is not defined in this repository"
                        ),
                    )
                )
        return findings


class InheritanceDepthLint:
    """Policy inheritance chain exceeds depth-1.

    csfwctl supports single-level inheritance only. If policy A inherits
    from policy B, then B must not itself have an ``inherits`` field.
    Chains deeper than one level are rejected at apply time; this rule
    surfaces the violation at validate time.
    """

    rule_id = "inheritance-depth"
    description = "policy inherits from another policy that itself uses inherits"
    default_severity = Severity.error

    def check(self, ctx: LintContext) -> list[LintFinding]:
        findings: list[LintFinding] = []
        policies_dir = ctx.repo.root / POLICIES_DIR
        for slug, policy in sorted(ctx.repo.policies.items()):
            if policy.inherits is None:
                continue
            parent = ctx.repo.policies.get(policy.inherits)
            if parent is None:
                continue  # orphan-inherits will fire
            if parent.inherits is not None:
                findings.append(
                    LintFinding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        path=policies_dir / f"{slug}.yaml",
                        field_path="inherits",
                        message=(
                            f"policy {slug!r} inherits from {policy.inherits!r}, "
                            f"which itself inherits from {parent.inherits!r}; "
                            "inheritance depth is limited to 1"
                        ),
                    )
                )
        return findings


class CrossPlatformInheritanceLint:
    """Child policy has a different ``platform`` than its parent.

    Rule groups are platform-scoped; a Windows child cannot meaningfully
    inherit Mac rule groups and vice-versa. This is almost certainly a
    copy-paste error.
    """

    rule_id = "cross-platform-inheritance"
    description = "child policy platform does not match parent policy platform"
    default_severity = Severity.error

    def check(self, ctx: LintContext) -> list[LintFinding]:
        findings: list[LintFinding] = []
        policies_dir = ctx.repo.root / POLICIES_DIR
        for slug, policy in sorted(ctx.repo.policies.items()):
            if policy.inherits is None:
                continue
            parent = ctx.repo.policies.get(policy.inherits)
            if parent is None:
                continue  # orphan-inherits will fire
            if policy.platform is not parent.platform:
                findings.append(
                    LintFinding(
                        rule_id=self.rule_id,
                        severity=self.default_severity,
                        path=policies_dir / f"{slug}.yaml",
                        field_path="platform",
                        message=(
                            f"policy {slug!r} is platform {policy.platform.value!r} "
                            f"but parent {policy.inherits!r} is {parent.platform.value!r}; "
                            "cross-platform inheritance is not supported"
                        ),
                    )
                )
        return findings


# ---- registry -------------------------------------------------------------


LINT_REGISTRY: dict[str, Lint] = {}
"""Map of ``rule_id`` to lint instance. Insertion order is preserved."""


def register_lint(lint: Lint) -> None:
    """Register ``lint`` under its ``rule_id``.

    Overwrites any existing registration with the same id so plug-ins
    can replace a built-in if needed. Call at import time from a
    site-specific module.
    """
    LINT_REGISTRY[lint.rule_id] = lint


def _register_builtins() -> None:
    register_lint(PrecedenceCycleLint())
    register_lint(OrphanRuleGroupLint())
    register_lint(PolicyWithoutHostGroupsLint())
    register_lint(DeletedWithoutTombstoneLint())
    register_lint(BroadAllowLint())
    register_lint(OrphanInheritsLint())
    register_lint(InheritanceDepthLint())
    register_lint(CrossPlatformInheritanceLint())


_register_builtins()


def run_lints(
    repo: ConfigRepo,
    *,
    disabled: set[str] | None = None,
    options: dict[str, Any] | None = None,
) -> list[LintFinding]:
    """Run every registered lint and return findings in registry order.

    ``disabled`` is unioned with ``repo.tool_config.lint.disabled`` so
    operators can opt out of a rule in ``csfwctl.toml`` once rather than
    on every command invocation. Findings keep registry insertion order
    so output is deterministic across runs.
    """
    runtime_disabled: set[str] = set(disabled or [])
    repo_disabled: set[str] = set(repo.tool_config.lint.disabled)
    skip = runtime_disabled | repo_disabled

    ctx = LintContext(repo=repo, options=_merge_options(repo, options))
    findings: list[LintFinding] = []
    for rule_id, lint in LINT_REGISTRY.items():
        if rule_id in skip:
            continue
        findings.extend(lint.check(ctx))
    return findings


def _merge_options(repo: ConfigRepo, runtime: dict[str, Any] | None) -> dict[str, Any]:
    """Merge per-rule options from ``csfwctl.toml`` with runtime overrides."""
    merged: dict[str, Any] = dict(repo.tool_config.lint.options)
    if runtime:
        for key, value in runtime.items():
            merged[key] = value
    return merged


def has_errors(findings: list[LintFinding]) -> bool:
    """Convenience: any error-severity finding in the list?"""
    return any(f.severity is Severity.error for f in findings)


__all__ = [
    "BroadAllowLint",
    "CrossPlatformInheritanceLint",
    "DeletedWithoutTombstoneLint",
    "InheritanceDepthLint",
    "LINT_REGISTRY",
    "Lint",
    "LintContext",
    "LintFinding",
    "OrphanInheritsLint",
    "OrphanRuleGroupLint",
    "PolicyWithoutHostGroupsLint",
    "PrecedenceCycleLint",
    "Severity",
    "has_errors",
    "register_lint",
    "run_lints",
]
