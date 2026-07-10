"""Policy schema model."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from csfwctl.schema._common import (
    CrowdStrikeName,
    HostGroupEnv,
    Platform,
    PrecedenceBucket,
    Slug,
    Status,
)
from csfwctl.schema.policy_settings import PolicySettings
from csfwctl.schema.rule import Rule


class Policy(BaseModel):
    """A firewall policy.

    Each policy file represents one logical policy. Three CrowdStrike
    objects are managed for it — one per environment — sharing this base
    ``name`` with the environment suffix appended at apply time.

    ``rules`` are inline policy-specific overrides that the applier
    renders as an anonymous rule group named
    ``<policy-name>-overrides-<env>`` and inserts at the top of the
    policy's rule-group list. ``rule_groups`` lists shared rule-group
    slugs in precedence order.

    ``inherits`` names a parent policy slug. At apply/diff time the
    resolver materialises the effective policy by merging parent fields
    with any fields explicitly set on this policy. Collections default to
    **replace** semantics; set ``append_rule_groups`` or ``append_rules``
    to append instead (parent's items first, then child's).

    ``managed_host_groups`` maps each environment to a list of hostnames.
    The applier creates (or updates) a CrowdStrike dynamic host group for
    each env whose FQL is ``hostname:'a' or hostname:'b' …`` and assigns
    that group to the policy. Must not overlap with ``host_groups`` envs.

    ``skip_unassigned_envs`` restricts the policy (and its synthesised
    ``<slug>-overrides-<env>`` rule group) to environments that carry a
    host-group binding — an entry in either ``host_groups`` or
    ``managed_host_groups``. Useful for override-style policies that only
    apply to a single environment, so the applier does not create empty
    per-env objects for the environments where the policy is unused.

    ``tombstone_unassigned_envs`` opts the policy into auto-tombstoning:
    when combined with ``skip_unassigned_envs``, a live managed object
    for this policy in a now-unassigned env is emitted as a delete
    (still gated by ``--allow-delete``) instead of being reported as
    drift. Off by default — the "deletions require an explicit
    tombstone" invariant otherwise stands.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Slug
    display_name: CrowdStrikeName | None = None
    platform: Platform
    priority: PrecedenceBucket = PrecedenceBucket.default
    status: Status = Status.enabled
    description: str = Field(default="", max_length=2000)
    host_groups: dict[CrowdStrikeName, HostGroupEnv] = Field(default_factory=dict)
    rules: list[Rule] = Field(default_factory=list)
    rule_groups: list[Slug] = Field(default_factory=list)
    inherits: Slug | None = None
    append_rule_groups: bool = False
    append_rules: bool = False
    settings: PolicySettings | None = None
    managed_host_groups: dict[HostGroupEnv, list[str]] = Field(default_factory=dict)
    skip_unassigned_envs: bool = False
    tombstone_unassigned_envs: bool = False

    @model_validator(mode="after")
    def _rule_names_unique(self) -> Policy:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                duplicates.add(rule.name)
            seen.add(rule.name)
        if duplicates:
            joined = ", ".join(sorted(duplicates))
            raise ValueError(f"duplicate inline rule names within policy: {joined}")
        return self

    @model_validator(mode="after")
    def _rule_groups_unique(self) -> Policy:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for slug in self.rule_groups:
            if slug in seen:
                duplicates.add(slug)
            seen.add(slug)
        if duplicates:
            joined = ", ".join(sorted(duplicates))
            raise ValueError(f"duplicate rule-group references in policy: {joined}")
        return self

    @model_validator(mode="after")
    def _host_group_envs_unique(self) -> Policy:
        envs_seen: dict[HostGroupEnv, str] = {}
        for group_name, env in self.host_groups.items():
            if env in envs_seen:
                raise ValueError(
                    f"multiple host groups mapped to env {env.value!r}: "
                    f"{envs_seen[env]!r} and {group_name!r}"
                )
            envs_seen[env] = group_name
        return self

    @model_validator(mode="after")
    def _no_self_inheritance(self) -> Policy:
        if self.inherits is not None and self.inherits == self.name:
            raise ValueError(f"policy {self.name!r} cannot inherit from itself")
        return self

    @model_validator(mode="after")
    def _tombstone_requires_skip(self) -> Policy:
        if self.tombstone_unassigned_envs and not self.skip_unassigned_envs:
            raise ValueError("tombstone_unassigned_envs requires skip_unassigned_envs to be true")
        return self

    @model_validator(mode="after")
    def _managed_host_groups_no_env_overlap(self) -> Policy:
        host_group_envs = set(self.host_groups.values())
        managed_envs = set(self.managed_host_groups.keys())
        overlap = host_group_envs & managed_envs
        if overlap:
            envs_str = ", ".join(sorted(e.value for e in overlap))
            raise ValueError(
                f"env(s) {envs_str} appear in both host_groups and managed_host_groups; "
                "use one or the other per environment"
            )
        return self

    def referenced_locations(self) -> set[str]:
        """Union of non-``any`` location slugs referenced by inline rules."""
        result: set[str] = set()
        for rule in self.rules:
            result.update(rule.referenced_locations())
        return result


__all__ = ["Policy"]
