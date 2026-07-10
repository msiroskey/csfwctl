"""Policy inheritance resolver.

Resolves a policy's ``inherits`` reference against the config repo,
producing a flat materialised :class:`Policy` with no ``inherits`` field.
The YAML stays abstract; only the materialised form is passed to the
differ and applier.

Inheritance is depth-1 only: a parent policy must not itself have an
``inherits`` field. The ``inheritance-depth`` lint rule enforces this
statically; the resolver additionally raises at materialise time if the
constraint is violated.

Collection merge behaviour:

- All scalar fields default to **replace**: the child's explicit value
  wins; un-set fields fall back to the parent's value.
- ``rule_groups`` and ``rules`` also default to replace. Set
  ``append_rule_groups: true`` or ``append_rules: true`` on the child to
  prepend parent items before the child's own items instead.
- ``host_groups`` and ``managed_host_groups`` use replace semantics
  jointly. If the child sets *either* map, both are treated as
  child-authoritative — the parent's contribution to whichever map the
  child left unset is dropped, so an override policy that only sets
  ``managed_host_groups: {test: [...]}`` does not silently inherit the
  parent's Pilot / Production ``host_groups`` entries. Only when the
  child sets neither map are both inherited from the parent unchanged.
- The overlap check between the two maps still runs at the end as a
  belt-and-braces guard: any env that ends up in both after inheritance
  keeps the ``managed_host_groups`` entry and drops ``host_groups``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from csfwctl.schema._common import HostGroupEnv
from csfwctl.schema.policy import Policy

if TYPE_CHECKING:
    from csfwctl.loader import ConfigRepo


def managed_host_group_cs_name(policy: Policy, env: str) -> str:
    """CrowdStrike display name for the auto-managed dynamic host group.

    Follows the convention ``{base}-Managed-{Env}`` where ``base`` is the
    policy's ``display_name`` if set, otherwise the slug run through
    ``str.title()`` to produce a DisplayName-compatible string.
    """
    base = policy.display_name or policy.name.title()
    return f"{base}-Managed-{env.title()}"


def managed_host_group_fql(hostnames: list[str]) -> str:
    """Generate an FQL filter string for a list of hostnames.

    Produces ``hostname:'a' or hostname:'b' …``.  An empty list returns
    an empty string (the caller must guard against creating a group with
    no filter).
    """
    return " or ".join(f"hostname:'{h}'" for h in hostnames)


def resolve_inheritance(policy: Policy, repo: ConfigRepo) -> Policy:
    """Return a materialised copy of ``policy`` with its parent merged in.

    If ``policy.inherits`` is ``None`` the policy is returned unchanged.
    If the parent slug is not found in ``repo`` (orphan — the lint rule
    catches this) the policy is returned unchanged.

    The returned policy always has ``inherits=None``, ``append_rule_groups
    =False``, and ``append_rules=False`` so it is safe to pass directly to
    the differ and applier.
    """
    if policy.inherits is None:
        return policy

    parent = repo.policies.get(policy.inherits)
    if parent is None:
        return policy

    # Start from the parent's full state.
    base: dict[str, Any] = parent.model_dump(mode="json")

    # When the child explicitly declares any host binding — either
    # ``host_groups`` or ``managed_host_groups`` — its declaration is
    # authoritative for both maps. The parent's contribution to whichever
    # map the child did *not* set is wiped before the child's value is
    # applied, so an override-style policy that only sets
    # ``managed_host_groups: {test: [...]}`` doesn't silently inherit the
    # parent's Pilot / Production ``host_groups`` entries. When the child
    # sets neither, both maps come from the parent unchanged.
    child_sets_bindings = (
        "host_groups" in policy.model_fields_set or "managed_host_groups" in policy.model_fields_set
    )
    if child_sets_bindings:
        base["host_groups"] = {}
        base["managed_host_groups"] = {}

    # Override with every field the child explicitly set in its YAML.
    child_data: dict[str, Any] = policy.model_dump(mode="json")
    for field_name in policy.model_fields_set:
        if field_name in ("inherits", "append_rule_groups", "append_rules"):
            continue
        base[field_name] = child_data[field_name]

    # Apply collection-append semantics after the scalar-override pass.
    if policy.append_rule_groups:
        base["rule_groups"] = list(parent.rule_groups) + list(policy.rule_groups)

    if policy.append_rules:
        parent_rules = [r.model_dump(mode="json") for r in parent.rules]
        child_rules = [r.model_dump(mode="json") for r in policy.rules]
        base["rules"] = parent_rules + child_rules

    # Belt-and-braces: if both maps ended up covering the same env
    # (child set both, or the child inherited both from a parent that
    # did), managed takes precedence and the host_groups entry for that
    # env is dropped. The child-side validators reject direct overlap
    # inside a single policy; this branch only fires on inheritance.
    managed_envs: set[HostGroupEnv] = {
        HostGroupEnv(e) for e, hosts in base.get("managed_host_groups", {}).items() if hosts
    }
    if managed_envs:
        base["host_groups"] = {
            name: e
            for name, e in base.get("host_groups", {}).items()
            if HostGroupEnv(e) not in managed_envs
        }

    # Clear inheritance markers so the materialised policy validates cleanly.
    base["inherits"] = None
    base["append_rule_groups"] = False
    base["append_rules"] = False

    return Policy.model_validate(base)


__all__ = [
    "managed_host_group_cs_name",
    "managed_host_group_fql",
    "resolve_inheritance",
]
