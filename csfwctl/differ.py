"""Desired-vs-live state differ — the engine behind ``csfwctl diff``.

The differ takes a loaded :class:`ConfigRepo` plus a snapshot of one
environment's live CrowdStrike state and produces a structured
:class:`ChangeSet` listing creates, updates, deletes, and host-group
reassignments. The same change set is what Phase 5's applier will
consume, and what the drift-check job will emit on its scheduled run.

Design notes:

- Comparison happens in the *schema* domain. Live API records are
  translated into Pydantic models via ``exporter.*_from_api`` (with
  env-suffix stripping); desired state is projected into the same
  per-env shape. We then compare ``model_dump`` dicts.
- Per CLAUDE.md, inline policy ``rules`` are inverted into an anonymous
  rule group named ``<policy-slug>-overrides-<env>``. The differ
  synthesises that rule group on the desired side so live and desired
  see the same rule-group reference list.
- Managed-vs-unmanaged is decided by scanning the live ``description``
  for the metadata signature token. Unmanaged live objects are reported
  but never queued for change unless a tombstone explicitly opts them in.
- Locations are tenant-global (not env-suffixed). The differ still emits
  them in the per-env change set so the apply can converge them.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from csfwctl.exporter import (
    OVERRIDE_SUFFIX_RE,
    _enrich_policy_records_with_containers,
    is_override_group_name,
    location_from_api,
    policy_from_api,
    rule_group_from_api,
    strip_env_suffix,
    to_slug,
)
from csfwctl.falcon.client import FalconClient
from csfwctl.loader import ConfigRepo
from csfwctl.resolver import managed_host_group_cs_name, managed_host_group_fql, resolve_inheritance
from csfwctl.schema import (
    HostGroupEnv,
    Location,
    Policy,
    RuleGroup,
    Status,
)

METADATA_SIGNATURE_TOKEN = "Managed by csfwctl"
"""Substring whose presence in a description marks an object as csfwctl-managed."""

KIND_POLICY = "policy"
KIND_RULE_GROUP = "rule-group"
KIND_LOCATION = "location"

KIND_ORDER: tuple[str, ...] = (KIND_LOCATION, KIND_RULE_GROUP, KIND_POLICY)
"""Order kinds appear in human output. Matches the apply order (Phase 5)."""


class DiffOp(StrEnum):
    """The action the applier will take for a single object."""

    create = "create"
    update = "update"
    delete = "delete"
    no_change = "no-change"


class ManagedStatus(StrEnum):
    """Where the object sits relative to csfwctl management.

    ``managed`` — live description carries the metadata signature.
    ``unmanaged`` — live exists but lacks the signature.
    ``new`` — desired only; nothing live yet to inspect.
    """

    managed = "managed"
    unmanaged = "unmanaged"
    new = "new"


@dataclass(frozen=True)
class FieldChange:
    """One leaf-level difference between desired and live model dicts."""

    path: str
    before: Any
    after: Any

    def to_json(self) -> dict[str, Any]:
        return {"path": self.path, "before": self.before, "after": self.after}


@dataclass(frozen=True)
class HostGroupChange:
    """Add/remove of a host group on a policy for the current env."""

    op: str  # "add" | "remove"
    group_name: str
    env: HostGroupEnv

    def to_json(self) -> dict[str, Any]:
        return {"op": self.op, "group_name": self.group_name, "env": self.env.value}


@dataclass(frozen=True)
class ManagedGroupChange:
    """Create/update/no-change for a csfwctl-managed dynamic host group.

    Emitted for each env where a policy defines ``managed_host_groups``.
    The applier uses this to create or update the dynamic CrowdStrike
    group before assigning it to the policy.
    """

    op: str  # "create" | "update" | "no-change"
    group_name: str
    env: HostGroupEnv
    desired_fql: str
    live_fql: str | None = None

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "op": self.op,
            "group_name": self.group_name,
            "env": self.env.value,
            "desired_fql": self.desired_fql,
        }
        if self.live_fql is not None:
            payload["live_fql"] = self.live_fql
        return payload


@dataclass(frozen=True)
class ObjectChange:
    """One create/update/delete/no-change row in a :class:`ChangeSet`."""

    kind: str
    op: DiffOp
    slug: str
    display_name: str
    managed: ManagedStatus
    field_changes: tuple[FieldChange, ...] = ()
    host_group_changes: tuple[HostGroupChange, ...] = ()
    managed_group_changes: tuple[ManagedGroupChange, ...] = ()
    reason: str = ""

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "op": self.op.value,
            "slug": self.slug,
            "display_name": self.display_name,
            "managed": self.managed.value,
        }
        if self.field_changes:
            payload["field_changes"] = [fc.to_json() for fc in self.field_changes]
        if self.host_group_changes:
            payload["host_group_changes"] = [hg.to_json() for hg in self.host_group_changes]
        if self.managed_group_changes:
            payload["managed_group_changes"] = [mg.to_json() for mg in self.managed_group_changes]
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass
class LiveState:
    """Snapshot of one tenant's live state for a single ``diff`` run.

    The differ does not care where the records came from — the production
    code calls :func:`fetch_live_state`; tests construct one directly
    with hand-authored shapes.

    ``host_groups`` carries all host-group records; the differ uses them
    to detect create/update/no-change for ``managed_host_groups`` entries.
    """

    policies: list[dict[str, Any]] = field(default_factory=list)
    rule_groups: list[dict[str, Any]] = field(default_factory=list)
    locations: list[dict[str, Any]] = field(default_factory=list)
    rules_by_id: dict[str, dict[str, Any]] = field(default_factory=dict)
    host_groups: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ChangeSet:
    """Aggregate diff result for one ``--env`` run."""

    env: str
    creates: list[ObjectChange] = field(default_factory=list)
    updates: list[ObjectChange] = field(default_factory=list)
    deletes: list[ObjectChange] = field(default_factory=list)
    no_changes: list[ObjectChange] = field(default_factory=list)
    unmanaged: list[ObjectChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total_changes(self) -> int:
        """Count of creates + updates + deletes (no-change excluded)."""
        return len(self.creates) + len(self.updates) + len(self.deletes)

    @property
    def has_changes(self) -> bool:
        """``True`` when at least one create/update/delete is queued."""
        return self.total_changes > 0

    def all_actionable(self) -> list[ObjectChange]:
        """Flattened create/update/delete list in apply-order."""
        return [*self.creates, *self.updates, *self.deletes]

    def to_json(self) -> dict[str, Any]:
        """Render the change set as a plain dict suitable for ``json.dumps``."""
        return {
            "env": self.env,
            "summary": {
                "creates": len(self.creates),
                "updates": len(self.updates),
                "deletes": len(self.deletes),
                "no_changes": len(self.no_changes),
                "unmanaged": len(self.unmanaged),
                "warnings": len(self.warnings),
            },
            "creates": [c.to_json() for c in self.creates],
            "updates": [c.to_json() for c in self.updates],
            "deletes": [c.to_json() for c in self.deletes],
            "no_changes": [c.to_json() for c in self.no_changes],
            "unmanaged": [c.to_json() for c in self.unmanaged],
            "warnings": list(self.warnings),
        }


# ---- env-aware name helpers ----------------------------------------------


def env_suffix(env: str) -> str:
    """``"-Test"`` for ``"test"``, etc. Match the exporter's convention."""
    return f"-{env.title()}"


def env_to_host_group_env(env: str) -> HostGroupEnv:
    """Coerce the CLI's lowercase env into a :class:`HostGroupEnv`."""
    return HostGroupEnv(env)


def is_managed_description(description: str | None) -> bool:
    """``True`` if the live description carries the metadata signature."""
    if not description:
        return False
    return METADATA_SIGNATURE_TOKEN in description


# ---- desired-state projection --------------------------------------------


def synthesise_override_rule_groups(repo: ConfigRepo, env: str) -> dict[str, RuleGroup]:
    """Build override rule groups for every policy with inline rules.

    The slug follows ``<policy-slug>-overrides-<env>`` so it matches what
    the importer's ``is_override_group_name`` detects on a re-import. The
    platform mirrors the policy's so the loader's cross-platform
    invariants remain satisfied.
    """
    out: dict[str, RuleGroup] = {}
    for slug, policy in repo.policies.items():
        if not policy.rules:
            continue
        override_slug = f"{slug}-overrides-{env}"
        out[override_slug] = RuleGroup(
            name=override_slug,
            platform=policy.platform,
            status=Status.enabled,
            description=f"Inline overrides for policy {policy.name} ({env}).",
            rules=list(policy.rules),
        )
    return out


def project_policy_for_env(
    policy: Policy, slug: str, env: str, *, override_present: bool
) -> Policy:
    """Return a :class:`Policy` projected onto one env.

    - ``host_groups`` is filtered to just the entry whose value matches
      ``env`` (zero or one entry — duplicates are rejected at load time).
    - If the policy defines ``managed_host_groups`` for this env, the
      auto-managed group's display name is added to ``host_groups`` so
      the diff reflects the pending assignment.
    - When the policy carries inline ``rules`` and ``override_present``
      is true, those rules move out into the synthesised override group;
      the projected policy has ``rules=[]`` and the override slug
      prepended to ``rule_groups``.
    - ``settings`` is forwarded unchanged.
    """
    hg_env = env_to_host_group_env(env)
    host_groups = {name: hg for name, hg in policy.host_groups.items() if hg is hg_env}
    # Inject the managed host group name so the host-group assignment diff
    # reflects the create-and-assign that the applier will perform.
    if policy.managed_host_groups.get(hg_env):
        managed_name = managed_host_group_cs_name(policy, env)
        host_groups[managed_name] = hg_env
    rule_groups = list(policy.rule_groups)
    rules = list(policy.rules)
    if rules and override_present:
        rule_groups = [f"{slug}-overrides-{env}", *rule_groups]
        rules = []
    return Policy(
        name=policy.name,
        display_name=policy.display_name,
        platform=policy.platform,
        priority=policy.priority,
        status=policy.status,
        description=policy.description,
        host_groups=host_groups,
        rules=rules,
        rule_groups=rule_groups,
        settings=policy.settings,
    )


def build_desired_state(
    repo: ConfigRepo, env: str
) -> tuple[dict[str, Policy], dict[str, RuleGroup], dict[str, Location]]:
    """Build the per-env desired state as schema models keyed by slug.

    Inheritance is resolved before projection so the differ and applier
    always work with flat, materialised policies.
    """
    materialised: dict[str, Policy] = {
        slug: resolve_inheritance(policy, repo) for slug, policy in repo.policies.items()
    }
    overrides = synthesise_override_rule_groups_from(materialised, repo, env)
    desired_rule_groups: dict[str, RuleGroup] = {**repo.rule_groups, **overrides}
    desired_policies: dict[str, Policy] = {
        slug: project_policy_for_env(policy, slug, env, override_present=bool(policy.rules))
        for slug, policy in materialised.items()
    }
    desired_locations: dict[str, Location] = dict(repo.locations)
    return desired_policies, desired_rule_groups, desired_locations


def synthesise_override_rule_groups_from(
    materialised: dict[str, Policy], repo: ConfigRepo, env: str
) -> dict[str, RuleGroup]:
    """Build override rule groups from already-materialised policies."""
    out: dict[str, RuleGroup] = {}
    for slug, policy in materialised.items():
        if not policy.rules:
            continue
        override_slug = f"{slug}-overrides-{env}"
        out[override_slug] = RuleGroup(
            name=override_slug,
            platform=policy.platform,
            status=Status.enabled,
            description=f"Inline overrides for policy {policy.name} ({env}).",
            rules=list(policy.rules),
        )
    return out


# ---- live-state translation -----------------------------------------------


def fetch_live_state(client: FalconClient) -> LiveState:
    """Pull every policy, rule group, location, rule, and host group.

    Read-only. Used by the ``diff`` and drift-check commands.
    """
    policies = client.policies.list_all()
    _enrich_policy_records_with_containers(client, policies)
    rule_groups = client.rule_groups.list_all()
    locations = client.locations.list_all()
    host_groups = client.host_groups.list_all()
    rule_ids: list[str] = []
    seen: set[str] = set()
    for rg in rule_groups:
        for rid in rg.get("rule_ids") or []:
            rid_str = str(rid)
            if rid_str in seen:
                continue
            seen.add(rid_str)
            rule_ids.append(rid_str)
    rule_records = client.rule_groups.get_rules(rule_ids) if rule_ids else []
    # CrowdStrike rule-group GET records carry hex "family IDs" in rule_ids
    # (e.g. "838b17a58aab40e59c9a952299fd0b00"), but the rule detail records
    # returned by get_rules have a separate numeric id field.  Keying only
    # by numeric id means lookups by family id silently fail in
    # rule_group_from_api, causing the group to be dropped from the live
    # state and the differ to treat it as "new" on every run.  Use the same
    # multi-strategy approach as exporter._fetch_rules_for_groups:
    # 1. key by numeric id, 2. scan all string values for a family-id match,
    # 3. positional fallback when the count matches.
    rule_id_set = set(rule_ids)
    rules_by_id: dict[str, Any] = {}
    for r in rule_records:
        if "id" in r:
            rules_by_id[str(r["id"])] = r
        for v in r.values():
            if isinstance(v, str) and v in rule_id_set:
                rules_by_id[v] = r
    if len(rule_records) == len(rule_ids):
        for req_id, r in zip(rule_ids, rule_records, strict=False):
            rules_by_id.setdefault(req_id, r)
    return LiveState(
        policies=policies,
        rule_groups=rule_groups,
        locations=locations,
        rules_by_id=rules_by_id,
        host_groups=host_groups,
    )


def _record_matches_env(record: dict[str, Any], env: str) -> bool:
    """``True`` when the record's name ends with the env-suffix marker."""
    _, suffix_env = strip_env_suffix(str(record.get("name", "")))
    return suffix_env == env


def _filter_live_records_by_env(
    records: Iterable[dict[str, Any]], env: str
) -> list[dict[str, Any]]:
    """Return only the records whose display name carries the env suffix."""
    return [r for r in records if _record_matches_env(r, env)]


def _slug_for_live_record(record: dict[str, Any]) -> str:
    """Derive the env-stripped slug from a live record's display name."""
    base, _ = strip_env_suffix(str(record.get("name", "")))
    return to_slug(base)


@dataclass
class _LiveByKind:
    """Live records re-keyed by slug, plus the raw records for managed-status."""

    policies: dict[str, tuple[Policy, dict[str, Any]]]
    rule_groups: dict[str, tuple[RuleGroup, dict[str, Any]]]
    locations: dict[str, tuple[Location, dict[str, Any]]]


def _translate_live_state(state: LiveState, env: str, cs: ChangeSet | None = None) -> _LiveByKind:
    """Translate env-filtered live records into schema models keyed by slug.

    Failures translating individual records are recorded as warnings on
    ``cs`` (when provided) and the record is skipped, so a single corrupt
    record cannot black-hole the rest of the diff. Surfacing the warning
    matters because a silently-dropped live policy or rule group looks
    identical to "does not exist" to the differ and produces a spurious
    create on the next apply — which CrowdStrike then rejects with
    ``Duplicate ... name``.
    """
    rg_records_env = _filter_live_records_by_env(state.rule_groups, env)
    rule_groups_by_id_env: dict[str, dict[str, Any]] = {
        str(r["id"]): r for r in rg_records_env if "id" in r
    }
    # Index by env-stripped slug.
    rule_groups: dict[str, tuple[RuleGroup, dict[str, Any]]] = {}
    for record in rg_records_env:
        try:
            rg_model = rule_group_from_api(record, state.rules_by_id, strip_suffix=True)
        except Exception as exc:  # noqa: BLE001
            if cs is not None:
                cs.warnings.append(
                    f"live rule group {record.get('name', '?')!r} could not be translated: {exc}"
                )
            continue
        rule_groups[rg_model.name] = (rg_model, record)

    policies: dict[str, tuple[Policy, dict[str, Any]]] = {}
    for record in _filter_live_records_by_env(state.policies, env):
        try:
            policy_model = policy_from_api(
                record,
                rule_groups_by_id=rule_groups_by_id_env,
                rule_groups_by_slug={},
                strip_suffix=True,
                fold_overrides=False,
                tolerant_rule_group_refs=True,
            )
        except Exception as exc:  # noqa: BLE001
            if cs is not None:
                cs.warnings.append(
                    f"live policy {record.get('name', '?')!r} could not be translated: {exc}"
                )
            continue
        slug = _slug_for_live_record(record)
        policies[slug] = (policy_model, record)

    locations: dict[str, tuple[Location, dict[str, Any]]] = {}
    for record in state.locations:
        try:
            loc_model = location_from_api(record)
        except Exception as exc:  # noqa: BLE001
            if cs is not None:
                cs.warnings.append(
                    f"live location {record.get('name', '?')!r} could not be translated: {exc}"
                )
            continue
        locations[loc_model.name] = (loc_model, record)

    return _LiveByKind(policies=policies, rule_groups=rule_groups, locations=locations)


# ---- comparison primitives ------------------------------------------------


def _diff_dicts(before: Any, after: Any, prefix: str = "") -> list[FieldChange]:
    """Walk two ``model_dump`` dicts and emit one entry per leaf difference.

    Lists are treated as opaque scalars: when they differ at all, a
    single :class:`FieldChange` records the full before/after. The
    operator-facing summary stays terse and the JSON payload stays
    machine-parseable.
    """
    if before == after:
        return []
    if not isinstance(before, dict) or not isinstance(after, dict):
        return [FieldChange(path=prefix or ".", before=before, after=after)]
    out: list[FieldChange] = []
    for key in sorted(set(before) | set(after)):
        path = f"{prefix}.{key}" if prefix else key
        if key not in before:
            out.append(FieldChange(path=path, before=None, after=after[key]))
        elif key not in after:
            out.append(FieldChange(path=path, before=before[key], after=None))
        else:
            out.extend(_diff_dicts(before[key], after[key], path))
    return out


def _classify_managed(live_record: dict[str, Any]) -> ManagedStatus:
    """Decide managed vs. unmanaged purely from the description trailer."""
    description = str(live_record.get("description", "") or "")
    return ManagedStatus.managed if is_managed_description(description) else ManagedStatus.unmanaged


# Fields on Policy that exist only in the config-repo representation and
# have no counterpart on the live API record — exclude from diff comparison.
_POLICY_DIFF_EXCLUDE: frozenset[str] = frozenset(
    {"inherits", "append_rule_groups", "append_rules", "managed_host_groups"}
)


def _model_dump(model: Policy | RuleGroup | Location) -> dict[str, Any]:
    """Stable JSON-style dump that ignores non-essential metadata noise."""
    data = model.model_dump(mode="json", exclude_none=True)
    # Drop description from comparison: live carries the metadata trailer
    # and that is the applier's business, not the differ's.
    data.pop("description", None)
    # ``name`` and ``display_name`` are identity, not state — the differ
    # matches records via slug / display-name index lookup, so including
    # them here only produces phantom diffs when slug canonicalisation
    # is not reversible (e.g. ``ASC-MacEndpoints`` collapses to
    # ``asc-macendpoints`` while the YAML carries ``asc-mac-endpoints``).
    data.pop("name", None)
    data.pop("display_name", None)
    if isinstance(model, Policy):
        for key in _POLICY_DIFF_EXCLUDE:
            data.pop(key, None)
    return data


def _compare_models(
    desired: Policy | RuleGroup | Location, live: Policy | RuleGroup | Location
) -> list[FieldChange]:
    """Field-level diff between a desired and a live schema model."""
    return _diff_dicts(_model_dump(live), _model_dump(desired))


def _host_group_changes(desired: Policy, live: Policy, env: str) -> list[HostGroupChange]:
    """Add/remove operations to converge live's host-group set to desired.

    Each env has its own CrowdStrike policy (``-Test`` / ``-Pilot`` /
    ``-Production``), so a Test policy should only have the test-env
    host group attached. Any other group on the live record is drift
    and must be removed, including a cross-env group whose name carries
    a different ``-Pilot`` / ``-Production`` suffix.

    Compares the full host-group set on both sides (no env filter on
    the live side). ``desired`` is already projected for the env via
    :func:`project_policy_for_env`, so its keys are the only groups
    that should remain attached.
    """
    hg_env = env_to_host_group_env(env)
    desired_names = set(desired.host_groups.keys())
    live_names = set(live.host_groups.keys())
    out: list[HostGroupChange] = []
    for name in sorted(desired_names - live_names):
        out.append(HostGroupChange(op="add", group_name=name, env=hg_env))
    for name in sorted(live_names - desired_names):
        # Preserve the live env on the remove record when known so the
        # report makes it obvious that we are removing a cross-env stray;
        # fall back to the current env if the live record was not labelled.
        remove_env = live.host_groups.get(name, hg_env)
        out.append(HostGroupChange(op="remove", group_name=name, env=remove_env))
    return out


def _managed_group_changes(
    policy: Policy,
    env: str,
    live_host_groups_by_name: dict[str, dict[str, Any]],
) -> list[ManagedGroupChange]:
    """Create/update/no-change operations for managed dynamic host groups.

    ``policy`` should be the *raw* (pre-projection) materialised policy
    so that ``managed_host_groups`` is still accessible.
    ``live_host_groups_by_name`` maps CrowdStrike group display name to
    its raw API record (keyed from :attr:`LiveState.host_groups`).
    """
    hg_env = env_to_host_group_env(env)
    hostnames = policy.managed_host_groups.get(hg_env)
    if not hostnames:
        return []
    group_name = managed_host_group_cs_name(policy, env)
    desired_fql = managed_host_group_fql(hostnames)
    live_record = live_host_groups_by_name.get(group_name)
    if live_record is None:
        return [
            ManagedGroupChange(
                op="create",
                group_name=group_name,
                env=hg_env,
                desired_fql=desired_fql,
            )
        ]
    live_fql = str(live_record.get("assignment_rule", "") or "")
    if live_fql == desired_fql:
        return [
            ManagedGroupChange(
                op="no-change",
                group_name=group_name,
                env=hg_env,
                desired_fql=desired_fql,
                live_fql=live_fql,
            )
        ]
    return [
        ManagedGroupChange(
            op="update",
            group_name=group_name,
            env=hg_env,
            desired_fql=desired_fql,
            live_fql=live_fql,
        )
    ]


# ---- per-kind diff drivers -----------------------------------------------


def _diff_locations(
    desired: dict[str, Location],
    live: dict[str, tuple[Location, dict[str, Any]]],
    repo: ConfigRepo,
    cs: ChangeSet,
) -> None:
    """Append location creates/updates/deletes/no-changes to ``cs``."""
    tombstoned = {entry.name for entry in repo.tombstones.locations}
    for slug, model in sorted(desired.items()):
        if slug in live:
            live_model, live_record = live[slug]
            changes = _compare_models(model, live_model)
            managed = _classify_managed(live_record)
            change = ObjectChange(
                kind=KIND_LOCATION,
                op=DiffOp.no_change if not changes else DiffOp.update,
                slug=slug,
                display_name=model.display_name or model.name,
                managed=managed,
                field_changes=tuple(changes),
            )
            (cs.no_changes if not changes else cs.updates).append(change)
        else:
            cs.creates.append(
                ObjectChange(
                    kind=KIND_LOCATION,
                    op=DiffOp.create,
                    slug=slug,
                    display_name=model.display_name or model.name,
                    managed=ManagedStatus.new,
                )
            )
    for slug in sorted(set(live) - set(desired)):
        live_model, live_record = live[slug]
        if slug in tombstoned:
            cs.deletes.append(
                ObjectChange(
                    kind=KIND_LOCATION,
                    op=DiffOp.delete,
                    slug=slug,
                    display_name=live_model.display_name or live_model.name,
                    managed=_classify_managed(live_record),
                    reason="tombstoned",
                )
            )
        else:
            cs.unmanaged.append(
                ObjectChange(
                    kind=KIND_LOCATION,
                    op=DiffOp.no_change,
                    slug=slug,
                    display_name=live_model.display_name or live_model.name,
                    managed=_classify_managed(live_record),
                    reason="not in YAML and not tombstoned",
                )
            )


def _diff_rule_groups(
    desired: dict[str, RuleGroup],
    live: dict[str, tuple[RuleGroup, dict[str, Any]]],
    repo: ConfigRepo,
    env: str,
    cs: ChangeSet,
) -> None:
    """Append rule-group creates/updates/deletes/no-changes to ``cs``."""
    tombstoned = {entry.name for entry in repo.tombstones.rule_groups}
    suffix = env_suffix(env)
    # Secondary index: live records keyed by their raw CrowdStrike display
    # name (env suffix included). Required because ``to_slug`` does not
    # insert hyphens at camelCase boundaries, so a YAML slug
    # ``asc-mac-endpoints`` paired with display name ``ASC-MacEndpoints``
    # cannot be recovered from the live name ``ASC-MacEndpoints-Pilot``
    # by slug normalisation alone (which yields ``asc-macendpoints``).
    # Falling back to display-name matching prevents the applier from
    # attempting to recreate a rule group that already exists, which the
    # API rejects with ``Duplicate rule group name``.
    live_by_display_name: dict[str, str] = {
        str(record.get("name", "")): live_slug for live_slug, (_, record) in live.items()
    }
    matched_live_slugs: set[str] = set()
    for slug, model in sorted(desired.items()):
        display_name = (
            _override_display_name(slug, env)
            if _is_override_slug(slug)
            else f"{model.display_name or model.name}{suffix}"
        )
        live_slug: str | None = None
        if slug in live:
            live_slug = slug
        elif display_name in live_by_display_name:
            live_slug = live_by_display_name[display_name]
        if live_slug is not None:
            matched_live_slugs.add(live_slug)
            live_model, live_record = live[live_slug]
            changes = _compare_models(model, live_model)
            managed = _classify_managed(live_record)
            change = ObjectChange(
                kind=KIND_RULE_GROUP,
                op=DiffOp.no_change if not changes else DiffOp.update,
                slug=slug,
                display_name=display_name,
                managed=managed,
                field_changes=tuple(changes),
            )
            (cs.no_changes if not changes else cs.updates).append(change)
        else:
            cs.creates.append(
                ObjectChange(
                    kind=KIND_RULE_GROUP,
                    op=DiffOp.create,
                    slug=slug,
                    display_name=display_name,
                    managed=ManagedStatus.new,
                )
            )
    for slug in sorted(set(live) - set(desired) - matched_live_slugs):
        live_model, live_record = live[slug]
        display = f"{live_model.display_name or live_model.name}{suffix}"
        if slug in tombstoned:
            cs.deletes.append(
                ObjectChange(
                    kind=KIND_RULE_GROUP,
                    op=DiffOp.delete,
                    slug=slug,
                    display_name=display,
                    managed=_classify_managed(live_record),
                    reason="tombstoned",
                )
            )
        elif _is_override_slug(slug):
            # Orphan override group: the policy that produced it lost its
            # inline rules. Apply will drop it; until then it's drift.
            cs.warnings.append(
                f"orphan override rule group {display!r} (no matching policy inline rules)"
            )
        else:
            cs.unmanaged.append(
                ObjectChange(
                    kind=KIND_RULE_GROUP,
                    op=DiffOp.no_change,
                    slug=slug,
                    display_name=display,
                    managed=_classify_managed(live_record),
                    reason="not in YAML and not tombstoned",
                )
            )


def _diff_policies(
    desired: dict[str, Policy],
    live: dict[str, tuple[Policy, dict[str, Any]]],
    repo: ConfigRepo,
    env: str,
    cs: ChangeSet,
    materialised: dict[str, Policy],
    live_hg_by_name: dict[str, dict[str, Any]],
) -> None:
    """Append policy creates/updates/deletes/no-changes to ``cs``."""
    tombstoned = {entry.name for entry in repo.tombstones.policies}
    suffix = env_suffix(env)
    # Secondary index by the live raw display name. The slug-only lookup
    # misses cases where ``to_slug`` is not reversible (e.g. camelCase
    # display names). Without the fallback the live record is invisible
    # to the diff and the applier issues a duplicate-name create.
    live_by_display_name: dict[str, str] = {
        str(record.get("name", "")): live_slug for live_slug, (_, record) in live.items()
    }
    matched_live_slugs: set[str] = set()
    for slug, model in sorted(desired.items()):
        display_name = f"{model.display_name or model.name}{suffix}"
        # Compute managed-group changes from the pre-projection materialised policy.
        raw_policy = materialised.get(slug, model)
        mg_changes = _managed_group_changes(raw_policy, env, live_hg_by_name)
        live_slug: str | None = None
        if slug in live:
            live_slug = slug
        elif display_name in live_by_display_name:
            live_slug = live_by_display_name[display_name]
        if live_slug is not None:
            matched_live_slugs.add(live_slug)
            live_model, live_record = live[live_slug]
            field_changes = _compare_models(model, live_model)
            hg_changes = _host_group_changes(model, live_model, env)
            managed = _classify_managed(live_record)
            has_change = bool(
                field_changes or hg_changes or any(mgc.op != "no-change" for mgc in mg_changes)
            )
            change = ObjectChange(
                kind=KIND_POLICY,
                op=DiffOp.no_change if not has_change else DiffOp.update,
                slug=slug,
                display_name=display_name,
                managed=managed,
                field_changes=tuple(field_changes),
                host_group_changes=tuple(hg_changes),
                managed_group_changes=tuple(mg_changes),
            )
            (cs.no_changes if not has_change else cs.updates).append(change)
        else:
            cs.creates.append(
                ObjectChange(
                    kind=KIND_POLICY,
                    op=DiffOp.create,
                    slug=slug,
                    display_name=display_name,
                    managed=ManagedStatus.new,
                    managed_group_changes=tuple(mg_changes),
                )
            )
    for slug in sorted(set(live) - set(desired) - matched_live_slugs):
        live_model, live_record = live[slug]
        display = f"{live_model.display_name or live_model.name}{suffix}"
        if slug in tombstoned:
            cs.deletes.append(
                ObjectChange(
                    kind=KIND_POLICY,
                    op=DiffOp.delete,
                    slug=slug,
                    display_name=display,
                    managed=_classify_managed(live_record),
                    reason="tombstoned",
                )
            )
        else:
            cs.unmanaged.append(
                ObjectChange(
                    kind=KIND_POLICY,
                    op=DiffOp.no_change,
                    slug=slug,
                    display_name=display,
                    managed=_classify_managed(live_record),
                    reason="not in YAML and not tombstoned",
                )
            )


# ---- override-rule-group naming helpers ----------------------------------


def _is_override_slug(slug: str) -> bool:
    """``True`` when the slug fits the ``<base>-overrides-<env>`` pattern."""
    return OVERRIDE_SUFFIX_RE.match(slug) is not None


def _override_display_name(slug: str, env: str) -> str:
    """Render the env-suffixed display name for an override-RG slug.

    Override RGs already carry the env in their slug; the applier still
    appends the env suffix on the CrowdStrike-visible name, matching the
    convention used by ``rule_group_to_api_shape`` and the importer
    round-trip tests.
    """
    _, slug_env = is_override_group_name(slug)
    del slug_env
    return f"{slug}{env_suffix(env)}"


# ---- public entrypoint ----------------------------------------------------


def compute_diff(repo: ConfigRepo, env: str, state: LiveState) -> ChangeSet:
    """Compare a config repo against one environment's live state.

    Returns a :class:`ChangeSet` ready for human or JSON rendering. Does
    not raise on translation errors against individual live records; the
    surviving objects are still diffed and the failures (if any) become
    entries on :attr:`ChangeSet.warnings`.
    """
    if env not in {e.value for e in HostGroupEnv}:
        raise ValueError(f"unknown env {env!r}; must be one of test/pilot/production")

    cs = ChangeSet(env=env)

    # Materialise inherited policies once; reuse for both desired-state
    # projection and managed-group diff.
    materialised: dict[str, Policy] = {
        slug: resolve_inheritance(policy, repo) for slug, policy in repo.policies.items()
    }

    desired_policies, desired_rule_groups, desired_locations = build_desired_state(repo, env)
    live = _translate_live_state(state, env, cs)

    # Index live host groups by display name for managed-group lookup.
    live_hg_by_name: dict[str, dict[str, Any]] = {
        str(r.get("name", "")): r for r in state.host_groups if r.get("name")
    }

    _diff_locations(desired_locations, live.locations, repo, cs)
    _diff_rule_groups(desired_rule_groups, live.rule_groups, repo, env, cs)
    _diff_policies(
        desired_policies,
        live.policies,
        repo,
        env,
        cs,
        materialised=materialised,
        live_hg_by_name=live_hg_by_name,
    )

    return cs


__all__ = [
    "ChangeSet",
    "DiffOp",
    "FieldChange",
    "HostGroupChange",
    "KIND_LOCATION",
    "KIND_ORDER",
    "KIND_POLICY",
    "KIND_RULE_GROUP",
    "LiveState",
    "METADATA_SIGNATURE_TOKEN",
    "ManagedGroupChange",
    "ManagedStatus",
    "ObjectChange",
    "build_desired_state",
    "compute_diff",
    "env_suffix",
    "env_to_host_group_env",
    "fetch_live_state",
    "is_managed_description",
    "project_policy_for_env",
    "synthesise_override_rule_groups",
    "synthesise_override_rule_groups_from",
]
