"""Idempotent applier — the engine behind ``csfwctl apply``.

The applier consumes a :class:`csfwctl.differ.ChangeSet`, runs the
safety rails from :mod:`csfwctl.safety`, then drives the FalconClient
sub-clients to converge the live tenant. Operation order matches the
project plan:

1. **Locations** (creates and updates).
2. **Rule groups** (creates and updates).
3. **Policies** (creates and updates) — host-group membership is set on
   the policy payload at create time.
4. **Host-group reassignments** for already-existing policies whose
   ``groups`` set drifted (the ``HostGroupChange`` rows on each policy
   update).
5. **Precedence ordering** (Phase 6 stub — left as a hook).
6. **Deletes** — policies, then rule groups, then locations.

Every touched object's ``description`` is rewritten to carry the
canonical metadata trailer (``Managed by csfwctl | version: N | …``).
:func:`apply_change_set` is the public entrypoint; the CLI command body
in :mod:`csfwctl.apply_cmd` is its thin caller.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from csfwctl.differ import (
    KIND_LOCATION,
    KIND_POLICY,
    KIND_RULE_GROUP,
    ChangeSet,
    FieldChange,
    HostGroupChange,
    ManagedGroupChange,
    ObjectChange,
    build_desired_state,
    env_suffix,
)
from csfwctl.exporter import (
    location_to_api_shape,
    policy_to_api_shape,
    rule_group_to_api_shape,
)
from csfwctl.falcon.client import FalconClient
from csfwctl.loader import ConfigRepo
from csfwctl.observability import get_logger
from csfwctl.safety import (
    MetadataSignature,
    SafetyError,
    SafetyOptions,
    check_blast_radius,
    check_bootstrap,
    check_deletes,
    check_drift,
    inject_signature,
    next_signature,
    parse_signature,
)
from csfwctl.schema import Location, Platform, Policy, RuleGroup, Status

_logger = get_logger("applier")


class HostGroupPolicy(StrEnum):
    """Behaviour when a policy references a missing host group.

    ``warn`` (default): log + skip the missing assignment.
    ``strict``: raise :class:`ApplyError` and abort.
    ``create``: create the host group with an empty membership.
    """

    warn = "warn"
    strict = "strict"
    create = "create"


@dataclass(frozen=True)
class ApplyOptions:
    """All apply-time flags surfaced on the CLI.

    Kept separate from :class:`csfwctl.safety.SafetyOptions` so the
    safety module can be unit-tested without dragging the applier in,
    and so the applier can read its own flags without going back through
    the CLI parser.
    """

    env: str
    git_sha: str
    dry_run: bool = False
    initial_bootstrap: bool = False
    host_group_policy: HostGroupPolicy = HostGroupPolicy.warn

    @property
    def env_suffix(self) -> str:
        """``"-Test"`` etc. — matches the exporter convention."""
        return env_suffix(self.env)


@dataclass(frozen=True)
class AppliedAction:
    """One write the applier performed (or would have, in dry-run).

    ``field_changes`` / ``host_group_changes`` / ``managed_group_changes``
    carry the diff that produced the action so the apply log, the
    ``apply.succeeded`` notifier payload, and any ``--output`` JSON
    record exactly *what* changed — not just *which object* changed.
    Deletes and metadata-only bootstrap writes carry empty tuples.
    """

    kind: str  # "location" | "rule-group" | "policy" | "host-group"
    op: str  # "create" | "update" | "delete" | "metadata" | "host-group"
    slug: str
    display_name: str
    detail: str = ""
    field_changes: tuple[FieldChange, ...] = ()
    host_group_changes: tuple[HostGroupChange, ...] = ()
    managed_group_changes: tuple[ManagedGroupChange, ...] = ()

    def to_json(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "op": self.op,
            "slug": self.slug,
            "display_name": self.display_name,
        }
        if self.detail:
            payload["detail"] = self.detail
        if self.field_changes:
            payload["field_changes"] = [fc.to_json() for fc in self.field_changes]
        if self.host_group_changes:
            payload["host_group_changes"] = [hg.to_json() for hg in self.host_group_changes]
        if self.managed_group_changes:
            payload["managed_group_changes"] = [mg.to_json() for mg in self.managed_group_changes]
        return payload


@dataclass
class ApplyReport:
    """Aggregate result returned by :func:`apply_change_set`."""

    env: str
    dry_run: bool
    bootstrap: bool
    actions: list[AppliedAction] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def count(self, op: str) -> int:
        """Number of recorded actions matching ``op``."""
        return sum(1 for a in self.actions if a.op == op)

    def to_json(self) -> dict[str, Any]:
        return {
            "env": self.env,
            "dry_run": self.dry_run,
            "bootstrap": self.bootstrap,
            "summary": {
                "create": self.count("create"),
                "update": self.count("update"),
                "delete": self.count("delete"),
                "metadata": self.count("metadata"),
                "host_group": self.count("host-group"),
            },
            "actions": [a.to_json() for a in self.actions],
            "warnings": list(self.warnings),
        }


class ApplyError(Exception):
    """Raised when an apply cannot complete (e.g., missing host group, strict)."""


# ---- live-record indexing -------------------------------------------------


@dataclass
class _LiveIndex:
    """Slug → ``(id, raw description)`` lookup for each managed kind.

    ``rule_group_live`` stores the full raw live record for each rule group
    so the update path can extract ``tracking`` and ``rule_ids`` for the
    diff-based PATCH endpoint.

    ``rule_groups_by_display_name`` is a secondary index by the full
    env-suffixed CrowdStrike display name. The differ falls back to a
    display-name match when slug normalisation is not reversible (e.g.
    YAML slug ``asc-mac-endpoints`` vs. CrowdStrike name
    ``ASC-MacEndpoints``, which ``to_slug`` collapses to
    ``asc-macendpoints``). The applier needs the same fallback to retrieve
    the live ID for the update path.
    """

    policies: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    rule_groups: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    locations: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    rule_group_live: dict[str, dict[str, Any]] = field(default_factory=dict)
    rule_groups_by_display_name: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    rule_group_live_by_display_name: dict[str, dict[str, Any]] = field(default_factory=dict)
    policies_by_display_name: dict[str, tuple[str, str | None]] = field(default_factory=dict)


def _build_live_index(state: Any, env: str) -> _LiveIndex:
    """Index live records by env-stripped slug.

    Mirrors the slug derivation used by the differ so creates / updates /
    deletes from a change set line up exactly with what we find here.
    """
    from csfwctl.exporter import strip_env_suffix, to_slug

    idx = _LiveIndex()
    for record in state.policies:
        if not isinstance(record, dict) or "id" not in record:
            continue
        raw_name = str(record.get("name", ""))
        base, suffix_env = strip_env_suffix(raw_name)
        if suffix_env != env:
            continue
        entry = (str(record["id"]), record.get("description"))
        idx.policies[to_slug(base)] = entry
        idx.policies_by_display_name[raw_name] = entry
    for record in state.rule_groups:
        if not isinstance(record, dict) or "id" not in record:
            continue
        raw_name = str(record.get("name", ""))
        base, suffix_env = strip_env_suffix(raw_name)
        if suffix_env != env:
            continue
        slug = to_slug(base)
        entry = (str(record["id"]), record.get("description"))
        idx.rule_groups[slug] = entry
        idx.rule_group_live[slug] = record
        idx.rule_groups_by_display_name[raw_name] = entry
        idx.rule_group_live_by_display_name[raw_name] = record
    for record in state.locations:
        if not isinstance(record, dict) or "id" not in record:
            continue
        # Locations are tenant-global; no env suffix to strip.
        name = str(record.get("name", ""))
        if not name:
            continue
        idx.locations[to_slug(name)] = (str(record["id"]), record.get("description"))
    return idx


def _rule_group_live_lookup(
    index: _LiveIndex, slug: str, display_name: str
) -> tuple[tuple[str, str | None] | None, dict[str, Any] | None]:
    """Return ``((id, description), full_record)`` for a desired rule group.

    Primary lookup is by env-stripped slug; falls back to the full
    env-suffixed display name to cover camelCase display names that do
    not round-trip through ``to_slug``. Returns ``(None, None)`` if
    neither matches.
    """
    entry = index.rule_groups.get(slug)
    record = index.rule_group_live.get(slug)
    if entry is None:
        entry = index.rule_groups_by_display_name.get(display_name)
        record = index.rule_group_live_by_display_name.get(display_name)
    return entry, record


def _policy_live_lookup(
    index: _LiveIndex, slug: str, display_name: str
) -> tuple[str, str | None] | None:
    """Return ``(id, description)`` for a desired policy.

    Mirrors :func:`_rule_group_live_lookup`: primary lookup by
    env-stripped slug, fallback by full env-suffixed display name. The
    fallback prevents the applier from issuing a duplicate-name policy
    create when the YAML slug and the live CrowdStrike display name do
    not round-trip through ``to_slug``.
    """
    entry = index.policies.get(slug)
    if entry is None:
        entry = index.policies_by_display_name.get(display_name)
    return entry


# ---- payload builders -----------------------------------------------------


def _signature_for(description: str | None, options: ApplyOptions) -> tuple[str, MetadataSignature]:
    """Compute the new description trailer for one object.

    Returns ``(new_description, signature)`` so callers can stamp the
    description on the outgoing payload and also surface the signature
    in the apply report.
    """
    previous = parse_signature(description)
    sig = next_signature(previous, git_sha=options.git_sha, env=options.env)
    return inject_signature(description, sig), sig


def _build_location_payload(
    location: Location,
    options: ApplyOptions,
    *,
    live_id: str | None,
    live_description: str | None,
) -> dict[str, Any]:
    """Render a location into the API payload, injecting the trailer."""
    shape = location_to_api_shape(location)
    shape.pop("id", None)
    if live_id is not None:
        shape["id"] = live_id
    new_description, _ = _signature_for(live_description or location.description, options)
    shape["description"] = new_description
    return shape


def _build_rule_group_payload(
    rule_group: RuleGroup,
    options: ApplyOptions,
    *,
    live_id: str | None,
    live_description: str | None,
) -> dict[str, Any]:
    """Render a rule group into the API payload, injecting the trailer."""
    shape = rule_group_to_api_shape(rule_group, options.env)
    shape.pop("id", None)
    if live_id is not None:
        shape["id"] = live_id
    new_description, _ = _signature_for(live_description or rule_group.description, options)
    shape["description"] = new_description
    return shape


def _build_rule_group_update_payload(
    rule_group: RuleGroup,
    options: ApplyOptions,
    *,
    live_id: str,
    live_description: str | None,
    live_record: dict[str, Any] | None,
    change: ObjectChange | None = None,
) -> dict[str, Any]:
    """Build a diff-based rule-group PATCH payload.

    The rule-group update endpoint rejects any payload missing ``diff_type``,
    ``tracking``, or ``rule_ids`` with HTTP 400.  All changes are expressed as
    JSON Patch operations against the rule group document:

    - the metadata trailer as ``replace /description``;
    - rule content as ``add`` / ``remove`` operations on the ``/rules`` array.
      The endpoint rejects a ``replace`` targeting a whole ``/rules/<i>`` object
      ("unhandled replace operation in payload"), so a modified rule is emitted
      as a remove + add pair (see ``_rule_content_diff_ops``).

    ``tracking`` is copied verbatim from the live record for optimistic
    concurrency.  ``rule_ids`` is the live list with removed entries dropped and
    a ``temp_id`` placeholder appended for each added rule; the server maps each
    ``temp_id`` to the real id it assigns (confirmed against a real tenant —
    the endpoint rejects an added rule without a non-empty ``temp_id``).
    """
    new_description, _ = _signature_for(live_description or rule_group.description, options)
    record = live_record or {}
    live_rule_ids = [str(rid) for rid in (record.get("rule_ids") or [])]

    operations: list[dict[str, Any]] = [
        {"op": "replace", "path": "/description", "value": new_description}
    ]
    rule_ids = live_rule_ids

    rules_change = _find_field_change(change, "rules")
    if rules_change is not None:
        rule_ops, rule_ids = _rule_content_diff_ops(
            rule_group, options.env, rules_change, live_rule_ids
        )
        operations.extend(rule_ops)

    payload: dict[str, Any] = {
        "id": live_id,
        "diff_type": _RULE_GROUP_DIFF_TYPE,
        "diff_operations": operations,
        "rule_ids": rule_ids,
    }
    tracking = record.get("tracking")
    if tracking:
        payload["tracking"] = tracking
    return payload


def _find_field_change(change: ObjectChange | None, path: str) -> FieldChange | None:
    """Return the field change at ``path`` on ``change`` (or ``None``)."""
    if change is None:
        return None
    for fc in change.field_changes:
        if fc.path == path:
            return fc
    return None


def _rule_content_diff_ops(
    rule_group: RuleGroup,
    env: str,
    rules_change: FieldChange,
    live_rule_ids: list[str],
) -> tuple[list[dict[str, Any]], list[str]]:
    """Translate a ``rules`` list change into JSON-Patch ops on ``/rules``.

    ``rules_change.before`` is the live rule list (parallel to
    ``live_rule_ids``); ``rules_change.after`` is the desired list.  Rules are
    matched by name — csfwctl's stable per-rule identity.  Returns
    ``(operations, rule_ids)`` where ``rule_ids`` is the live list minus removed
    entries.

    The rule-group update endpoint only handles ``add`` / ``remove`` ops on the
    ``/rules`` array — a ``replace`` targeting a whole ``/rules/<i>`` object is
    rejected with HTTP 400 ``"unhandled replace operation in payload"`` (only the
    scalar ``replace /description`` is accepted).  A content change to an
    existing rule is therefore expressed as a **remove + add** pair, not a
    replace.  Because csfwctl matches rules by name rather than server id, the
    re-added rule taking a fresh server-assigned id is harmless.

    Operations are emitted in an order that keeps array indices valid: removes
    (descending index) first, then appends.
    """
    before = list(rules_change.before or [])
    after = list(rules_change.after or [])

    if len(before) != len(live_rule_ids):
        raise SafetyError(
            f"rule group {rule_group.name!r}: live rule count ({len(before)}) does "
            f"not match rule_ids ({len(live_rule_ids)}); refusing to build an "
            "ambiguous rule update"
        )

    desired_shapes = {s["name"]: s for s in rule_group_to_api_shape(rule_group, env)["rules"]}
    before_by_name = {r.get("name"): (i, r) for i, r in enumerate(before)}
    after_by_name = {r.get("name"): r for r in after}

    # A rule present on both sides whose content differs is "modified": removed
    # at its live index and re-added with the desired content below.
    modified_names = {
        name
        for name, (_i, live_rule) in before_by_name.items()
        if name in after_by_name and after_by_name[name] != live_rule
    }

    operations: list[dict[str, Any]] = []

    # Removes: gone from desired, or modified (re-added below). Descending index
    # so earlier indices stay valid; drop the entry from rule_ids.
    remove_indices = sorted(
        (
            i
            for i, r in enumerate(before)
            if r.get("name") not in after_by_name or r.get("name") in modified_names
        ),
        reverse=True,
    )
    rule_ids = list(live_rule_ids)
    for i in remove_indices:
        operations.append({"op": "remove", "path": f"/rules/{i}"})
        del rule_ids[i]

    # Adds: new in desired, plus modified rules re-added. Append; the server
    # assigns the real id, mapping it from the client-supplied ``temp_id``. The
    # endpoint requires a non-empty ``temp_id`` on each added rule and the same
    # token in ``rule_ids`` at the rule's final position ("Rule 'temp_id' cannot
    # be empty." otherwise).
    temp_counter = 0
    for rule in after:
        name = rule.get("name")
        if name not in before_by_name or name in modified_names:
            temp_counter += 1
            temp_id = f"temp_{temp_counter}"
            shape = dict(desired_shapes[name])
            shape.pop("id", None)
            shape["temp_id"] = temp_id
            operations.append({"op": "add", "path": "/rules/-", "value": shape})
            rule_ids.append(temp_id)

    return operations, rule_ids


def _build_policy_payload(
    policy: Policy,
    options: ApplyOptions,
    *,
    live_id: str | None,
    live_description: str | None,
    host_group_ids: dict[str, str],
    rule_group_ids: dict[str, str],
) -> dict[str, Any]:
    """Render a policy into the API payload with real host-group / RG IDs."""
    shape = policy_to_api_shape(policy, options.env)
    shape.pop("id", None)
    if live_id is not None:
        shape["id"] = live_id
    new_description, _ = _signature_for(live_description or policy.description, options)
    shape["description"] = new_description
    shape["groups"] = [
        {"id": host_group_ids[name], "name": name}
        for name in policy.host_groups
        if name in host_group_ids
    ]
    settings = shape.setdefault("settings", {})
    # rule_group_to_api_shape uses fake_uuid; replace with real live IDs
    # for any rule groups that already exist. Newly-created rule groups
    # have a real id assigned by their create() call upstream of policy.
    resolved: list[str] = []
    for slug in _projected_rule_group_slugs(policy):
        rg_id = rule_group_ids.get(slug)
        if rg_id is None:
            raise ApplyError(
                f"policy {policy.name!r} references rule group {slug!r} but no live "
                "or freshly-created ID is available; was the rule group apply skipped?"
            )
        resolved.append(rg_id)
    settings["rule_group_ids"] = resolved
    # Inject enforcement and default-traffic settings when specified.
    if policy.settings is not None:
        ps = policy.settings
        if ps.enforcement_mode is not None:
            from csfwctl.schema.policy_settings import EnforcementMode

            # ``monitor`` requires enforcement enabled; ``test_mode`` is what
            # distinguishes it from a full ``enforce``.
            settings["enforce"] = ps.enforcement_mode in (
                EnforcementMode.enforce,
                EnforcementMode.monitor,
            )
            settings["test_mode"] = ps.enforcement_mode is EnforcementMode.monitor
        if ps.local_logging is not None:
            settings["local_logging"] = ps.local_logging
        if ps.default_inbound is not None:
            settings["inbound"] = ps.default_inbound.upper()
        if ps.default_outbound is not None:
            settings["outbound"] = ps.default_outbound.upper()
    return shape


def _projected_rule_group_slugs(policy: Policy) -> list[str]:
    """The ordered rule-group slugs the policy will reference on apply.

    The differ's :func:`project_policy_for_env` already inserts the
    override slug at index 0 for policies that carry inline rules; the
    applier therefore just trusts the projected ``rule_groups`` list.
    """
    return list(policy.rule_groups)


def _resolve_container_str(desired: str | None, existing: Any, default: str) -> str:
    """Pick the value to send for a required string container field.

    The ``update_policy_container`` endpoint rejects payloads where
    ``default_inbound`` / ``default_outbound`` are missing or empty, so
    we always have to send a value: the YAML's if specified, otherwise
    whatever the live container holds, otherwise the API's standard
    permissive default.
    """
    if desired is not None:
        return desired
    if existing is not None and str(existing).strip():
        return str(existing).upper()
    return default


def _resolve_container_bool(desired: bool | None, existing: Any, default: bool) -> bool:
    """Pick the value to send for a required boolean container field."""
    if desired is not None:
        return desired
    if isinstance(existing, bool):
        return existing
    return default


def _apply_policy_relations(
    client: FalconClient,
    *,
    policy: Policy,
    policy_id: str,
    host_group_ids: dict[str, str],
    rule_group_ids: dict[str, str],
    host_group_changes: tuple[HostGroupChange, ...],
    status_changed: bool,
    options: ApplyOptions,
    report: ApplyReport,
    is_create: bool,
) -> None:
    """Apply rule-group, host-group, and enabled state for one policy.

    ``policies.update`` / ``policies.create`` only persist
    ``id``/``name``/``description``/``platform_name``; rule-group
    assignments, host-group memberships, and the enabled flag all need
    dedicated endpoints. Without these calls ``apply`` reports success
    but the policy in CrowdStrike remains empty and disabled.

    Resolution order (must match the API's preconditions — the host
    group has to exist before it can be attached, etc.):

    1. ``update_policy_container`` — sets ``rule_group_ids`` plus the
       default-traffic / enforcement / local-logging settings.
    2. For creates: attach every desired host group via
       ``perform_action add-host-group``. For updates: process each
       :class:`HostGroupChange` add/remove.
    3. Toggle the enabled flag via ``perform_action enable`` /
       ``disable`` when the desired status differs from live (for
       updates) or when a newly created policy should be enabled.
    """
    if options.dry_run:
        return

    rg_ids: list[str] = []
    for slug in _projected_rule_group_slugs(policy):
        rg_id = rule_group_ids.get(slug)
        if rg_id is None:
            raise ApplyError(
                f"policy {policy.name!r} references rule group {slug!r} but no live "
                "or freshly-created ID is available; was the rule group apply skipped?"
            )
        rg_ids.append(rg_id)

    # Fetch the existing policy container so the update has PUT semantics:
    # the API rejects payloads where ``default_inbound``, ``default_outbound``,
    # ``enforce``, or ``test_mode`` are missing with HTTP 400
    # ``"... attribute cannot be empty"``. Fields not set in the YAML
    # ``settings`` block fall back to the live container value, then to
    # safe defaults if the container fetch returned nothing (the
    # newly-created-policy case, where eventual consistency can briefly
    # mask the container).
    existing_container: dict[str, Any] = {}
    try:
        containers = client.policies.get_policy_containers([policy_id])
        if containers:
            existing_container = containers[0]
    except Exception as exc:  # noqa: BLE001
        report.warnings.append(
            f"policy {policy.name!r}: get_policy_containers failed ({exc}); "
            "falling back to defaults for unspecified container fields"
        )

    desired_inbound: str | None = None
    desired_outbound: str | None = None
    desired_enforce: bool | None = None
    desired_test_mode: bool | None = None
    desired_local_logging: bool | None = None
    if policy.settings is not None:
        from csfwctl.schema.policy_settings import EnforcementMode

        ps = policy.settings
        if ps.enforcement_mode is not None:
            # ``monitor`` requires enforcement enabled; ``test_mode`` is what
            # distinguishes it from a full ``enforce``.
            desired_enforce = ps.enforcement_mode in (
                EnforcementMode.enforce,
                EnforcementMode.monitor,
            )
            desired_test_mode = ps.enforcement_mode is EnforcementMode.monitor
        if ps.local_logging is not None:
            desired_local_logging = ps.local_logging
        if ps.default_inbound is not None:
            desired_inbound = ps.default_inbound.upper()
        if ps.default_outbound is not None:
            desired_outbound = ps.default_outbound.upper()

    platform_id = policy.platform.value
    container_kwargs: dict[str, Any] = {
        "policy_id": policy_id,
        "platform_id": platform_id,
        "rule_group_ids": rg_ids,
        "default_inbound": _resolve_container_str(
            desired_inbound, existing_container.get("default_inbound"), "ALLOW"
        ),
        "default_outbound": _resolve_container_str(
            desired_outbound, existing_container.get("default_outbound"), "ALLOW"
        ),
        "enforce": _resolve_container_bool(
            desired_enforce, existing_container.get("enforce"), False
        ),
        "test_mode": _resolve_container_bool(
            desired_test_mode, existing_container.get("test_mode"), False
        ),
        "local_logging": _resolve_container_bool(
            desired_local_logging, existing_container.get("local_logging"), False
        ),
    }
    tracking = existing_container.get("tracking")
    if tracking:
        container_kwargs["tracking"] = str(tracking)
    client.policies.update_policy_container(**container_kwargs)

    if is_create:
        for hg_name in policy.host_groups:
            hg_id = host_group_ids.get(hg_name)
            if hg_id is None:
                report.warnings.append(
                    f"policy {policy.name!r}: host group {hg_name!r} not resolved; skipping attach"
                )
                continue
            client.policies.add_host_group(policy_id, hg_id)
    else:
        for hgc in host_group_changes:
            hg_id = host_group_ids.get(hgc.group_name)
            if hg_id is None:
                report.warnings.append(
                    f"policy {policy.name!r}: host group {hgc.group_name!r} "
                    f"not resolved; skipping {hgc.op}"
                )
                continue
            if hgc.op == "add":
                client.policies.add_host_group(policy_id, hg_id)
            else:
                client.policies.remove_host_group(policy_id, hg_id)

    desired_enabled = policy.status is Status.enabled
    should_toggle = status_changed if not is_create else desired_enabled
    if should_toggle:
        if desired_enabled:
            client.policies.enable([policy_id])
        else:
            client.policies.disable([policy_id])


# ---- host-group resolution -----------------------------------------------


def _lookup_host_group_ids(
    client: FalconClient,
    names: Iterable[str],
    report: ApplyReport,
) -> dict[str, str]:
    """Resolve host-group names to ids without ever creating them.

    Used for the *remove* side of host-group churn: we need an id so
    ``perform_action remove-host-group`` can target the live record,
    but creating a group we are about to detach is nonsensical and a
    naive call to :func:`_resolve_host_group_ids` would do exactly
    that under ``--create-groups``. Names that cannot be resolved are
    recorded as warnings on the report; the applier then skips the
    remove instead of aborting.
    """
    resolved: dict[str, str] = {}
    for name in dict.fromkeys(names):
        try:
            record = client.host_groups.find_by_name(name)
        except Exception as exc:  # noqa: BLE001 — surface as warning
            report.warnings.append(f"host group lookup {name!r} failed: {exc}")
            continue
        if record and record.get("id"):
            resolved[name] = str(record["id"])
    return resolved


def _resolve_host_group_ids(
    client: FalconClient,
    names: Iterable[str],
    options: ApplyOptions,
    report: ApplyReport,
) -> dict[str, str]:
    """Look up (and optionally create) the host groups by display name.

    Behaviour matches :class:`HostGroupPolicy`:

    - ``warn`` — record a warning and skip the missing assignment.
    - ``strict`` — raise :class:`ApplyError`.
    - ``create`` — create the group as empty (unless ``dry_run``) and
      record a synthesised id so subsequent payload building can refer
      to it.
    """
    resolved: dict[str, str] = {}
    for name in dict.fromkeys(names):  # de-dupe while preserving order
        record: dict[str, Any] | None = None
        try:
            record = client.host_groups.find_by_name(name)
        except Exception as exc:  # noqa: BLE001 — surface as warning
            report.warnings.append(f"host group lookup {name!r} failed: {exc}")
            record = None
        if record and record.get("id"):
            resolved[name] = str(record["id"])
            continue
        if options.host_group_policy is HostGroupPolicy.strict:
            raise ApplyError(f"host group {name!r} not found (and --strict-groups is set)")
        if options.host_group_policy is HostGroupPolicy.create:
            if options.dry_run:
                synth_id = f"dry-run-host-group-{name}"
                resolved[name] = synth_id
                _append_action(
                    report,
                    AppliedAction(
                        kind="host-group",
                        op="create",
                        slug=name.lower(),
                        display_name=name,
                        detail="dry-run",
                    ),
                )
                continue
            created = client.host_groups.create(name)
            if not created or "id" not in created:
                raise ApplyError(f"failed to create host group {name!r}: empty response")
            resolved[name] = str(created["id"])
            _append_action(
                report,
                AppliedAction(kind="host-group", op="create", slug=name.lower(), display_name=name),
            )
            continue
        # warn
        report.warnings.append(
            f"host group {name!r} not found; assignment skipped (pass --strict-groups "
            "to fail or --create-groups to create it)"
        )
    return resolved


def _apply_managed_host_groups(
    client: FalconClient,
    managed_group_changes: list[tuple[str, ManagedGroupChange]],
    options: ApplyOptions,
    report: ApplyReport,
) -> dict[str, str]:
    """Create or update dynamic host groups for ``managed_host_groups`` entries.

    Returns a mapping of ``group_name → group_id`` for all managed groups
    that were created, updated, or already existed.  The caller threads
    these IDs into ``host_group_ids`` before building policy payloads.

    ``managed_group_changes`` is a list of ``(policy_slug, ManagedGroupChange)``
    pairs collected from all policy creates/updates in the change set.
    """
    resolved: dict[str, str] = {}
    seen: set[str] = set()
    for policy_slug, mgc in managed_group_changes:
        if mgc.group_name in seen:
            continue
        seen.add(mgc.group_name)

        if mgc.op == "no-change":
            # Group already has the right FQL; just look up its ID.
            try:
                record = client.host_groups.find_by_name(mgc.group_name)
            except Exception as exc:  # noqa: BLE001
                report.warnings.append(
                    f"managed host group {mgc.group_name!r} lookup failed: {exc}"
                )
                continue
            if record and record.get("id"):
                resolved[mgc.group_name] = str(record["id"])
            continue

        if mgc.op == "create":
            if options.dry_run:
                synth_id = f"dry-run-managed-hg-{policy_slug}"
                resolved[mgc.group_name] = synth_id
                _append_action(
                    report,
                    AppliedAction(
                        kind="host-group",
                        op="create",
                        slug=policy_slug,
                        display_name=mgc.group_name,
                        detail=f"dry-run (dynamic, fql={mgc.desired_fql!r})",
                        managed_group_changes=(mgc,),
                    ),
                )
                continue
            try:
                created = client.host_groups.create_dynamic(
                    mgc.group_name,
                    fql=mgc.desired_fql,
                    description=f"Managed by csfwctl for policy {policy_slug}",
                )
            except Exception as exc:  # noqa: BLE001
                report.warnings.append(
                    f"failed to create managed host group {mgc.group_name!r}: {exc}"
                )
                continue
            if created and created.get("id"):
                resolved[mgc.group_name] = str(created["id"])
                _append_action(
                    report,
                    AppliedAction(
                        kind="host-group",
                        op="create",
                        slug=policy_slug,
                        display_name=mgc.group_name,
                        detail=str(created["id"]),
                        managed_group_changes=(mgc,),
                    ),
                )
            continue

        # op == "update": FQL changed.
        try:
            live_record = client.host_groups.find_by_name(mgc.group_name)
        except Exception as exc:  # noqa: BLE001
            report.warnings.append(f"managed host group {mgc.group_name!r} lookup failed: {exc}")
            continue
        if not live_record or not live_record.get("id"):
            report.warnings.append(
                f"managed host group {mgc.group_name!r} marked for update but "
                "not found in CrowdStrike; it will be created on next apply"
            )
            continue
        live_id = str(live_record["id"])
        if options.dry_run:
            resolved[mgc.group_name] = live_id
            _append_action(
                report,
                AppliedAction(
                    kind="host-group",
                    op="update",
                    slug=policy_slug,
                    display_name=mgc.group_name,
                    detail=f"dry-run (fql={mgc.desired_fql!r})",
                    managed_group_changes=(mgc,),
                ),
            )
            continue
        # Check managed-status: warn if group exists but isn't csfwctl-managed.
        live_desc = str(live_record.get("description", "") or "")
        from csfwctl.differ import METADATA_SIGNATURE_TOKEN

        if METADATA_SIGNATURE_TOKEN not in live_desc:
            report.warnings.append(
                f"managed host group {mgc.group_name!r} exists but was not "
                "created by csfwctl; FQL will be updated but external membership "
                "changes are not tracked"
            )
        try:
            client.host_groups.update_fql(live_id, mgc.desired_fql)
        except Exception as exc:  # noqa: BLE001
            report.warnings.append(
                f"failed to update FQL for managed host group {mgc.group_name!r}: {exc}"
            )
            continue
        resolved[mgc.group_name] = live_id
        _append_action(
            report,
            AppliedAction(
                kind="host-group",
                op="update",
                slug=policy_slug,
                display_name=mgc.group_name,
                detail=live_id,
                managed_group_changes=(mgc,),
            ),
        )
    return resolved


def _platform_api_name(platform: Platform) -> str:
    """``Windows`` / ``Mac`` — the casing CrowdStrike accepts."""
    return "Windows" if platform is Platform.windows else "Mac"


# ---- main entrypoint ------------------------------------------------------


def apply_change_set(
    *,
    client: FalconClient,
    repo: ConfigRepo,
    change_set: ChangeSet,
    state: Any,
    options: ApplyOptions,
    safety_options: SafetyOptions,
) -> ApplyReport:
    """Apply ``change_set`` against ``client``'s tenant.

    Order: locations → rule groups → policies (with host groups set) →
    host-group reassignments → precedence (stub) → deletes. The metadata
    trailer is rewritten on every object the applier touches.

    ``state`` is the same :class:`csfwctl.differ.LiveState` the diff
    consumed; the applier re-indexes it to resolve slug → live id and
    pull the previous description for trailer-merging.

    All safety rails fire **before** any write:

    - Bootstrap gate (:func:`csfwctl.safety.check_bootstrap`).
    - Drift gate (:func:`csfwctl.safety.check_drift`).
    - Delete gate (:func:`csfwctl.safety.check_deletes`).
    - Blast-radius gate (:func:`csfwctl.safety.check_blast_radius`).
    """
    report = ApplyReport(
        env=options.env,
        dry_run=options.dry_run,
        bootstrap=options.initial_bootstrap,
        warnings=list(change_set.warnings),
    )

    # ---- safety rails (raise on refusal) ----------------------------------
    live_descriptions: list[str | None] = []
    for collection in (state.policies, state.rule_groups, state.locations):
        for record in collection:
            if isinstance(record, dict):
                live_descriptions.append(record.get("description"))
    check_bootstrap(live_descriptions=live_descriptions, options=safety_options)
    check_drift(change_set, safety_options)
    check_deletes(change_set, safety_options)
    check_blast_radius(change_set, safety_options)

    index = _build_live_index(state, options.env)

    if options.initial_bootstrap:
        _bootstrap_metadata(client, repo, options, report, index, state)
        return report

    # ---- desired-state projection (matches the differ) --------------------
    desired_policies, desired_rule_groups, desired_locations = build_desired_state(
        repo, options.env
    )

    # ---- 1. locations: creates + updates ----------------------------------
    for change in _ordered(change_set.creates, KIND_LOCATION):
        loc_model = desired_locations[change.slug]
        loc_payload = _build_location_payload(
            loc_model, options, live_id=None, live_description=None
        )
        _do_write(
            client,
            kind=KIND_LOCATION,
            op="create",
            slug=change.slug,
            display_name=change.display_name,
            payload=loc_payload,
            index=index,
            options=options,
            report=report,
            change=change,
        )
    for change in _ordered(change_set.updates, KIND_LOCATION):
        loc_model = desired_locations[change.slug]
        loc_live = index.locations.get(change.slug)
        loc_payload = _build_location_payload(
            loc_model,
            options,
            live_id=loc_live[0] if loc_live else None,
            live_description=loc_live[1] if loc_live else None,
        )
        _do_write(
            client,
            kind=KIND_LOCATION,
            op="update",
            slug=change.slug,
            display_name=change.display_name,
            payload=loc_payload,
            index=index,
            options=options,
            report=report,
            change=change,
        )

    # ---- 2. rule groups: creates + updates --------------------------------
    for change in _ordered(change_set.creates, KIND_RULE_GROUP):
        rg_model = desired_rule_groups[change.slug]
        rg_payload = _build_rule_group_payload(
            rg_model, options, live_id=None, live_description=None
        )
        _do_write(
            client,
            kind=KIND_RULE_GROUP,
            op="create",
            slug=change.slug,
            display_name=change.display_name,
            payload=rg_payload,
            index=index,
            options=options,
            report=report,
            change=change,
        )
    for change in _ordered(change_set.updates, KIND_RULE_GROUP):
        rg_model = desired_rule_groups[change.slug]
        rg_live, rg_live_record = _rule_group_live_lookup(index, change.slug, change.display_name)
        rg_payload = _build_rule_group_update_payload(
            rg_model,
            options,
            live_id=rg_live[0] if rg_live else "",
            live_description=rg_live[1] if rg_live else None,
            live_record=rg_live_record,
            change=change,
        )
        _do_write(
            client,
            kind=KIND_RULE_GROUP,
            op="update",
            slug=change.slug,
            display_name=change.display_name,
            payload=rg_payload,
            index=index,
            options=options,
            report=report,
            change=change,
        )

    # ---- 3. policies (with host groups + RG IDs) --------------------------
    policy_creates = _ordered(change_set.creates, KIND_POLICY)
    policy_updates = _ordered(change_set.updates, KIND_POLICY)

    # 3a. Create/update managed dynamic host groups before resolving IDs.
    all_managed_changes: list[tuple[str, ManagedGroupChange]] = []
    for change in (*policy_creates, *policy_updates):
        for mgc in change.managed_group_changes:
            all_managed_changes.append((change.slug, mgc))
    managed_group_ids = _apply_managed_host_groups(client, all_managed_changes, options, report)

    needed_host_groups: list[str] = []
    remove_host_group_names: list[str] = []
    for change in (*policy_creates, *policy_updates):
        p_model = desired_policies[change.slug]
        needed_host_groups.extend(p_model.host_groups.keys())
    for change in policy_updates:
        for hg_change in change.host_group_changes:
            if hg_change.op == "add":
                needed_host_groups.append(hg_change.group_name)
            else:
                remove_host_group_names.append(hg_change.group_name)
    host_group_ids = _resolve_host_group_ids(client, needed_host_groups, options, report)
    # Look up (but never create) IDs for groups we are detaching. Without
    # this, ``--create-groups`` would accidentally try to create the very
    # group we are about to remove, and the perform_action remove call
    # would be skipped with a "not resolved" warning.
    host_group_ids.update(_lookup_host_group_ids(client, remove_host_group_names, report))
    # Merge managed group IDs so policy payloads can reference them.
    host_group_ids.update(managed_group_ids)

    rule_group_ids: dict[str, str] = {
        slug: live_id for slug, (live_id, _desc) in index.rule_groups.items()
    }
    # Seed entries for desired slugs whose CrowdStrike display name does
    # not round-trip through ``to_slug`` (e.g. ``ASC-MacEndpoints``
    # collapses to ``asc-macendpoints`` while the YAML carries
    # ``asc-mac-endpoints``). Without this fallback the policy payload
    # builder cannot resolve a live RG id and either re-creates the
    # group (``Duplicate rule group name``) or raises ApplyError.
    for desired_slug, rg_model in desired_rule_groups.items():
        if desired_slug in rule_group_ids:
            continue
        display_name = f"{rg_model.display_name or rg_model.name}{env_suffix(options.env)}"
        entry = index.rule_groups_by_display_name.get(display_name)
        if entry is not None:
            rule_group_ids[desired_slug] = entry[0]
    # Add the IDs of rule groups we just created (or would create in
    # dry-run, with a synthetic id so the policy payload still builds).
    for action in report.actions:
        if action.kind == KIND_RULE_GROUP and action.op == "create":
            rule_group_ids.setdefault(action.slug, action.detail or f"dry-run-{action.slug}")

    for change in policy_creates:
        p_model = desired_policies[change.slug]
        p_payload = _build_policy_payload(
            p_model,
            options,
            live_id=None,
            live_description=None,
            host_group_ids=host_group_ids,
            rule_group_ids=rule_group_ids,
        )
        _do_write(
            client,
            kind=KIND_POLICY,
            op="create",
            slug=change.slug,
            display_name=change.display_name,
            payload=p_payload,
            index=index,
            options=options,
            report=report,
            change=change,
        )
        # ``create_policies`` only persists name/description/platform_name;
        # everything else (rule groups, host groups, enabled flag) lands
        # via dedicated endpoints in :func:`_apply_policy_relations`.
        created_entry = index.policies.get(change.slug)
        if created_entry is not None:
            _apply_policy_relations(
                client,
                policy=p_model,
                policy_id=created_entry[0],
                host_group_ids=host_group_ids,
                rule_group_ids=rule_group_ids,
                host_group_changes=(),
                status_changed=False,
                options=options,
                report=report,
                is_create=True,
            )
    for change in policy_updates:
        p_model = desired_policies[change.slug]
        p_live = _policy_live_lookup(index, change.slug, change.display_name)
        p_payload = _build_policy_payload(
            p_model,
            options,
            live_id=p_live[0] if p_live else None,
            live_description=p_live[1] if p_live else None,
            host_group_ids=host_group_ids,
            rule_group_ids=rule_group_ids,
        )
        _do_write(
            client,
            kind=KIND_POLICY,
            op="update",
            slug=change.slug,
            display_name=change.display_name,
            payload=p_payload,
            index=index,
            options=options,
            report=report,
            change=change,
        )
        # ``update_policies`` only patches name/description. Apply rule-
        # group, host-group, and enabled-state changes via dedicated
        # endpoints. Without this the differ reports the update but
        # nothing actually changes on the live policy.
        if p_live is not None:
            status_changed = any(fc.path == "status" for fc in change.field_changes)
            _apply_policy_relations(
                client,
                policy=p_model,
                policy_id=p_live[0],
                host_group_ids=host_group_ids,
                rule_group_ids=rule_group_ids,
                host_group_changes=change.host_group_changes,
                status_changed=status_changed,
                options=options,
                report=report,
                is_create=False,
            )
        # Record host-group reassignments on the report for visibility.
        for hg_change in change.host_group_changes:
            _record_host_group_change(report, change, hg_change)

    # ---- 4. precedence (Phase 6 stub) -------------------------------------
    # Resolving bucket → ordinal precedence + calling set_precedence is a
    # Phase 6 concern. The hook is here so the order in apply is fixed
    # before precedence resolution lands.

    # ---- 5. deletes (policies → rule groups → locations) ------------------
    for change in _ordered(change_set.deletes, KIND_POLICY):
        live = index.policies.get(change.slug)
        if live is None:
            report.warnings.append(f"delete policy {change.slug!r}: not in live state; skipped")
            continue
        _do_delete(
            client,
            kind=KIND_POLICY,
            slug=change.slug,
            display_name=change.display_name,
            live_id=live[0],
            options=options,
            report=report,
            change=change,
        )
    for change in _ordered(change_set.deletes, KIND_RULE_GROUP):
        live = index.rule_groups.get(change.slug)
        if live is None:
            report.warnings.append(f"delete rule-group {change.slug!r}: not in live state; skipped")
            continue
        _do_delete(
            client,
            kind=KIND_RULE_GROUP,
            slug=change.slug,
            display_name=change.display_name,
            live_id=live[0],
            options=options,
            report=report,
            change=change,
        )
    for change in _ordered(change_set.deletes, KIND_LOCATION):
        live = index.locations.get(change.slug)
        if live is None:
            report.warnings.append(f"delete location {change.slug!r}: not in live state; skipped")
            continue
        _do_delete(
            client,
            kind=KIND_LOCATION,
            slug=change.slug,
            display_name=change.display_name,
            live_id=live[0],
            options=options,
            report=report,
            change=change,
        )

    return report


# ---- bootstrap mode ------------------------------------------------------


def _bootstrap_metadata(
    client: FalconClient,
    repo: ConfigRepo,
    options: ApplyOptions,
    report: ApplyReport,
    index: _LiveIndex,
    state: Any,
) -> None:
    """``--initial-bootstrap`` body: rewrite metadata only.

    For every live object whose env-stripped slug matches a desired
    object, replay an update that touches *only* ``description``. Rule
    content, status, host groups, and rule-group references are left
    alone. Live objects without a matching YAML are reported as
    warnings; YAML objects without a matching live record are likewise
    reported (creation requires a subsequent normal apply).
    """
    desired_policies, desired_rule_groups, desired_locations = build_desired_state(
        repo, options.env
    )

    for slug, (live_id, live_description) in index.locations.items():
        if slug not in desired_locations:
            report.warnings.append(
                f"bootstrap: live location {slug!r} has no YAML counterpart; skipped"
            )
            continue
        new_description, _ = _signature_for(live_description, options)
        _bootstrap_write(
            client,
            kind=KIND_LOCATION,
            slug=slug,
            display_name=desired_locations[slug].display_name or slug,
            live_id=live_id,
            new_description=new_description,
            options=options,
            report=report,
        )
    for slug in sorted(desired_locations):
        if slug not in index.locations:
            report.warnings.append(
                f"bootstrap: YAML location {slug!r} has no live counterpart; "
                "rerun without --initial-bootstrap to create it"
            )

    from csfwctl.exporter import strip_env_suffix
    from csfwctl.exporter import to_slug as _to_slug

    rg_by_slug: dict[str, dict[str, Any]] = {}
    for record in state.rule_groups:
        if not isinstance(record, dict) or "id" not in record:
            continue
        base, _ = strip_env_suffix(str(record.get("name", "")))
        rg_by_slug[_to_slug(base)] = record

    for slug, (live_id, live_description) in index.rule_groups.items():
        if slug not in desired_rule_groups:
            report.warnings.append(
                f"bootstrap: live rule group {slug!r} has no YAML counterpart; skipped"
            )
            continue
        new_description, _ = _signature_for(live_description, options)
        _bootstrap_write(
            client,
            kind=KIND_RULE_GROUP,
            slug=slug,
            display_name=f"{desired_rule_groups[slug].display_name or slug}{options.env_suffix}",
            live_id=live_id,
            new_description=new_description,
            live_record=rg_by_slug.get(slug),
            options=options,
            report=report,
        )
    for slug in sorted(desired_rule_groups):
        if slug not in index.rule_groups:
            report.warnings.append(
                f"bootstrap: YAML rule group {slug!r} has no live counterpart; "
                "rerun without --initial-bootstrap to create it"
            )

    for slug, (live_id, live_description) in index.policies.items():
        if slug not in desired_policies:
            report.warnings.append(
                f"bootstrap: live policy {slug!r} has no YAML counterpart; skipped"
            )
            continue
        new_description, _ = _signature_for(live_description, options)
        pol = desired_policies[slug]
        display = f"{pol.display_name or pol.name}{options.env_suffix}"
        _bootstrap_write(
            client,
            kind=KIND_POLICY,
            slug=slug,
            display_name=display,
            live_id=live_id,
            new_description=new_description,
            options=options,
            report=report,
        )
    for slug in sorted(desired_policies):
        if slug not in index.policies:
            report.warnings.append(
                f"bootstrap: YAML policy {slug!r} has no live counterpart; "
                "rerun without --initial-bootstrap to create it"
            )


# The firewall rule-group update endpoint is diff-based. ``diff_type`` has
# exactly one accepted value, and a field can only be changed via a JSON
# Patch operation in ``diff_operations`` — a top-level ``description`` key is
# silently ignored.
_RULE_GROUP_DIFF_TYPE = "application/json-patch+json"


def _rule_group_metadata_payload(
    live_id: str,
    new_description: str,
    live_record: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build a metadata-only rule-group update as a JSON Patch.

    The update endpoint rejects payloads missing ``diff_type``,
    ``tracking``, or ``rule_ids`` and ignores a top-level ``description``,
    so the trailer change is expressed as a ``replace /description`` patch.
    ``rule_ids`` and ``tracking`` are copied verbatim from the live record
    so rule content and the optimistic-concurrency token are preserved —
    bootstrap never touches rule content.
    """
    record = live_record or {}
    payload: dict[str, Any] = {
        "id": live_id,
        "diff_type": _RULE_GROUP_DIFF_TYPE,
        "diff_operations": [{"op": "replace", "path": "/description", "value": new_description}],
        "rule_ids": list(record.get("rule_ids") or []),
    }
    tracking = record.get("tracking")
    if tracking:
        payload["tracking"] = tracking
    return payload


def _bootstrap_write(
    client: FalconClient,
    *,
    kind: str,
    slug: str,
    display_name: str,
    live_id: str,
    new_description: str,
    live_record: dict[str, Any] | None = None,
    options: ApplyOptions,
    report: ApplyReport,
) -> None:
    """Issue a metadata-only update for one bootstrap target.

    Locations and policies accept a minimal ``{id, description}`` update.
    Rule groups go through the diff-based update endpoint instead — see
    :func:`_rule_group_metadata_payload`.
    """
    payload: dict[str, Any]
    if kind == KIND_RULE_GROUP:
        payload = _rule_group_metadata_payload(live_id, new_description, live_record)
    else:
        payload = {"id": live_id, "description": new_description}
    if options.dry_run:
        _append_action(
            report,
            AppliedAction(
                kind=kind,
                op="metadata",
                slug=slug,
                display_name=display_name,
                detail="dry-run",
            ),
        )
        return
    if kind == KIND_LOCATION:
        client.locations.upsert([payload])
    elif kind == KIND_RULE_GROUP:
        client.rule_groups.update(payload)
    else:  # policy
        client.policies.update([payload])
    _append_action(
        report,
        AppliedAction(kind=kind, op="metadata", slug=slug, display_name=display_name),
    )


# ---- write helpers --------------------------------------------------------


def _ordered(items: list[ObjectChange], kind: str) -> list[ObjectChange]:
    """Filter ``items`` to one kind, sorted by slug for determinism."""
    return sorted((c for c in items if c.kind == kind), key=lambda c: c.slug)


def _do_write(
    client: FalconClient,
    *,
    kind: str,
    op: str,
    slug: str,
    display_name: str,
    payload: dict[str, Any],
    index: _LiveIndex,
    options: ApplyOptions,
    report: ApplyReport,
    change: ObjectChange | None = None,
) -> None:
    """Dispatch one create/update to the right sub-client.

    Records the action on the report and, on a successful create,
    threads the new id back into ``index`` so subsequent payloads (e.g.,
    a policy that references a freshly-created rule group) can resolve
    it without a second round-trip. ``change`` carries the diff that
    produced this write so the recorded action surfaces the field-level
    detail (rule edits, host-group adds/removes, managed-group FQL).
    """
    if options.dry_run:
        _append_action(
            report,
            _build_action(kind, op, slug, display_name, "dry-run", change),
        )
        # Even in dry-run, allocate a synthetic id so downstream payloads
        # (e.g. a policy referencing a freshly-created RG) still build.
        if op == "create":
            synth = f"dry-run-{kind}-{slug}"
            if kind == KIND_LOCATION:
                index.locations[slug] = (synth, payload.get("description"))
            elif kind == KIND_RULE_GROUP:
                index.rule_groups[slug] = (synth, payload.get("description"))
            else:
                index.policies[slug] = (synth, payload.get("description"))
        return

    new_id: str | None = None
    if kind == KIND_LOCATION:
        results = client.locations.upsert([payload])
        if results and "id" in results[0]:
            new_id = str(results[0]["id"])
    elif kind == KIND_RULE_GROUP:
        if op == "create":
            result = client.rule_groups.create(payload)
        else:
            result = client.rule_groups.update(payload)
        if result and "id" in result:
            new_id = str(result["id"])
    elif kind == KIND_POLICY:
        if op == "create":
            results = client.policies.create([payload])
        else:
            results = client.policies.update([payload])
        if results and "id" in results[0]:
            new_id = str(results[0]["id"])

    detail = new_id or ""
    _append_action(report, _build_action(kind, op, slug, display_name, detail, change))

    if op == "create" and new_id is not None:
        if kind == KIND_LOCATION:
            index.locations[slug] = (new_id, payload.get("description"))
        elif kind == KIND_RULE_GROUP:
            index.rule_groups[slug] = (new_id, payload.get("description"))
        else:
            index.policies[slug] = (new_id, payload.get("description"))


def _do_delete(
    client: FalconClient,
    *,
    kind: str,
    slug: str,
    display_name: str,
    live_id: str,
    options: ApplyOptions,
    report: ApplyReport,
    change: ObjectChange | None = None,
) -> None:
    """Delete one live object via the matching sub-client."""
    if options.dry_run:
        _append_action(
            report,
            _build_action(kind, "delete", slug, display_name, "dry-run", change),
        )
        return
    if kind == KIND_LOCATION:
        client.locations.delete([live_id])
    elif kind == KIND_RULE_GROUP:
        client.rule_groups.delete([live_id])
    else:
        client.policies.delete([live_id])
    _append_action(report, _build_action(kind, "delete", slug, display_name, "", change))


def _record_host_group_change(
    report: ApplyReport, change: ObjectChange, hg_change: HostGroupChange
) -> None:
    """Record a host-group add/remove for the apply report.

    The actual membership change rides on the policy update payload's
    ``groups`` list; this entry exists so the operator-facing summary
    distinguishes "policy rule content changed" from "policy host group
    changed". ``hg_change`` is preserved on the action so JSON consumers
    see the structured op/group_name/env triple, not just the formatted
    ``detail`` string.
    """
    _append_action(
        report,
        AppliedAction(
            kind="host-group",
            op="host-group",
            slug=change.slug,
            display_name=change.display_name,
            detail=f"{hg_change.op} {hg_change.group_name}",
            host_group_changes=(hg_change,),
        ),
    )


def _build_action(
    kind: str,
    op: str,
    slug: str,
    display_name: str,
    detail: str,
    change: ObjectChange | None,
) -> AppliedAction:
    """Assemble an :class:`AppliedAction`, copying diff detail off ``change``."""
    return AppliedAction(
        kind=kind,
        op=op,
        slug=slug,
        display_name=display_name,
        detail=detail,
        field_changes=change.field_changes if change else (),
        host_group_changes=change.host_group_changes if change else (),
        managed_group_changes=change.managed_group_changes if change else (),
    )


def _append_action(report: ApplyReport, action: AppliedAction) -> None:
    """Append an action to the report and emit a structured log record.

    The log record's ``extra`` dict carries the same structured detail
    as :meth:`AppliedAction.to_json` so the text + JSON formatters in
    :mod:`csfwctl.observability` surface field-level changes correlated
    by request ID.
    """
    report.actions.append(action)
    extra: dict[str, Any] = {
        "kind": action.kind,
        "op": action.op,
        "slug": action.slug,
        "display_name": action.display_name,
    }
    if action.detail:
        extra["detail"] = action.detail
    if action.field_changes:
        extra["field_changes"] = [fc.to_json() for fc in action.field_changes]
    if action.host_group_changes:
        extra["host_group_changes"] = [hg.to_json() for hg in action.host_group_changes]
    if action.managed_group_changes:
        extra["managed_group_changes"] = [mg.to_json() for mg in action.managed_group_changes]
    _logger.info(
        f"apply.action {action.op} {action.kind} {action.display_name}",
        extra=extra,
    )


def now_utc() -> datetime:
    """Indirection so tests can monkeypatch the applier's clock."""
    from datetime import UTC

    return datetime.now(UTC)


__all__ = [
    "AppliedAction",
    "ApplyError",
    "ApplyOptions",
    "ApplyReport",
    "HostGroupPolicy",
    "_platform_api_name",
    "apply_change_set",
    "now_utc",
]
