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
    SafetyOptions,
    check_blast_radius,
    check_bootstrap,
    check_deletes,
    check_drift,
    inject_signature,
    next_signature,
    parse_signature,
)
from csfwctl.schema import Location, Platform, Policy, RuleGroup

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
    """One write the applier performed (or would have, in dry-run)."""

    kind: str  # "location" | "rule-group" | "policy" | "host-group"
    op: str  # "create" | "update" | "delete" | "metadata" | "host-group"
    slug: str
    display_name: str
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "op": self.op,
            "slug": self.slug,
            "display_name": self.display_name,
            **({"detail": self.detail} if self.detail else {}),
        }


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
    """Slug → ``(id, raw description)`` lookup for each managed kind."""

    policies: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    rule_groups: dict[str, tuple[str, str | None]] = field(default_factory=dict)
    locations: dict[str, tuple[str, str | None]] = field(default_factory=dict)


def _build_live_index(state: Any, env: str) -> _LiveIndex:
    """Index live records by env-stripped slug.

    Mirrors the slug derivation used by the differ so creates / updates /
    deletes from a change set line up exactly with what we find here.
    """
    from csfwctl.exporter import strip_env_suffix

    idx = _LiveIndex()
    for record in state.policies:
        if not isinstance(record, dict) or "id" not in record:
            continue
        base, suffix_env = strip_env_suffix(str(record.get("name", "")))
        if suffix_env != env:
            continue
        idx.policies[base.lower()] = (str(record["id"]), record.get("description"))
    for record in state.rule_groups:
        if not isinstance(record, dict) or "id" not in record:
            continue
        base, suffix_env = strip_env_suffix(str(record.get("name", "")))
        if suffix_env != env:
            continue
        idx.rule_groups[base.lower()] = (str(record["id"]), record.get("description"))
    for record in state.locations:
        if not isinstance(record, dict) or "id" not in record:
            continue
        # Locations are tenant-global; no env suffix to strip.
        name = str(record.get("name", ""))
        if not name:
            continue
        idx.locations[name.lower()] = (str(record["id"]), record.get("description"))
    return idx


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

            settings["enforce"] = ps.enforcement_mode is EnforcementMode.enforce
            settings["local_logging"] = (
                ps.enforcement_mode is EnforcementMode.local_logging
            )
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


# ---- host-group resolution -----------------------------------------------


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
                report.actions.append(
                    AppliedAction(
                        kind="host-group",
                        op="create",
                        slug=name.lower(),
                        display_name=name,
                        detail="dry-run",
                    )
                )
                continue
            created = client.host_groups.create(name)
            if not created or "id" not in created:
                raise ApplyError(f"failed to create host group {name!r}: empty response")
            resolved[name] = str(created["id"])
            report.actions.append(
                AppliedAction(kind="host-group", op="create", slug=name.lower(), display_name=name)
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
                report.actions.append(
                    AppliedAction(
                        kind="host-group",
                        op="create",
                        slug=policy_slug,
                        display_name=mgc.group_name,
                        detail=f"dry-run (dynamic, fql={mgc.desired_fql!r})",
                    )
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
                report.actions.append(
                    AppliedAction(
                        kind="host-group",
                        op="create",
                        slug=policy_slug,
                        display_name=mgc.group_name,
                        detail=str(created["id"]),
                    )
                )
            continue

        # op == "update": FQL changed.
        try:
            live_record = client.host_groups.find_by_name(mgc.group_name)
        except Exception as exc:  # noqa: BLE001
            report.warnings.append(
                f"managed host group {mgc.group_name!r} lookup failed: {exc}"
            )
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
            report.actions.append(
                AppliedAction(
                    kind="host-group",
                    op="update",
                    slug=policy_slug,
                    display_name=mgc.group_name,
                    detail=f"dry-run (fql={mgc.desired_fql!r})",
                )
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
        report.actions.append(
            AppliedAction(
                kind="host-group",
                op="update",
                slug=policy_slug,
                display_name=mgc.group_name,
                detail=live_id,
            )
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
        _bootstrap_metadata(client, repo, options, report, index)
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
        )
    for change in _ordered(change_set.updates, KIND_RULE_GROUP):
        rg_model = desired_rule_groups[change.slug]
        rg_live = index.rule_groups.get(change.slug)
        rg_payload = _build_rule_group_payload(
            rg_model,
            options,
            live_id=rg_live[0] if rg_live else None,
            live_description=rg_live[1] if rg_live else None,
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
        )

    # ---- 3. policies (with host groups + RG IDs) --------------------------
    policy_creates = _ordered(change_set.creates, KIND_POLICY)
    policy_updates = _ordered(change_set.updates, KIND_POLICY)

    # 3a. Create/update managed dynamic host groups before resolving IDs.
    all_managed_changes: list[tuple[str, ManagedGroupChange]] = []
    for change in (*policy_creates, *policy_updates):
        for mgc in change.managed_group_changes:
            all_managed_changes.append((change.slug, mgc))
    managed_group_ids = _apply_managed_host_groups(
        client, all_managed_changes, options, report
    )

    needed_host_groups: list[str] = []
    for change in (*policy_creates, *policy_updates):
        p_model = desired_policies[change.slug]
        needed_host_groups.extend(p_model.host_groups.keys())
    for change in policy_updates:
        for hg_change in change.host_group_changes:
            if hg_change.op == "add":
                needed_host_groups.append(hg_change.group_name)
    host_group_ids = _resolve_host_group_ids(client, needed_host_groups, options, report)
    # Merge managed group IDs so policy payloads can reference them.
    host_group_ids.update(managed_group_ids)

    rule_group_ids: dict[str, str] = {
        slug: live_id for slug, (live_id, _desc) in index.rule_groups.items()
    }
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
        )
    for change in policy_updates:
        p_model = desired_policies[change.slug]
        p_live = index.policies.get(change.slug)
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
        )
        # Host-group reassignments are recorded explicitly so the report
        # surfaces them; the policy update payload above already carries
        # the new ``groups`` list, so the API call covers the membership
        # change in one round-trip.
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
        )

    return report


# ---- bootstrap mode ------------------------------------------------------


def _bootstrap_metadata(
    client: FalconClient,
    repo: ConfigRepo,
    options: ApplyOptions,
    report: ApplyReport,
    index: _LiveIndex,
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


def _bootstrap_write(
    client: FalconClient,
    *,
    kind: str,
    slug: str,
    display_name: str,
    live_id: str,
    new_description: str,
    options: ApplyOptions,
    report: ApplyReport,
) -> None:
    """Issue a metadata-only update for one bootstrap target.

    The payload is intentionally minimal: just ``id`` and the new
    ``description``. The CrowdStrike API treats unspecified fields as
    unchanged, so rule content, status, and assignments stay where they
    were even if the live record drifted earlier.
    """
    payload = {"id": live_id, "description": new_description}
    if options.dry_run:
        report.actions.append(
            AppliedAction(
                kind=kind,
                op="metadata",
                slug=slug,
                display_name=display_name,
                detail="dry-run",
            )
        )
        return
    if kind == KIND_LOCATION:
        client.locations.upsert([payload])
    elif kind == KIND_RULE_GROUP:
        client.rule_groups.update(payload)
    else:  # policy
        client.policies.update([payload])
    report.actions.append(
        AppliedAction(kind=kind, op="metadata", slug=slug, display_name=display_name)
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
) -> None:
    """Dispatch one create/update to the right sub-client.

    Records the action on the report and, on a successful create,
    threads the new id back into ``index`` so subsequent payloads (e.g.,
    a policy that references a freshly-created rule group) can resolve
    it without a second round-trip.
    """
    if options.dry_run:
        report.actions.append(
            AppliedAction(kind=kind, op=op, slug=slug, display_name=display_name, detail="dry-run")
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
    report.actions.append(
        AppliedAction(kind=kind, op=op, slug=slug, display_name=display_name, detail=detail)
    )

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
) -> None:
    """Delete one live object via the matching sub-client."""
    if options.dry_run:
        report.actions.append(
            AppliedAction(
                kind=kind,
                op="delete",
                slug=slug,
                display_name=display_name,
                detail="dry-run",
            )
        )
        return
    if kind == KIND_LOCATION:
        client.locations.delete([live_id])
    elif kind == KIND_RULE_GROUP:
        client.rule_groups.delete([live_id])
    else:
        client.policies.delete([live_id])
    report.actions.append(
        AppliedAction(kind=kind, op="delete", slug=slug, display_name=display_name)
    )


def _record_host_group_change(
    report: ApplyReport, change: ObjectChange, hg_change: HostGroupChange
) -> None:
    """Record a host-group add/remove for the apply report.

    The actual membership change rides on the policy update payload's
    ``groups`` list; this entry exists so the operator-facing summary
    distinguishes "policy rule content changed" from "policy host group
    changed".
    """
    report.actions.append(
        AppliedAction(
            kind="host-group",
            op="host-group",
            slug=change.slug,
            display_name=change.display_name,
            detail=f"{hg_change.op} {hg_change.group_name}",
        )
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
