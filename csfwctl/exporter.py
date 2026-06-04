"""CrowdStrike-to-YAML exporter — the ``csfwctl import`` command body.

Reads live CrowdStrike objects through :class:`FalconClient` sub-clients,
translates them into Pydantic schema models, and writes round-trippable
YAML files under a config-repo directory layout. ``import`` is read-only;
nothing in this module performs a write against CrowdStrike.

Translation goes both ways for testability: :func:`policy_to_api_shape`
(and siblings) render Pydantic models into the API shape we expect to
see, which the round-trip tests use as the mock response. Phase 5 will
reuse the same render functions when building apply requests.

The API shapes here are inferred from the CrowdStrike Falcon Firewall
documentation and FalconPy. See ``docs/architecture.md`` for the
assumptions still pending real-tenant confirmation.
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML

from csfwctl.falcon.client import FalconClient
from csfwctl.falcon.locations import ANY_LOCATION_NAME
from csfwctl.schema import (
    Action,
    ConnectionState,
    Direction,
    Endpoint,
    HostGroupEnv,
    Location,
    Platform,
    Policy,
    PolicySettings,
    PrecedenceBucket,
    Protocol,
    Rule,
    RuleGroup,
    Status,
)
from csfwctl.schema._common import SLUG_RE
from csfwctl.schema.policy_settings import DefaultTrafficAction, EnforcementMode

ENV_SUFFIXES: tuple[str, ...] = ("-Production", "-Pilot", "-Test")
"""Environment suffixes appended to CrowdStrike display names. Longest first
so ``-Production`` matches before any shorter prefix could."""

ENV_RANK: dict[str, int] = {"test": 0, "pilot": 1, "production": 2}
"""Stable ordering used when multiple env-suffixed records describe the
same logical object; Test wins because it is the trunk in our flow."""

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
"""Loose UUID detector. ``find_*`` helpers branch on this to decide
between an ID lookup and a name lookup."""

OVERRIDE_SUFFIX_RE = re.compile(r"^(.*)-overrides-(test|pilot|production)$", re.IGNORECASE)
"""Pattern for the anonymous per-policy override rule group; the applier
will synthesise these from a policy's ``rules:`` field at apply time,
and the importer folds them back."""

METADATA_SIGNATURE_RE = re.compile(
    r"(?:\s*\n)?Managed by csfwctl\s*\|.*$",
    re.DOTALL,
)
"""Metadata block appended to descriptions by the applier. The importer
strips it so subsequent re-imports stay clean."""

_SLUG_NORMALIZE_RE = re.compile(r"[\s_]+")
_SLUG_COLLAPSE_RE = re.compile(r"-{2,}")


def to_slug(name: str) -> str:
    """Normalise an arbitrary CrowdStrike name to a lowercase-kebab slug.

    Lowercases, replaces runs of whitespace or underscores with a single
    hyphen, collapses consecutive hyphens, and strips leading/trailing
    hyphens. Does **not** validate the result against :data:`SLUG_RE` —
    callers that need strict validation should check afterward.
    """
    slug = name.lower()
    slug = _SLUG_NORMALIZE_RE.sub("-", slug)
    slug = _SLUG_COLLAPSE_RE.sub("-", slug)
    return slug.strip("-")


# ---- API shape translation: Action / Direction / Protocol / Status ----

_ACTION_FROM_API: dict[str, Action] = {
    "ALLOW": Action.allow,
    "DENY": Action.block,
    "BLOCK": Action.block,
    "MONITOR": Action.monitor,
}

_ACTION_TO_API: dict[Action, str] = {
    Action.allow: "ALLOW",
    Action.block: "DENY",
    Action.monitor: "MONITOR",
}

_DIRECTION_FROM_API: dict[str, Direction] = {
    "IN": Direction.inbound,
    "OUT": Direction.outbound,
    "INBOUND": Direction.inbound,
    "OUTBOUND": Direction.outbound,
    "BOTH": Direction.both,
}

_DIRECTION_TO_API: dict[Direction, str] = {
    Direction.inbound: "IN",
    Direction.outbound: "OUT",
    Direction.both: "BOTH",
}

_PROTOCOL_FROM_API: dict[str, Protocol] = {
    "0": Protocol.any,
    "1": Protocol.icmp,
    "2": Protocol.igmp,
    "4": Protocol.ipip,
    "6": Protocol.tcp,
    "17": Protocol.udp,
    "41": Protocol.ipv6,
    "47": Protocol.gre,
    "58": Protocol.icmpv6,
    "ANY": Protocol.any,
    "TCP": Protocol.tcp,
    "UDP": Protocol.udp,
    "ICMP": Protocol.icmp,
    "IGMP": Protocol.igmp,
    "IPIP": Protocol.ipip,
    "IPV6": Protocol.ipv6,
    "GRE": Protocol.gre,
    "ICMPV6": Protocol.icmpv6,
    "*": Protocol.any,
}

_PROTOCOL_TO_API: dict[Protocol, str] = {
    Protocol.any: "*",
    Protocol.tcp: "6",
    Protocol.udp: "17",
    Protocol.icmp: "1",
    Protocol.igmp: "2",
    Protocol.ipip: "4",
    Protocol.ipv6: "41",
    Protocol.gre: "47",
    Protocol.icmpv6: "58",
}

_PLATFORM_FROM_API: dict[str, Platform] = {
    "windows": Platform.windows,
    "Windows": Platform.windows,
    "0": Platform.windows,
    "mac": Platform.mac,
    "Mac": Platform.mac,
    "1": Platform.mac,
}

_PLATFORM_TO_API_NAME: dict[Platform, str] = {
    Platform.windows: "Windows",
    Platform.mac: "Mac",
}

_PLATFORM_TO_API_ID: dict[Platform, str] = {
    Platform.windows: "0",
    Platform.mac: "1",
}


class ImporterError(Exception):
    """Raised when an importer lookup fails or an API record is malformed."""


@dataclass(frozen=True)
class ImportResult:
    """Outcome of importing a single object.

    ``model`` is the validated Pydantic instance; ``path`` is where the
    YAML was written (``None`` when the caller opted out of writing).
    """

    kind: str  # "policy" | "rule-group" | "location"
    slug: str
    model: Policy | RuleGroup | Location
    path: Path | None = None


# ---- Name / slug helpers --------------------------------------------------


def strip_env_suffix(display_name: str) -> tuple[str, str | None]:
    """Return ``(base_name, env_label_or_None)`` for a display name.

    Matches ``-Test`` / ``-Pilot`` / ``-Production`` (case-sensitive in
    practice; CrowdStrike preserves the casing we wrote). Returns the
    name unchanged plus ``None`` when no suffix is present.
    """
    for suffix in ENV_SUFFIXES:
        if display_name.endswith(suffix):
            return display_name[: -len(suffix)], suffix.lstrip("-").lower()
    return display_name, None


def display_name_to_slug(display_name: str) -> str:
    """Derive a lowercase-kebab slug from a CrowdStrike display name.

    Strips any env suffix first, then normalises spaces and underscores to
    hyphens. Raises :class:`ImporterError` if the result still does not
    satisfy :data:`SLUG_RE` (e.g. a name starting with a digit).
    """
    base, _ = strip_env_suffix(display_name)
    slug = to_slug(base)
    if not SLUG_RE.match(slug):
        raise ImporterError(
            f"cannot derive a valid slug from display name {display_name!r}: "
            f"would produce {slug!r}, which does not match {SLUG_RE.pattern}"
        )
    return slug


def host_group_env(host_group_name: str) -> HostGroupEnv | None:
    """Infer the deployment env for a host group from its name suffix."""
    _, env = strip_env_suffix(host_group_name)
    if env is None:
        return None
    try:
        return HostGroupEnv(env)
    except ValueError:
        return None


def clean_description(description: str | None) -> str:
    """Strip the csfwctl metadata signature trailer if present."""
    if not description:
        return ""
    cleaned = METADATA_SIGNATURE_RE.sub("", description)
    return cleaned.strip()


def is_uuid(text: str) -> bool:
    """``True`` when ``text`` looks like a CrowdStrike resource UUID."""
    return bool(UUID_RE.match(text))


def is_override_group_name(slug: str) -> tuple[str, str | None]:
    """Detect ``<policy>-overrides-<env>`` rule-group names.

    Returns ``(base_policy_slug, env_label)`` when ``slug`` matches; the
    second element is ``None`` otherwise. The policy importer uses this
    to fold the synthesised override group back into the policy's inline
    ``rules`` list.
    """
    match = OVERRIDE_SUFFIX_RE.match(slug)
    if match is None:
        return slug, None
    return match.group(1), match.group(2).lower()


# ---- API → model translation ----------------------------------------------


def _endpoint_from_api(data: dict[str, Any] | None) -> Endpoint | None:
    """Build an :class:`Endpoint` from a CrowdStrike address/port block.

    Returns ``None`` if ``data`` is missing/empty so that the importer
    omits the field rather than serialising an empty Endpoint.
    """
    if not data:
        return None
    addresses = _flatten_addresses(data.get("addresses"))
    ports = _flatten_ports(data.get("ports"))
    if not addresses and not ports:
        return None
    return Endpoint(
        addresses=addresses,
        addresses_negated=bool(data.get("addresses_negated", False)),
        ports=ports,
        ports_negated=bool(data.get("ports_negated", False)),
    )


def _flatten_addresses(value: Any) -> list[str]:
    """Accept ``["10.0.0.0/8"]``, ``[{"address": ...}]``, or ``[{"address": ..., "netmask": N}]``.

    The real API returns address dicts with a numeric ``netmask`` (CIDR prefix
    length).  A non-zero netmask is appended as ``/N`` so the schema stores a
    proper CIDR string.  Zero means "any host in that address", which is
    typically written without a prefix.

    The API wildcard ``"*"`` (meaning "any address") is dropped; in the schema
    an empty ``addresses`` list already conveys "no address constraint".
    """
    if not value:
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            if item != "*":
                out.append(item)
        elif isinstance(item, dict):
            addr = item.get("address")
            if isinstance(addr, str) and addr != "*":
                netmask = item.get("netmask")
                if isinstance(netmask, int) and netmask > 0 and "/" not in addr:
                    out.append(f"{addr}/{netmask}")
                else:
                    out.append(addr)
    return out


def _flatten_ports(value: Any) -> list[int | str]:
    """Accept ``[80]`` or ``["80-90"]`` or ``[{"start": 80, "end": 90}]``.

    The CrowdStrike API uses ``end: 0`` as a sentinel meaning "same as start"
    (i.e., a single port, not a range). Both fields being 0 signals "any port"
    and is dropped so the schema treats the endpoint as unconstrained on ports.
    """
    if not value:
        return []
    out: list[int | str] = []
    for item in value:
        if isinstance(item, int):
            out.append(item)
        elif isinstance(item, str):
            out.append(_coerce_port_string(item))
        elif isinstance(item, dict):
            start = item.get("start")
            end = item.get("end", start)
            if isinstance(start, int) and isinstance(end, int):
                # end=0 is a CS API sentinel for "same as start"
                if end == 0:
                    end = start
                # start=0 and end=0 means "any port" — drop it
                if start == 0 and end == 0:
                    continue
                out.append(start if start == end else f"{start}-{end}")
    return out


def _coerce_port_string(text: str) -> int | str:
    """Turn ``"80"`` into ``80`` and leave ``"80-90"`` alone."""
    if text.isdigit():
        return int(text)
    return text


def _endpoint_from_api_flat(record: dict[str, Any], side: str) -> Endpoint | None:
    """Build an :class:`Endpoint` from the flat ``{side}_address`` / ``{side}_port`` fields.

    The real CrowdStrike API returns rules with separate top-level
    ``local_address``, ``local_port``, ``remote_address``, ``remote_port``
    fields rather than the nested ``local``/``remote`` objects used in the
    test-fixture shape.  This helper handles that wire format.
    """
    addresses = _flatten_addresses(record.get(f"{side}_address"))
    ports = _flatten_ports(record.get(f"{side}_port"))
    if not addresses and not ports:
        return None
    return Endpoint(
        addresses=addresses,
        addresses_negated=bool(record.get(f"{side}_address_negated", False)),
        ports=ports,
        ports_negated=bool(record.get(f"{side}_port_negated", False)),
    )


def rule_from_api(record: dict[str, Any]) -> Rule:
    """Convert a CrowdStrike rule detail record to a :class:`Rule`.

    The CrowdStrike representation uses uppercase tokens for action and
    direction, numeric protocol IDs, and a ``fields`` array for the
    optional connection-state qualifier. We normalise into the lowercase
    enums csfwctl exposes.

    Endpoint information is accepted in two shapes: the nested
    ``local``/``remote`` objects used by the test-fixture generator, and
    the flat ``local_address``/``local_port``/``remote_address``/
    ``remote_port`` fields returned by the real ``GET /fwmgr/entities/rules/v1``
    API.
    """
    try:
        name = record["name"]
        raw_action = record["action"]
        raw_direction = record["direction"]
        raw_protocol = record["protocol"]
    except KeyError as exc:
        raise ImporterError(f"rule record missing required field {exc.args[0]!r}") from exc

    action = _ACTION_FROM_API.get(str(raw_action).upper())
    if action is None:
        raise ImporterError(f"unknown action {raw_action!r} on rule {name!r}")
    direction = _DIRECTION_FROM_API.get(str(raw_direction).upper())
    if direction is None:
        raise ImporterError(f"unknown direction {raw_direction!r} on rule {name!r}")
    protocol: Protocol | int | None = _PROTOCOL_FROM_API.get(str(raw_protocol).upper())
    if protocol is None:
        # Fall back to raw IANA protocol number ("Advanced" mode).
        try:
            proto_num = int(raw_protocol)
        except (TypeError, ValueError):
            raise ImporterError(f"unknown protocol {raw_protocol!r} on rule {name!r}") from None
        if not (0 <= proto_num <= 255):
            raise ImporterError(
                f"protocol number {proto_num} on rule {name!r} is out of range 0-255"
            )
        protocol = proto_num

    state = _state_from_fields(record.get("fields"))
    locations = _locations_from_api(record.get("locations"), record.get("network_locations"))

    local = _endpoint_from_api(record.get("local")) or _endpoint_from_api_flat(record, "local")
    remote = _endpoint_from_api(record.get("remote")) or _endpoint_from_api_flat(record, "remote")

    return Rule(
        name=str(name),
        enabled=bool(record.get("enabled", True)),
        action=action,
        direction=direction,
        protocol=protocol,
        state=state,
        locations=locations,
        local=local,
        remote=remote,
    )


def _state_from_fields(fields: Any) -> ConnectionState | None:
    """Pluck a connection-state token out of CrowdStrike's ``fields`` list.

    The CrowdStrike rule record may carry per-rule constraints under
    ``fields``: ``[{"name": "tcp_state", "value": "established"}]``. The
    importer maps that single token onto our ``state`` enum. Absent or
    unknown values return ``None``.
    """
    if not fields:
        return None
    for entry in fields:
        if not isinstance(entry, dict):
            continue
        if entry.get("name") != "tcp_state":
            continue
        value = str(entry.get("value", "")).lower()
        if value in {s.value for s in ConnectionState}:
            return ConnectionState(value)
    return None


def _locations_from_api(simple: Any, ids: Any) -> list[str]:
    """Build the location-slug list our schema expects.

    The mocked API may give us either bare slugs (``locations``) or a
    list of network-location IDs that need a separate resolution step.
    The importer flows the simple list straight through; ID-based
    locations are resolved by the caller before calling this helper
    (Phase 3 lookups happen in :func:`policy_from_api` /
    :func:`rule_group_from_api`).
    """
    del ids  # see docstring
    if not simple:
        return [ANY_LOCATION_NAME]
    out: list[str] = []
    for item in simple:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            slug = item.get("slug") or item.get("name")
            if isinstance(slug, str):
                out.append(slug)
    return out or [ANY_LOCATION_NAME]


def rule_group_from_api(
    record: dict[str, Any],
    rules_by_id: dict[str, dict[str, Any]],
    *,
    strip_suffix: bool = True,
) -> RuleGroup:
    """Convert a rule-group detail + its resolved rule records.

    ``rules_by_id`` must contain entries for every ID in
    ``record["rule_ids"]`` (the importer fetches and dedupes them
    upstream). Missing entries raise :class:`ImporterError` so silent
    data loss is impossible.
    """
    raw_name = str(record["name"])
    base, _ = strip_env_suffix(raw_name) if strip_suffix else (raw_name, None)
    slug = to_slug(base)
    if not SLUG_RE.match(slug):
        raise ImporterError(f"rule-group name {raw_name!r} does not derive a valid slug ({slug!r})")
    rg_display_name: str | None = base if base != slug else None

    platform = _PLATFORM_FROM_API.get(str(record.get("platform", "")).lower())
    if platform is None:
        # try other casings
        platform = _PLATFORM_FROM_API.get(str(record.get("platform", "")))
    if platform is None:
        platform = _PLATFORM_FROM_API.get(str(record.get("platform_name", "")))
    if platform is None:
        raise ImporterError(
            f"unknown platform on rule group {raw_name!r}: {record.get('platform')!r}"
        )

    status = Status.enabled if record.get("enabled", True) else Status.disabled
    description = clean_description(record.get("description"))

    rules: list[Rule] = []
    rule_ids = list(record.get("rule_ids") or [])
    if rule_ids:
        # Real CrowdStrike shape: rule_ids drives a separate get_rules call.
        for rule_id in rule_ids:
            rule_record = rules_by_id.get(str(rule_id))
            if rule_record is None:
                raise ImporterError(
                    f"rule group {raw_name!r} references rule {rule_id!r} but the record was not fetched"
                )
            rules.append(rule_from_api(rule_record))
    else:
        # Snapshot / fixture shape: rule contents are inline.
        for rule_record in record.get("rules") or []:
            rules.append(rule_from_api(rule_record))

    return RuleGroup(
        name=slug,
        display_name=rg_display_name,
        platform=platform,
        status=status,
        description=description,
        rules=rules,
    )


def location_from_api(record: dict[str, Any]) -> Location:
    """Convert a network-location detail record."""
    raw_name = str(record["name"])
    slug = to_slug(raw_name)
    if not SLUG_RE.match(slug):
        raise ImporterError(f"location name {raw_name!r} does not derive a valid slug ({slug!r})")
    loc_display_name: str | None = raw_name if raw_name != slug else None
    status = Status.enabled if record.get("enabled", True) else Status.disabled
    return Location(
        name=slug,
        display_name=loc_display_name,
        status=status,
        description=clean_description(record.get("description")),
        addresses=_flatten_addresses(record.get("addresses")),
        dns_servers=_flatten_addresses(record.get("dns_servers")),
        dns_resolution_targets=_flatten_hostnames(record.get("dns_resolution_targets")),
        default_gateways=_flatten_addresses(record.get("default_gateways")),
    )


def _flatten_hostnames(value: Any) -> list[str]:
    """Accept ``["host"]``, ``[{"hostname": "..."}]``, or ``{"targets": [...]}``."""
    if not value:
        return []
    items = value
    if isinstance(value, dict):
        items = value.get("targets") or value.get("hostnames") or []
    out: list[str] = []
    for item in items:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            host = item.get("hostname") or item.get("host") or item.get("address")
            if isinstance(host, str):
                out.append(host)
    return out


def policy_from_api(
    record: dict[str, Any],
    *,
    rule_groups_by_id: dict[str, dict[str, Any]] | None = None,
    rule_groups_by_slug: dict[str, RuleGroup] | None = None,
    strip_suffix: bool = True,
    fold_overrides: bool = True,
    tolerant_rule_group_refs: bool = False,
) -> Policy:
    """Convert a CrowdStrike firewall-policy detail record.

    Inline override rule groups (named ``<policy>-overrides-<env>``) are
    folded back into the policy's ``rules`` field when ``fold_overrides``
    is true (the importer's default). Set it to ``False`` when the
    caller — e.g. the Phase 4 differ — wants to keep the override-group
    reference visible in ``rule_groups`` instead.

    When ``tolerant_rule_group_refs`` is ``True``, a referenced rule
    group whose record is missing from ``rule_groups_by_id`` is logged
    and skipped instead of raising :class:`ImporterError`. The differ
    fetches rule groups filtered by env suffix, so a live policy that
    references a suffixless or cross-env rule group would otherwise
    cause the entire live record to be dropped via the differ's
    blanket except, masking the policy from the diff and producing a
    spurious duplicate-name create on the next apply.
    """
    rule_groups_by_id = rule_groups_by_id or {}
    rule_groups_by_slug = rule_groups_by_slug or {}

    raw_name = str(record["name"])
    base, _ = strip_env_suffix(raw_name) if strip_suffix else (raw_name, None)
    slug = to_slug(base)
    if not SLUG_RE.match(slug):
        raise ImporterError(f"policy name {raw_name!r} does not derive a valid slug ({slug!r})")
    pol_display_name: str | None = base if base != slug else None

    platform = _PLATFORM_FROM_API.get(str(record.get("platform_name", "")))
    if platform is None:
        platform = _PLATFORM_FROM_API.get(str(record.get("platform_name", "")).lower())
    if platform is None:
        raise ImporterError(
            f"unknown platform_name on policy {raw_name!r}: {record.get('platform_name')!r}"
        )
    status = Status.enabled if record.get("enabled", True) else Status.disabled
    description = clean_description(record.get("description"))

    # The policy's own env (from its name suffix) is the fallback env for
    # any assigned host group whose name does not itself carry a suffix.
    # This is the common case when bootstrapping a tenant whose host groups
    # predate csfwctl's naming convention; without this fallback such groups
    # were dropped silently, leaving the policy looking like it had none.
    _, policy_env_label = strip_env_suffix(raw_name)
    policy_env: HostGroupEnv | None = None
    if policy_env_label is not None:
        try:
            policy_env = HostGroupEnv(policy_env_label)
        except ValueError:
            policy_env = None

    host_groups: dict[str, HostGroupEnv] = {}
    used_envs: set[HostGroupEnv] = set()
    for entry in record.get("groups") or []:
        hg_name = entry["name"] if isinstance(entry, dict) else str(entry)
        env = host_group_env(hg_name)
        if env is None:
            # No suffix on the group itself: fall back to the policy's env,
            # then to production. A legacy un-promoted policy is assumed to
            # be live in production, so defaulting there means a later
            # ``apply --env production`` keeps the assignment instead of
            # detaching the group.
            env = policy_env or HostGroupEnv.production
        if env in used_envs:
            # csfwctl models at most one host group per env per policy. A
            # live policy that assigns several groups to the same env cannot
            # be represented; keep the first and warn about the rest rather
            # than dropping them silently or raising a validation error that
            # would abort a bulk import.
            from csfwctl.observability import get_logger

            get_logger("exporter").warning(
                "import dropped host group: env already assigned",
                extra={
                    "event": "import.policy.host_group.skipped",
                    "policy_name": raw_name,
                    "host_group_name": hg_name,
                    "env": env.value,
                },
            )
            continue
        host_groups[hg_name] = env
        used_envs.add(env)

    settings = record.get("settings") or {}
    rule_group_ids = settings.get("rule_group_ids") or record.get("rule_group_ids") or []

    # Parse optional enforcement and default-traffic settings.
    policy_settings: PolicySettings | None = None
    enforce_val = settings.get("enforce")
    local_logging_val = settings.get("local_logging", False)
    inbound_val = settings.get("inbound")
    outbound_val = settings.get("outbound")
    if any(v is not None for v in (enforce_val, inbound_val, outbound_val)):
        enforcement_mode: EnforcementMode | None = None
        if enforce_val is not None:
            if local_logging_val:
                enforcement_mode = EnforcementMode.local_logging
            elif enforce_val:
                enforcement_mode = EnforcementMode.enforce
            else:
                enforcement_mode = EnforcementMode.monitor
        policy_settings = PolicySettings(
            enforcement_mode=enforcement_mode,
            default_inbound=(DefaultTrafficAction(inbound_val.lower()) if inbound_val else None),
            default_outbound=(DefaultTrafficAction(outbound_val.lower()) if outbound_val else None),
        )

    inline_rules: list[Rule] = []
    referenced_slugs: list[str] = []
    base_policy_slug = slug

    for rg_id in rule_group_ids:
        rg_record = rule_groups_by_id.get(str(rg_id))
        if rg_record is None:
            if tolerant_rule_group_refs:
                from csfwctl.observability import get_logger

                get_logger("exporter").warning(
                    "import skipped unresolved rule group reference",
                    extra={
                        "event": "import.policy.rule_group.unresolved",
                        "policy_name": raw_name,
                        "rule_group_id": str(rg_id),
                    },
                )
                continue
            raise ImporterError(
                f"policy {raw_name!r} references rule group id {rg_id!r} but no record was fetched; "
                "pass the full rule_groups_by_id map or import the rule group separately"
            )
        rg_name = str(rg_record.get("name", ""))
        rg_base, _ = strip_env_suffix(rg_name)
        rg_slug = to_slug(rg_base)
        derived_base, override_env = is_override_group_name(rg_slug)
        if fold_overrides and override_env is not None and derived_base == base_policy_slug:
            # Fold the synthesised override group back into inline rules.
            folded = rule_groups_by_slug.get(rg_slug)
            if folded is None:
                # We have the record but no validated RuleGroup; build one
                # on the fly using whatever rule contents are inline.
                folded = rule_group_from_api(rg_record, {}, strip_suffix=False)
            inline_rules.extend(folded.rules)
            continue
        referenced_slugs.append(rg_slug)

    return Policy(
        name=slug,
        display_name=pol_display_name,
        platform=platform,
        priority=PrecedenceBucket.default,
        status=status,
        description=description,
        host_groups=host_groups,
        rules=inline_rules,
        rule_groups=referenced_slugs,
        settings=policy_settings,
    )


# ---- model → API translation (used by tests + Phase 5 applier) ------------


def policy_to_api_shape(policy: Policy, env: str) -> dict[str, Any]:
    """Render a :class:`Policy` into the API shape we expect to consume.

    The Phase 5 applier will reuse this. The synthesised override rule
    group (when ``policy.rules`` is non-empty) is emitted as a sibling
    rule group with a deterministic name and ID; the test harness then
    feeds that record back through the importer to verify round-tripping.
    """
    suffix = _env_suffix(env)
    cs_name = policy.display_name or policy.name
    display_name = f"{cs_name}{suffix}"
    rule_group_refs = list(policy.rule_groups)
    if policy.rules:
        override_slug = f"{policy.name}-overrides-{env}"
        rule_group_refs.insert(0, override_slug)
    api_settings: dict[str, Any] = {
        "rule_group_ids": [_fake_uuid("rule-group", f"{slug}{suffix}") for slug in rule_group_refs],
    }
    if policy.settings is not None:
        ps = policy.settings
        if ps.enforcement_mode is not None:
            api_settings["enforce"] = ps.enforcement_mode is EnforcementMode.enforce
            api_settings["local_logging"] = ps.enforcement_mode is EnforcementMode.local_logging
        if ps.default_inbound is not None:
            api_settings["inbound"] = ps.default_inbound.upper()
        if ps.default_outbound is not None:
            api_settings["outbound"] = ps.default_outbound.upper()
    return {
        "id": _fake_uuid("policy", display_name),
        "name": display_name,
        "description": policy.description,
        "platform_name": _PLATFORM_TO_API_NAME[policy.platform],
        "enabled": policy.status is Status.enabled,
        "groups": [
            {"id": _fake_uuid("host-group", group_name), "name": group_name}
            for group_name, _ in policy.host_groups.items()
        ],
        "settings": api_settings,
    }


def rule_group_to_api_shape(rule_group: RuleGroup, env: str) -> dict[str, Any]:
    """Render a :class:`RuleGroup` plus its rules into API shape.

    The real CrowdStrike rule-group response carries only ``rule_ids``;
    rule contents come from a separate ``get_rules`` call. The shape
    also embeds the rule records under ``rules`` for the test harness's
    convenience — the importer ignores that field when ``rule_ids`` is
    populated, so it does not affect round-tripping.

    ``platform`` uses the platform-ID string (``"windows"``/``"mac"``),
    which is what the CREATE and UPDATE endpoints require. The GET response
    uses numeric IDs (``"0"``/``"1"``); :data:`_PLATFORM_FROM_API` handles
    both forms on import.

    Rule endpoint fields use the flat ``local_address`` / ``local_port`` /
    ``remote_address`` / ``remote_port`` shape that the CREATE endpoint
    expects. The importer's :func:`_endpoint_from_api_flat` handles both
    the flat form (real API) and the nested ``local``/``remote`` form
    (legacy test fixtures), so round-trips work regardless.
    """
    suffix = _env_suffix(env)
    display_name = f"{rule_group.display_name or rule_group.name}{suffix}"
    rule_records = [
        _rule_to_api_shape(rule, display_name, index) for index, rule in enumerate(rule_group.rules)
    ]
    return {
        "id": _fake_uuid("rule-group", display_name),
        "name": display_name,
        "description": rule_group.description,
        "platform": _PLATFORM_TO_API_NAME[rule_group.platform].lower(),
        "enabled": rule_group.status is Status.enabled,
        "rule_ids": [r["id"] for r in rule_records],
        "rules": rule_records,
    }


def location_to_api_shape(location: Location) -> dict[str, Any]:
    """Render a :class:`Location` into API shape."""
    cs_name = location.display_name or location.name
    return {
        "id": _fake_uuid("location", cs_name),
        "name": cs_name,
        "description": location.description,
        "enabled": location.status is Status.enabled,
        "addresses": [{"address": a} for a in location.addresses],
        "dns_servers": [{"address": a} for a in location.dns_servers],
        "dns_resolution_targets": {
            "targets": [{"hostname": h} for h in location.dns_resolution_targets]
        },
        "default_gateways": [{"address": a} for a in location.default_gateways],
    }


def _address_to_api_dict(addr: str) -> dict[str, Any]:
    """Convert ``'ip[/prefix]'`` to ``{'address': ip, 'netmask': prefix}``.

    The CREATE/UPDATE rule endpoint expects address dicts with a numeric
    ``netmask`` (CIDR prefix length). Zero is used when no prefix is
    specified (host address). The import side's ``_flatten_addresses``
    already handles both forms, so round-trips work correctly.
    """
    if "/" in addr:
        ip, prefix = addr.rsplit("/", 1)
        return {"address": ip, "netmask": int(prefix)}
    return {"address": addr, "netmask": 0}


def _infer_address_family(rule: Rule) -> str:
    """Return ``"IP6"`` for IPv6-family rules, else ``"IP4"``.

    CrowdStrike's rule CREATE/UPDATE endpoint requires a non-empty
    ``address_family`` field and rejects mismatches with
    ``"Address family IPv4 is not allowed with protocol ICMPv6"`` (and
    the analogous IPv6 variant). Resolution order:

    1. If the protocol is an IPv6-family named protocol (:attr:`Protocol.ipv6`
       or :attr:`Protocol.icmpv6`), the family is always ``"IP6"`` — even
       when no explicit IPv6 address is configured (e.g. an ICMPv6 wildcard
       rule for neighbor discovery).
    2. Otherwise, if any local/remote address contains ``":"`` it is an
       IPv6 CIDR and the family is ``"IP6"``.
    3. Otherwise ``"IP4"``.

    Raw-integer ("Advanced") protocols bypass the named-enum check; the
    user is expected to supply matching addresses in that case.
    """
    if rule.protocol in (Protocol.ipv6, Protocol.icmpv6):
        return "IP6"
    all_addresses: list[str] = []
    if rule.local:
        all_addresses.extend(rule.local.addresses)
    if rule.remote:
        all_addresses.extend(rule.remote.addresses)
    for addr in all_addresses:
        if ":" in addr:
            return "IP6"
    return "IP4"


def _rule_to_api_shape(rule: Rule, parent_display_name: str, index: int) -> dict[str, Any]:
    """Render a :class:`Rule` into API shape (used by the round-trip harness)."""
    proto_api = (
        str(rule.protocol) if isinstance(rule.protocol, int) else _PROTOCOL_TO_API[rule.protocol]
    )
    record: dict[str, Any] = {
        "id": _fake_uuid("rule", f"{parent_display_name}#{index}:{rule.name}"),
        "name": rule.name,
        "enabled": rule.enabled,
        "action": _ACTION_TO_API[rule.action],
        "direction": _DIRECTION_TO_API[rule.direction],
        "protocol": proto_api,
        "address_family": _infer_address_family(rule),
        "fields": [],
        "locations": list(rule.locations),
    }
    if rule.state is not None:
        record["fields"].append({"name": "tcp_state", "value": rule.state.value})
    if rule.local is not None:
        record["local_address"] = [_address_to_api_dict(a) for a in rule.local.addresses]
        if rule.local.addresses_negated:
            record["local_address_negated"] = True
        record["local_port"] = [_port_to_api_shape(p) for p in rule.local.ports]
        if rule.local.ports_negated:
            record["local_port_negated"] = True
    if rule.remote is not None:
        record["remote_address"] = [_address_to_api_dict(a) for a in rule.remote.addresses]
        if rule.remote.addresses_negated:
            record["remote_address_negated"] = True
        record["remote_port"] = [_port_to_api_shape(p) for p in rule.remote.ports]
        if rule.remote.ports_negated:
            record["remote_port_negated"] = True
    return record


def _endpoint_to_api_shape(endpoint: Endpoint) -> dict[str, Any]:
    return {
        "addresses": [{"address": a} for a in endpoint.addresses],
        "addresses_negated": endpoint.addresses_negated,
        "ports": [_port_to_api_shape(p) for p in endpoint.ports],
        "ports_negated": endpoint.ports_negated,
    }


def _port_to_api_shape(port: int | str) -> dict[str, int]:
    """Encode a port or port-range as the CrowdStrike API dict format.

    CrowdStrike uses ``end: 0`` as the sentinel meaning "same as start"
    (i.e., a single port). Sending ``end == start`` is rejected by the
    create endpoint with "Duplicate ports listed in range." For a range
    (``"80-90"``) both start and end are set to their respective values.
    """
    if isinstance(port, int):
        return {"start": port, "end": 0}
    low, _, high = port.partition("-")
    return {"start": int(low), "end": int(high)}


def _env_suffix(env: str) -> str:
    return f"-{env.title()}"


def _fake_uuid(kind: str, identity: str) -> str:
    """Deterministic UUID-ish string for tests/mocks. Not cryptographic."""
    import hashlib

    digest = hashlib.sha1(f"{kind}:{identity}".encode(), usedforsecurity=False).hexdigest()
    return f"{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


# ---- lookup helpers -------------------------------------------------------


def find_policy_record(client: FalconClient, name_or_uuid: str) -> dict[str, Any]:
    """Resolve a policy by UUID or display name. Raises if absent/ambiguous.

    Display-name lookup tries the literal string first, then the same
    string with each env suffix appended. The lowest-rank env (Test)
    wins on tie so the importer always reads from trunk-first state.
    """
    if is_uuid(name_or_uuid):
        records = client.policies.get([name_or_uuid])
        if not records:
            raise ImporterError(f"policy id {name_or_uuid!r} not found")
        return records[0]
    return _find_named_record(
        candidates=_name_candidates(name_or_uuid),
        query=lambda filter_: client.policies.query(filter=filter_),
        get=client.policies.get,
        kind="policy",
        original=name_or_uuid,
    )


def find_rule_group_record(client: FalconClient, name_or_uuid: str) -> dict[str, Any]:
    """Resolve a rule group by UUID or display name."""
    if is_uuid(name_or_uuid):
        records = client.rule_groups.get([name_or_uuid])
        if not records:
            raise ImporterError(f"rule group id {name_or_uuid!r} not found")
        return records[0]
    return _find_named_record(
        candidates=_name_candidates(name_or_uuid),
        query=lambda filter_: client.rule_groups.query(filter=filter_),
        get=client.rule_groups.get,
        kind="rule group",
        original=name_or_uuid,
    )


def find_location_record(client: FalconClient, name_or_uuid: str) -> dict[str, Any]:
    """Resolve a location by UUID or name. Locations have no env suffix."""
    if is_uuid(name_or_uuid):
        records = client.locations.get_details([name_or_uuid])
        if not records:
            raise ImporterError(f"location id {name_or_uuid!r} not found")
        return records[0]
    ids = client.locations.query(filter=f"name:'{name_or_uuid}'")
    if not ids:
        raise ImporterError(f"location {name_or_uuid!r} not found")
    records = client.locations.get_details(ids)
    if not records:
        raise ImporterError(
            f"location {name_or_uuid!r} resolved to id {ids[0]!r} but get_details was empty"
        )
    return records[0]


def _name_candidates(name: str) -> list[str]:
    """Generate the literal name plus each env-suffixed variant."""
    return [name, *(f"{name}-{env.title()}" for env in ("Test", "Pilot", "Production"))]


def _find_named_record(
    *,
    candidates: list[str],
    query: Any,
    get: Any,
    kind: str,
    original: str,
) -> dict[str, Any]:
    """Shared name-lookup logic for policies and rule groups."""
    for candidate in candidates:
        ids = query(f"name:'{candidate}'")
        if not ids:
            continue
        records = get(ids)
        if records:
            return _pick_lowest_env(records)
    raise ImporterError(f"{kind} {original!r} not found (also tried env-suffixed variants)")


def _pick_lowest_env(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Pick the Test record when multiple env-variant records come back."""

    def rank(record: dict[str, Any]) -> int:
        _, env = strip_env_suffix(str(record.get("name", "")))
        return ENV_RANK.get(env or "production", ENV_RANK["production"])

    return min(records, key=rank)


# ---- import entrypoints ---------------------------------------------------


def _enrich_policy_records_with_containers(
    client: FalconClient, policy_records: list[dict[str, Any]]
) -> None:
    """Inject rule_group_ids from policy containers into policy records in-place.

    ``getFirewallPolicies`` does not include rule group assignments — those
    come from the ``get_policy_containers`` endpoint.  The importer and
    differ both call this before handing records to :func:`policy_from_api`.
    """
    ids = [str(r["id"]) for r in policy_records if "id" in r]
    if not ids:
        return
    containers = client.policies.get_policy_containers(ids)
    by_policy_id: dict[str, dict[str, Any]] = {}
    for c in containers:
        pid = str(c.get("policy_id") or c.get("id") or "")
        if pid:
            by_policy_id[pid] = c
    for record in policy_records:
        container = by_policy_id.get(str(record.get("id", "")))
        if container is None:
            continue
        rg_ids = list(container.get("rule_group_ids") or [])
        record.setdefault("settings", {})["rule_group_ids"] = rg_ids


_RULE_FETCH_BATCH_SIZE = 100
"""Max IDs per ``get_rules`` call; keeps query strings under URL-length limits."""


def _fetch_rules_for_groups(
    client: FalconClient, rg_records: list[dict[str, Any]]
) -> dict[str, dict[str, Any]]:
    """Batch-fetch every rule referenced by the given rule-group records.

    Sends IDs in batches of :data:`_RULE_FETCH_BATCH_SIZE` to stay within
    URL length limits.

    The real API returns rule records keyed by a numeric ``id``, but the
    ``rule_ids`` field on rule-group records may contain hex "family IDs"
    (32-character strings like ``838b17a58aab40e59c9a952299fd0b00``).
    The returned records do not echo the family ID under a known field name,
    so we use two strategies to build the lookup:

    1. **Value scan**: for each returned record we check every top-level
       string field value against the set of requested IDs.  If the API
       happens to include the family ID under any field name, this catches it.

    2. **Positional fallback**: when the batch length matches the returned
       count (the common REST convention), we zip request IDs with returned
       records and use ``setdefault`` to fill any still-missing keys without
       overwriting entries already found by strategy 1.
    """
    rule_ids: list[str] = []
    seen: set[str] = set()
    for rg in rg_records:
        for rid in rg.get("rule_ids") or []:
            rid_str = str(rid)
            if rid_str in seen:
                continue
            seen.add(rid_str)
            rule_ids.append(rid_str)
    if not rule_ids:
        return {}
    rules_by_id: dict[str, dict[str, Any]] = {}
    for i in range(0, len(rule_ids), _RULE_FETCH_BATCH_SIZE):
        batch = rule_ids[i : i + _RULE_FETCH_BATCH_SIZE]
        batch_set = set(batch)
        fetched = client.rule_groups.get_rules(batch)
        for r in fetched:
            if "id" in r:
                rules_by_id[str(r["id"])] = r
            # Strategy 1: search all top-level string values for a match
            # against a requested ID (handles family_id under any field name).
            for v in r.values():
                if isinstance(v, str) and v in batch_set:
                    rules_by_id[v] = r
        # Strategy 2: positional fallback when count matches.
        if len(fetched) == len(batch):
            for req_id, r in zip(batch, fetched, strict=False):
                rules_by_id.setdefault(req_id, r)
    return rules_by_id


def import_policy(
    client: FalconClient,
    name_or_uuid: str,
    *,
    output_dir: Path | None = None,
    strip_env_suffix: bool = True,
    fold_overrides: bool = True,
) -> ImportResult:
    """Fetch one CrowdStrike policy and translate it into YAML.

    Resolves rule-group references (and their rules) so that the
    override-group folding can fire. The resulting :class:`Policy` is
    validated by Pydantic before writing.
    """
    record = find_policy_record(client, name_or_uuid)
    _enrich_policy_records_with_containers(client, [record])
    settings = record.get("settings") or {}
    rule_group_ids = list(settings.get("rule_group_ids") or record.get("rule_group_ids") or [])
    rg_records: list[dict[str, Any]] = []
    if rule_group_ids:
        rg_records = client.rule_groups.get([str(i) for i in rule_group_ids])
    rule_groups_by_id = {str(r["id"]): r for r in rg_records if "id" in r}

    rule_groups_by_slug: dict[str, RuleGroup] = {}
    if fold_overrides and rg_records:
        rules_by_id = _fetch_rules_for_groups(client, rg_records)
        for rg in rg_records:
            try:
                # Strip env suffix so the keying matches policy_from_api's
                # rg_slug derivation (which always strips first).
                model = rule_group_from_api(rg, rules_by_id, strip_suffix=True)
            except ImporterError:
                continue
            rule_groups_by_slug[model.name] = model

    policy = policy_from_api(
        record,
        rule_groups_by_id=rule_groups_by_id,
        rule_groups_by_slug=rule_groups_by_slug,
        strip_suffix=strip_env_suffix,
    )
    slug = policy.name.lower()
    path = _maybe_write(output_dir, "policies", slug, policy)
    return ImportResult(kind="policy", slug=slug, model=policy, path=path)


def import_rule_group(
    client: FalconClient,
    name_or_uuid: str,
    *,
    output_dir: Path | None = None,
    strip_env_suffix: bool = True,
) -> ImportResult:
    """Fetch one rule group plus its rules and translate to YAML."""
    record = find_rule_group_record(client, name_or_uuid)
    rule_ids = [str(r) for r in (record.get("rule_ids") or [])]
    rules_records = client.rule_groups.get_rules(rule_ids) if rule_ids else []
    rules_by_id = {str(r["id"]): r for r in rules_records if "id" in r}
    rg = rule_group_from_api(record, rules_by_id, strip_suffix=strip_env_suffix)
    path = _maybe_write(output_dir, "rule_groups", rg.name, rg)
    return ImportResult(kind="rule-group", slug=rg.name, model=rg, path=path)


def import_location(
    client: FalconClient,
    name_or_uuid: str,
    *,
    output_dir: Path | None = None,
) -> ImportResult:
    """Fetch one network location and translate to YAML."""
    record = find_location_record(client, name_or_uuid)
    location = location_from_api(record)
    path = _maybe_write(output_dir, "locations", location.name, location)
    return ImportResult(kind="location", slug=location.name, model=location, path=path)


def import_all(client: FalconClient, output_dir: Path) -> list[ImportResult]:
    """Bulk import every object in the tenant.

    Walks rule groups → locations → policies (the order minimises the
    chance of a missing-reference error when the validator later runs
    over the freshly imported repo). Per-kind directories are created
    on demand; the caller is responsible for the repo root.
    """
    results: list[ImportResult] = []

    from csfwctl.observability import get_logger

    logger = get_logger("exporter")

    # Rule groups first so the policy importer can fold override groups.
    rg_records = client.rule_groups.list_all()
    rules_by_id = _fetch_rules_for_groups(client, rg_records)
    rule_groups_by_id: dict[str, dict[str, Any]] = {}
    rule_groups_by_slug: dict[str, RuleGroup] = {}
    written_rule_group_slugs: dict[str, ImportResult] = {}
    for record in rg_records:
        if "id" in record:
            rule_groups_by_id[str(record["id"])] = record
        try:
            model = rule_group_from_api(record, rules_by_id, strip_suffix=True)
        except ImporterError as exc:
            logger.warning(
                "import skipped rule-group",
                extra={
                    "event": "import.rule_group.skipped",
                    "rule_group_name": record.get("name"),
                    "reason": str(exc),
                },
            )
            continue
        rule_groups_by_slug[model.name] = model
        # Skip override groups when writing; the policy importer folds them.
        _, override_env = is_override_group_name(model.name)
        if override_env is not None:
            continue
        # Multiple env variants reduce to one shared YAML; keep the first
        # we see (sub-clients return them in API order) but skip
        # duplicates so the file is not rewritten three times.
        if model.name in written_rule_group_slugs:
            continue
        path = _maybe_write(output_dir, "rule_groups", model.name, model)
        result = ImportResult(kind="rule-group", slug=model.name, model=model, path=path)
        written_rule_group_slugs[model.name] = result
        results.append(result)

    # Locations.
    location_records = client.locations.list_all()
    written_locations: set[str] = set()
    for record in location_records:
        try:
            location = location_from_api(record)
        except ImporterError as exc:
            logger.warning(
                "import skipped location",
                extra={
                    "event": "import.location.skipped",
                    "location_name": record.get("name"),
                    "reason": str(exc),
                },
            )
            continue
        if location.name in written_locations:
            continue
        written_locations.add(location.name)
        path = _maybe_write(output_dir, "locations", location.name, location)
        results.append(ImportResult(kind="location", slug=location.name, model=location, path=path))

    # Policies last.
    policy_records = client.policies.list_all()
    _enrich_policy_records_with_containers(client, policy_records)
    written_policy_slugs: set[str] = set()
    # Sort so that Test variants are imported before Pilot/Production; the
    # importer skips duplicates so subsequent envs reuse Test's YAML.
    policy_records.sort(
        key=lambda r: ENV_RANK.get(
            strip_env_suffix(str(r.get("name", "")))[1] or "production",
            ENV_RANK["production"],
        )
    )
    for record in policy_records:
        try:
            policy = policy_from_api(
                record,
                rule_groups_by_id=rule_groups_by_id,
                rule_groups_by_slug=rule_groups_by_slug,
                strip_suffix=True,
            )
        except ImporterError as exc:
            logger.warning(
                "import skipped policy",
                extra={
                    "event": "import.policy.skipped",
                    "policy_name": record.get("name"),
                    "reason": str(exc),
                },
            )
            continue
        slug = policy.name.lower()
        if slug in written_policy_slugs:
            continue
        written_policy_slugs.add(slug)
        path = _maybe_write(output_dir, "policies", slug, policy)
        results.append(ImportResult(kind="policy", slug=slug, model=policy, path=path))

    return results


# ---- YAML output ----------------------------------------------------------


def dump_yaml(model: Policy | RuleGroup | Location) -> str:
    """Render a model to YAML text. Drops Pydantic defaults to keep the
    output close to a hand-authored file: empty lists, ``status: enabled``,
    and ``locations: ['any']`` are omitted.
    """
    data = _trim_defaults(model)
    yaml = _yaml_writer()
    buf = io.StringIO()
    yaml.dump(data, buf)
    return buf.getvalue()


def _yaml_writer() -> YAML:
    yaml = YAML(typ="rt")
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.default_flow_style = False
    return yaml


def _trim_defaults(model: Policy | RuleGroup | Location) -> dict[str, Any]:
    """Strip default fields so emitted YAML matches the hand-authored shape.

    ``mode="json"`` converts enums to their string values so ruamel can
    serialise the result without a custom representer.
    """
    data = model.model_dump(mode="json", exclude_none=True)
    if isinstance(model, Policy):
        return _trim_policy(data)
    if isinstance(model, RuleGroup):
        return _trim_rule_group(data)
    return _trim_location(data)


def _trim_policy(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"name": data["name"]}
    if data.get("display_name"):
        out["display_name"] = data["display_name"]
    out["platform"] = data["platform"]
    out["priority"] = data.get("priority", PrecedenceBucket.default.value)
    out["status"] = data.get("status", Status.enabled.value)
    if data.get("description"):
        out["description"] = data["description"]
    if data.get("host_groups"):
        out["host_groups"] = dict(data["host_groups"])
    if data.get("rules"):
        out["rules"] = [_trim_rule(rule) for rule in data["rules"]]
    if data.get("rule_groups"):
        out["rule_groups"] = list(data["rule_groups"])
    return out


def _trim_rule_group(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"name": data["name"]}
    if data.get("display_name"):
        out["display_name"] = data["display_name"]
    out["platform"] = data["platform"]
    out["status"] = data.get("status", Status.enabled.value)
    if data.get("description"):
        out["description"] = data["description"]
    if data.get("rules"):
        out["rules"] = [_trim_rule(rule) for rule in data["rules"]]
    return out


def _trim_location(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {"name": data["name"]}
    if data.get("display_name"):
        out["display_name"] = data["display_name"]
    out["status"] = data.get("status", Status.enabled.value)
    if data.get("description"):
        out["description"] = data["description"]
    for field in ("addresses", "dns_servers", "dns_resolution_targets", "default_gateways"):
        if data.get(field):
            out[field] = list(data[field])
    return out


def _trim_rule(rule: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "name": rule["name"],
        "enabled": rule.get("enabled", True),
        "action": rule["action"],
        "direction": rule["direction"],
        "protocol": rule["protocol"],
    }
    if rule.get("state"):
        out["state"] = rule["state"]
    locations = rule.get("locations") or [ANY_LOCATION_NAME]
    out["locations"] = list(locations)
    if rule.get("local"):
        out["local"] = _trim_endpoint(rule["local"])
    if rule.get("remote"):
        out["remote"] = _trim_endpoint(rule["remote"])
    return out


def _trim_endpoint(endpoint: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if endpoint.get("addresses"):
        out["addresses"] = list(endpoint["addresses"])
    if endpoint.get("addresses_negated"):
        out["addresses_negated"] = True
    if endpoint.get("ports"):
        out["ports"] = list(endpoint["ports"])
    if endpoint.get("ports_negated"):
        out["ports_negated"] = True
    return out


def _maybe_write(
    output_dir: Path | None,
    subdir: str,
    slug: str,
    model: Policy | RuleGroup | Location,
) -> Path | None:
    """Write ``<output_dir>/<subdir>/<slug>.yaml`` if ``output_dir`` is given."""
    if output_dir is None:
        return None
    target_dir = output_dir / subdir
    target_dir.mkdir(parents=True, exist_ok=True)
    path = target_dir / f"{slug}.yaml"
    path.write_text(dump_yaml(model), encoding="utf-8")
    return path


__all__ = [
    "ENV_RANK",
    "ENV_SUFFIXES",
    "ImportResult",
    "ImporterError",
    "OVERRIDE_SUFFIX_RE",
    "UUID_RE",
    "clean_description",
    "display_name_to_slug",
    "to_slug",
    "dump_yaml",
    "find_location_record",
    "find_policy_record",
    "find_rule_group_record",
    "host_group_env",
    "import_all",
    "import_location",
    "import_policy",
    "import_rule_group",
    "is_override_group_name",
    "is_uuid",
    "location_from_api",
    "location_to_api_shape",
    "policy_from_api",
    "policy_to_api_shape",
    "rule_from_api",
    "rule_group_from_api",
    "rule_group_to_api_shape",
    "strip_env_suffix",
]
