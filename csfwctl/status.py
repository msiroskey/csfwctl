"""Tenant-state introspection — the engine behind ``csfwctl status``.

Reads every policy, rule group, and location in the tenant, parses the
``Managed by csfwctl`` metadata trailer off each description, and
returns a structured :class:`StatusReport` grouped by ``(kind, slug)``
with one :class:`EnvState` per environment.

Design notes:

- Slugs follow the same convention as the differ: env-stripped lowercase
  of the display name. Locations are tenant-global, so their slug is
  just the raw lowercased name and the env tag is taken from whatever
  the signature most recently recorded (``signature.env``).
- Managed-vs-unmanaged is decided purely by the presence of the
  ``Managed by csfwctl`` token in the description (the same rule the
  differ uses). The signature parse is best-effort — a malformed
  trailer still counts as "managed" but yields ``signature=None``.
- The status command is read-only. It uses
  :func:`csfwctl.differ.fetch_live_state` so the same code path that the
  diff and drift-check rely on populates the snapshot.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from csfwctl.differ import (
    KIND_LOCATION,
    KIND_ORDER,
    KIND_POLICY,
    KIND_RULE_GROUP,
    LiveState,
    is_managed_description,
)
from csfwctl.exporter import strip_env_suffix
from csfwctl.safety import MetadataSignature, parse_signature
from csfwctl.schema import HostGroupEnv

ENV_ORDER: tuple[str, ...] = tuple(e.value for e in HostGroupEnv)
"""Canonical column order for ``--all-envs`` output: test, pilot, production."""

UNSUFFIXED_ENV = "(no-env)"
"""Pseudo-env tag for live objects whose display name carries no env suffix.

These are typically console-created or hand-managed objects we will not
own. Status surfaces them so operators see what is out there; the
applier never touches them.
"""

LOCATION_ENV = "any"
"""Pseudo-env tag for locations that carry no signature.

Locations are tenant-global; a managed location with a signature is
shown in whichever env the signature most recently recorded. Without
a signature we have nothing to derive from, so we tag them ``any``.
"""


@dataclass(frozen=True)
class EnvState:
    """One environment's record of a single logical object.

    ``managed`` is true when the live description carries the
    ``Managed by csfwctl`` token regardless of whether the trailer
    parses; ``signature`` is the structured form (or ``None`` if the
    trailer is missing or malformed). ``object_id`` is the CrowdStrike
    UUID so JSON consumers can correlate against drift reports.
    """

    env: str
    object_id: str | None
    display_name: str
    managed: bool
    signature: MetadataSignature | None

    def to_json(self) -> dict[str, Any]:
        return {
            "env": self.env,
            "object_id": self.object_id,
            "display_name": self.display_name,
            "managed": self.managed,
            "signature": _signature_to_json(self.signature),
        }


def _signature_to_json(sig: MetadataSignature | None) -> dict[str, Any] | None:
    """Render a parsed signature as a plain dict; ``None`` stays ``None``."""
    if sig is None:
        return None
    return {
        "version": sig.version,
        "git_sha": sig.git_sha,
        "applied": sig.applied,
        "env": sig.env,
    }


@dataclass(frozen=True)
class StatusEntry:
    """One logical object viewed across every environment we found.

    ``envs`` is keyed by the env label discovered from the live name
    suffix (policies, rule groups) or the trailer (locations); a missing
    key means we found no live record for that env.
    """

    kind: str
    slug: str
    envs: dict[str, EnvState] = field(default_factory=dict)

    @property
    def display_name(self) -> str:
        """A reader-friendly name picked from whichever env exists."""
        for env in ENV_ORDER:
            es = self.envs.get(env)
            if es is not None:
                return _strip_env_label(es.display_name)
        if self.envs:
            first = next(iter(self.envs.values()))
            return first.display_name
        return self.slug

    @property
    def managed_envs(self) -> list[str]:
        """Sorted env labels (canonical order first) where this is managed."""
        ordered = [e for e in ENV_ORDER if e in self.envs and self.envs[e].managed]
        extras = sorted(e for e in self.envs if e not in ENV_ORDER and self.envs[e].managed)
        return ordered + extras

    @property
    def is_managed(self) -> bool:
        """``True`` if at least one env's live record carries the signature."""
        return any(state.managed for state in self.envs.values())

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "slug": self.slug,
            "display_name": self.display_name,
            "managed": self.is_managed,
            "envs": {env: state.to_json() for env, state in self.envs.items()},
        }


def _strip_env_label(display_name: str) -> str:
    """Return ``display_name`` minus its ``-Test``/``-Pilot``/``-Production`` suffix."""
    base, _ = strip_env_suffix(display_name)
    return base


@dataclass
class StatusReport:
    """Aggregate status result for one tenant snapshot."""

    entries: list[StatusEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        """Number of logical objects (across all kinds)."""
        return len(self.entries)

    @property
    def managed(self) -> int:
        """Number of logical objects with at least one managed env."""
        return sum(1 for e in self.entries if e.is_managed)

    @property
    def unmanaged(self) -> int:
        """Number of logical objects with no managed env."""
        return self.total - self.managed

    def by_kind(self, kind: str) -> list[StatusEntry]:
        """Entries filtered to one ``kind`` (``policy`` / ``rule-group`` / ``location``)."""
        return [e for e in self.entries if e.kind == kind]

    def to_json(self) -> dict[str, Any]:
        return {
            "summary": {
                "total": self.total,
                "managed": self.managed,
                "unmanaged": self.unmanaged,
                "by_kind": {
                    kind: len(self.by_kind(kind))
                    for kind in (KIND_POLICY, KIND_RULE_GROUP, KIND_LOCATION)
                },
            },
            "entries": [e.to_json() for e in self.entries],
        }


# ---- public entrypoint ----------------------------------------------------


def build_status_report(state: LiveState) -> StatusReport:
    """Group ``state`` into one :class:`StatusEntry` per ``(kind, slug)``.

    Locations are tenant-global; the env label comes from the signature
    when present, otherwise the literal ``"any"``. Policies and rule
    groups derive their env label from the display name suffix (matching
    the differ's :func:`csfwctl.differ._record_matches_env`).
    """
    by_key: dict[tuple[str, str], dict[str, EnvState]] = defaultdict(dict)

    for record in state.policies:
        slug, env, es = _entry_from_suffixed(record, KIND_POLICY)
        if slug is None:
            continue
        by_key[(KIND_POLICY, slug)][env] = es
    for record in state.rule_groups:
        slug, env, es = _entry_from_suffixed(record, KIND_RULE_GROUP)
        if slug is None:
            continue
        by_key[(KIND_RULE_GROUP, slug)][env] = es
    for record in state.locations:
        slug, env, es = _entry_from_location(record)
        if slug is None:
            continue
        by_key[(KIND_LOCATION, slug)][env] = es

    entries: list[StatusEntry] = []
    for (kind, slug), envs in by_key.items():
        entries.append(StatusEntry(kind=kind, slug=slug, envs=envs))
    entries.sort(key=lambda e: (KIND_ORDER.index(e.kind), e.slug))
    return StatusReport(entries=entries)


def _entry_from_suffixed(record: Any, kind: str) -> tuple[str | None, str, EnvState]:
    """Build a slug/env/EnvState triple from a live policy or rule-group record.

    ``slug`` is ``None`` when the record is unusable (no name, wrong
    type); the caller drops it on the floor.
    """
    if not isinstance(record, dict):
        return (None, "", _empty_state(""))
    raw_name = str(record.get("name", "")).strip()
    if not raw_name:
        return (None, "", _empty_state(""))
    base, env = strip_env_suffix(raw_name)
    env_label = env or UNSUFFIXED_ENV
    slug = base.lower()
    description = record.get("description")
    es = EnvState(
        env=env_label,
        object_id=_record_id(record),
        display_name=raw_name,
        managed=is_managed_description(description),
        signature=parse_signature(description),
    )
    del kind  # kind is decided by the caller; passed only for signature symmetry
    return (slug, env_label, es)


def _entry_from_location(record: Any) -> tuple[str | None, str, EnvState]:
    """Build a slug/env/EnvState triple from a live location record.

    Locations are tenant-global; the env comes from the signature when
    available, otherwise :data:`LOCATION_ENV`.
    """
    if not isinstance(record, dict):
        return (None, "", _empty_state(""))
    raw_name = str(record.get("name", "")).strip()
    if not raw_name:
        return (None, "", _empty_state(""))
    description = record.get("description")
    signature = parse_signature(description)
    env_label = signature.env if signature is not None else LOCATION_ENV
    slug = raw_name.lower()
    es = EnvState(
        env=env_label,
        object_id=_record_id(record),
        display_name=raw_name,
        managed=is_managed_description(description),
        signature=signature,
    )
    return (slug, env_label, es)


def _empty_state(env: str) -> EnvState:
    """Sentinel returned alongside an unusable record; never stored on a report."""
    return EnvState(
        env=env,
        object_id=None,
        display_name="",
        managed=False,
        signature=None,
    )


def _record_id(record: dict[str, Any]) -> str | None:
    """Coerce ``record['id']`` to a string, returning ``None`` when missing."""
    rid = record.get("id")
    if rid is None:
        return None
    return str(rid)


__all__ = [
    "ENV_ORDER",
    "EnvState",
    "LOCATION_ENV",
    "StatusEntry",
    "StatusReport",
    "UNSUFFIXED_ENV",
    "build_status_report",
]
