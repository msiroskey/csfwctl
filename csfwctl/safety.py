"""Safety rails for ``csfwctl apply``.

These checks run before the applier writes anything to a tenant. They
implement the CLAUDE.md hard rules:

- Blast-radius limits (``--max-deletes`` / ``--max-changes``) checked
  before any write.
- ``--initial-bootstrap`` is the only way to apply against an
  unbootstrapped tenant; a tenant counts as bootstrapped once at least
  one live object carries the metadata signature.
- Drifted live state (managed objects whose desired-vs-live diff is
  non-empty) only gets overwritten when ``--enforce`` is passed.
- Unmanaged live objects without a matching tombstone are reported but
  never touched.

The applier owns the metadata trailer on every object's ``description``.
:func:`render_signature` / :func:`parse_signature` / :func:`inject_signature`
encode the fixed format from CLAUDE.md so that ``status`` (Phase 6) and
the importer parse the same shape.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from csfwctl.differ import (
    METADATA_SIGNATURE_TOKEN,
    ChangeSet,
    ManagedStatus,
    is_managed_description,
)

ENV_GIT_SHA = "CSFWCTL_GIT_SHA"

SIGNATURE_LINE_RE = re.compile(
    r"^Managed by csfwctl\s*\|\s*version:\s*(?P<version>\d+)"
    r"\s*\|\s*git_sha:\s*(?P<git_sha>\S+)"
    r"\s*\|\s*applied:\s*(?P<applied>\S+)"
    r"\s*\|\s*env:\s*(?P<env>\S+)\s*$",
    re.MULTILINE,
)
"""Parses one signature line. The applier rewrites the trailer on every
touched object so the line is always present in its canonical shape."""

SIGNATURE_BLOCK_RE = re.compile(
    r"(?:\n+)?Managed by csfwctl\b.*$",
    re.DOTALL,
)
"""Strips the entire metadata block (signature line and any trailing
content) from a description. Mirrors the importer's
``exporter.METADATA_SIGNATURE_RE`` but is local to the applier so the
two modules can evolve independently."""


class SafetyError(Exception):
    """Base class for refused-apply errors. The CLI maps these to exit 1."""


class BlastRadiusExceeded(SafetyError):  # noqa: N818 — domain term reads cleaner than "Error" suffix
    """The plan exceeds ``--max-changes`` or ``--max-deletes``."""


class UnbootstrappedTenantError(SafetyError):
    """Normal apply attempted against a tenant with no managed objects."""


class DriftBlocked(SafetyError):  # noqa: N818 — domain term reads cleaner than "Error" suffix
    """Live state has drifted from desired and ``--enforce`` was not passed."""


class UnmanagedBlockedError(SafetyError):
    """Live has unmanaged objects and the config requires bootstrap-first."""


@dataclass(frozen=True)
class MetadataSignature:
    """One ``Managed by csfwctl | …`` trailer parsed or rendered."""

    version: int
    git_sha: str
    applied: str  # ISO 8601 UTC timestamp, e.g. "2026-05-19T14:30:00Z"
    env: str


@dataclass(frozen=True)
class SafetyOptions:
    """Operator-controlled knobs for one apply run."""

    max_changes: int = 10
    max_deletes: int = 1
    enforce: bool = False
    allow_delete: bool = False
    initial_bootstrap: bool = False
    require_bootstrap_for_unmanaged: bool = True


# ---- metadata signature ---------------------------------------------------


def render_signature(sig: MetadataSignature) -> str:
    """Render the canonical one-line trailer.

    Format is fixed by CLAUDE.md — do not reorder fields. The status
    command and the importer parse this exact shape.
    """
    return (
        f"{METADATA_SIGNATURE_TOKEN}"
        f" | version: {sig.version}"
        f" | git_sha: {sig.git_sha}"
        f" | applied: {sig.applied}"
        f" | env: {sig.env}"
    )


def parse_signature(description: str | None) -> MetadataSignature | None:
    """Return the latest signature embedded in ``description`` or ``None``.

    Tolerates additional free-text before the trailer: we only look at
    the last match in the string so a re-applied object still parses
    cleanly. Returns ``None`` if no signature is present or the line
    cannot be parsed.
    """
    if not description:
        return None
    match: re.Match[str] | None = None
    for found in SIGNATURE_LINE_RE.finditer(description):
        match = found
    if match is None:
        return None
    return MetadataSignature(
        version=int(match.group("version")),
        git_sha=match.group("git_sha"),
        applied=match.group("applied"),
        env=match.group("env"),
    )


def strip_signature(description: str | None) -> str:
    """Return ``description`` with any trailing metadata block removed."""
    if not description:
        return ""
    cleaned = SIGNATURE_BLOCK_RE.sub("", description)
    return cleaned.strip()


def inject_signature(description: str | None, sig: MetadataSignature) -> str:
    """Return ``description`` with the metadata trailer rewritten.

    Pre-existing free-text in the description is preserved; only the
    trailer is replaced. When the input has no trailer, the new one is
    appended on its own line (or as the sole content if the description
    was empty).
    """
    body = strip_signature(description)
    line = render_signature(sig)
    if body:
        return f"{body}\n\n{line}"
    return line


def next_signature(
    previous: MetadataSignature | None,
    *,
    git_sha: str,
    env: str,
    now: datetime | None = None,
) -> MetadataSignature:
    """Build the signature to write on the *next* apply.

    Version monotonically increments when a previous signature is
    present; bootstrap of a previously-unmanaged object starts at 1.
    """
    version = (previous.version + 1) if previous else 1
    timestamp = (now or datetime.now(UTC)).replace(microsecond=0)
    applied = timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    return MetadataSignature(version=version, git_sha=git_sha, applied=applied, env=env)


# ---- tenant bootstrap state ----------------------------------------------


def is_tenant_bootstrapped(descriptions: list[str | None]) -> bool:
    """``True`` if any live description carries the metadata signature.

    Accepts an arbitrary list rather than a typed live-state object so
    callers (applier, status command, drift-check) can feed it whatever
    they have at hand.
    """
    return any(is_managed_description(d) for d in descriptions)


def check_bootstrap(
    *,
    live_descriptions: list[str | None],
    options: SafetyOptions,
) -> None:
    """Refuse a normal apply against an unbootstrapped tenant.

    ``--initial-bootstrap`` bypasses the check (that mode exists to
    write the first signatures). Otherwise we raise so the applier
    cannot accidentally make changes against a fresh tenant.
    """
    if options.initial_bootstrap:
        return
    if not is_tenant_bootstrapped(live_descriptions):
        raise UnbootstrappedTenantError(
            "tenant is not bootstrapped (no live object carries the "
            f"'{METADATA_SIGNATURE_TOKEN}' signature); rerun with "
            "--initial-bootstrap to write the first metadata trailers"
        )


# ---- blast-radius check --------------------------------------------------


@dataclass(frozen=True)
class BlastRadiusReport:
    """Counts compared against the configured limits.

    Returned by :func:`check_blast_radius` for the CLI to surface even
    when the check passes. ``total_changes`` covers creates + updates +
    deletes (matches the ``ChangeSet`` field).
    """

    total_changes: int
    deletes: int
    max_changes: int
    max_deletes: int


def check_blast_radius(change_set: ChangeSet, options: SafetyOptions) -> BlastRadiusReport:
    """Refuse the apply if planned writes exceed the configured limits.

    Bootstrap mode is exempt from the change limit because writing the
    signature to every live object is the explicit goal of that run;
    deletes still count toward ``max_deletes`` because bootstrap mode
    must not delete anything.
    """
    deletes = len(change_set.deletes)
    total = change_set.total_changes
    report = BlastRadiusReport(
        total_changes=total,
        deletes=deletes,
        max_changes=options.max_changes,
        max_deletes=options.max_deletes,
    )
    if deletes > options.max_deletes:
        raise BlastRadiusExceeded(
            f"plan has {deletes} delete(s); the limit is {options.max_deletes}. "
            "Rerun with --max-deletes to authorise a larger change."
        )
    if not options.initial_bootstrap and total > options.max_changes:
        raise BlastRadiusExceeded(
            f"plan has {total} change(s); the limit is {options.max_changes}. "
            "Rerun with --max-changes to authorise a larger change."
        )
    return report


# ---- drift / enforce / allow-delete --------------------------------------


def check_drift(change_set: ChangeSet, options: SafetyOptions) -> None:
    """Refuse updates against managed-but-drifted objects unless ``--enforce``.

    A drifted object is one we are about to rewrite (``op = update``)
    whose live record still carries the metadata signature — i.e.
    csfwctl owns it but the console (or another tool) has changed
    something. Bootstrap mode skips the check because it never touches
    rule content.
    """
    if options.enforce or options.initial_bootstrap:
        return
    drifted = [change for change in change_set.updates if change.managed is ManagedStatus.managed]
    if drifted:
        names = ", ".join(f"{c.kind}:{c.slug}" for c in drifted[:5])
        more = "" if len(drifted) <= 5 else f" (+{len(drifted) - 5} more)"
        raise DriftBlocked(
            f"{len(drifted)} managed object(s) have drifted: {names}{more}. "
            "Rerun with --enforce to overwrite drifted state."
        )


def check_deletes(change_set: ChangeSet, options: SafetyOptions) -> None:
    """Refuse deletes unless ``--allow-delete`` was passed.

    The differ only emits deletes for tombstoned live objects, so the
    presence of any delete here means a tombstone is in place; this
    check is the second gate (``--allow-delete``) from the project plan.
    """
    if not change_set.deletes:
        return
    if options.initial_bootstrap:
        raise SafetyError(
            "bootstrap mode does not delete objects; remove tombstones "
            "or rerun without --initial-bootstrap"
        )
    if not options.allow_delete:
        slugs = ", ".join(f"{c.kind}:{c.slug}" for c in change_set.deletes[:5])
        raise SafetyError(
            f"plan has {len(change_set.deletes)} delete(s) ({slugs}); "
            "pass --allow-delete to proceed"
        )


# ---- git sha resolution --------------------------------------------------


def current_git_sha(repo_root: Path | None = None) -> str:
    """Resolve the git SHA to embed in the metadata trailer.

    Order of preference:

    1. ``$CSFWCTL_GIT_SHA`` (set by CI to the deploying commit).
    2. ``git -C <repo> rev-parse HEAD``.
    3. The literal ``"unknown"`` so a misconfigured environment never
       blocks the apply.
    """
    sha = os.environ.get(ENV_GIT_SHA)
    if sha:
        return sha.strip()
    try:
        cmd = ["git", "rev-parse", "HEAD"]
        if repo_root is not None:
            cmd = ["git", "-C", str(repo_root), "rev-parse", "HEAD"]
        result = subprocess.run(  # noqa: S603 — fixed argv, no shell
            cmd, capture_output=True, text=True, check=False, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip() or "unknown"


__all__ = [
    "BlastRadiusExceeded",
    "BlastRadiusReport",
    "DriftBlocked",
    "ENV_GIT_SHA",
    "MetadataSignature",
    "SIGNATURE_BLOCK_RE",
    "SIGNATURE_LINE_RE",
    "SafetyError",
    "SafetyOptions",
    "UnbootstrappedTenantError",
    "UnmanagedBlockedError",
    "check_blast_radius",
    "check_bootstrap",
    "check_deletes",
    "check_drift",
    "current_git_sha",
    "inject_signature",
    "is_tenant_bootstrapped",
    "next_signature",
    "parse_signature",
    "render_signature",
    "strip_signature",
]
