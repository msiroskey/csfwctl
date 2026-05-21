"""Implementation of ``csfwctl drift-check``.

The drift-check job is the scheduled monitor that runs against a single
environment (typically Production), recomputes the YAML-vs-live diff, and
emits ``drift.detected`` / ``drift.cleared`` notifier events on
transitions. It is the read-only sibling of ``apply``: it never writes to
the tenant and never modifies the config repo.

State tracking
--------------

To distinguish "still drifted" from "newly drifted" — and to know when
to emit ``drift.cleared`` — the command persists a tiny per-environment
state file under ``<repo>/.csfwctl/drift-state-<env>.json``. The file
stores the previous drift verdict, last run timestamp, and the last
change-set summary. ``--state-file`` overrides the path; ``--no-state``
disables persistence entirely, in which case ``drift.detected`` fires
whenever drift exists and ``drift.cleared`` never fires (Phase 10
will layer dedupe and alert-window logic on top of this primitive).

Exit codes
----------

``0`` on a successful run regardless of whether drift was detected;
``1`` if the config repo fails to load or the live-state fetch errors;
``2`` if drift was detected and ``--fail-on-drift`` was passed (for
CI integrations that want a hard signal).
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.config import load_credentials
from csfwctl.differ import (
    ChangeSet,
    LiveState,
    compute_diff,
    fetch_live_state,
)
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.loader import ConfigRepoError, load_config_repo
from csfwctl.notifiers import Notifier, emit, make_event, setup_notifiers
from csfwctl.observability import get_logger
from csfwctl.safety import current_git_sha

_logger = get_logger("drift_cmd")

DRIFT_STATE_DIRNAME = ".csfwctl"
"""Directory under the repo root that holds drift-state files."""

DRIFT_STATE_FILENAME_TEMPLATE = "drift-state-{env}.json"
"""File template for the per-env drift-state file."""

DRIFT_EXIT_CODE = 2
"""Exit code returned with ``--fail-on-drift`` when drift was detected."""


# ---- state-file persistence -----------------------------------------------


@dataclass
class DriftState:
    """Last-known drift verdict for one environment.

    Persisted between drift-check runs so the command can recognise the
    transition from "drift" to "no drift" and emit ``drift.cleared``.
    """

    env: str
    has_drift: bool
    last_run: str  # ISO-8601 UTC timestamp
    summary: dict[str, int]

    def to_json(self) -> dict[str, Any]:
        return {
            "env": self.env,
            "has_drift": self.has_drift,
            "last_run": self.last_run,
            "summary": dict(self.summary),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> DriftState:
        return cls(
            env=str(data["env"]),
            has_drift=bool(data["has_drift"]),
            last_run=str(data["last_run"]),
            summary={k: int(v) for k, v in (data.get("summary") or {}).items()},
        )


def default_state_path(repo_root: Path, env: str) -> Path:
    """Return the default per-env drift-state path under ``<repo>/.csfwctl/``."""
    return repo_root / DRIFT_STATE_DIRNAME / DRIFT_STATE_FILENAME_TEMPLATE.format(env=env)


def load_drift_state(path: Path) -> DriftState | None:
    """Read ``path`` and return the prior :class:`DriftState`, or ``None``.

    Missing files yield ``None`` (first run). A malformed file is logged
    and treated as ``None`` so a corrupted state never blocks the job.
    """
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _logger.warning("drift state file %s unreadable: %s", path, exc)
        return None
    try:
        return DriftState.from_json(payload)
    except (KeyError, TypeError, ValueError) as exc:
        _logger.warning("drift state file %s malformed: %s", path, exc)
        return None


def save_drift_state(path: Path, state: DriftState) -> None:
    """Atomically rewrite ``path`` with ``state``. Creates parent dirs."""
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(state.to_json(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
    tmp.replace(path)


# ---- summary helpers ------------------------------------------------------


def change_set_summary(cs: ChangeSet) -> dict[str, int]:
    """Counts dict used in events, state file, and the human renderer."""
    return {
        "creates": len(cs.creates),
        "updates": len(cs.updates),
        "deletes": len(cs.deletes),
        "unmanaged": len(cs.unmanaged),
    }


def has_drift(cs: ChangeSet) -> bool:
    """``True`` when at least one create/update/delete is queued."""
    return cs.has_changes


# ---- command body ---------------------------------------------------------


StateProvider = Callable[[], LiveState]


def run_drift_check(
    env: str,
    *,
    repo: Path | None = None,
    state_file: Path | None = None,
    no_state: bool = False,
    fail_on_drift: bool = False,
    output: Path | None = None,
    profile: str | None = None,
    credentials_file: Path | None = None,
    state_provider: StateProvider | None = None,
) -> None:
    """Compute drift for ``env`` and emit ``drift.detected`` / ``drift.cleared``.

    Mirrors :func:`csfwctl.diff_cmd.run_diff` for the load + fetch + diff
    path; the difference is the persistent-state dance and the event types.
    ``state_provider`` is the same test seam used by ``run_diff``.
    """
    out = Console()
    err = Console(stderr=True)

    repo_path = (repo or Path.cwd()).resolve()
    try:
        config = load_config_repo(repo_path)
    except ConfigRepoError as exc:
        err.print(
            f"[red]drift-check: config repo failed to validate ({len(exc.errors)} error(s))[/red]"
        )
        for entry in exc.errors:
            err.print(f"  {entry.format()}")
        raise typer.Exit(code=1) from exc

    provider = state_provider or _default_state_provider(profile, credentials_file)
    try:
        live = provider()
    except (FalconAPIError, Exception) as exc:  # noqa: BLE001 — surface and exit
        err.print(f"[red]drift-check: failed to fetch live state: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    change_set = compute_diff(config, env, live)
    drift_now = has_drift(change_set)
    summary = change_set_summary(change_set)

    state_path = state_file or default_state_path(repo_path, env)
    prior = None if no_state else load_drift_state(state_path)
    prior_drift = bool(prior.has_drift) if prior is not None else False

    notifiers = setup_notifiers(config.tool_config)
    git_sha = current_git_sha(repo_path)

    if drift_now:
        _emit_drift_detected(env, summary, git_sha, change_set, notifiers)
    elif prior is not None and prior.has_drift:
        _emit_drift_cleared(env, prior, git_sha, notifiers)

    if not no_state:
        save_drift_state(
            state_path,
            DriftState(
                env=env,
                has_drift=drift_now,
                last_run=datetime.now(tz=UTC).isoformat(),
                summary=summary,
            ),
        )

    if output is not None:
        _write_json(output, env, change_set, drift_now, prior_drift)

    _render_text(out, env, change_set, drift_now, prior_drift, state_path, no_state)

    if drift_now and fail_on_drift:
        raise typer.Exit(code=DRIFT_EXIT_CODE)


def _emit_drift_detected(
    env: str,
    summary: dict[str, int],
    git_sha: str,
    change_set: ChangeSet,
    notifiers: list[Notifier],
) -> None:
    """Send a ``drift.detected`` event carrying counts + full change set."""
    emit(
        make_event(
            "drift.detected",
            severity="warn",
            env=env,
            git_sha=git_sha,
            summary=(
                f"drift detected in env={env}: "
                f"{summary['creates']} create(s), "
                f"{summary['updates']} update(s), "
                f"{summary['deletes']} delete(s)"
            ),
            details={
                "env": env,
                "summary": summary,
                "change_set": change_set.to_json(),
            },
        ),
        notifiers,
    )


def _emit_drift_cleared(
    env: str,
    prior: DriftState,
    git_sha: str,
    notifiers: list[Notifier],
) -> None:
    """Send a ``drift.cleared`` event with the prior verdict for context."""
    emit(
        make_event(
            "drift.cleared",
            severity="info",
            env=env,
            git_sha=git_sha,
            summary=f"drift cleared in env={env}",
            details={
                "env": env,
                "previous_summary": dict(prior.summary),
                "previous_run": prior.last_run,
            },
        ),
        notifiers,
    )


def _default_state_provider(
    profile: str | None, credentials_file: Path | None
) -> StateProvider:
    """Build the lambda that, on call, returns live state from the tenant."""

    def _provider() -> LiveState:
        creds = load_credentials(profile, credentials_path=credentials_file)
        client = FalconClient(creds)
        return fetch_live_state(client)

    return _provider


def _write_json(path: Path, env: str, cs: ChangeSet, drift_now: bool, prior_drift: bool) -> None:
    """Persist the drift report (change set + transition) as JSON."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "env": env,
        "drift": drift_now,
        "previous_drift": prior_drift,
        "transition": _transition_name(drift_now, prior_drift),
        "summary": change_set_summary(cs),
        "change_set": cs.to_json(),
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _transition_name(drift_now: bool, prior_drift: bool) -> str:
    """Label the transition between two consecutive drift verdicts."""
    if drift_now and not prior_drift:
        return "detected"
    if drift_now and prior_drift:
        return "ongoing"
    if not drift_now and prior_drift:
        return "cleared"
    return "stable"


def _render_text(
    console: Console,
    env: str,
    cs: ChangeSet,
    drift_now: bool,
    prior_drift: bool,
    state_path: Path,
    no_state: bool,
) -> None:
    """Print a per-env verdict and a small counts table."""
    transition = _transition_name(drift_now, prior_drift)
    if drift_now:
        verdict = f"[yellow]drift detected ({transition})[/yellow]"
    elif transition == "cleared":
        verdict = "[green]drift cleared[/green]"
    else:
        verdict = "[green]no drift[/green]"
    console.print(f"csfwctl drift-check --env {env}: {verdict}")

    table = Table(show_header=True, title_justify="left")
    table.add_column("Section", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("creates", str(len(cs.creates)))
    table.add_row("updates", str(len(cs.updates)))
    table.add_row("deletes", str(len(cs.deletes)))
    table.add_row("unmanaged (live-only)", str(len(cs.unmanaged)))
    console.print(table)

    if no_state:
        console.print("[dim]drift-check: state tracking disabled (--no-state)[/dim]")
    else:
        console.print(f"[dim]drift-check: state saved to {state_path}[/dim]")


__all__ = [
    "DRIFT_EXIT_CODE",
    "DRIFT_STATE_DIRNAME",
    "DRIFT_STATE_FILENAME_TEMPLATE",
    "DriftState",
    "change_set_summary",
    "default_state_path",
    "has_drift",
    "load_drift_state",
    "run_drift_check",
    "save_drift_state",
]
