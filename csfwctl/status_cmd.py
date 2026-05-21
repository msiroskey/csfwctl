"""Implementation of ``csfwctl status``.

Reads the tenant's live state, builds a :class:`StatusReport`, and
renders it as either a Rich table or JSON. The command body follows the
same pattern as ``validate_cmd`` / ``diff_cmd`` / ``apply_cmd`` so it
can be tested without the Typer runner.

Default output is one row per ``(kind, slug, env)`` triple; passing
``--all-envs`` pivots into one row per logical object with one column
per environment so an operator can spot version drift across the three
environments at a glance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.config import load_credentials
from csfwctl.differ import (
    KIND_LOCATION,
    KIND_ORDER,
    KIND_POLICY,
    KIND_RULE_GROUP,
    LiveState,
    fetch_live_state,
)
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.status import (
    ENV_ORDER,
    EnvState,
    StatusEntry,
    StatusReport,
    build_status_report,
)

KIND_LABELS: dict[str, str] = {
    KIND_POLICY: "policy",
    KIND_RULE_GROUP: "rule-group",
    KIND_LOCATION: "location",
}


def run_status(
    *,
    all_envs: bool,
    output_format: str,
    profile: str | None = None,
    credentials_file: Path | None = None,
    state_provider: Any = None,
) -> StatusReport:
    """Fetch live state and render a status report.

    ``state_provider`` is a test-injection point matching ``diff_cmd``:
    a zero-arg callable returning :class:`LiveState`. When ``None`` the
    real :func:`fetch_live_state` runs against a real
    :class:`FalconClient` built from credentials.
    """
    out = Console()
    err = Console(stderr=True)

    provider = (
        state_provider
        if state_provider is not None
        else _default_state_provider(profile, credentials_file)
    )
    try:
        state = provider()
    except (FalconAPIError, Exception) as exc:  # noqa: BLE001 — surface and exit
        err.print(f"[red]status: failed to fetch live state: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    report = build_status_report(state)

    if output_format == "json":
        out.print_json(json.dumps(report.to_json()))
        return report

    if all_envs:
        _render_pivot_table(out, report)
    else:
        _render_flat_table(out, report)
    return report


def _default_state_provider(profile: str | None, credentials_file: Path | None) -> Any:
    """Build the lambda that, on call, returns live state from the tenant."""

    def _provider() -> LiveState:
        creds = load_credentials(profile, credentials_path=credentials_file)
        client = FalconClient(creds)
        return fetch_live_state(client)

    return _provider


# ---- rendering ------------------------------------------------------------


def _render_flat_table(console: Console, report: StatusReport) -> None:
    """One row per ``(kind, slug, env)``. Useful for grepping the output."""
    table = Table(title="csfwctl status", title_justify="left")
    table.add_column("Kind", style="bold")
    table.add_column("Slug")
    table.add_column("Env")
    table.add_column("Managed", justify="center")
    table.add_column("Ver", justify="right")
    table.add_column("git_sha")
    table.add_column("Applied")

    rows = 0
    for entry in _sorted_entries(report.entries):
        for env in _env_order_for(entry):
            state = entry.envs[env]
            table.add_row(*_flat_row(entry, env, state))
            rows += 1

    console.print(table)
    _render_summary(console, report, rows=rows)


def _flat_row(entry: StatusEntry, env: str, state: EnvState) -> tuple[str, ...]:
    """Cell values for one row of the flat table."""
    managed = "[green]M[/green]" if state.managed else "[yellow]U[/yellow]"
    sig = state.signature
    version = str(sig.version) if sig else "-"
    git_sha = sig.git_sha[:10] if sig else "-"
    applied = sig.applied if sig else "-"
    return (
        KIND_LABELS.get(entry.kind, entry.kind),
        entry.slug,
        env,
        managed,
        version,
        git_sha,
        applied,
    )


def _render_pivot_table(console: Console, report: StatusReport) -> None:
    """One row per ``(kind, slug)`` with one column per env.

    The cell value is ``version@sha`` when managed, ``U`` when present
    but unmanaged, or blank when the env has no live record.
    """
    table = Table(title="csfwctl status --all-envs", title_justify="left")
    table.add_column("Kind", style="bold")
    table.add_column("Slug")
    table.add_column("Display name")
    for env in ENV_ORDER:
        table.add_column(env)
    table.add_column("Other", overflow="fold")

    for entry in _sorted_entries(report.entries):
        row = [
            KIND_LABELS.get(entry.kind, entry.kind),
            entry.slug,
            entry.display_name,
        ]
        for env in ENV_ORDER:
            row.append(_pivot_cell(entry.envs.get(env)))
        extras = sorted(env for env in entry.envs if env not in ENV_ORDER)
        if extras:
            row.append(", ".join(f"{e}:{_pivot_cell(entry.envs[e])}" for e in extras))
        else:
            row.append("")
        table.add_row(*row)

    console.print(table)
    _render_summary(console, report, rows=len(report.entries))


def _pivot_cell(state: EnvState | None) -> str:
    """One cell of the pivot table: ``v@sha`` / ``U`` / blank."""
    if state is None:
        return ""
    if not state.managed:
        return "[yellow]U[/yellow]"
    if state.signature is None:
        return "[yellow]M (unparseable)[/yellow]"
    short_sha = state.signature.git_sha[:7]
    return f"[green]v{state.signature.version}@{short_sha}[/green]"


def _render_summary(console: Console, report: StatusReport, *, rows: int) -> None:
    """Footer with counts so the operator can sanity-check the snapshot."""
    summary = (
        f"[bold]{report.total}[/bold] logical object(s) — "
        f"[green]{report.managed} managed[/green], "
        f"[yellow]{report.unmanaged} unmanaged[/yellow]; "
        f"{rows} row(s) displayed"
    )
    console.print(summary)


def _sorted_entries(entries: list[StatusEntry]) -> list[StatusEntry]:
    """Sort entries by kind (apply-order), then slug for determinism."""
    return sorted(entries, key=lambda e: (KIND_ORDER.index(e.kind), e.slug))


def _env_order_for(entry: StatusEntry) -> list[str]:
    """Env labels for an entry in canonical order, with extras alphabetised."""
    base = [env for env in ENV_ORDER if env in entry.envs]
    extras = sorted(env for env in entry.envs if env not in ENV_ORDER)
    return base + extras


__all__ = ["run_status"]
