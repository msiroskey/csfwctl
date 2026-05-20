"""Implementation of ``csfwctl diff``.

Kept separate from :mod:`csfwctl.cli` so the command body can be tested
without the Typer runner. Follows the same pattern as
``validate_cmd`` and ``import_cmd``.
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
    KIND_ORDER,
    ChangeSet,
    DiffOp,
    LiveState,
    ManagedStatus,
    ObjectChange,
    compute_diff,
    fetch_live_state,
)
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.loader import ConfigRepoError, load_config_repo


def run_diff(
    env: str,
    repo: Path | None,
    output: Path | None,
    *,
    profile: str | None = None,
    state_provider: Any = None,
) -> None:
    """Compute a ``ConfigRepo``-vs-live diff for ``env`` and render it.

    ``state_provider`` is an optional callable ``(FalconClient) -> LiveState``
    that tests can pass to bypass the real API. When ``None`` the real
    :func:`fetch_live_state` runs.
    """
    out = Console()
    err = Console(stderr=True)

    repo_path = (repo or Path.cwd()).resolve()
    try:
        config = load_config_repo(repo_path)
    except ConfigRepoError as exc:
        err.print(f"[red]diff: config repo failed to validate ({len(exc.errors)} error(s))[/red]")
        for entry in exc.errors:
            err.print(f"  {entry.format()}")
        raise typer.Exit(code=1) from exc

    provider = state_provider or _default_state_provider(profile)
    try:
        state = provider()
    except (FalconAPIError, Exception) as exc:  # noqa: BLE001 — surface and exit
        err.print(f"[red]diff: failed to fetch live state: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    change_set = compute_diff(config, env, state)

    if output is not None:
        _write_json(output, change_set)
        out.print(f"[green]diff: JSON written to {output}[/green]")

    _render_text(out, change_set)


def _default_state_provider(profile: str | None) -> Any:
    """Build the lambda that, on call, returns live state from the tenant."""

    def _provider() -> LiveState:
        creds = load_credentials(profile)
        client = FalconClient(creds)
        return fetch_live_state(client)

    return _provider


def _write_json(path: Path, change_set: ChangeSet) -> None:
    """Serialise the change set as pretty JSON to ``path``."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(change_set.to_json(), indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )


def _render_text(console: Console, cs: ChangeSet) -> None:
    """Pretty-print a per-env summary table plus per-change details."""
    table = Table(title=f"csfwctl diff --env {cs.env}", title_justify="left")
    table.add_column("Section", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("creates", str(len(cs.creates)))
    table.add_row("updates", str(len(cs.updates)))
    table.add_row("deletes", str(len(cs.deletes)))
    table.add_row("no-change", str(len(cs.no_changes)))
    table.add_row("unmanaged (live-only)", str(len(cs.unmanaged)))
    table.add_row("warnings", str(len(cs.warnings)))
    console.print(table)

    if cs.has_changes:
        for section, items in (
            ("creates", cs.creates),
            ("updates", cs.updates),
            ("deletes", cs.deletes),
        ):
            if not items:
                continue
            console.print(f"\n[bold]{section}[/bold]")
            for item in _sorted_by_kind(items):
                _render_change(console, item)
    else:
        console.print("[green]diff: no changes[/green]")

    if cs.unmanaged:
        console.print("\n[yellow]unmanaged live objects (not in YAML, not tombstoned):[/yellow]")
        for item in _sorted_by_kind(cs.unmanaged):
            console.print(f"  [{item.kind}] {item.display_name} ({item.managed.value})")

    if cs.warnings:
        console.print("\n[yellow]warnings:[/yellow]")
        for warning in cs.warnings:
            console.print(f"  {warning}")


def _sorted_by_kind(items: list[ObjectChange]) -> list[ObjectChange]:
    """Sort changes so kinds appear in apply-order, slug alphabetical within."""
    return sorted(items, key=lambda c: (KIND_ORDER.index(c.kind), c.slug))


def _render_change(console: Console, change: ObjectChange) -> None:
    """One indented block per change with field-level details if present."""
    op_color = _OP_COLOR.get(change.op, "white")
    managed_tag = "" if change.managed is ManagedStatus.new else f" [{change.managed.value}]"
    header = (
        f"  [{op_color}]{change.op.value}[/{op_color}] "
        f"{change.kind} [bold]{change.display_name}[/bold]{managed_tag}"
    )
    if change.reason:
        header += f"  ({change.reason})"
    console.print(header)
    for fc in change.field_changes:
        console.print(f"      {fc.path}: {fc.before!r} -> {fc.after!r}")
    for hg in change.host_group_changes:
        console.print(f"      host_group:{hg.op} {hg.group_name}")


_OP_COLOR: dict[DiffOp, str] = {
    DiffOp.create: "green",
    DiffOp.update: "yellow",
    DiffOp.delete: "red",
    DiffOp.no_change: "white",
}


__all__ = ["run_diff"]
