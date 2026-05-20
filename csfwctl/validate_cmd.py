"""Implementation of ``csfwctl validate``.

Kept separate from :mod:`csfwctl.cli` so the command body can be tested
without going through the Typer runner. The CLI layer just delegates.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.loader import ConfigRepo, ConfigRepoError, LoadError, load_config_repo


def run_validate(repo: Path | None) -> None:
    """Validate the config repo at ``repo`` (or ``cwd`` when ``None``).

    Writes a human-readable summary to stdout and a per-error listing to
    stderr on failure. Exits 0 on success, 1 on any validation error.
    """
    out = Console()
    err = Console(stderr=True)
    repo_path = (repo or Path.cwd()).resolve()

    try:
        config = load_config_repo(repo_path)
    except ConfigRepoError as exc:
        _render_errors(err, exc.errors)
        raise typer.Exit(code=1) from exc

    _render_summary(out, config)


def _render_summary(console: Console, config: ConfigRepo) -> None:
    """Pretty-print a one-line-per-kind summary of the loaded repo."""
    table = Table(title=f"csfwctl validate {config.root}", title_justify="left")
    table.add_column("Kind", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("policies", str(len(config.policies)))
    table.add_row("rule_groups", str(len(config.rule_groups)))
    table.add_row("locations", str(len(config.locations)))
    table.add_row("tombstones", str(_count_tombstones(config)))
    table.add_row("precedence overrides", str(len(config.precedence_overrides.overrides)))
    console.print(table)
    console.print("[green]validate: OK[/green]")


def _count_tombstones(config: ConfigRepo) -> int:
    return (
        len(config.tombstones.policies)
        + len(config.tombstones.rule_groups)
        + len(config.tombstones.locations)
    )


def _render_errors(console: Console, errors: list[LoadError]) -> None:
    """Print each error on its own line, prefixed with file:line:field."""
    console.print(f"[red]validate: {len(errors)} error(s)[/red]")
    for entry in errors:
        console.print(f"  {entry.format()}")


__all__ = ["run_validate"]
