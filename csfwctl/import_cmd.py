"""Implementation of ``csfwctl import`` subcommands.

Kept separate from :mod:`csfwctl.cli` so the command bodies can be
tested without going through the Typer runner. The CLI layer just
delegates here.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.config import load_credentials
from csfwctl.exporter import (
    ImporterError,
    ImportResult,
    import_all,
    import_location,
    import_policy,
    import_rule_group,
)
from csfwctl.falcon.client import FalconAPIError, FalconClient


def run_import_policy(
    name_or_uuid: str,
    *,
    output: Path | None,
    strip_env_suffix: bool,
    profile: str | None = None,
) -> None:
    """``csfwctl import policy <name|uuid>`` body."""
    client = _build_client(profile)
    output_dir, target_path = _split_single_output(output, "policies")
    try:
        result = import_policy(
            client,
            name_or_uuid,
            output_dir=output_dir,
            strip_env_suffix=strip_env_suffix,
        )
    except (ImporterError, FalconAPIError) as exc:
        _abort(str(exc))
    if target_path is not None and result.path is not None and result.path != target_path:
        _rename_imported(result.path, target_path)
        result = ImportResult(
            kind=result.kind, slug=result.slug, model=result.model, path=target_path
        )
    _print_single(result)


def run_import_rule_group(
    name_or_uuid: str,
    *,
    output: Path | None,
    strip_env_suffix: bool,
    profile: str | None = None,
) -> None:
    """``csfwctl import rule-group <name|uuid>`` body."""
    client = _build_client(profile)
    output_dir, target_path = _split_single_output(output, "rule_groups")
    try:
        result = import_rule_group(
            client,
            name_or_uuid,
            output_dir=output_dir,
            strip_env_suffix=strip_env_suffix,
        )
    except (ImporterError, FalconAPIError) as exc:
        _abort(str(exc))
    if target_path is not None and result.path is not None and result.path != target_path:
        _rename_imported(result.path, target_path)
        result = ImportResult(
            kind=result.kind, slug=result.slug, model=result.model, path=target_path
        )
    _print_single(result)


def run_import_location(
    name_or_uuid: str,
    *,
    output: Path | None,
    profile: str | None = None,
) -> None:
    """``csfwctl import location <name|uuid>`` body."""
    client = _build_client(profile)
    output_dir, target_path = _split_single_output(output, "locations")
    try:
        result = import_location(client, name_or_uuid, output_dir=output_dir)
    except (ImporterError, FalconAPIError) as exc:
        _abort(str(exc))
    if target_path is not None and result.path is not None and result.path != target_path:
        _rename_imported(result.path, target_path)
        result = ImportResult(
            kind=result.kind, slug=result.slug, model=result.model, path=target_path
        )
    _print_single(result)


def run_import_all(output_dir: Path | None, *, profile: str | None = None) -> None:
    """``csfwctl import all`` body."""
    client = _build_client(profile)
    target = (output_dir or Path.cwd()).resolve()
    target.mkdir(parents=True, exist_ok=True)
    try:
        results = import_all(client, target)
    except (ImporterError, FalconAPIError) as exc:
        _abort(str(exc))
    _print_bulk(target, results)


# ---- helpers --------------------------------------------------------------


def _build_client(profile: str | None) -> FalconClient:
    """Resolve credentials and return an authenticated ``FalconClient``."""
    try:
        creds = load_credentials(profile)
    except Exception as exc:
        _abort(str(exc))
    return FalconClient(creds)


def _split_single_output(
    output: Path | None, default_subdir: str
) -> tuple[Path | None, Path | None]:
    """Split ``--output`` into (output_dir, explicit_target_path).

    The exporter always writes into ``<dir>/<subdir>/<slug>.yaml``.
    When ``--output`` is an explicit file path, we write into a temporary
    layout under its parent and rename to the final filename so the
    caller controls the on-disk name.
    """
    if output is None:
        return Path.cwd().resolve(), None
    output = output.expanduser().resolve()
    if output.suffix in {".yaml", ".yml"}:
        return (
            output.parent.parent if output.parent.name == default_subdir else output.parent,
            output,
        )
    return output, None


def _rename_imported(written: Path, target: Path) -> None:
    """Move ``written`` to ``target``, creating parents and overwriting."""
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        target.unlink()
    written.replace(target)
    try:
        written.parent.rmdir()
    except OSError:
        pass


def _print_single(result: ImportResult) -> None:
    """Print a one-liner summary of a single-object import."""
    console = Console()
    location = str(result.path) if result.path else "(model only; no file written)"
    console.print(f"[green]imported[/green] {result.kind} [bold]{result.slug}[/bold] -> {location}")


def _print_bulk(target: Path, results: list[ImportResult]) -> None:
    """Tabulate an ``import all`` run."""
    console = Console()
    table = Table(title=f"csfwctl import all -> {target}", title_justify="left")
    table.add_column("Kind", style="bold")
    table.add_column("Count", justify="right")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.kind] = counts.get(r.kind, 0) + 1
    for kind in ("rule-group", "location", "policy"):
        table.add_row(kind, str(counts.get(kind, 0)))
    console.print(table)
    if not results:
        console.print("[yellow]no objects imported[/yellow]")


def _abort(message: str) -> None:
    """Print an error to stderr and exit 1. ``NoReturn``-ish helper."""
    err = Console(stderr=True)
    err.print(f"[red]import: {message}[/red]")
    raise typer.Exit(code=1)


__all__ = [
    "run_import_all",
    "run_import_location",
    "run_import_policy",
    "run_import_rule_group",
]
