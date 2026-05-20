"""Implementation of ``csfwctl record-fixtures``.

Captures sanitised API responses to disk for the integration test
suite. Lives in its own module so the body can be tested without going
through Typer; CLI delegates here.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.config import load_credentials
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.fixtures import (
    RecordResult,
    Sanitizer,
    default_operations,
    filter_operations,
    record_fixtures,
)


def run_record_fixtures(
    operations: str | None,
    output: Path | None,
    *,
    profile: str | None = None,
) -> None:
    """``csfwctl record-fixtures`` body.

    ``operations`` is the user's comma-separated filter; ``output`` is
    the target directory (default: ``tests/fixtures/api_responses`` in
    the current working tree).
    """
    target = (output or Path.cwd() / "tests" / "fixtures" / "api_responses").resolve()

    try:
        creds = load_credentials(profile)
    except Exception as exc:
        _abort(str(exc))
    client = FalconClient(creds)

    ops = default_operations()
    if operations:
        names = [piece.strip() for piece in operations.split(",")]
        ops = filter_operations(ops, names)
    if not ops:
        _abort(
            "no operations selected; use --operations with one of: "
            + ", ".join(Path(op.filename).stem for op in default_operations())
        )

    try:
        results = record_fixtures(client, target, operations=ops, sanitizer=Sanitizer())
    except FalconAPIError as exc:
        _abort(str(exc))

    _print_results(target, results)


def _print_results(target: Path, results: list[RecordResult]) -> None:
    """Render the per-operation outcome table."""
    console = Console()
    table = Table(title=f"csfwctl record-fixtures -> {target}", title_justify="left")
    table.add_column("File", style="bold")
    table.add_column("Bytes", justify="right")
    table.add_column("Status")
    any_error = False
    for r in results:
        if r.error is None:
            table.add_row(r.filename, str(r.bytes_written), "[green]ok[/green]")
        else:
            any_error = True
            table.add_row(r.filename, "0", f"[red]error: {r.error}[/red]")
    console.print(table)
    if any_error:
        raise typer.Exit(code=1)


def _abort(message: str) -> None:
    """Print an error to stderr and exit 1."""
    err = Console(stderr=True)
    err.print(f"[red]record-fixtures: {message}[/red]")
    raise typer.Exit(code=1)


__all__ = ["run_record_fixtures"]
