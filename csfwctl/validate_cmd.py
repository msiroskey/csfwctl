"""Implementation of ``csfwctl validate``.

Kept separate from :mod:`csfwctl.cli` so the command body can be tested
without going through the Typer runner. The CLI layer just delegates.

Validation runs in two passes:

1. :func:`csfwctl.loader.load_config_repo` parses and schema-validates
   every YAML/TOML file and runs the hard cross-reference checks. Any
   failure here is a fatal error (exit 1).
2. :func:`csfwctl.linter.run_lints` runs the pluggable semantic linter
   (Phase 7). Findings are emitted on stderr; ``warning``/``info`` are
   non-fatal by default, ``error`` findings always fail. ``--strict``
   promotes every finding to fatal.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from csfwctl.linter import LintFinding, Severity, has_errors, run_lints
from csfwctl.loader import ConfigRepo, ConfigRepoError, LoadError, load_config_repo


def run_validate(repo: Path | None, *, strict: bool = False) -> None:
    """Validate the config repo at ``repo`` (or ``cwd`` when ``None``).

    Writes a human-readable summary to stdout and per-error / per-lint
    listings to stderr. Exits 0 on success, 1 on any schema or
    cross-reference error, any lint error finding, or (with ``strict``)
    any lint finding regardless of severity.
    """
    out = Console()
    err = Console(stderr=True)
    repo_path = (repo or Path.cwd()).resolve()

    try:
        config = load_config_repo(repo_path)
    except ConfigRepoError as exc:
        _render_errors(err, exc.errors)
        raise typer.Exit(code=1) from exc

    findings = run_lints(config)
    if findings:
        _render_findings(err, findings)

    fatal_lints = has_errors(findings) or (strict and findings)
    if fatal_lints:
        err.print(
            f"[red]validate: {_count_label(findings)} (strict={strict}); exiting non-zero[/red]"
        )
        raise typer.Exit(code=1)

    _render_summary(out, config, findings)


def _render_summary(console: Console, config: ConfigRepo, findings: list[LintFinding]) -> None:
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
    if findings:
        console.print(f"[yellow]validate: OK with {_count_label(findings)}[/yellow]")
    else:
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


def _render_findings(console: Console, findings: list[LintFinding]) -> None:
    """Print every lint finding on stderr, grouped by severity.

    Uses ``soft_wrap`` plus ``overflow="ignore"`` so the rule id and
    file path are preserved verbatim — long paths under ``/tmp`` would
    otherwise get ellipsised by Rich.
    """
    console.print(f"[bold]validate: {_count_label(findings)}[/bold]")
    for finding in findings:
        colour = _severity_colour(finding.severity)
        console.print(
            f"  [{colour}]{escape(finding.format())}[/{colour}]",
            soft_wrap=True,
            overflow="ignore",
            crop=False,
        )


def _severity_colour(severity: Severity) -> str:
    if severity is Severity.error:
        return "red"
    if severity is Severity.warning:
        return "yellow"
    return "cyan"


def _count_label(findings: list[LintFinding]) -> str:
    """Build ``N error(s), M warning(s), K info(s)`` from the finding list."""
    counts: dict[Severity, int] = {Severity.error: 0, Severity.warning: 0, Severity.info: 0}
    for finding in findings:
        counts[finding.severity] += 1
    parts: list[str] = []
    if counts[Severity.error]:
        parts.append(f"{counts[Severity.error]} error(s)")
    if counts[Severity.warning]:
        parts.append(f"{counts[Severity.warning]} warning(s)")
    if counts[Severity.info]:
        parts.append(f"{counts[Severity.info]} info note(s)")
    return ", ".join(parts) if parts else "0 findings"


__all__ = ["run_validate"]
