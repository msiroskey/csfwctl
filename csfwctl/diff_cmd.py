"""Implementation of ``csfwctl diff``.

Kept separate from :mod:`csfwctl.cli` so the command body can be tested
without the Typer runner. Follows the same pattern as
``validate_cmd`` and ``import_cmd``.

Two modes:

- **Single env** (``--env test``): compares the config repo against one
  environment's live state and renders that change set.
- **All envs** (``--env`` omitted): fetches live state once and diffs it
  against all three environments (test/pilot/production), rendering a
  combined view plus a cross-env ripple warning when a downstream env
  (pilot/production) carries more pending changes than test. See
  :class:`csfwctl.differ.MultiEnvDiff`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from csfwctl.config import load_credentials
from csfwctl.differ import (
    KIND_ORDER,
    ChangeSet,
    DiffOp,
    FieldChange,
    LiveState,
    ManagedStatus,
    MultiEnvDiff,
    ObjectChange,
    compute_all_envs_diff,
    compute_diff,
    expand_field_change,
    fetch_live_state,
)
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.loader import ConfigRepo, ConfigRepoError, load_config_repo
from csfwctl.notifiers import Notifier, emit, make_event, setup_notifiers

ENV_DRIFT_EXIT_CODE = 2
"""Exit code when ``--fail-on-env-drift`` is set and a ripple is detected.

Distinct from ``1`` (config-repo load / live-fetch failure) so a pipeline
can tell a successful-but-blocked run from an error. Parallels
``drift-check --fail-on-drift``.
"""


def run_diff(
    env: str | None,
    repo: Path | None,
    output: Path | None,
    *,
    profile: str | None = None,
    credentials_file: Path | None = None,
    state_provider: Any = None,
    fail_on_env_drift: bool = False,
) -> None:
    """Compute a ``ConfigRepo``-vs-live diff and render it.

    When ``env`` is ``None`` the diff runs across all three environments
    (all-envs mode); otherwise it runs for the single named env.

    ``state_provider`` is an optional callable ``() -> LiveState`` that
    tests can pass to bypass the real API. When ``None`` the real
    :func:`fetch_live_state` runs.

    ``fail_on_env_drift`` only applies in all-envs mode: when set and a
    downstream env exceeds test's change count, the command exits
    :data:`ENV_DRIFT_EXIT_CODE`.
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

    provider = state_provider or _default_state_provider(profile, credentials_file)
    try:
        state = provider()
    except (FalconAPIError, Exception) as exc:  # noqa: BLE001 — surface and exit
        err.print(f"[red]diff: failed to fetch live state: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    if env is None:
        _run_all_envs(out, config, state, output, fail_on_env_drift)
    else:
        _run_single_env(out, config, env, state, output)


def _run_single_env(
    out: Console,
    config: ConfigRepo,
    env: str,
    state: LiveState,
    output: Path | None,
) -> None:
    """Single-env diff: compute, notify, optionally write JSON, render."""
    change_set = compute_diff(config, env, state)

    if change_set.has_changes:
        notifiers = setup_notifiers(config.tool_config)
        _emit_single_env(env, change_set, notifiers)

    if output is not None:
        _write_json(output, change_set.to_json())
        out.print(f"[green]diff: JSON written to {output}[/green]")

    _render_text(out, change_set)


def _run_all_envs(
    out: Console,
    config: ConfigRepo,
    state: LiveState,
    output: Path | None,
    fail_on_env_drift: bool,
) -> None:
    """All-envs diff: one fetch, three passes, combined render + ripple check."""
    multi = compute_all_envs_diff(config, state)

    if multi.has_changes:
        notifiers = setup_notifiers(config.tool_config)
        _emit_all_envs(multi, notifiers)

    if output is not None:
        _write_json(output, multi.to_json())
        out.print(f"[green]diff: JSON written to {output}[/green]")

    _render_multi_env_text(out, multi)

    if fail_on_env_drift and multi.has_env_drift:
        raise typer.Exit(code=ENV_DRIFT_EXIT_CODE)


def _emit_single_env(env: str, change_set: ChangeSet, notifiers: list[Notifier]) -> None:
    """Emit ``diff.changes_detected`` carrying the full change set."""
    emit(
        make_event(
            "diff.changes_detected",
            severity="warn",
            env=env,
            summary=(
                f"diff: {len(change_set.creates)} create(s),"
                f" {len(change_set.updates)} update(s),"
                f" {len(change_set.deletes)} delete(s)"
            ),
            details={
                "env": env,
                "creates": len(change_set.creates),
                "updates": len(change_set.updates),
                "deletes": len(change_set.deletes),
                "change_set": change_set.to_json(),
            },
        ),
        notifiers,
    )


def _emit_all_envs(multi: MultiEnvDiff, notifiers: list[Notifier]) -> None:
    """Emit one consolidated ``diff.changes_detected`` for all envs.

    A single event (and therefore a single MR comment) carries every
    env's change set plus the cross-env ripple warnings, so the reviewer
    sees the full picture without opening the pipeline. Severity escalates
    to ``warn`` whenever a ripple is detected.
    """
    parts = [f"{env}: {cs.total_changes} change(s)" for env, cs in multi.change_sets.items()]
    summary = "diff (all envs): " + ", ".join(parts)
    if multi.has_env_drift:
        summary += " — cross-env ripple detected"
    emit(
        make_event(
            "diff.changes_detected",
            severity="warn",
            env=None,
            summary=summary,
            details=multi.to_json(),
        ),
        notifiers,
    )


def _default_state_provider(profile: str | None, credentials_file: Path | None) -> Any:
    """Build the lambda that, on call, returns live state from the tenant."""

    def _provider() -> LiveState:
        creds = load_credentials(profile, credentials_path=credentials_file)
        client = FalconClient(creds)
        return fetch_live_state(client)

    return _provider


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    """Serialise ``payload`` as pretty JSON to ``path``."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


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


def _render_multi_env_text(console: Console, multi: MultiEnvDiff) -> None:
    """Combined summary table at the top, per-env detail logs below."""
    table = Table(title="csfwctl diff (all environments)", title_justify="left")
    table.add_column("Env", style="bold")
    table.add_column("creates", justify="right")
    table.add_column("updates", justify="right")
    table.add_column("deletes", justify="right")
    table.add_column("no-change", justify="right")
    table.add_column("unmanaged", justify="right")
    table.add_column("warnings", justify="right")
    for env, cs in multi.change_sets.items():
        table.add_row(
            env,
            str(len(cs.creates)),
            str(len(cs.updates)),
            str(len(cs.deletes)),
            str(len(cs.no_changes)),
            str(len(cs.unmanaged)),
            str(len(cs.warnings)),
        )
    console.print(table)

    _render_env_matrix_table(console, multi)

    if multi.has_env_drift:
        console.print(
            "\n[bold yellow]⚠ cross-env ripple detected "
            "(downstream env has more pending changes than test):[/bold yellow]"
        )
        for warning in multi.env_drift_warnings:
            console.print(f"  [yellow]{warning}[/yellow]")

    for env, cs in multi.change_sets.items():
        console.print(f"\n[bold underline]{env}[/bold underline]")
        if not cs.has_changes:
            console.print("  [green]no changes[/green]")
            continue
        for section, items in (
            ("creates", cs.creates),
            ("updates", cs.updates),
            ("deletes", cs.deletes),
        ):
            if not items:
                continue
            console.print(f"  [bold]{section}[/bold]")
            for item in _sorted_by_kind(items):
                _render_change(console, item)


_MATRIX_EMPTY_CELL = "—"
"""Rendered when an env has no matching change for the row's ``Change on`` key."""

_MATRIX_MAX_WIDTH = 140
"""Cap on the matrix table's total width, in terminal columns.

Wide enough to keep most ``before -> after`` cells on one line without
overflowing a typical two-pane review layout (editor + terminal, GitHub
PR view). The table auto-sizes below this when the data is narrow.
"""

_MATRIX_COL_OVERHEAD = 3
"""Non-content chars each column contributes to the rendered total.

Rich draws a 1-char left border plus, per column, 2 chars of padding and
1 char of right border. We use this to compute the natural width from
raw content lengths.
"""


def _render_env_matrix_table(console: Console, multi: MultiEnvDiff) -> None:
    """Per-object matrix showing what each env would apply.

    Rows are keyed by ``(kind, slug, change_on)``. ``change_on`` is
    ``(new)`` for a create, ``(deleted)`` for a delete, or a field path
    for an update. Each env column shows ``before -> after`` for that
    field (or a ``create`` / ``delete`` marker for op-summary rows), and
    :data:`_MATRIX_EMPTY_CELL` when the env has no matching change.

    Width is sized from the data: the table renders at its natural width
    (no forced wrapping) unless that exceeds :data:`_MATRIX_MAX_WIDTH`,
    in which case it caps there and Rich distributes the shrink across
    the widest columns.
    """
    envs = tuple(multi.change_sets.keys())
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for env, cs in multi.change_sets.items():
        for change in cs.all_actionable():
            entry = grouped.setdefault(
                (change.kind, change.slug),
                {"display_name": change.display_name, "per_env": {}},
            )
            entry["per_env"][env] = change

    if not grouped:
        return

    header = ["Type", "Name", "Change on", *(env.title() for env in envs)]
    body: list[list[str]] = []

    ordered_keys = sorted(grouped.keys(), key=lambda k: (KIND_ORDER.index(k[0]), k[1]))
    for key in ordered_keys:
        kind, _slug = key
        entry = grouped[key]
        display_name: str = entry["display_name"]
        per_env: dict[str, ObjectChange] = entry["per_env"]

        env_ops = {env: change.op for env, change in per_env.items()}
        env_fields: dict[str, dict[str, FieldChange]] = {}
        for env, change in per_env.items():
            leaves: dict[str, FieldChange] = {}
            for fc in change.field_changes:
                for leaf in expand_field_change(fc):
                    leaves[leaf.path] = leaf
            env_fields[env] = leaves

        obj_rows: list[tuple[str, list[str]]] = []
        if any(op is DiffOp.create for op in env_ops.values()):
            obj_rows.append(
                ("(new)", [_op_summary_cell(env_ops.get(env), DiffOp.create) for env in envs])
            )
        if any(op is DiffOp.delete for op in env_ops.values()):
            obj_rows.append(
                ("(deleted)", [_op_summary_cell(env_ops.get(env), DiffOp.delete) for env in envs])
            )

        for path in sorted({p for leaves in env_fields.values() for p in leaves}):
            cells: list[str] = []
            for env in envs:
                env_leaf: FieldChange | None = env_fields.get(env, {}).get(path)
                if env_leaf is not None:
                    cells.append(f"{env_leaf.before!r} -> {env_leaf.after!r}")
                elif env_ops.get(env) is DiffOp.create:
                    cells.append("[green](new)[/green]")
                elif env_ops.get(env) is DiffOp.delete:
                    cells.append("[red](deleted)[/red]")
                else:
                    cells.append(_MATRIX_EMPTY_CELL)
            obj_rows.append((path, cells))

        for change_on, cells in obj_rows:
            body.append([kind, display_name, change_on, *cells])

    table = Table(
        title="Per-object changes by environment",
        title_justify="left",
        width=_optimal_matrix_width(header, body),
    )
    table.add_column("Type", style="bold")
    table.add_column("Name")
    table.add_column("Change on")
    for env in envs:
        table.add_column(env.title(), overflow="fold")

    for row in body:
        table.add_row(*row)

    # ``crop=False`` keeps the matrix at its intended width even when
    # Rich can't detect a real terminal (CI logs, piped capture, Docker
    # exec) — otherwise Rich falls back to an 80-column console and
    # silently clips the Pilot / Production columns off the right edge.
    console.print(table, crop=False)


def _cell_visible_width(cell: str) -> int:
    """Longest visible line-width of a cell, ignoring Rich ``[tag]`` markup."""
    plain = Text.from_markup(cell).plain
    return max((len(line) for line in plain.splitlines()), default=len(plain))


def _optimal_matrix_width(header: list[str], body: list[list[str]]) -> int:
    """Total width the matrix table should render at.

    Walks the header and every row to find the maximum visible width per
    column, adds Rich's per-column overhead, and caps at
    :data:`_MATRIX_MAX_WIDTH`. Returning the natural width when it fits
    lets Rich render without any forced wrapping; over the cap, Rich
    distributes the shrink across the widest columns.
    """
    ncols = len(header)
    col_widths = [len(h) for h in header]
    for row in body:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], _cell_visible_width(cell))
    natural = sum(col_widths) + _MATRIX_COL_OVERHEAD * ncols + 1
    return min(_MATRIX_MAX_WIDTH, natural)


def _op_summary_cell(env_op: DiffOp | None, target: DiffOp) -> str:
    """Cell for a ``(new)`` / ``(deleted)`` summary row.

    Renders the op verb in colour when the env's op matches ``target``,
    otherwise the empty-cell sentinel.
    """
    if env_op is not target:
        return _MATRIX_EMPTY_CELL
    colour = _OP_COLOR.get(target, "white")
    return f"[{colour}]{target.value}[/{colour}]"


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
        for leaf in expand_field_change(fc):
            console.print(f"      {leaf.path}: {leaf.before!r} -> {leaf.after!r}")
    for hg in change.host_group_changes:
        console.print(f"      host_group:{hg.op} {hg.group_name}")


_OP_COLOR: dict[DiffOp, str] = {
    DiffOp.create: "green",
    DiffOp.update: "yellow",
    DiffOp.delete: "red",
    DiffOp.no_change: "white",
}


__all__ = ["run_diff"]
