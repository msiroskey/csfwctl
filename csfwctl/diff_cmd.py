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
from csfwctl.precedence_resolver import PrecedenceDelta
from csfwctl.schema import Platform

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

    if multi.has_changes or multi.has_precedence_changes:
        notifiers = setup_notifiers(config.tool_config)
        _emit_all_envs(multi, notifiers)

    if output is not None:
        _write_json(output, multi.to_json())
        out.print(f"[green]diff: JSON written to {output}[/green]")

    _render_multi_env_text(out, multi)
    _render_precedence_deltas(out, multi.precedence_deltas, multi.precedence_warnings)

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
    if multi.has_precedence_changes:
        move_total = sum(len(delta.moves) for delta in multi.precedence_deltas.values())
        summary += f" — {move_total} precedence move(s)"
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

    _render_env_matrix_tables(console, multi)

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


def _render_env_matrix_tables(console: Console, multi: MultiEnvDiff) -> None:
    """One table per changed object, all sharing the same column widths.

    Each object gets its own titled table (``kind: display_name``) with
    the columns ``Change on / Test / Pilot / Production``. Rows follow
    the same conventions as before: ``(new)`` for a create summary,
    ``(deleted)`` for a delete summary, and one row per field path for
    an update. Cell content is ``before -> after`` for that env, or the
    empty-cell sentinel when the env has no matching change.

    Column widths are computed once across every object's data so all
    tables render at the same total width and columns visually line up
    down the page. Natural width is used when it fits under
    :data:`_MATRIX_MAX_WIDTH`; otherwise columns shrink proportionally
    (bounded below by their header labels) and Rich's ``overflow="fold"``
    wraps long ``before -> after`` cells.
    """
    envs = tuple(multi.change_sets.keys())
    per_object = _build_per_object_rows(multi, envs)
    if not per_object:
        return

    header = ["Change on", *(env.title() for env in envs)]
    all_rows = [row for _, _, rows in per_object for row in rows]
    col_widths = _shared_column_widths(header, all_rows)
    total_width = sum(col_widths) + _MATRIX_COL_OVERHEAD * len(col_widths) + 1

    for kind, display_name, rows in per_object:
        table = Table(
            title=f"[bold]{kind}:[/bold] {display_name}",
            title_justify="left",
            width=total_width,
        )
        for i, label in enumerate(header):
            table.add_column(label, width=col_widths[i], overflow="fold")
        for row in rows:
            table.add_row(*row)
        # ``crop=False`` keeps each table at its intended width even when
        # Rich can't detect a real terminal (CI logs, piped capture,
        # Docker exec) — otherwise Rich falls back to an 80-column
        # console and silently clips the Pilot / Production columns off
        # the right edge.
        console.print(table, crop=False)


def _build_per_object_rows(
    multi: MultiEnvDiff, envs: tuple[str, ...]
) -> list[tuple[str, str, list[list[str]]]]:
    """Group actionable changes into ``(kind, display_name, rows)`` triples.

    Each ``rows`` entry has the shape ``[change_on, cell_env0, cell_env1, ...]``,
    ready to be rendered without further transformation. Objects are
    ordered by apply-order (kind) then slug; within an object rows go
    ``(new)`` first, ``(deleted)`` next, then field paths alphabetically.
    """
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for env, cs in multi.change_sets.items():
        for change in cs.all_actionable():
            entry = grouped.setdefault(
                (change.kind, change.slug),
                {"display_name": change.display_name, "per_env": {}},
            )
            entry["per_env"][env] = change

    out: list[tuple[str, str, list[list[str]]]] = []
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

        rows: list[list[str]] = []
        if any(op is DiffOp.create for op in env_ops.values()):
            rows.append(
                ["(new)", *(_op_summary_cell(env_ops.get(env), DiffOp.create) for env in envs)]
            )
        if any(op is DiffOp.delete for op in env_ops.values()):
            rows.append(
                [
                    "(deleted)",
                    *(_op_summary_cell(env_ops.get(env), DiffOp.delete) for env in envs),
                ]
            )

        managed_row = _managed_group_row(per_env, envs)
        if managed_row is not None:
            rows.append(managed_row)

        for path in sorted({p for leaves in env_fields.values() for p in leaves}):
            cells: list[str] = [path]
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
            rows.append(cells)

        out.append((kind, display_name, rows))

    return out


def _cell_visible_width(cell: str) -> int:
    """Longest visible line-width of a cell, ignoring Rich ``[tag]`` markup."""
    plain = Text.from_markup(cell).plain
    return max((len(line) for line in plain.splitlines()), default=len(plain))


def _shared_column_widths(header: list[str], body: list[list[str]]) -> list[int]:
    """Per-column widths applied to every per-object table.

    Sizes each column to its widest visible cell across header + every
    row of every object. When the summed natural widths + overhead fit
    under :data:`_MATRIX_MAX_WIDTH`, natural widths are returned as-is —
    tables render without any forced wrapping. Over the cap columns
    shrink proportionally (never below their header labels) so long
    ``before -> after`` cells wrap via Rich's ``overflow="fold"``.
    """
    ncols = len(header)
    natural = [len(h) for h in header]
    for row in body:
        for i, cell in enumerate(row):
            natural[i] = max(natural[i], _cell_visible_width(cell))

    overhead = _MATRIX_COL_OVERHEAD * ncols + 1
    budget = _MATRIX_MAX_WIDTH - overhead
    total = sum(natural)
    if total <= budget:
        return natural

    # Proportional shrink first, honouring each column's header-label
    # floor. That floor may push the total back above budget, so pull
    # any remaining overrun from the widest column still above its floor
    # (typically a ``before -> after`` cell that wraps cleanly).
    widths = [max(len(h), round(w * budget / total)) for h, w in zip(header, natural, strict=True)]
    while sum(widths) > budget:
        candidates = [i for i, w in enumerate(widths) if w > len(header[i])]
        if not candidates:
            break
        widest = max(candidates, key=lambda i: widths[i])
        widths[widest] -= 1
    return widths


def _render_precedence_deltas(
    console: Console,
    deltas: dict[Platform, PrecedenceDelta],
    warnings: list[str],
) -> None:
    """One table per platform whose ``set_precedence`` payload will change.

    Skipped entirely when the resolver could not run (a warning is
    surfaced instead) and skipped per-platform when the family order
    already matches live. Rows list only the families whose position is
    moving; a positional delta of zero would be uninformative.
    """
    if warnings:
        console.print()
        console.print("[yellow]precedence:[/yellow]")
        for warning in warnings:
            console.print(f"  [yellow]{warning}[/yellow]")

    changed = [(platform, delta) for platform, delta in deltas.items() if delta.has_changes]
    if not changed:
        return

    for platform, delta in sorted(changed, key=lambda pd: pd[0].value):
        console.print()
        table = Table(
            title=f"precedence changes — {platform.value}",
            title_justify="left",
        )
        table.add_column("Slug")
        table.add_column("Name")
        table.add_column("Bucket")
        table.add_column("Live #", justify="right")
        table.add_column("New #", justify="right")
        table.add_column("Δ", justify="right")
        for move in delta.moves:
            live_cell = (
                "[green](new)[/green]" if move.live_ordinal is None else str(move.live_ordinal)
            )
            new_cell = str(move.resolved_ordinal)
            if move.delta is None:
                delta_cell = "[green]+[/green]"
            elif move.delta < 0:
                delta_cell = f"[green]{move.delta}[/green]"
            else:
                delta_cell = f"[yellow]+{move.delta}[/yellow]"
            table.add_row(
                move.slug,
                move.name,
                move.bucket.value,
                live_cell,
                new_cell,
                delta_cell,
            )
        console.print(table, crop=False)


def _managed_group_row(per_env: dict[str, ObjectChange], envs: tuple[str, ...]) -> list[str] | None:
    """Row rendering managed-host-group create/update ops across envs.

    Returns ``None`` when no env has an actionable managed-group op — a
    ``no-change`` or an env with no managed-group entry does not warrant
    its own row. Otherwise cells follow the same conventions as the
    field-path rows: ``before -> after`` for updates, an ``(new) <fql>``
    prefix for creates, and the empty-cell sentinel elsewhere.
    """
    cells: list[str] = ["managed-host-group"]
    any_actionable = False
    for env in envs:
        change = per_env.get(env)
        actionable = None
        if change is not None:
            for mgc in change.managed_group_changes:
                if mgc.op != "no-change":
                    actionable = mgc
                    break
        if actionable is None:
            cells.append(_MATRIX_EMPTY_CELL)
            continue
        any_actionable = True
        if actionable.op == "create":
            cells.append(f"[green](new)[/green] {actionable.desired_fql!r}")
        else:  # "update"
            live = actionable.live_fql or ""
            cells.append(f"{live!r} -> {actionable.desired_fql!r}")
    return cells if any_actionable else None


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
    for mg in change.managed_group_changes:
        if mg.op == "no-change":
            continue
        console.print(f"      managed-group:{mg.op} {mg.group_name} fql={mg.desired_fql!r}")


_OP_COLOR: dict[DiffOp, str] = {
    DiffOp.create: "green",
    DiffOp.update: "yellow",
    DiffOp.delete: "red",
    DiffOp.no_change: "white",
}


__all__ = ["run_diff"]
