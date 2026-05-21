"""Implementation of ``csfwctl apply``.

Mirrors the ``validate_cmd`` / ``diff_cmd`` / ``import_cmd`` pattern: a
single ``run_apply`` function that the Typer-side wrapper delegates to,
plus a clutch of small render helpers. Keeping the body out of
:mod:`csfwctl.cli` lets us drive the apply end-to-end in tests without
the Typer runner.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.applier import (
    AppliedAction,
    ApplyError,
    ApplyOptions,
    ApplyReport,
    HostGroupPolicy,
    apply_change_set,
)
from csfwctl.config import load_credentials
from csfwctl.differ import (
    KIND_LOCATION,
    KIND_POLICY,
    KIND_RULE_GROUP,
    ChangeSet,
    LiveState,
    compute_diff,
    fetch_live_state,
)
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.loader import ConfigRepo, ConfigRepoError, load_config_repo
from csfwctl.notifiers import emit, make_event, setup_notifiers
from csfwctl.safety import (
    SafetyError,
    SafetyOptions,
    current_git_sha,
)


def run_apply(
    *,
    env: str,
    repo: Path | None,
    dry_run: bool,
    enforce: bool,
    allow_delete: bool,
    strict_groups: bool,
    create_groups: bool,
    initial_bootstrap: bool,
    max_deletes: int,
    max_changes: int,
    profile: str | None = None,
    credentials_file: Path | None = None,
    state_provider: Any = None,
    client_factory: Any = None,
    git_sha: str | None = None,
    output: Path | None = None,
) -> ApplyReport:
    """Run a full apply cycle: load → diff → safety → write.

    Test-injection points:

    - ``state_provider`` — zero-arg callable returning a
      :class:`LiveState`. Lets tests bypass the real client for state
      fetching.
    - ``client_factory`` — zero-arg callable returning a
      :class:`FalconClient`-shaped object. The applier only uses the
      sub-client surface, so any compatible fake works.
    - ``git_sha`` — overrides the auto-detected SHA written into the
      metadata trailer. CI passes this; humans usually let
      :func:`csfwctl.safety.current_git_sha` resolve it.
    """
    out = Console()
    err = Console(stderr=True)
    repo_path = (repo or Path.cwd()).resolve()

    config = _load_config_or_exit(err, repo_path)
    sha = git_sha if git_sha is not None else current_git_sha(repo_path)
    notifiers = setup_notifiers(config.tool_config)

    client = _build_client(client_factory, profile, credentials_file, err)
    state = _fetch_state(state_provider, client, err)

    change_set = compute_diff(config, env, state)

    emit(
        make_event(
            "apply.started",
            severity="info",
            env=env,
            git_sha=sha,
            summary=f"apply started for env={env} dry_run={dry_run}",
            details={
                "env": env,
                "dry_run": dry_run,
                "bootstrap": initial_bootstrap,
                "changes": {
                    "creates": len(change_set.creates),
                    "updates": len(change_set.updates),
                    "deletes": len(change_set.deletes),
                },
            },
        ),
        notifiers,
    )

    safety_options = _build_safety_options(
        config=config,
        enforce=enforce,
        allow_delete=allow_delete,
        initial_bootstrap=initial_bootstrap,
        max_deletes=max_deletes,
        max_changes=max_changes,
    )
    apply_options = ApplyOptions(
        env=env,
        git_sha=sha,
        dry_run=dry_run,
        initial_bootstrap=initial_bootstrap,
        host_group_policy=_host_group_policy(
            strict_groups=strict_groups, create_groups=create_groups
        ),
    )

    try:
        report = apply_change_set(
            client=client,
            repo=config,
            change_set=change_set,
            state=state,
            options=apply_options,
            safety_options=safety_options,
        )
    except (SafetyError, ApplyError, FalconAPIError) as exc:
        err.print(f"[red]apply: {exc}[/red]")
        emit(
            make_event(
                "apply.failed",
                severity="error",
                env=env,
                git_sha=sha,
                summary=f"apply failed for env={env}: {exc}",
                details={"env": env, "error": str(exc)},
            ),
            notifiers,
        )
        raise typer.Exit(code=1) from exc

    emit(
        make_event(
            "apply.succeeded",
            severity="info",
            env=env,
            git_sha=sha,
            summary=f"apply succeeded for env={env}",
            details={"report": report.to_json()},
        ),
        notifiers,
    )

    if output is not None:
        _write_json(output, change_set, report)
        out.print(f"[green]apply: JSON written to {output}[/green]")

    _render_report(out, change_set, report)
    return report


# ---- helpers --------------------------------------------------------------


def _load_config_or_exit(err: Console, repo_path: Path) -> ConfigRepo:
    """Validate the config repo or surface a 1-exit listing every error."""
    try:
        return load_config_repo(repo_path)
    except ConfigRepoError as exc:
        err.print(f"[red]apply: config repo failed to validate ({len(exc.errors)} error(s))[/red]")
        for entry in exc.errors:
            err.print(f"  {entry.format()}")
        raise typer.Exit(code=1) from exc


def _build_client(
    client_factory: Any,
    profile: str | None,
    credentials_file: Path | None,
    err: Console,
) -> FalconClient:
    """Build a :class:`FalconClient` (or test stand-in)."""
    if client_factory is not None:
        stub: FalconClient = client_factory()
        return stub
    try:
        creds = load_credentials(profile, credentials_path=credentials_file)
    except Exception as exc:  # noqa: BLE001
        err.print(f"[red]apply: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    return FalconClient(creds)


def _fetch_state(state_provider: Any, client: FalconClient, err: Console) -> LiveState:
    """Pull live state through the optional injection point."""
    provider = state_provider if state_provider is not None else (lambda: fetch_live_state(client))
    try:
        return provider()
    except (FalconAPIError, Exception) as exc:  # noqa: BLE001
        err.print(f"[red]apply: failed to fetch live state: {exc}[/red]")
        raise typer.Exit(code=1) from exc


def _build_safety_options(
    *,
    config: ConfigRepo,
    enforce: bool,
    allow_delete: bool,
    initial_bootstrap: bool,
    max_deletes: int,
    max_changes: int,
) -> SafetyOptions:
    """Merge ``csfwctl.toml`` safety defaults with CLI overrides."""
    safety = config.tool_config.safety
    return SafetyOptions(
        max_changes=max_changes if max_changes is not None else safety.max_changes,
        max_deletes=max_deletes if max_deletes is not None else safety.max_deletes,
        enforce=enforce,
        allow_delete=allow_delete,
        initial_bootstrap=initial_bootstrap,
        require_bootstrap_for_unmanaged=safety.require_bootstrap_for_unmanaged,
    )


def _host_group_policy(*, strict_groups: bool, create_groups: bool) -> HostGroupPolicy:
    """Resolve the trio of host-group flags into one enum."""
    if strict_groups and create_groups:
        raise typer.BadParameter("--strict-groups and --create-groups are mutually exclusive")
    if create_groups:
        return HostGroupPolicy.create
    if strict_groups:
        return HostGroupPolicy.strict
    return HostGroupPolicy.warn


def _write_json(path: Path, change_set: ChangeSet, report: ApplyReport) -> None:
    """Persist a machine-readable apply record."""
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "diff": change_set.to_json(),
        "apply": report.to_json(),
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _render_report(console: Console, change_set: ChangeSet, report: ApplyReport) -> None:
    """Operator-facing summary table + per-action list."""
    title = f"csfwctl apply --env {report.env}"
    if report.dry_run:
        title += " (dry-run)"
    if report.bootstrap:
        title += " (initial-bootstrap)"
    table = Table(title=title, title_justify="left")
    table.add_column("Section", style="bold")
    table.add_column("Count", justify="right")
    for op in ("create", "update", "delete", "metadata", "host-group"):
        table.add_row(op, str(report.count(op)))
    table.add_row("warnings", str(len(report.warnings)))
    console.print(table)

    if report.actions:
        console.print()
        for action in report.actions:
            _render_action(console, action)
    elif change_set.has_changes:
        console.print("[yellow]apply: change set non-empty but no actions taken[/yellow]")
    else:
        console.print("[green]apply: tenant already matches desired state[/green]")

    if report.warnings:
        console.print("\n[yellow]warnings:[/yellow]")
        for warning in report.warnings:
            console.print(f"  {warning}")


def _render_action(console: Console, action: AppliedAction) -> None:
    """One line per action with colour matching the operation."""
    colour = _OP_COLOR.get(action.op, "white")
    suffix = ""
    if action.detail and action.op != "host-group":
        suffix = f" [{action.detail}]"
    elif action.op == "host-group":
        suffix = f" ({action.detail})"
    console.print(
        f"  [{colour}]{action.op}[/{colour}] {action.kind} "
        f"[bold]{action.display_name}[/bold]{suffix}"
    )


_OP_COLOR: dict[str, str] = {
    "create": "green",
    "update": "yellow",
    "delete": "red",
    "metadata": "cyan",
    "host-group": "magenta",
}


__all__ = ["run_apply"]


# ---- friendly re-exports so cli.py can stay slim --------------------------
_KIND_ORDER = (KIND_LOCATION, KIND_RULE_GROUP, KIND_POLICY)
