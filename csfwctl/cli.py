"""Typer-based CLI surface for csfwctl.

All subcommands are stubbed in Phase 0; each prints a "not implemented"
message and exits with status 2. The shape of the command tree is fixed
by the project plan (section 4) so downstream phases can wire behaviour
in without changing the surface.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer

from csfwctl.observability import (
    LogFormat as _ObsLogFormat,
)
from csfwctl.observability import (
    configure_logging,
    new_request_id,
    set_request_id,
)

NOT_IMPLEMENTED_EXIT = 2

app = typer.Typer(
    name="csfwctl",
    help="Config-as-code for CrowdStrike Falcon firewall policies, rule groups, and locations.",
    no_args_is_help=True,
    add_completion=False,
)

import_app = typer.Typer(
    name="import",
    help="Bootstrap YAML from live CrowdStrike objects.",
    no_args_is_help=True,
)
app.add_typer(import_app, name="import")


class Env(StrEnum):
    """Deployment environment for a managed object."""

    test = "test"
    pilot = "pilot"
    production = "production"


class ImportEnv(StrEnum):
    """Subset of envs used by the promote command."""

    test = "test"
    pilot = "pilot"


class PromoteTarget(StrEnum):
    """Promotion targets for the promote command."""

    pilot = "pilot"
    production = "production"


class StatusFormat(StrEnum):
    """Output format for the status command."""

    table = "table"
    json = "json"


class LogFormat(StrEnum):
    """Global log/output format."""

    text = "text"
    json = "json"


class Profile(StrEnum):
    """Credential profile selector."""

    prod = "prod"
    dev = "dev"


def _not_implemented(command: str) -> None:
    """Print a uniform 'not implemented' message and exit with status 2."""
    typer.echo(f"csfwctl {command}: not implemented (Phase 0 scaffold)", err=True)
    raise typer.Exit(code=NOT_IMPLEMENTED_EXIT)


@app.callback()
def main(
    ctx: typer.Context,
    repo: Annotated[
        Path | None,
        typer.Option("--repo", help="Path to the config repository.", show_default=False),
    ] = None,
    profile: Annotated[
        Profile,
        typer.Option("--profile", help="Credential profile to use."),
    ] = Profile.prod,
    credentials_file: Annotated[
        Path | None,
        typer.Option(
            "--credentials-file",
            help=(
                "Path to credentials TOML. Overrides $CSFWCTL_CREDENTIALS_PATH "
                "and the default /etc/csfwctl/credentials.toml."
            ),
        ),
    ] = None,
    log_format: Annotated[
        LogFormat,
        typer.Option("--log-format", help="Output format for logs and machine output."),
    ] = LogFormat.text,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable verbose output.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Suppress non-error output.")] = False,
) -> None:
    """Global options applied to every subcommand."""
    set_request_id(new_request_id())
    configure_logging(
        log_format=_ObsLogFormat(log_format.value),
        quiet=quiet,
    )
    ctx.obj = {
        "repo": repo,
        "profile": profile.value,
        "credentials_file": credentials_file,
        "verbose": verbose,
    }


@app.command()
def validate(
    repo: Annotated[
        Path | None,
        typer.Option("--repo", help="Path to the config repository."),
    ] = None,
    strict: Annotated[
        bool,
        typer.Option("--strict", help="Treat lint warnings and info as fatal."),
    ] = False,
) -> None:
    """Schema and semantic lint. No API calls. Exit 1 on any error."""
    from csfwctl.validate_cmd import run_validate

    run_validate(repo, strict=strict)


@app.command()
def diff(
    ctx: typer.Context,
    env: Annotated[
        Env | None,
        typer.Option(
            "--env",
            help="Target environment. Omit to diff all environments (test/pilot/production).",
        ),
    ] = None,
    repo: Annotated[Path | None, typer.Option("--repo", help="Config repo path.")] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write JSON diff to this path."),
    ] = None,
    fail_on_env_drift: Annotated[
        bool,
        typer.Option(
            "--fail-on-env-drift",
            help=(
                "All-envs mode only: exit non-zero when a downstream env "
                "(pilot/production) has more pending changes than test."
            ),
        ),
    ] = False,
) -> None:
    """Show YAML vs. live state for one environment, or all when --env is omitted."""
    from csfwctl.diff_cmd import run_diff

    run_diff(
        env.value if env is not None else None,
        repo,
        output,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
        fail_on_env_drift=fail_on_env_drift,
    )


@app.command()
def apply(
    ctx: typer.Context,
    env: Annotated[Env, typer.Option("--env", help="Target environment.")],
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan only; no writes.")] = False,
    enforce: Annotated[bool, typer.Option("--enforce", help="Overwrite drifted state.")] = False,
    allow_delete: Annotated[
        bool, typer.Option("--allow-delete", help="Permit tombstoned deletions.")
    ] = False,
    strict_groups: Annotated[
        bool, typer.Option("--strict-groups", help="Fail on missing host groups.")
    ] = False,
    create_groups: Annotated[
        bool, typer.Option("--create-groups", help="Create missing host groups as empty.")
    ] = False,
    initial_bootstrap: Annotated[
        bool,
        typer.Option(
            "--initial-bootstrap",
            help="First-run mode: only add metadata; never modify rules.",
        ),
    ] = False,
    max_deletes: Annotated[
        int, typer.Option("--max-deletes", help="Blast-radius limit for deletes.")
    ] = 1,
    max_changes: Annotated[
        int, typer.Option("--max-changes", help="Blast-radius limit for total changes.")
    ] = 10,
    repo: Annotated[Path | None, typer.Option("--repo", help="Config repo path.")] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write JSON apply record to this path."),
    ] = None,
) -> None:
    """Idempotent apply. Refuses destructive ops without explicit flags."""
    from csfwctl.apply_cmd import run_apply

    run_apply(
        env=env.value,
        repo=repo,
        dry_run=dry_run,
        enforce=enforce,
        allow_delete=allow_delete,
        strict_groups=strict_groups,
        create_groups=create_groups,
        initial_bootstrap=initial_bootstrap,
        max_deletes=max_deletes,
        max_changes=max_changes,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
        output=output,
    )


@app.command()
def status(
    ctx: typer.Context,
    all_envs: Annotated[
        bool, typer.Option("--all-envs", help="Show all three environments side by side.")
    ] = False,
    output_format: Annotated[
        StatusFormat, typer.Option("--format", help="Output format.")
    ] = StatusFormat.table,
) -> None:
    """Show managed/unmanaged objects in the tenant with version/SHA per env."""
    from csfwctl.status_cmd import run_status

    run_status(
        all_envs=all_envs,
        output_format=output_format.value,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@app.command()
def precedence(
    ctx: typer.Context,
    env: Annotated[
        Env | None, typer.Option("--env", help="Compare against this environment.")
    ] = None,
    output_format: Annotated[
        StatusFormat, typer.Option("--format", help="Output format.")
    ] = StatusFormat.table,
    repo: Annotated[Path | None, typer.Option("--repo", help="Config repo path.")] = None,
) -> None:
    """Print the resolved policy precedence order."""
    from csfwctl.precedence_cmd import run_precedence

    run_precedence(
        repo,
        env.value if env is not None else None,
        output_format=output_format.value,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@import_app.command("policy")
def import_policy(
    ctx: typer.Context,
    name_or_uuid: Annotated[str, typer.Argument(help="Policy name or UUID.")],
    strip_env_suffix: Annotated[
        bool, typer.Option("--strip-env-suffix/--no-strip-env-suffix")
    ] = True,
    output: Annotated[Path | None, typer.Option("--output", help="Output YAML path.")] = None,
) -> None:
    """Bootstrap a policy YAML from a live CrowdStrike policy."""
    from csfwctl.import_cmd import run_import_policy

    run_import_policy(
        name_or_uuid,
        output=output or _repo_from_ctx(ctx),
        strip_env_suffix=strip_env_suffix,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@import_app.command("rule-group")
def import_rule_group(
    ctx: typer.Context,
    name_or_uuid: Annotated[str, typer.Argument(help="Rule group name or UUID.")],
    strip_env_suffix: Annotated[
        bool, typer.Option("--strip-env-suffix/--no-strip-env-suffix")
    ] = True,
    output: Annotated[Path | None, typer.Option("--output", help="Output YAML path.")] = None,
) -> None:
    """Bootstrap a rule-group YAML from a live CrowdStrike rule group."""
    from csfwctl.import_cmd import run_import_rule_group

    run_import_rule_group(
        name_or_uuid,
        output=output or _repo_from_ctx(ctx),
        strip_env_suffix=strip_env_suffix,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@import_app.command("location")
def import_location(
    ctx: typer.Context,
    name_or_uuid: Annotated[str, typer.Argument(help="Location name or UUID.")],
    output: Annotated[Path | None, typer.Option("--output", help="Output YAML path.")] = None,
) -> None:
    """Bootstrap a location YAML from a live CrowdStrike location."""
    from csfwctl.import_cmd import run_import_location

    run_import_location(
        name_or_uuid,
        output=output or _repo_from_ctx(ctx),
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@import_app.command("all")
def import_all(
    ctx: typer.Context,
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory to write imported YAML into."),
    ] = None,
) -> None:
    """Bulk import every object in the tenant. Used for initial repo population."""
    from csfwctl.import_cmd import run_import_all

    run_import_all(
        output_dir or _repo_from_ctx(ctx),
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@app.command("record-fixtures")
def record_fixtures(
    ctx: typer.Context,
    operations: Annotated[
        str | None,
        typer.Option("--operations", help="Comma-separated operation names to record."),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Output directory for fixtures.")
    ] = None,
) -> None:
    """Capture sanitized API responses for offline tests."""
    from csfwctl.record_fixtures_cmd import run_record_fixtures

    run_record_fixtures(
        operations,
        output,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


def _profile_from_ctx(ctx: typer.Context) -> str | None:
    """Pull the resolved ``--profile`` value out of the Typer context."""
    if isinstance(ctx.obj, dict):
        profile = ctx.obj.get("profile")
        if isinstance(profile, str):
            return profile
    return None


def _credentials_file_from_ctx(ctx: typer.Context) -> Path | None:
    """Pull the resolved ``--credentials-file`` value out of the Typer context."""
    if isinstance(ctx.obj, dict):
        path = ctx.obj.get("credentials_file")
        if isinstance(path, Path):
            return path
    return None


def _repo_from_ctx(ctx: typer.Context) -> Path | None:
    """Pull the resolved ``--repo`` value out of the Typer context."""
    if isinstance(ctx.obj, dict):
        path = ctx.obj.get("repo")
        if isinstance(path, Path):
            return path
    return None


@app.command("drift-check")
def drift_check(
    ctx: typer.Context,
    env: Annotated[Env, typer.Option("--env", help="Target environment.")],
    repo: Annotated[Path | None, typer.Option("--repo", help="Config repo path.")] = None,
    state_file: Annotated[
        Path | None,
        typer.Option("--state-file", help="Path to the persisted drift-state file."),
    ] = None,
    no_state: Annotated[
        bool,
        typer.Option(
            "--no-state",
            help="Disable state persistence (drift.cleared will never fire).",
        ),
    ] = False,
    fail_on_drift: Annotated[
        bool,
        typer.Option("--fail-on-drift", help="Exit with code 2 if drift was detected."),
    ] = False,
    alert_window: Annotated[
        int,
        typer.Option(
            "--alert-window",
            help=(
                "Suppress repeated drift.detected alerts for ongoing drift within this "
                "window (minutes). 0 disables deduplication."
            ),
        ),
    ] = 60,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write the drift report as JSON to this path."),
    ] = None,
) -> None:
    """Scheduled drift monitor — emits drift.detected/drift.cleared on transitions."""
    from csfwctl.drift_cmd import run_drift_check

    run_drift_check(
        env.value,
        repo=repo,
        state_file=state_file,
        no_state=no_state,
        fail_on_drift=fail_on_drift,
        alert_window=alert_window,
        output=output,
        profile=_profile_from_ctx(ctx),
        credentials_file=_credentials_file_from_ctx(ctx),
    )


@app.command()
def promote(
    source: Annotated[ImportEnv, typer.Option("--from", help="Source environment.")],
    target: Annotated[PromoteTarget, typer.Option("--to", help="Target environment.")],
) -> None:
    """Convenience wrapper that triggers the corresponding GitLab CI job."""
    del source, target
    _not_implemented("promote")


@app.command("notify-test")
def notify_test(
    ctx: typer.Context,
    channel: Annotated[
        str | None, typer.Option("--channel", help="Notifier channel to test.")
    ] = None,
    repo: Annotated[Path | None, typer.Option("--repo", help="Config repo path.")] = None,
) -> None:
    """Send a test notification to verify channel configuration."""
    from csfwctl.notify_test_cmd import run_notify_test

    effective_repo = repo or (ctx.obj.get("repo") if isinstance(ctx.obj, dict) else None)
    run_notify_test(channel, repo=effective_repo)


if __name__ == "__main__":
    app()
