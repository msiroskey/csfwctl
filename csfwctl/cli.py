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
    repo: Annotated[
        Path | None,
        typer.Option("--repo", help="Path to the config repository.", show_default=False),
    ] = None,
    profile: Annotated[
        Profile,
        typer.Option("--profile", help="Credential profile to use."),
    ] = Profile.prod,
    log_format: Annotated[
        LogFormat,
        typer.Option("--log-format", help="Output format for logs and machine output."),
    ] = LogFormat.text,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable verbose output.")] = False,
    quiet: Annotated[bool, typer.Option("--quiet", help="Suppress non-error output.")] = False,
) -> None:
    """Global options applied to every subcommand."""
    # Global flag plumbing lands in a later phase; accepted here so the
    # CLI surface matches the project plan from day one.
    del repo, profile, log_format, verbose, quiet


@app.command()
def validate(
    repo: Annotated[
        Path | None,
        typer.Option("--repo", help="Path to the config repository."),
    ] = None,
) -> None:
    """Schema and semantic lint. No API calls. Exit 1 on any error."""
    from csfwctl.validate_cmd import run_validate

    run_validate(repo)


@app.command()
def diff(
    env: Annotated[Env, typer.Option("--env", help="Target environment.")],
    repo: Annotated[Path | None, typer.Option("--repo", help="Config repo path.")] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Write JSON diff to this path."),
    ] = None,
) -> None:
    """Show YAML vs. live state for the named environment."""
    del env, repo, output
    _not_implemented("diff")


@app.command()
def apply(
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
) -> None:
    """Idempotent apply. Refuses destructive ops without explicit flags."""
    del (
        env,
        dry_run,
        enforce,
        allow_delete,
        strict_groups,
        create_groups,
        initial_bootstrap,
        max_deletes,
        max_changes,
        repo,
    )
    _not_implemented("apply")


@app.command()
def status(
    all_envs: Annotated[
        bool, typer.Option("--all-envs", help="Show all three environments.")
    ] = False,
    output_format: Annotated[
        StatusFormat, typer.Option("--format", help="Output format.")
    ] = StatusFormat.table,
) -> None:
    """Show managed/unmanaged objects in the tenant with version/SHA per env."""
    del all_envs, output_format
    _not_implemented("status")


@app.command()
def precedence(
    env: Annotated[
        Env | None, typer.Option("--env", help="Compare against this environment.")
    ] = None,
) -> None:
    """Print the resolved policy precedence order."""
    del env
    _not_implemented("precedence")


@import_app.command("policy")
def import_policy(
    name_or_uuid: Annotated[str, typer.Argument(help="Policy name or UUID.")],
    strip_env_suffix: Annotated[
        bool, typer.Option("--strip-env-suffix", help="Strip -Test/-Pilot/-Production suffix.")
    ] = True,
    output: Annotated[Path | None, typer.Option("--output", help="Output YAML path.")] = None,
) -> None:
    """Bootstrap a policy YAML from a live CrowdStrike policy."""
    del name_or_uuid, strip_env_suffix, output
    _not_implemented("import policy")


@import_app.command("rule-group")
def import_rule_group(
    name_or_uuid: Annotated[str, typer.Argument(help="Rule group name or UUID.")],
    strip_env_suffix: Annotated[
        bool, typer.Option("--strip-env-suffix", help="Strip env suffix from the name.")
    ] = True,
    output: Annotated[Path | None, typer.Option("--output", help="Output YAML path.")] = None,
) -> None:
    """Bootstrap a rule-group YAML from a live CrowdStrike rule group."""
    del name_or_uuid, strip_env_suffix, output
    _not_implemented("import rule-group")


@import_app.command("location")
def import_location(
    name_or_uuid: Annotated[str, typer.Argument(help="Location name or UUID.")],
    output: Annotated[Path | None, typer.Option("--output", help="Output YAML path.")] = None,
) -> None:
    """Bootstrap a location YAML from a live CrowdStrike location."""
    del name_or_uuid, output
    _not_implemented("import location")


@import_app.command("all")
def import_all(
    output_dir: Annotated[
        Path | None,
        typer.Option("--output-dir", help="Directory to write imported YAML into."),
    ] = None,
) -> None:
    """Bulk import every object in the tenant. Used for initial repo population."""
    del output_dir
    _not_implemented("import all")


@app.command("record-fixtures")
def record_fixtures(
    operations: Annotated[
        str | None,
        typer.Option("--operations", help="Comma-separated operation names to record."),
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", help="Output directory for fixtures.")
    ] = None,
) -> None:
    """Capture sanitized API responses for offline tests."""
    del operations, output
    _not_implemented("record-fixtures")


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
    channel: Annotated[
        str | None, typer.Option("--channel", help="Notifier channel to test.")
    ] = None,
) -> None:
    """Send a test notification to verify channel configuration."""
    del channel
    _not_implemented("notify-test")


if __name__ == "__main__":
    app()
