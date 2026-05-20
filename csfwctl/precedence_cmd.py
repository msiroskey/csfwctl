"""Implementation of ``csfwctl precedence``.

Loads a config repo, resolves bucket → ordinal precedence (applying the
``precedence.yaml`` overrides), and prints the per-platform policy
ordering. When ``--env`` is given, also fetches the live tenant order
and shows a side-by-side comparison.

The actual write — calling
:meth:`csfwctl.falcon.policies.PoliciesAPI.set_precedence` to converge
live state — is owned by the applier's step-4 hook; this command is
read-only and exists so operators can preview what that step will do.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from csfwctl.config import load_credentials
from csfwctl.falcon.client import FalconAPIError, FalconClient
from csfwctl.loader import ConfigRepo, ConfigRepoError, load_config_repo
from csfwctl.precedence_resolver import (
    PrecedenceComparison,
    PrecedenceError,
    ResolvedPolicy,
    compare_to_live,
    resolve_precedence,
)
from csfwctl.schema import Platform

PLATFORM_FQL: dict[Platform, str] = {
    Platform.windows: "platform_name:'Windows'",
    Platform.mac: "platform_name:'Mac'",
}


def run_precedence(
    repo: Path | None,
    env: str | None,
    *,
    output_format: str = "table",
    profile: str | None = None,
    client_factory: Any = None,
    live_provider: Any = None,
) -> dict[Platform, list[ResolvedPolicy]]:
    """Resolve precedence for ``repo`` and render it (optionally vs. live).

    ``live_provider`` is a test-injection point: a callable
    ``(Platform) -> list[dict]`` returning live policy records in
    precedence order. When ``None`` and ``env`` is set, the real
    :class:`FalconClient` is built and queried; when ``None`` and
    ``env`` is also ``None``, no live comparison runs.
    """
    out = Console()
    err = Console(stderr=True)
    repo_path = (repo or Path.cwd()).resolve()

    try:
        config = _load_config(repo_path)
    except ConfigRepoError as exc:
        _emit_load_errors(err, exc)
        raise typer.Exit(code=1) from exc

    try:
        resolved = resolve_precedence(config)
    except PrecedenceError as exc:
        err.print(f"[red]precedence: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    comparisons: dict[Platform, PrecedenceComparison] = {}
    if env is not None:
        comparisons = _gather_comparisons(
            resolved=resolved,
            env=env,
            err=err,
            profile=profile,
            client_factory=client_factory,
            live_provider=live_provider,
        )

    if output_format == "json":
        out.print_json(json.dumps(_to_json(resolved, comparisons, env=env)))
        return resolved

    _render_tables(out, resolved, comparisons, env=env)
    return resolved


# ---- helpers --------------------------------------------------------------


def _load_config(repo_path: Path) -> ConfigRepo:
    """Load and validate a config repo. Surfacing errors is the caller's job."""
    return load_config_repo(repo_path)


def _emit_load_errors(err: Console, exc: ConfigRepoError) -> None:
    """Print each :class:`LoadError` on its own indented line."""
    err.print(f"[red]precedence: config repo failed to validate ({len(exc.errors)} error(s))[/red]")
    for entry in exc.errors:
        err.print(f"  {entry.format()}")


def _gather_comparisons(
    *,
    resolved: dict[Platform, list[ResolvedPolicy]],
    env: str,
    err: Console,
    profile: str | None,
    client_factory: Any,
    live_provider: Any,
) -> dict[Platform, PrecedenceComparison]:
    """Pull live ordering for each platform we care about and diff it.

    Failures fetching live state surface as a 1-exit so the operator
    sees what went wrong rather than a silently empty comparison.
    """
    provider = (
        live_provider
        if live_provider is not None
        else _default_live_provider(profile=profile, client_factory=client_factory, err=err)
    )
    comparisons: dict[Platform, PrecedenceComparison] = {}
    for platform, resolved_list in resolved.items():
        try:
            records = provider(platform)
        except (FalconAPIError, Exception) as exc:  # noqa: BLE001 — surface and exit
            err.print(f"[red]precedence: failed to fetch live policies: {exc}[/red]")
            raise typer.Exit(code=1) from exc
        comparisons[platform] = compare_to_live(resolved_list, records, env=env)
    return comparisons


def _default_live_provider(
    *,
    profile: str | None,
    client_factory: Any,
    err: Console,
) -> Any:
    """Build the lambda that, per platform, fetches live policies in order."""

    def _build_client() -> FalconClient:
        if client_factory is not None:
            stub: FalconClient = client_factory()
            return stub
        try:
            creds = load_credentials(profile)
        except Exception as exc:  # noqa: BLE001
            err.print(f"[red]precedence: {exc}[/red]")
            raise typer.Exit(code=1) from exc
        return FalconClient(creds)

    client_holder: dict[str, FalconClient] = {}

    def _provider(platform: Platform) -> list[dict[str, Any]]:
        if "client" not in client_holder:
            client_holder["client"] = _build_client()
        client = client_holder["client"]
        ids = client.policies.query(filter=PLATFORM_FQL[platform])
        return client.policies.get(ids) if ids else []

    return _provider


def _to_json(
    resolved: dict[Platform, list[ResolvedPolicy]],
    comparisons: dict[Platform, PrecedenceComparison],
    *,
    env: str | None,
) -> dict[str, Any]:
    """Render the full result (resolved + optional comparison) as a dict."""
    payload: dict[str, Any] = {
        "platforms": {
            platform.value: [p.to_json() for p in policies]
            for platform, policies in resolved.items()
        },
    }
    if env is not None:
        payload["env"] = env
        payload["comparisons"] = {
            platform.value: comparison.to_json() for platform, comparison in comparisons.items()
        }
    return payload


# ---- table rendering -----------------------------------------------------


def _render_tables(
    console: Console,
    resolved: dict[Platform, list[ResolvedPolicy]],
    comparisons: dict[Platform, PrecedenceComparison],
    *,
    env: str | None,
) -> None:
    """One per-platform table; if ``env`` was given, also show live diff."""
    if not resolved:
        console.print("[yellow]precedence: no policies to order[/yellow]")
        return
    for platform in sorted(resolved.keys(), key=lambda p: p.value):
        _render_platform(console, platform, resolved[platform])
        if env is not None:
            comp = comparisons.get(platform)
            if comp is not None:
                _render_comparison(console, comp, env=env)
            console.print()


def _render_platform(console: Console, platform: Platform, policies: list[ResolvedPolicy]) -> None:
    """Resolved per-platform table: ordinal, slug, name, bucket."""
    table = Table(
        title=f"resolved precedence — {platform.value}",
        title_justify="left",
    )
    table.add_column("#", justify="right")
    table.add_column("Slug")
    table.add_column("Name")
    table.add_column("Bucket")
    for policy in policies:
        table.add_row(
            str(policy.ordinal),
            policy.slug,
            policy.name,
            policy.bucket.value,
        )
    console.print(table)


def _render_comparison(console: Console, comparison: PrecedenceComparison, *, env: str) -> None:
    """Live-vs-resolved comparison block."""
    if comparison.matches:
        console.print(
            f"[green]live precedence matches resolved order "
            f"({comparison.platform.value} / {env})[/green]"
        )
        return
    console.print(
        f"[yellow]live precedence differs from resolved order "
        f"({comparison.platform.value} / {env}):[/yellow]"
    )
    table = Table(title=None, title_justify="left")
    table.add_column("#", justify="right")
    table.add_column("Resolved")
    table.add_column("Live")
    rows = max(len(comparison.resolved_slugs), len(comparison.live_slugs))
    for i in range(rows):
        resolved = comparison.resolved_slugs[i] if i < len(comparison.resolved_slugs) else ""
        live = comparison.live_slugs[i] if i < len(comparison.live_slugs) else ""
        mark = "" if resolved == live else " *"
        table.add_row(str(i), resolved, f"{live}{mark}")
    console.print(table)


__all__ = ["run_precedence"]
