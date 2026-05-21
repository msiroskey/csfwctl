"""Implementation of ``csfwctl notify-test``.

Sends a synthetic test event directly to one or all configured notifier
channels. Useful for verifying channel configuration (webhook URLs, API
tokens, syslog reachability) without triggering a real apply or validate.

The test event type is ``"notify.test"`` so it does not match typical
routing patterns like ``"apply.*"``. :func:`run_notify_test` bypasses
the :func:`emit` bus and calls :meth:`Notifier.send` directly so the
channel is exercised regardless of the ``events`` filter.
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from csfwctl.loader import ConfigRepoError, load_config_repo
from csfwctl.notifiers import Notifier, make_event, setup_notifiers


def run_notify_test(channel: str | None, repo: Path | None) -> None:
    """Send a test event to one or all configured notifier channels.

    If ``channel`` is given, only that notifier is exercised; if ``None``
    all configured notifiers are tested. Exits 1 if any notifier fails
    and no notifier succeeds.
    """
    out = Console()
    err = Console(stderr=True)
    repo_path = (repo or Path.cwd()).resolve()

    try:
        config = load_config_repo(repo_path)
    except ConfigRepoError as exc:
        err.print(f"[red]notify-test: config repo error: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    notifiers = setup_notifiers(config.tool_config)

    target: list[Notifier]
    if channel is not None:
        target = [n for n in notifiers if n.name == channel]
        if not target:
            configured = ", ".join(n.name for n in notifiers) or "(none)"
            err.print(
                f"[red]notify-test: channel {channel!r} not found. Configured: {configured}[/red]"
            )
            raise typer.Exit(code=1)
    else:
        target = notifiers

    if not target:
        out.print("[yellow]notify-test: no notifiers configured in csfwctl.toml[/yellow]")
        return

    event = make_event(
        "notify.test",
        severity="info",
        summary="Test notification from csfwctl notify-test",
        details={"channels_tested": [n.name for n in target]},
    )

    sent: list[str] = []
    failed: list[tuple[str, str]] = []
    for notifier in target:
        try:
            notifier.send(event)
            sent.append(notifier.name)
        except Exception as exc:  # noqa: BLE001
            failed.append((notifier.name, str(exc)))

    if sent:
        out.print(f"[green]notify-test: sent to {', '.join(sent)}[/green]")
    for name, reason in failed:
        err.print(f"[red]notify-test: {name} failed: {reason}[/red]")

    if failed and not sent:
        raise typer.Exit(code=1)


__all__ = ["run_notify_test"]
