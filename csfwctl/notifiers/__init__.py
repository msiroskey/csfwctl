"""Pluggable notifier system.

Event bus and channel registry for csfwctl notifications.

Event types emitted by command bodies:

- ``validate.failed`` — validation or lint errors prevented success.
- ``diff.changes_detected`` — the diff found at least one change.
- ``apply.started`` — an apply cycle is about to write to the tenant.
- ``apply.succeeded`` — apply completed with no errors.
- ``apply.failed`` — apply aborted due to a safety, API, or config error.
- ``drift.detected`` / ``drift.cleared`` — reserved for a future drift-check job.
- ``notify.test`` — synthetic event emitted by ``csfwctl notify-test``.

Each channel is registered under its ``csfwctl.toml`` table key (e.g.
``"log"``, ``"teams"``). Active notifiers are built by
:func:`setup_notifiers` from the loaded :class:`ToolConfig` and
dispatched to by :func:`emit`. A failure in one notifier never
propagates to others or to the calling command.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from csfwctl.observability import current_request_id, get_logger
from csfwctl.schema.tool_config import NotifierConfig, ToolConfig

_logger = get_logger("notifiers")


# ---- Event ----------------------------------------------------------------


@dataclass
class Event:
    """Structured notification payload emitted by command bodies."""

    type: str
    severity: str  # "info" | "warn" | "error"
    timestamp: datetime
    env: str | None
    git_sha: str | None
    summary: str
    details: dict[str, Any]
    request_id: str

    def to_json(self) -> dict[str, Any]:
        """JSON-serialisable representation for log and API payloads."""
        return {
            "type": self.type,
            "severity": self.severity,
            "timestamp": self.timestamp.isoformat(),
            "env": self.env,
            "git_sha": self.git_sha,
            "summary": self.summary,
            "details": self.details,
            "request_id": self.request_id,
        }


def make_event(
    event_type: str,
    *,
    severity: str = "info",
    env: str | None = None,
    git_sha: str | None = None,
    summary: str,
    details: dict[str, Any] | None = None,
) -> Event:
    """Build an :class:`Event` stamped with the current timestamp and request ID."""
    return Event(
        type=event_type,
        severity=severity,
        timestamp=datetime.now(tz=UTC),
        env=env,
        git_sha=git_sha,
        summary=summary,
        details=details or {},
        request_id=current_request_id(),
    )


# ---- Notifier protocol ----------------------------------------------------


@runtime_checkable
class Notifier(Protocol):
    """Plug-in notification channel.

    Implementations are plain classes constructed by their channel
    factory with the parsed :class:`NotifierConfig` from ``csfwctl.toml``.
    """

    name: str

    def supports(self, event_type: str) -> bool:
        """Return True if this notifier handles ``event_type``."""
        ...

    def send(self, event: Event) -> None:
        """Deliver ``event`` through this channel."""
        ...


# ---- Registry and factory -------------------------------------------------

NotifierFactory = Callable[[NotifierConfig], Any]

NOTIFIER_REGISTRY: dict[str, NotifierFactory] = {}
"""Map of channel name → factory callable. Insertion order preserved."""


def register_notifier(channel: str, factory: NotifierFactory) -> None:
    """Register a notifier factory for ``channel``.

    The factory is called with the channel's :class:`NotifierConfig` when
    :func:`setup_notifiers` builds the active notifier list. Call at
    import time from a plug-in module to add a new channel without
    touching this file.
    """
    NOTIFIER_REGISTRY[channel] = factory


# ---- Bus setup and dispatch -----------------------------------------------


def setup_notifiers(tool_config: ToolConfig) -> list[Notifier]:
    """Instantiate notifiers from ``csfwctl.toml`` ``[notifications.*]`` tables.

    Unknown channel names are logged at WARNING and skipped. Factory
    errors (missing required env vars, bad config) are logged at WARNING
    and skipped — a misconfigured notifier never prevents the command
    from running.
    """
    result: list[Notifier] = []
    for channel, notifier_config in tool_config.notifications.items():
        factory = NOTIFIER_REGISTRY.get(channel)
        if factory is None:
            _logger.warning("unknown notifier channel %r — skipping", channel)
            continue
        try:
            instance: Notifier = factory(notifier_config)
            result.append(instance)
        except Exception as exc:
            _logger.warning("failed to initialise notifier %r: %s", channel, exc)
    return result


def emit(event: Event, notifiers: list[Notifier]) -> None:
    """Dispatch ``event`` to every notifier whose ``supports()`` returns True.

    Individual notifier failures are logged at WARNING level and swallowed
    so that a broken channel never prevents the apply or validate from
    completing.
    """
    for notifier in notifiers:
        if not notifier.supports(event.type):
            continue
        try:
            notifier.send(event)
        except Exception as exc:
            _logger.warning(
                "notifier %r failed for event %r: %s", notifier.name, event.type, exc
            )


def event_matches(event_type: str, patterns: list[str]) -> bool:
    """Return True if ``event_type`` matches any glob pattern in ``patterns``."""
    return any(fnmatch.fnmatchcase(event_type, pat) for pat in patterns)


# ---- Built-in channel registration ----------------------------------------


def _register_builtins() -> None:
    from csfwctl.notifiers.console import ConsoleNotifier
    from csfwctl.notifiers.gitlab import GitLabNotifier
    from csfwctl.notifiers.log import LogNotifier
    from csfwctl.notifiers.syslog import SyslogNotifier
    from csfwctl.notifiers.teams import TeamsNotifier

    register_notifier("log", LogNotifier)
    register_notifier("console", ConsoleNotifier)
    register_notifier("teams", TeamsNotifier)
    register_notifier("gitlab", GitLabNotifier)
    register_notifier("syslog", SyslogNotifier)


_register_builtins()


__all__ = [
    "Event",
    "NOTIFIER_REGISTRY",
    "Notifier",
    "NotifierFactory",
    "emit",
    "event_matches",
    "make_event",
    "register_notifier",
    "setup_notifiers",
]
