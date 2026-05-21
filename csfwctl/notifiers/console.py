"""Rich console notifier.

Prints a one-line event summary to stderr. Suppressed in CI environments
(``CI`` env var is set) so pipeline logs stay clean.
"""

from __future__ import annotations

import os

from rich.console import Console

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig

_SEVERITY_STYLE: dict[str, str] = {
    "error": "bold red",
    "warn": "yellow",
    "info": "cyan",
}


class ConsoleNotifier:
    """Writes a Rich-formatted event line to stderr; silenced in CI."""

    name = "console"

    def __init__(self, config: NotifierConfig) -> None:
        """Initialise the console notifier from ``config``."""
        self._patterns: list[str] = config.events if config.events else ["*"]
        self._console = Console(stderr=True)

    def supports(self, event_type: str) -> bool:
        """Return False when running under CI (``CI`` env var is set)."""
        if os.environ.get("CI"):
            return False
        return event_matches(event_type, self._patterns)

    def send(self, event: Event) -> None:
        """Print a one-line severity-coloured event summary to stderr."""
        style = _SEVERITY_STYLE.get(event.severity, "white")
        self._console.print(f"[{style}][csfwctl] {event.type}[/{style}]: {event.summary}")
