"""Log (JSON Lines) notifier.

Appends one JSON object per event to a file. Suitable as an audit trail
and the lowest-overhead channel to configure. All events are written
regardless of CI detection.
"""

from __future__ import annotations

import json
from pathlib import Path

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig


class LogNotifier:
    """Appends one JSON line per event to a configurable file path."""

    name = "log"

    def __init__(self, config: NotifierConfig) -> None:
        """Initialise the log notifier from ``config``."""
        extra = config.model_extra or {}
        path_str = extra.get("path")
        if not path_str:
            raise ValueError("log notifier requires 'path' in [notifications.log]")
        self._path = Path(str(path_str))
        self._patterns: list[str] = config.events if config.events else ["*"]

    def supports(self, event_type: str) -> bool:
        """Return True if ``event_type`` matches any configured pattern."""
        return event_matches(event_type, self._patterns)

    def send(self, event: Event) -> None:
        """Append one JSON line to the log file, creating parent dirs as needed."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(event.to_json(), default=str) + "\n"
        with self._path.open("a", encoding="utf-8") as fp:
            fp.write(line)
