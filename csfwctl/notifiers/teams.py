"""Microsoft Teams incoming-webhook notifier (MessageCard format).

Posts a MessageCard to a Teams incoming-webhook URL. The webhook URL is
read from an environment variable rather than stored in ``csfwctl.toml``
so it never appears in the config repo.

Config table (``csfwctl.toml``):

.. code-block:: toml

    [notifications.teams]
    url_env = "TEAMS_WEBHOOK_URL"   # env var that holds the webhook URL
    events  = ["apply.failed", "drift.detected"]
"""

from __future__ import annotations

import json
import os
import urllib.request

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig

_THEME_COLORS: dict[str, str] = {
    "error": "FF0000",
    "warn": "FFA500",
    "info": "0078D4",
}


class TeamsNotifier:
    """Posts a MessageCard to a Microsoft Teams incoming webhook."""

    name = "teams"

    def __init__(self, config: NotifierConfig) -> None:
        """Initialise the Teams notifier from ``config``."""
        extra = config.model_extra or {}
        url_env = str(extra.get("url_env", "TEAMS_WEBHOOK_URL"))
        url = os.environ.get(url_env)
        if not url:
            raise ValueError(f"Teams notifier: env var {url_env!r} is not set or empty")
        self._url = url
        self._patterns: list[str] = config.events if config.events else ["*"]

    def supports(self, event_type: str) -> bool:
        """Return True if ``event_type`` matches any configured pattern."""
        return event_matches(event_type, self._patterns)

    def send(self, event: Event) -> None:
        """POST a MessageCard to the Teams webhook URL."""
        color = _THEME_COLORS.get(event.severity, "0078D4")
        card = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "themeColor": color,
            "summary": event.summary,
            "sections": [
                {
                    "activityTitle": f"csfwctl — {event.type}",
                    "facts": [
                        {"name": "Summary", "value": event.summary},
                        {"name": "Environment", "value": event.env or "—"},
                        {"name": "Git SHA", "value": event.git_sha or "—"},
                        {"name": "Severity", "value": event.severity},
                        {"name": "Request ID", "value": event.request_id},
                        {"name": "Timestamp", "value": event.timestamp.isoformat()},
                    ],
                }
            ],
        }
        body = json.dumps(card).encode()
        req = urllib.request.Request(  # noqa: S310
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as _resp:  # noqa: S310
            pass
