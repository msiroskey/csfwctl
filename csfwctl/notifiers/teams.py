"""Microsoft Teams incoming-webhook notifier (MessageCard format).

Posts a MessageCard to a Teams incoming-webhook URL. The webhook URL is
read from an environment variable rather than stored in ``csfwctl.toml``
so it never appears in the config repo.

Config table (``csfwctl.toml``):

.. code-block:: toml

    [notifications.teams]
    url_env = "TEAMS_WEBHOOK_URL"   # env var that holds the webhook URL
    events  = ["apply.failed", "drift.detected"]

Security
--------

The notifier intentionally restricts which environment variables it will
read and which URL schemes it will POST to. See
:data:`TEAMS_URL_ENV_PATTERN` for the env-var-name allowlist and
:func:`_check_url_scheme` for the URL constraint. A compromised
``csfwctl.toml`` therefore cannot redirect this notifier at an arbitrary
secret env var or an attacker-controlled endpoint without first satisfying
both checks.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig

TEAMS_URL_ENV_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*(?:TEAMS|WEBHOOK)[A-Z0-9_]*$")
"""Env-var names this notifier will read. Must contain ``TEAMS`` or
``WEBHOOK`` so a malicious config can't ask the notifier to fetch an
unrelated secret (e.g. ``CSFWCTL_CLIENT_SECRET``)."""

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
        if not TEAMS_URL_ENV_PATTERN.match(url_env):
            raise ValueError(
                f"Teams notifier: env-var name {url_env!r} is not allowed; "
                f"name must match {TEAMS_URL_ENV_PATTERN.pattern!r}"
            )
        url = os.environ.get(url_env)
        if not url:
            raise ValueError(f"Teams notifier: env var {url_env!r} is not set or empty")
        _check_url_scheme(url, source=f"${url_env}")
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
        req = urllib.request.Request(  # noqa: S310 — scheme is validated above
            self._url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as _resp:  # noqa: S310
            pass


def _check_url_scheme(url: str, *, source: str) -> None:
    """Require ``url`` to be HTTPS so the webhook body isn't sent cleartext."""
    if not url.startswith("https://"):
        raise ValueError(f"Teams notifier: URL from {source} must use https:// (got {url!r})")
