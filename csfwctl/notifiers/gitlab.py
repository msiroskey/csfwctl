"""GitLab MR-comment notifier.

Posts a Markdown comment to a GitLab merge request. Designed for use in
GitLab CI pipelines where the project ID and MR IID are available as
built-in CI variables.

Config table (``csfwctl.toml``):

.. code-block:: toml

    [notifications.gitlab]
    token_env      = "GITLAB_TOKEN"          # env var holding the API token
    project_id_env = "CI_PROJECT_ID"         # env var or use project_id = "123"
    mr_iid_env     = "CI_MERGE_REQUEST_IID"  # env var or use mr_iid = "42"
    api_url        = "https://gitlab.com"    # optional; default gitlab.com
    events         = ["diff.changes_detected", "validate.failed"]
"""

from __future__ import annotations

import json
import os
import urllib.request

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig


class GitLabNotifier:
    """Posts a Markdown comment to a GitLab merge request."""

    name = "gitlab"

    def __init__(self, config: NotifierConfig) -> None:
        """Initialise the GitLab notifier from ``config``."""
        extra = config.model_extra or {}

        token_env = str(extra.get("token_env", "GITLAB_TOKEN"))
        self._token = os.environ.get(token_env, "")
        if not self._token:
            raise ValueError(f"GitLab notifier: env var {token_env!r} is not set or empty")

        project_id_env = str(extra.get("project_id_env", "CI_PROJECT_ID"))
        self._project_id = str(extra.get("project_id", "")) or os.environ.get(project_id_env, "")
        if not self._project_id:
            raise ValueError(
                f"GitLab notifier: 'project_id' not configured and"
                f" env var {project_id_env!r} is not set"
            )

        mr_iid_env = str(extra.get("mr_iid_env", "CI_MERGE_REQUEST_IID"))
        self._mr_iid = str(extra.get("mr_iid", "")) or os.environ.get(mr_iid_env, "")
        if not self._mr_iid:
            raise ValueError(
                f"GitLab notifier: 'mr_iid' not configured and env var {mr_iid_env!r} is not set"
            )

        api_url = str(extra.get("api_url", "https://gitlab.com"))
        self._api_url = api_url.rstrip("/")
        self._patterns: list[str] = config.events if config.events else ["*"]

    def supports(self, event_type: str) -> bool:
        """Return True if ``event_type`` matches any configured pattern."""
        return event_matches(event_type, self._patterns)

    def send(self, event: Event) -> None:
        """POST a Markdown comment to the configured MR."""
        body_text = _build_markdown(event)
        url = (
            f"{self._api_url}/api/v4/projects/{self._project_id}"
            f"/merge_requests/{self._mr_iid}/notes"
        )
        payload = json.dumps({"body": body_text}).encode()
        req = urllib.request.Request(  # noqa: S310
            url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "PRIVATE-TOKEN": self._token,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as _resp:  # noqa: S310
            pass


def _build_markdown(event: Event) -> str:
    """Build a Markdown comment body for a GitLab MR note."""
    icon = {"error": "🔴", "warn": "🟡", "info": "🔵"}.get(event.severity, "⚪")
    lines = [
        f"{icon} **csfwctl {event.type}**",
        "",
        event.summary,
        "",
        "| Field | Value |",
        "| ----- | ----- |",
        f"| Environment | `{event.env or '—'}` |",
        f"| Git SHA | `{event.git_sha or '—'}` |",
        f"| Severity | `{event.severity}` |",
        f"| Request ID | `{event.request_id}` |",
        f"| Timestamp | `{event.timestamp.isoformat()}` |",
    ]
    return "\n".join(lines)
