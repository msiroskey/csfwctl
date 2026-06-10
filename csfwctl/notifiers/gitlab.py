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

Security
--------

The notifier intentionally restricts which env-var names it will read for
the token, project id, and MR IID; see :data:`GITLAB_TOKEN_ENV_PATTERN`
and :data:`GITLAB_CI_ENV_PATTERN`. ``api_url`` must use ``https://``.
A compromised ``csfwctl.toml`` therefore cannot point the notifier at an
arbitrary secret env var or an attacker-controlled URL without first
satisfying both checks.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from typing import Any

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig

GITLAB_TOKEN_ENV_PATTERN = re.compile(r"^(?:GITLAB|CI)_[A-Z0-9_]*TOKEN[A-Z0-9_]*$")
"""Env-var names allowed for ``token_env``. Must start with ``GITLAB_`` or
``CI_`` and contain ``TOKEN`` so a malicious config can't ask the notifier
to read an unrelated secret (e.g. ``CSFWCTL_CLIENT_SECRET`` or
``AWS_SECRET_ACCESS_KEY``)."""

GITLAB_CI_ENV_PATTERN = re.compile(r"^(?:GITLAB|CI)_[A-Z0-9_]+$")
"""Env-var names allowed for ``project_id_env`` / ``mr_iid_env``. Same
intent as :data:`GITLAB_TOKEN_ENV_PATTERN` but without the ``TOKEN``
substring requirement, since these are bookkeeping IDs."""


class GitLabNotifier:
    """Posts a Markdown comment to a GitLab merge request."""

    name = "gitlab"

    def __init__(self, config: NotifierConfig) -> None:
        """Initialise the GitLab notifier from ``config``."""
        extra = config.model_extra or {}

        token_env = str(extra.get("token_env", "GITLAB_TOKEN"))
        if not GITLAB_TOKEN_ENV_PATTERN.match(token_env):
            raise ValueError(
                f"GitLab notifier: env-var name {token_env!r} is not allowed for token_env; "
                f"name must match {GITLAB_TOKEN_ENV_PATTERN.pattern!r}"
            )
        self._token = os.environ.get(token_env, "")
        if not self._token:
            raise ValueError(f"GitLab notifier: env var {token_env!r} is not set or empty")

        project_id_env = str(extra.get("project_id_env", "CI_PROJECT_ID"))
        if not GITLAB_CI_ENV_PATTERN.match(project_id_env):
            raise ValueError(
                f"GitLab notifier: env-var name {project_id_env!r} is not allowed for "
                f"project_id_env; name must match {GITLAB_CI_ENV_PATTERN.pattern!r}"
            )
        self._project_id = str(extra.get("project_id", "")) or os.environ.get(project_id_env, "")
        if not self._project_id:
            raise ValueError(
                f"GitLab notifier: 'project_id' not configured and"
                f" env var {project_id_env!r} is not set"
            )

        mr_iid_env = str(extra.get("mr_iid_env", "CI_MERGE_REQUEST_IID"))
        if not GITLAB_CI_ENV_PATTERN.match(mr_iid_env):
            raise ValueError(
                f"GitLab notifier: env-var name {mr_iid_env!r} is not allowed for "
                f"mr_iid_env; name must match {GITLAB_CI_ENV_PATTERN.pattern!r}"
            )
        self._mr_iid = str(extra.get("mr_iid", "")) or os.environ.get(mr_iid_env, "")
        if not self._mr_iid:
            raise ValueError(
                f"GitLab notifier: 'mr_iid' not configured and env var {mr_iid_env!r} is not set"
            )

        api_url = str(extra.get("api_url", "https://gitlab.com"))
        if not api_url.startswith("https://"):
            raise ValueError(f"GitLab notifier: api_url {api_url!r} must use https://")
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
        req = urllib.request.Request(  # noqa: S310 — scheme is validated in __init__
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


MAX_DETAIL_LINES = 400
"""Cap on rendered per-object detail lines so a huge change set cannot
blow past GitLab's note size limit. Truncated output ends with a count
of how many lines were dropped."""


def _build_markdown(event: Event) -> str:
    """Build a Markdown comment body for a GitLab MR note.

    Always renders the header, summary, and metadata table. When the
    event carries diff detail in ``details`` — a multi-env diff
    (``change_sets``) or a single change set (``change_set``) — a
    per-environment summary table is rendered first, followed by a
    per-object detail log. Cross-env ripple warnings, when present, are
    surfaced as a callout above the tables.
    """
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

    detail = _render_diff_detail(event.details)
    if detail:
        lines.append("")
        lines.extend(detail)

    return "\n".join(lines)


def _render_diff_detail(details: dict[str, Any]) -> list[str]:
    """Render diff tables + per-object detail from an event's ``details``.

    Returns an empty list when ``details`` carries no recognised diff
    payload, so non-diff events (apply, validate, drift) keep their
    existing comment shape.
    """
    change_sets = _change_sets_from_details(details)
    if not change_sets:
        return []

    lines: list[str] = []

    warnings = details.get("env_drift_warnings") or []
    if warnings:
        lines.append("> ⚠️ **Cross-env ripple detected** — a downstream env has more pending")
        lines.append("> changes than test; an apply there may advance still-in-testing changes.")
        for warning in warnings:
            lines.append(f"> - {warning}")
        lines.append("")

    # Summary table — one row per environment, at the top.
    lines.append("| Env | creates | updates | deletes | no-change | unmanaged |")
    lines.append("| --- | ------- | ------- | ------- | --------- | --------- |")
    for env, cs in change_sets.items():
        summary = cs.get("summary", {})
        lines.append(
            f"| `{env}` | {summary.get('creates', 0)} | {summary.get('updates', 0)} "
            f"| {summary.get('deletes', 0)} | {summary.get('no_changes', 0)} "
            f"| {summary.get('unmanaged', 0)} |"
        )
    lines.append("")

    # Per-object detail log below the table.
    detail: list[str] = []
    for env, cs in change_sets.items():
        env_detail = _render_change_set_detail(cs)
        if not env_detail:
            continue
        detail.append(f"#### {env}")
        detail.extend(env_detail)
        detail.append("")

    if len(detail) > MAX_DETAIL_LINES:
        dropped = len(detail) - MAX_DETAIL_LINES
        detail = detail[:MAX_DETAIL_LINES]
        detail.append(f"_… {dropped} more line(s) truncated; see the pipeline for the full diff._")

    lines.extend(detail)
    return lines


def _change_sets_from_details(details: dict[str, Any]) -> dict[str, Any]:
    """Normalise ``details`` into an ordered ``{env: change_set_json}`` map.

    Accepts the multi-env shape (``change_sets``) and the single-env shape
    (``change_set``). Returns ``{}`` for anything else.
    """
    multi = details.get("change_sets")
    if isinstance(multi, dict) and multi:
        return multi
    single = details.get("change_set")
    if isinstance(single, dict) and single:
        return {str(single.get("env", "—")): single}
    return {}


def _render_change_set_detail(cs: dict[str, Any]) -> list[str]:
    """Render the create/update/delete object detail for one change set."""
    lines: list[str] = []
    for section in ("creates", "updates", "deletes"):
        items = cs.get(section) or []
        if not items:
            continue
        lines.append(f"**{section}** ({len(items)})")
        for obj in items:
            line = f"- `{obj.get('op', '?')}` {obj.get('kind', '?')} **{obj.get('display_name', '?')}**"
            if obj.get("reason"):
                line += f" — {obj['reason']}"
            lines.append(line)
            for fc in obj.get("field_changes", []):
                lines.append(f"    - `{fc['path']}`: `{fc['before']}` → `{fc['after']}`")
            for hg in obj.get("host_group_changes", []):
                lines.append(f"    - host group {hg['op']}: `{hg['group_name']}`")
    return lines
