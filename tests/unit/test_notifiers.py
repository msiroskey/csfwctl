"""Tests for the Phase 8 notifier system."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from csfwctl.notifiers import (
    NOTIFIER_REGISTRY,
    Event,
    Notifier,
    emit,
    event_matches,
    make_event,
    register_notifier,
    setup_notifiers,
)
from csfwctl.notifiers.console import ConsoleNotifier
from csfwctl.notifiers.gitlab import GitLabNotifier, _build_markdown
from csfwctl.notifiers.log import LogNotifier
from csfwctl.notifiers.syslog import SyslogNotifier
from csfwctl.notifiers.teams import TeamsNotifier
from csfwctl.schema.tool_config import NotifierConfig, ToolConfig

# ---- helpers ---------------------------------------------------------------


def _make_tool_config(**channels: dict[str, Any]) -> ToolConfig:
    """Build a ToolConfig with the given notification channel dicts."""
    notifs = {ch: NotifierConfig(**cfg) for ch, cfg in channels.items()}
    return ToolConfig(notifications=notifs)


def _sample_event(**kwargs: Any) -> Event:
    base: dict[str, Any] = {
        "type": "apply.succeeded",
        "severity": "info",
        "timestamp": datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC),
        "env": "test",
        "git_sha": "abc1234",
        "summary": "Apply succeeded",
        "details": {"report": {}},
        "request_id": "req_aabbccdd",
    }
    base.update(kwargs)
    return Event(**base)


# ---- Event -----------------------------------------------------------------


def test_event_to_json() -> None:
    ts = datetime(2026, 5, 21, 12, 0, 0, tzinfo=UTC)
    ev = Event(
        type="apply.succeeded",
        severity="info",
        timestamp=ts,
        env="test",
        git_sha="abc123",
        summary="Done",
        details={"x": 1},
        request_id="req_abc",
    )
    payload = ev.to_json()
    assert payload["type"] == "apply.succeeded"
    assert payload["severity"] == "info"
    assert payload["env"] == "test"
    assert payload["git_sha"] == "abc123"
    assert payload["summary"] == "Done"
    assert payload["details"] == {"x": 1}
    assert payload["request_id"] == "req_abc"
    assert "2026-05-21" in payload["timestamp"]


def test_make_event_defaults() -> None:
    ev = make_event("apply.failed", summary="boom")
    assert ev.type == "apply.failed"
    assert ev.severity == "info"
    assert ev.env is None
    assert ev.git_sha is None
    assert ev.details == {}
    assert ev.timestamp.tzinfo is not None


def test_make_event_with_all_fields() -> None:
    ev = make_event(
        "apply.succeeded",
        severity="error",
        env="production",
        git_sha="deadbeef",
        summary="ok",
        details={"k": "v"},
    )
    assert ev.severity == "error"
    assert ev.env == "production"
    assert ev.git_sha == "deadbeef"
    assert ev.details == {"k": "v"}


# ---- event_matches --------------------------------------------------------


def test_event_matches_exact() -> None:
    assert event_matches("apply.succeeded", ["apply.succeeded"])


def test_event_matches_wildcard_all() -> None:
    assert event_matches("apply.succeeded", ["*"])


def test_event_matches_glob_prefix() -> None:
    assert event_matches("apply.failed", ["apply.*"])
    assert not event_matches("diff.changes_detected", ["apply.*"])


def test_event_matches_no_match() -> None:
    assert not event_matches("validate.failed", ["apply.*", "drift.*"])


def test_event_matches_multiple_patterns() -> None:
    assert event_matches("drift.detected", ["apply.*", "drift.*"])


# ---- Notifier protocol ----------------------------------------------------


def test_log_notifier_satisfies_protocol(tmp_path: Path) -> None:
    cfg = NotifierConfig(events=["*"], **{"path": str(tmp_path / "ev.jsonl")})
    n = LogNotifier(cfg)
    assert isinstance(n, Notifier)


# ---- Registry and setup ---------------------------------------------------


def test_register_notifier_adds_to_registry() -> None:
    original = dict(NOTIFIER_REGISTRY)
    try:
        sentinel_factory = lambda cfg: None  # noqa: E731
        register_notifier("_test_channel", sentinel_factory)
        assert NOTIFIER_REGISTRY["_test_channel"] is sentinel_factory
    finally:
        NOTIFIER_REGISTRY.pop("_test_channel", None)
        # Restore any keys we might have disturbed
        for k in list(NOTIFIER_REGISTRY):
            if k not in original:
                NOTIFIER_REGISTRY.pop(k)


def test_setup_notifiers_unknown_channel_skipped() -> None:
    tc = _make_tool_config(nonexistent={"events": ["*"]})
    # Should not raise; unknown channel is silently skipped
    notifiers = setup_notifiers(tc)
    assert all(n.name != "nonexistent" for n in notifiers)


def test_setup_notifiers_factory_error_skipped(tmp_path: Path) -> None:
    # Teams notifier will fail (url env var unset) — should be skipped
    tc = _make_tool_config(teams={"url_env": "DOES_NOT_EXIST_12345", "events": ["*"]})
    notifiers = setup_notifiers(tc)
    assert not any(n.name == "teams" for n in notifiers)


def test_setup_notifiers_empty_config() -> None:
    tc = ToolConfig()
    assert setup_notifiers(tc) == []


def test_setup_notifiers_log_channel(tmp_path: Path) -> None:
    tc = _make_tool_config(log={"path": str(tmp_path / "ev.jsonl"), "events": ["*"]})
    notifiers = setup_notifiers(tc)
    assert len(notifiers) == 1
    assert notifiers[0].name == "log"


# ---- emit -----------------------------------------------------------------


class _SpyNotifier:
    name = "spy"
    received: list[Event]

    def __init__(self, patterns: list[str]) -> None:
        self._patterns = patterns
        self.received = []

    def supports(self, event_type: str) -> bool:
        """Return True if event_type matches any pattern."""
        return event_matches(event_type, self._patterns)

    def send(self, event: Event) -> None:
        """Capture the event."""
        self.received.append(event)


class _FailingNotifier:
    name = "failing"

    def supports(self, event_type: str) -> bool:  # noqa: ARG002
        """Always returns True."""
        return True

    def send(self, event: Event) -> None:
        """Always raises."""
        raise RuntimeError("deliberate failure")


def test_emit_dispatches_to_matching() -> None:
    spy = _SpyNotifier(["apply.*"])
    ev = _sample_event(type="apply.succeeded")
    emit(ev, [spy])
    assert len(spy.received) == 1


def test_emit_skips_non_matching() -> None:
    spy = _SpyNotifier(["drift.*"])
    ev = _sample_event(type="apply.succeeded")
    emit(ev, [spy])
    assert spy.received == []


def test_emit_swallows_notifier_failure() -> None:
    failing = _FailingNotifier()
    ev = _sample_event()
    # Must not raise
    emit(ev, [failing])


def test_emit_continues_after_failure() -> None:
    spy = _SpyNotifier(["*"])
    failing = _FailingNotifier()
    ev = _sample_event()
    emit(ev, [failing, spy])
    assert len(spy.received) == 1


def test_emit_empty_notifiers() -> None:
    ev = _sample_event()
    emit(ev, [])  # must not raise


# ---- LogNotifier ----------------------------------------------------------


def test_log_notifier_writes_json_line(tmp_path: Path) -> None:
    log_path = tmp_path / "events.jsonl"
    cfg = NotifierConfig(events=["*"], **{"path": str(log_path)})
    n = LogNotifier(cfg)
    ev = _sample_event(type="apply.succeeded", summary="OK")
    n.send(ev)
    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["type"] == "apply.succeeded"
    assert payload["summary"] == "OK"


def test_log_notifier_appends_multiple(tmp_path: Path) -> None:
    log_path = tmp_path / "events.jsonl"
    cfg = NotifierConfig(events=["*"], **{"path": str(log_path)})
    n = LogNotifier(cfg)
    n.send(_sample_event(type="apply.started"))
    n.send(_sample_event(type="apply.succeeded"))
    lines = log_path.read_text().strip().split("\n")
    assert len(lines) == 2


def test_log_notifier_creates_parent_dirs(tmp_path: Path) -> None:
    log_path = tmp_path / "deep" / "dir" / "events.jsonl"
    cfg = NotifierConfig(events=["*"], **{"path": str(log_path)})
    n = LogNotifier(cfg)
    n.send(_sample_event())
    assert log_path.exists()


def test_log_notifier_supports_glob() -> None:
    cfg = NotifierConfig(events=["apply.*"], **{"path": "/tmp/x.jsonl"})
    n = LogNotifier(cfg)
    assert n.supports("apply.succeeded")
    assert not n.supports("validate.failed")


def test_log_notifier_missing_path_raises() -> None:
    cfg = NotifierConfig(events=["*"])
    with pytest.raises(ValueError, match="path"):
        LogNotifier(cfg)


# ---- ConsoleNotifier ------------------------------------------------------


def test_console_notifier_suppressed_in_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI", "true")
    cfg = NotifierConfig(events=["*"])
    n = ConsoleNotifier(cfg)
    assert not n.supports("apply.succeeded")


def test_console_notifier_active_outside_ci(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    cfg = NotifierConfig(events=["*"])
    n = ConsoleNotifier(cfg)
    assert n.supports("apply.succeeded")


def test_console_notifier_send(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("CI", raising=False)
    cfg = NotifierConfig(events=["*"])
    n = ConsoleNotifier(cfg)
    ev = _sample_event(type="apply.succeeded", summary="it worked")
    # send() must not raise
    n.send(ev)


# ---- TeamsNotifier --------------------------------------------------------


def test_teams_notifier_missing_url_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEAMS_WEBHOOK_URL", raising=False)
    cfg = NotifierConfig(events=["*"], **{"url_env": "TEAMS_WEBHOOK_URL"})
    with pytest.raises(ValueError, match="TEAMS_WEBHOOK_URL"):
        TeamsNotifier(cfg)


def test_teams_notifier_rejects_disallowed_env_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """A malicious config can't ask the notifier to read an unrelated secret."""
    monkeypatch.setenv("CSFWCTL_CLIENT_SECRET", "super-secret")
    cfg = NotifierConfig(events=["*"], **{"url_env": "CSFWCTL_CLIENT_SECRET"})
    with pytest.raises(ValueError, match="not allowed"):
        TeamsNotifier(cfg)


def test_teams_notifier_rejects_http_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "http://teams.example.com/hook")
    cfg = NotifierConfig(events=["*"], **{"url_env": "TEAMS_WEBHOOK_URL"})
    with pytest.raises(ValueError, match="https://"):
        TeamsNotifier(cfg)


def test_teams_notifier_sends_message_card(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MY_TEAMS_URL", "https://teams.example.com/webhook")
    cfg = NotifierConfig(events=["*"], **{"url_env": "MY_TEAMS_URL"})
    n = TeamsNotifier(cfg)

    captured: list[Any] = []

    class _FakeResponse:
        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    def _fake_urlopen(req: Any, timeout: int = 10) -> _FakeResponse:
        captured.append(req)
        return _FakeResponse()

    with patch("csfwctl.notifiers.teams.urllib.request.urlopen", _fake_urlopen):
        n.send(_sample_event(type="apply.failed", summary="boom"))

    assert len(captured) == 1
    req = captured[0]
    body = json.loads(req.data)
    assert body["@type"] == "MessageCard"
    assert "apply.failed" in body["sections"][0]["activityTitle"]


def test_teams_notifier_supports_glob(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEAMS_WEBHOOK_URL", "https://example.com/hook")
    cfg = NotifierConfig(events=["apply.*"], **{"url_env": "TEAMS_WEBHOOK_URL"})
    n = TeamsNotifier(cfg)
    assert n.supports("apply.failed")
    assert not n.supports("drift.detected")


# ---- GitLabNotifier -------------------------------------------------------


def _gitlab_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "glpat-test123")
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")


def _make_gitlab_notifier(monkeypatch: pytest.MonkeyPatch) -> GitLabNotifier:
    _gitlab_env(monkeypatch)
    cfg = NotifierConfig(events=["*"])
    return GitLabNotifier(cfg)


def test_gitlab_notifier_missing_token_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")
    cfg = NotifierConfig(events=["*"])
    with pytest.raises(ValueError, match="GITLAB_TOKEN"):
        GitLabNotifier(cfg)


def test_gitlab_notifier_missing_project_id_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITLAB_TOKEN", "tok")
    monkeypatch.delenv("CI_PROJECT_ID", raising=False)
    monkeypatch.delenv("CI_MERGE_REQUEST_IID", raising=False)
    cfg = NotifierConfig(events=["*"])
    with pytest.raises(ValueError, match="project_id"):
        GitLabNotifier(cfg)


def test_gitlab_notifier_sends_mr_comment(monkeypatch: pytest.MonkeyPatch) -> None:
    n = _make_gitlab_notifier(monkeypatch)
    captured: list[Any] = []

    class _FakeResp:
        def __enter__(self) -> _FakeResp:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

    def _fake_urlopen(req: Any, timeout: int = 10) -> _FakeResp:
        captured.append(req)
        return _FakeResp()

    with patch("csfwctl.notifiers.gitlab.urllib.request.urlopen", _fake_urlopen):
        n.send(_sample_event(type="apply.failed", summary="failed"))

    assert len(captured) == 1
    req = captured[0]
    assert "/merge_requests/7/notes" in req.full_url
    body = json.loads(req.data)
    assert "apply.failed" in body["body"]


def test_build_markdown_contains_event_fields() -> None:
    ev = _sample_event(type="apply.failed", severity="error", env="production")
    md = _build_markdown(ev)
    assert "apply.failed" in md
    assert "production" in md
    assert "🔴" in md


def test_gitlab_notifier_supports_glob(monkeypatch: pytest.MonkeyPatch) -> None:
    _gitlab_env(monkeypatch)
    cfg = NotifierConfig(events=["diff.*"], **{})
    n = GitLabNotifier(cfg)
    assert n.supports("diff.changes_detected")
    assert not n.supports("apply.started")


def test_gitlab_notifier_rejects_disallowed_token_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """A malicious config can't ask for ``CSFWCTL_CLIENT_SECRET`` etc."""
    monkeypatch.setenv("CSFWCTL_CLIENT_SECRET", "super-secret")
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")
    cfg = NotifierConfig(events=["*"], **{"token_env": "CSFWCTL_CLIENT_SECRET"})
    with pytest.raises(ValueError, match="not allowed"):
        GitLabNotifier(cfg)


def test_gitlab_notifier_rejects_disallowed_project_id_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _gitlab_env(monkeypatch)
    monkeypatch.setenv("AWS_ACCOUNT_ID", "123456789012")
    cfg = NotifierConfig(events=["*"], **{"project_id_env": "AWS_ACCOUNT_ID"})
    with pytest.raises(ValueError, match="not allowed"):
        GitLabNotifier(cfg)


def test_gitlab_notifier_rejects_http_api_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _gitlab_env(monkeypatch)
    cfg = NotifierConfig(events=["*"], **{"api_url": "http://gitlab.example.com"})
    with pytest.raises(ValueError, match="https://"):
        GitLabNotifier(cfg)


# ---- SyslogNotifier -------------------------------------------------------


def test_syslog_notifier_missing_host_raises() -> None:
    cfg = NotifierConfig(events=["*"], **{"facility": "local3"})
    with pytest.raises(ValueError, match="host"):
        SyslogNotifier(cfg)


def test_syslog_notifier_bad_facility_raises() -> None:
    cfg = NotifierConfig(events=["*"], **{"host": "syslog.example.com", "facility": "bogus"})
    with pytest.raises(ValueError, match="bogus"):
        SyslogNotifier(cfg)


def test_syslog_notifier_sends_udp_datagram() -> None:
    cfg = NotifierConfig(
        events=["*"],
        **{"host": "127.0.0.1", "port": 5514, "facility": "local3"},
    )
    n = SyslogNotifier(cfg)
    ev = _sample_event(type="apply.succeeded", summary="ok")

    sent: list[bytes] = []

    class _FakeSock:
        def __enter__(self) -> _FakeSock:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
            sent.append(data)

    with patch("csfwctl.notifiers.syslog.socket.socket", return_value=_FakeSock()):
        n.send(ev)

    assert len(sent) == 1
    frame = sent[0].decode()
    # Priority: local3 facility=19, info severity=6 → 19*8+6=158
    assert frame.startswith("<158>1 ")
    assert "apply.succeeded" in frame
    assert "ok" in frame


def test_syslog_notifier_supports_glob() -> None:
    cfg = NotifierConfig(
        events=["apply.*"],
        **{"host": "s.example.com", "port": 514, "facility": "local0"},
    )
    n = SyslogNotifier(cfg)
    assert n.supports("apply.failed")
    assert not n.supports("validate.failed")


# ---- notify-test command --------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def minimal_repo(tmp_path: Path) -> Path:
    """Minimal valid config repo with no notifiers configured."""
    root = tmp_path / "repo"
    (root / "policies").mkdir(parents=True)
    (root / "rule_groups").mkdir()
    (root / "locations").mkdir()
    _write(root / "tombstones.yaml", "policies: []\nrule_groups: []\nlocations: []\n")
    _write(root / "precedence.yaml", "overrides: []\n")
    return root


def test_notify_test_no_notifiers(minimal_repo: Path) -> None:
    from typer.testing import CliRunner

    from csfwctl.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["notify-test", "--repo", str(minimal_repo)])
    assert result.exit_code == 0
    assert "no notifiers" in result.output.lower()


def test_notify_test_unknown_channel(minimal_repo: Path) -> None:
    from typer.testing import CliRunner

    from csfwctl.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["notify-test", "--channel", "bogus", "--repo", str(minimal_repo)])
    assert result.exit_code == 1


def test_notify_test_log_channel(minimal_repo: Path, tmp_path: Path) -> None:
    log_path = tmp_path / "test_events.jsonl"
    # Write csfwctl.toml with log notifier
    _write(
        minimal_repo / "csfwctl.toml",
        f'[notifications.log]\npath = "{log_path}"\nevents = ["*"]\n',
    )
    from typer.testing import CliRunner

    from csfwctl.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["notify-test", "--repo", str(minimal_repo)])
    assert result.exit_code == 0
    assert log_path.exists()
    payload = json.loads(log_path.read_text().strip())
    assert payload["type"] == "notify.test"
