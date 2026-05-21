"""Tests for the ``csfwctl drift-check`` CLI command body (Phase 9).

The diff engine is covered in ``test_differ.py``; the diff CLI plumbing
in ``test_diff_cmd.py``. This file pins down the drift-check-specific
behaviour: state persistence across runs, the detected/cleared
transitions, the emitted notifier events, and the ``--fail-on-drift``
exit code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from csfwctl.cli import app
from csfwctl.differ import LiveState
from csfwctl.drift_cmd import (
    DRIFT_EXIT_CODE,
    DriftState,
    change_set_summary,
    default_state_path,
    has_drift,
    load_drift_state,
    run_drift_check,
    save_drift_state,
)
from csfwctl.loader import LoadError
from csfwctl.notifiers import Event


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def empty_repo(tmp_path: Path) -> Path:
    """An empty (no policies/rule_groups/locations) repo path."""
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


@pytest.fixture
def captured_events(monkeypatch: pytest.MonkeyPatch) -> list[Event]:
    """Replace :func:`csfwctl.drift_cmd.emit` with a recorder.

    The drift-check command imports ``emit`` from
    :mod:`csfwctl.notifiers` at module-load time, so the monkeypatch
    must target the binding inside ``drift_cmd``.
    """
    events: list[Event] = []

    def fake_emit(event: Event, notifiers: Any) -> None:
        events.append(event)

    monkeypatch.setattr("csfwctl.drift_cmd.emit", fake_emit)
    return events


# ---- DriftState round-trip ------------------------------------------------


def test_drift_state_json_round_trip() -> None:
    state = DriftState(
        env="production",
        has_drift=True,
        last_run="2026-05-21T00:00:00+00:00",
        summary={"creates": 1, "updates": 2, "deletes": 0, "unmanaged": 0},
    )
    payload = state.to_json()
    restored = DriftState.from_json(payload)
    assert restored == state


def test_save_and_load_drift_state_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "drift.json"
    state = DriftState(
        env="test",
        has_drift=False,
        last_run="2026-05-21T00:00:00+00:00",
        summary={"creates": 0, "updates": 0, "deletes": 0, "unmanaged": 0},
    )
    save_drift_state(path, state)
    assert path.is_file()
    assert load_drift_state(path) == state


def test_load_drift_state_missing_file_returns_none(tmp_path: Path) -> None:
    assert load_drift_state(tmp_path / "nope.json") is None


def test_load_drift_state_malformed_file_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "garbage.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert load_drift_state(path) is None


def test_load_drift_state_wrong_shape_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"unrelated": 1}), encoding="utf-8")
    assert load_drift_state(path) is None


def test_default_state_path_uses_csfwctl_dir(tmp_path: Path) -> None:
    p = default_state_path(tmp_path, "production")
    assert p == tmp_path / ".csfwctl" / "drift-state-production.json"


# ---- summary helpers ------------------------------------------------------


def test_change_set_summary_and_has_drift_on_empty_repo(empty_repo: Path) -> None:
    """An empty repo against empty live state has no drift."""
    from csfwctl.differ import compute_diff
    from csfwctl.loader import load_config_repo

    cs = compute_diff(load_config_repo(empty_repo), "test", LiveState())
    assert has_drift(cs) is False
    assert change_set_summary(cs) == {
        "creates": 0,
        "updates": 0,
        "deletes": 0,
        "unmanaged": 0,
    }


def test_change_set_summary_counts_realistic_creates(
    realistic_repo_path: Path,
) -> None:
    """The realistic repo against empty live state queues several creates."""
    from csfwctl.differ import compute_diff
    from csfwctl.loader import load_config_repo

    cs = compute_diff(load_config_repo(realistic_repo_path), "test", LiveState())
    summary = change_set_summary(cs)
    assert summary["creates"] > 0
    assert has_drift(cs) is True


# ---- run_drift_check happy paths ------------------------------------------


def test_drift_check_first_run_no_drift_emits_nothing(
    empty_repo: Path, captured_events: list[Event]
) -> None:
    """First run with no prior state and no drift: no events, state written."""
    try:
        run_drift_check(
            "test",
            repo=empty_repo,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0
    assert captured_events == []
    state_path = default_state_path(empty_repo, "test")
    assert state_path.is_file()
    loaded = load_drift_state(state_path)
    assert loaded is not None and loaded.has_drift is False


def test_drift_check_first_run_with_drift_emits_detected(
    realistic_repo_path: Path,
    captured_events: list[Event],
    tmp_path: Path,
) -> None:
    """Drift on first run emits drift.detected with a per-env summary."""
    state_file = tmp_path / "state.json"
    try:
        run_drift_check(
            "test",
            repo=realistic_repo_path,
            state_file=state_file,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    assert len(captured_events) == 1
    event = captured_events[0]
    assert event.type == "drift.detected"
    assert event.severity == "warn"
    assert event.env == "test"
    assert event.details["env"] == "test"
    assert event.details["summary"]["creates"] > 0
    assert "change_set" in event.details

    loaded = load_drift_state(state_file)
    assert loaded is not None and loaded.has_drift is True


def test_drift_check_transition_to_cleared_emits_cleared(
    empty_repo: Path,
    captured_events: list[Event],
    tmp_path: Path,
) -> None:
    """A prior drifted state plus a clean run emits drift.cleared once."""
    state_file = tmp_path / "state.json"
    save_drift_state(
        state_file,
        DriftState(
            env="production",
            has_drift=True,
            last_run="2026-05-20T00:00:00+00:00",
            summary={"creates": 2, "updates": 1, "deletes": 0, "unmanaged": 0},
        ),
    )

    try:
        run_drift_check(
            "production",
            repo=empty_repo,
            state_file=state_file,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    assert len(captured_events) == 1
    event = captured_events[0]
    assert event.type == "drift.cleared"
    assert event.severity == "info"
    assert event.env == "production"
    assert event.details["previous_summary"]["creates"] == 2
    assert event.details["previous_run"] == "2026-05-20T00:00:00+00:00"

    loaded = load_drift_state(state_file)
    assert loaded is not None and loaded.has_drift is False


def test_drift_check_stable_no_drift_emits_nothing(
    empty_repo: Path, captured_events: list[Event], tmp_path: Path
) -> None:
    """Two consecutive clean runs: only the first writes state; no events."""
    state_file = tmp_path / "state.json"
    save_drift_state(
        state_file,
        DriftState(
            env="test",
            has_drift=False,
            last_run="2026-05-20T00:00:00+00:00",
            summary={"creates": 0, "updates": 0, "deletes": 0, "unmanaged": 0},
        ),
    )

    try:
        run_drift_check(
            "test",
            repo=empty_repo,
            state_file=state_file,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0
    assert captured_events == []


def test_drift_check_repeat_drift_still_emits_detected(
    realistic_repo_path: Path, captured_events: list[Event], tmp_path: Path
) -> None:
    """Repeated drift still emits drift.detected (Phase 10 will dedupe)."""
    state_file = tmp_path / "state.json"
    save_drift_state(
        state_file,
        DriftState(
            env="test",
            has_drift=True,
            last_run="2026-05-20T00:00:00+00:00",
            summary={"creates": 5, "updates": 0, "deletes": 0, "unmanaged": 0},
        ),
    )

    try:
        run_drift_check(
            "test",
            repo=realistic_repo_path,
            state_file=state_file,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    assert len(captured_events) == 1
    assert captured_events[0].type == "drift.detected"


# ---- --no-state and --fail-on-drift ---------------------------------------


def test_drift_check_no_state_skips_persistence(
    empty_repo: Path, captured_events: list[Event]
) -> None:
    """``--no-state`` writes no file even when drift exists."""
    try:
        run_drift_check(
            "test",
            repo=empty_repo,
            no_state=True,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0
    assert not default_state_path(empty_repo, "test").exists()
    assert captured_events == []


def test_drift_check_no_state_never_emits_cleared(
    empty_repo: Path, captured_events: list[Event], tmp_path: Path
) -> None:
    """With ``--no-state`` a prior state file is ignored."""
    state_file = tmp_path / "state.json"
    save_drift_state(
        state_file,
        DriftState(
            env="test",
            has_drift=True,
            last_run="2026-05-20T00:00:00+00:00",
            summary={"creates": 1, "updates": 0, "deletes": 0, "unmanaged": 0},
        ),
    )
    try:
        run_drift_check(
            "test",
            repo=empty_repo,
            state_file=state_file,
            no_state=True,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0
    assert captured_events == []


def test_drift_check_fail_on_drift_exits_2(
    realistic_repo_path: Path, captured_events: list[Event], tmp_path: Path
) -> None:
    """``--fail-on-drift`` exits with code 2 when drift was detected."""
    state_file = tmp_path / "state.json"
    import typer

    with pytest.raises(typer.Exit) as excinfo:
        run_drift_check(
            "test",
            repo=realistic_repo_path,
            state_file=state_file,
            fail_on_drift=True,
            state_provider=lambda: LiveState(),
        )
    assert excinfo.value.exit_code == DRIFT_EXIT_CODE
    assert len(captured_events) == 1
    assert captured_events[0].type == "drift.detected"


def test_drift_check_fail_on_drift_zero_when_clean(
    empty_repo: Path, captured_events: list[Event]
) -> None:
    """``--fail-on-drift`` with no drift exits 0."""
    try:
        run_drift_check(
            "test",
            repo=empty_repo,
            fail_on_drift=True,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0
    assert captured_events == []


# ---- --output JSON --------------------------------------------------------


def test_drift_check_writes_output_json(
    realistic_repo_path: Path,
    captured_events: list[Event],
    tmp_path: Path,
) -> None:
    """``--output`` writes a structured drift report including the transition."""
    output = tmp_path / "report.json"
    state_file = tmp_path / "state.json"
    try:
        run_drift_check(
            "test",
            repo=realistic_repo_path,
            state_file=state_file,
            output=output,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["env"] == "test"
    assert payload["drift"] is True
    assert payload["previous_drift"] is False
    assert payload["transition"] == "detected"
    assert payload["summary"]["creates"] > 0
    assert payload["change_set"]["env"] == "test"


# ---- error paths ----------------------------------------------------------


def test_drift_check_surfaces_config_repo_errors(
    tmp_path: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid config repo should exit 1 with errors printed to stderr."""
    from csfwctl.loader import ConfigRepoError

    bad = tmp_path / "broken"
    bad.mkdir()

    def fail_loader(_: Path) -> None:
        raise ConfigRepoError([LoadError(path=bad, message="bad")])

    monkeypatch.setattr("csfwctl.drift_cmd.load_config_repo", fail_loader)

    result = runner.invoke(app, ["drift-check", "--env", "test", "--repo", str(bad)])
    assert result.exit_code == 1
    assert "failed to validate" in result.stderr


def test_drift_check_surfaces_live_fetch_errors(
    empty_repo: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A live-state fetch failure exits 1 with a stderr message."""

    def explode(profile: str | None, credentials_file: Any) -> Any:
        def _provider() -> LiveState:
            raise RuntimeError("API down")

        return _provider

    monkeypatch.setattr("csfwctl.drift_cmd._default_state_provider", explode)

    result = runner.invoke(
        app, ["drift-check", "--env", "test", "--repo", str(empty_repo), "--no-state"]
    )
    assert result.exit_code == 1
    assert "failed to fetch live state" in result.stderr


# ---- end-to-end via Typer -------------------------------------------------


def test_drift_check_cli_end_to_end_no_drift(
    empty_repo: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end Typer dispatch on a clean run."""
    monkeypatch.setattr(
        "csfwctl.drift_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(
        app, ["drift-check", "--env", "test", "--repo", str(empty_repo), "--no-state"]
    )
    assert result.exit_code == 0, result.output + result.stderr
    assert "no drift" in result.output


def test_drift_check_cli_end_to_end_with_drift(
    realistic_repo_path: Path,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """End-to-end Typer dispatch when drift exists prints the detected line."""
    monkeypatch.setattr(
        "csfwctl.drift_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(
        app,
        [
            "drift-check",
            "--env",
            "test",
            "--repo",
            str(realistic_repo_path),
            "--state-file",
            str(tmp_path / "state.json"),
        ],
    )
    assert result.exit_code == 0, result.output + result.stderr
    assert "drift detected" in result.output
