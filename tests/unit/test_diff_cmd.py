"""Tests for the ``csfwctl diff`` CLI command body.

The differ engine itself is covered in ``test_differ.py``; this file
exercises the CLI plumbing — exit codes, JSON output, error surfacing —
without making real API calls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from csfwctl.cli import app
from csfwctl.differ import LiveState
from csfwctl.loader import LoadError


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def realistic_repo_root(realistic_repo_path: Path) -> Path:
    return realistic_repo_path


def _stub_provider(state: LiveState) -> Any:
    """Return a callable that yields ``state`` regardless of who calls it."""
    return lambda: state


def test_diff_no_changes_against_realistic_repo(
    realistic_repo_root: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    """Hand-rolled empty-state diff: every desired object should be a create."""
    # Use the run_diff function directly with a stub state provider so we
    # don't need to mock ``load_credentials`` + ``FalconClient``.
    from csfwctl.diff_cmd import run_diff

    captured: dict[str, Any] = {}

    def fake_provider() -> LiveState:
        captured["called"] = True
        return LiveState()

    try:
        run_diff(
            env="test",
            repo=realistic_repo_root,
            output=None,
            state_provider=fake_provider,
        )
    except SystemExit as exc:  # typer raises SystemExit on Exit
        assert exc.code == 0
    assert captured["called"] is True


def test_diff_writes_json_when_output_given(realistic_repo_root: Path, tmp_path: Path) -> None:
    """``--output`` is the machine-readable channel."""
    from csfwctl.diff_cmd import run_diff

    output = tmp_path / "diff.json"
    try:
        run_diff(
            env="test",
            repo=realistic_repo_root,
            output=output,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    assert output.is_file()
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["env"] == "test"
    assert payload["summary"]["creates"] > 0
    # Realistic fixture has policies + rule groups + locations -> creates.
    assert any(c["kind"] == "policy" for c in payload["creates"])
    assert any(c["kind"] == "rule-group" for c in payload["creates"])


def test_diff_surfaces_config_repo_errors(
    tmp_path: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid config repo should exit 1 with errors printed to stderr."""
    from csfwctl.loader import ConfigRepoError

    bad = tmp_path / "broken"
    bad.mkdir()
    (bad / "policies").mkdir()
    (bad / "policies" / "broken.yaml").write_text("name: not-a-display-name\n", encoding="utf-8")

    def fail_loader(_: Path) -> None:
        raise ConfigRepoError([LoadError(path=bad / "policies" / "broken.yaml", message="bad")])

    monkeypatch.setattr("csfwctl.diff_cmd.load_config_repo", fail_loader)
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )

    result = runner.invoke(app, ["diff", "--env", "test", "--repo", str(bad)])
    assert result.exit_code == 1
    assert "failed to validate" in result.stderr


def test_diff_cli_wires_state_provider_through(
    realistic_repo_root: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end Typer dispatch: ``diff --env`` runs to completion."""
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )

    result = runner.invoke(app, ["diff", "--env", "test", "--repo", str(realistic_repo_root)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "csfwctl diff --env test" in result.output
    # Realistic repo > 0 creates against empty live state.
    assert "creates" in result.output


def test_diff_no_changes_shows_summary(
    tmp_path: Path,
    runner: CliRunner,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty repo against empty live state prints the 'no changes' line."""
    empty_repo = tmp_path / "empty-repo"
    empty_repo.mkdir()
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(app, ["diff", "--env", "test", "--repo", str(empty_repo)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "no changes" in result.output


# ---- all-envs mode (--env omitted) --------------------------------------


def test_diff_all_envs_renders_combined_table(
    realistic_repo_root: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Omitting --env runs the all-envs diff and prints the combined table."""
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(app, ["diff", "--repo", str(realistic_repo_root)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "all environments" in result.output
    # Each env appears as its own detail section.
    for env in ("test", "pilot", "production"):
        assert env in result.output


def test_diff_all_envs_writes_multi_env_json(realistic_repo_root: Path, tmp_path: Path) -> None:
    """All-envs ``--output`` carries the multi-env JSON shape."""
    from csfwctl.diff_cmd import run_diff

    output = tmp_path / "all.json"
    try:
        run_diff(
            env=None,
            repo=realistic_repo_root,
            output=output,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert set(payload["change_sets"].keys()) == {"test", "pilot", "production"}
    assert "env_drift" in payload


def test_diff_all_envs_fail_on_env_drift_exits_nonzero(
    realistic_repo_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--fail-on-env-drift`` exits ENV_DRIFT_EXIT_CODE when a ripple is found."""
    from csfwctl import diff_cmd
    from csfwctl.differ import (
        KIND_POLICY,
        ChangeSet,
        DiffOp,
        ManagedStatus,
        MultiEnvDiff,
        ObjectChange,
    )

    def fake_multi(_config: Any, _state: Any) -> MultiEnvDiff:
        test = ChangeSet(env="test")
        pilot = ChangeSet(env="pilot")
        pilot.creates.append(
            ObjectChange(
                kind=KIND_POLICY,
                op=DiffOp.create,
                slug="abc01-endpoints-windows",
                display_name="ABC01-Endpoints-Windows-Pilot",
                managed=ManagedStatus.new,
            )
        )
        production = ChangeSet(env="production")
        return MultiEnvDiff(change_sets={"test": test, "pilot": pilot, "production": production})

    monkeypatch.setattr(diff_cmd, "compute_all_envs_diff", fake_multi)

    import typer

    with pytest.raises(typer.Exit) as excinfo:
        diff_cmd.run_diff(
            env=None,
            repo=realistic_repo_root,
            output=None,
            state_provider=lambda: LiveState(),
            fail_on_env_drift=True,
        )
    assert excinfo.value.exit_code == diff_cmd.ENV_DRIFT_EXIT_CODE


def test_diff_single_env_still_works_with_explicit_env(
    realistic_repo_root: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Backward compatibility: ``--env test`` keeps the single-env output."""
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(app, ["diff", "--env", "test", "--repo", str(realistic_repo_root)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "csfwctl diff --env test" in result.output
