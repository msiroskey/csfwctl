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


# ---- per-object env matrix table (all-envs mode only) -------------------


def _stub_multi_env(monkeypatch: pytest.MonkeyPatch, multi: Any) -> None:
    from csfwctl import diff_cmd

    monkeypatch.setattr(diff_cmd, "compute_all_envs_diff", lambda _c, _s: multi)


def test_env_matrix_appears_in_all_envs_mode(
    realistic_repo_root: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The matrix table appears after the summary in all-envs mode."""
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(app, ["diff", "--repo", str(realistic_repo_root)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "Per-object changes by environment" in result.output


def test_env_matrix_omitted_in_single_env_mode(
    realistic_repo_root: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Single-env mode keeps its per-env details but does not render the matrix."""
    monkeypatch.setattr(
        "csfwctl.diff_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: LiveState(),
    )
    result = runner.invoke(app, ["diff", "--env", "test", "--repo", str(realistic_repo_root)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "Per-object changes by environment" not in result.output


def test_env_matrix_shows_create_and_delete_summary_rows(
    realistic_repo_root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Creates and deletes each get a single ``(new)`` / ``(deleted)`` row."""
    from csfwctl import diff_cmd
    from csfwctl.differ import (
        KIND_POLICY,
        ChangeSet,
        DiffOp,
        ManagedStatus,
        MultiEnvDiff,
        ObjectChange,
    )

    test = ChangeSet(env="test")
    test.creates.append(
        ObjectChange(
            kind=KIND_POLICY,
            op=DiffOp.create,
            slug="abc01-endpoints-windows",
            display_name="ABC01-Endpoints-Windows",
            managed=ManagedStatus.new,
        )
    )
    pilot = ChangeSet(env="pilot")
    production = ChangeSet(env="production")
    production.deletes.append(
        ObjectChange(
            kind=KIND_POLICY,
            op=DiffOp.delete,
            slug="legacy-policy",
            display_name="Legacy-Policy",
            managed=ManagedStatus.managed,
            reason="tombstoned",
        )
    )
    multi = MultiEnvDiff(change_sets={"test": test, "pilot": pilot, "production": production})
    _stub_multi_env(monkeypatch, multi)

    try:
        diff_cmd.run_diff(
            env=None,
            repo=realistic_repo_root,
            output=None,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    captured = capsys.readouterr().out
    assert "Per-object changes by environment" in captured
    assert "(new)" in captured
    assert "(deleted)" in captured
    assert "ABC01-Endpoints-Windows" in captured
    assert "Legacy-Policy" in captured


def test_env_matrix_shows_one_row_per_field_path_with_before_after(
    realistic_repo_root: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Updates emit one row per changed field; cell shows ``before -> after``."""
    from csfwctl import diff_cmd
    from csfwctl.differ import (
        KIND_POLICY,
        ChangeSet,
        DiffOp,
        FieldChange,
        ManagedStatus,
        MultiEnvDiff,
        ObjectChange,
    )

    def _mk_update(env: str, enabled_before: bool, enabled_after: bool) -> ChangeSet:
        cs = ChangeSet(env=env)
        cs.updates.append(
            ObjectChange(
                kind=KIND_POLICY,
                op=DiffOp.update,
                slug="abc01-endpoints-windows",
                display_name="ABC01-Endpoints-Windows",
                managed=ManagedStatus.managed,
                field_changes=(
                    FieldChange(path="enabled", before=enabled_before, after=enabled_after),
                    FieldChange(path="description", before="old", after="new"),
                ),
            )
        )
        return cs

    multi = MultiEnvDiff(
        change_sets={
            "test": _mk_update("test", False, True),
            "pilot": ChangeSet(env="pilot"),
            "production": _mk_update("production", False, True),
        }
    )
    _stub_multi_env(monkeypatch, multi)

    try:
        diff_cmd.run_diff(
            env=None,
            repo=realistic_repo_root,
            output=None,
            state_provider=lambda: LiveState(),
        )
    except SystemExit as exc:
        assert exc.code == 0

    out = capsys.readouterr().out
    assert "enabled" in out
    assert "description" in out
    assert "False -> True" in out
    assert "'old' -> 'new'" in out
    # Pilot has no change to this object — its cell for both field rows is the
    # empty-cell sentinel.
    assert "—" in out


# ---- matrix width sizing ------------------------------------------------


def test_optimal_matrix_width_returns_natural_when_narrow() -> None:
    """Small data → table sizes to its natural width, not the 140 cap."""
    from csfwctl.diff_cmd import _MATRIX_MAX_WIDTH, _optimal_matrix_width

    header = ["Type", "Name", "Change on", "Test", "Pilot", "Production"]
    body = [
        ["policy", "abc", "(new)", "create", "—", "—"],
        ["policy", "abc", "enabled", "False -> True", "—", "—"],
    ]
    width = _optimal_matrix_width(header, body)
    assert width < _MATRIX_MAX_WIDTH
    # Sanity: at least wide enough for the header cells plus overhead.
    assert width >= sum(len(h) for h in header)


def test_optimal_matrix_width_caps_at_140() -> None:
    """A very long cell forces the cap so the table stays reviewable."""
    from csfwctl.diff_cmd import _MATRIX_MAX_WIDTH, _optimal_matrix_width

    header = ["Type", "Name", "Change on", "Test", "Pilot", "Production"]
    huge = "x" * 500
    body = [["policy", "abc", "description", huge, "—", "—"]]
    assert _optimal_matrix_width(header, body) == _MATRIX_MAX_WIDTH


def test_optimal_matrix_width_ignores_rich_markup() -> None:
    """``[green]create[/green]`` counts as 6 visible chars, not 21."""
    from csfwctl.diff_cmd import _optimal_matrix_width

    header = ["A", "B"]
    plain = [["A", "create"]]
    marked = [["A", "[green]create[/green]"]]
    assert _optimal_matrix_width(header, plain) == _optimal_matrix_width(header, marked)


def test_env_matrix_not_cropped_in_non_tty_output() -> None:
    """Non-TTY consumers (CI logs, piped capture) must not lose right-side columns.

    Rich falls back to an 80-column console when it can't detect a real
    terminal. Without ``crop=False`` on the matrix print the Pilot and
    Production columns get silently clipped off the right edge — the
    exact symptom observed in the PR #69 log capture.
    """
    import io

    from rich.console import Console

    from csfwctl import diff_cmd
    from csfwctl.differ import (
        KIND_POLICY,
        ChangeSet,
        DiffOp,
        ManagedStatus,
        MultiEnvDiff,
        ObjectChange,
    )

    test = ChangeSet(env="test")
    test.creates.append(
        ObjectChange(
            kind=KIND_POLICY,
            op=DiffOp.create,
            slug="abc",
            display_name="ABC",
            managed=ManagedStatus.new,
        )
    )
    multi = MultiEnvDiff(
        change_sets={
            "test": test,
            "pilot": ChangeSet(env="pilot"),
            "production": ChangeSet(env="production"),
        }
    )

    buf = io.StringIO()
    console = Console(file=buf)
    assert not console.is_terminal, "test precondition: StringIO capture is non-tty"
    assert console.width < diff_cmd._MATRIX_MAX_WIDTH, "test precondition: width < cap"

    diff_cmd._render_env_matrix_table(console, multi)

    rendered = buf.getvalue()
    # All three env column headers must survive — a clipped table drops
    # Pilot / Production off the right side.
    assert "Test" in rendered
    assert "Pilot" in rendered
    assert "Production" in rendered
