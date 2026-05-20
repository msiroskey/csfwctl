"""Tests for the ``csfwctl validate`` command end-to-end."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from csfwctl.cli import app

runner = CliRunner()


def test_validate_minimal_repo_exits_zero(minimal_repo_path: Path) -> None:
    result = runner.invoke(app, ["validate", "--repo", str(minimal_repo_path)])
    assert result.exit_code == 0, result.output
    assert "validate: OK" in result.output


def test_validate_realistic_repo_exits_zero(realistic_repo_path: Path) -> None:
    result = runner.invoke(app, ["validate", "--repo", str(realistic_repo_path)])
    assert result.exit_code == 0, result.output


def test_validate_broken_repo_exits_one(minimal_repo_copy: Path) -> None:
    policy = minimal_repo_copy / "policies" / "abc01-endpoints-windows.yaml"
    policy.write_text(policy.read_text() + "  - does-not-exist\n")

    result = runner.invoke(app, ["validate", "--repo", str(minimal_repo_copy)])
    assert result.exit_code == 1
    assert "does-not-exist" in result.output


def test_validate_nonexistent_repo_exits_one(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", "--repo", str(tmp_path / "nope")])
    assert result.exit_code == 1


def test_validate_lint_warning_does_not_fail_by_default(realistic_repo_copy: Path) -> None:
    """A bare orphan rule group produces a warning but exit 0."""
    (realistic_repo_copy / "rule_groups" / "windows-orphan.yaml").write_text(
        "name: windows-orphan\nplatform: windows\nstatus: enabled\nrules: []\n"
    )
    result = runner.invoke(
        app, ["validate", "--repo", str(realistic_repo_copy)], env={"COLUMNS": "240"}
    )
    assert result.exit_code == 0, result.output
    assert "validate: OK with" in result.output
    assert "1 warning(s)" in result.output
    assert "orphan-rule-group" in result.output


def test_validate_strict_promotes_warnings_to_fatal(realistic_repo_copy: Path) -> None:
    """``--strict`` should fail validate on any lint finding."""
    (realistic_repo_copy / "rule_groups" / "windows-orphan.yaml").write_text(
        "name: windows-orphan\nplatform: windows\nstatus: enabled\nrules: []\n"
    )
    result = runner.invoke(
        app,
        ["validate", "--repo", str(realistic_repo_copy), "--strict"],
        env={"COLUMNS": "240"},
    )
    assert result.exit_code == 1
    assert "strict=True" in result.output
    assert "orphan-rule-group" in result.output


def test_validate_realistic_repo_clean_status_line(realistic_repo_path: Path) -> None:
    """A no-finding repo still prints ``validate: OK`` without the warning suffix."""
    result = runner.invoke(app, ["validate", "--repo", str(realistic_repo_path)])
    assert result.exit_code == 0, result.output
    assert "validate: OK" in result.output
    assert "with" not in result.output.split("validate: OK")[-1].splitlines()[0]
