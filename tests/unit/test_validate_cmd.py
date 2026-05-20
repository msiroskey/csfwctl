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
