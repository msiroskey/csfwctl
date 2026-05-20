"""Smoke tests confirming the Phase 0 scaffold is wired up correctly."""

from __future__ import annotations

from typer.testing import CliRunner

import csfwctl
from csfwctl.cli import NOT_IMPLEMENTED_EXIT, app

runner = CliRunner()


def test_version_is_set() -> None:
    """The package exposes a __version__ string."""
    assert isinstance(csfwctl.__version__, str)
    assert csfwctl.__version__


def test_cli_help_lists_all_top_level_commands() -> None:
    """`csfwctl --help` advertises every top-level subcommand from the plan."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    expected = {
        "validate",
        "diff",
        "apply",
        "status",
        "precedence",
        "import",
        "record-fixtures",
        "promote",
        "notify-test",
    }
    for command in expected:
        assert command in result.stdout, f"missing {command!r} in help output"


def test_status_is_stubbed() -> None:
    """Stub subcommands exit with the documented 'not implemented' code."""
    result = runner.invoke(app, ["status"])
    assert result.exit_code == NOT_IMPLEMENTED_EXIT
    assert "not implemented" in result.stderr.lower() or "not implemented" in result.output.lower()


def test_import_subgroup_lists_subcommands() -> None:
    """`csfwctl import --help` exposes the four import subcommands."""
    result = runner.invoke(app, ["import", "--help"])
    assert result.exit_code == 0
    for command in ("policy", "rule-group", "location", "all"):
        assert command in result.stdout
