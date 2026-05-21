"""Tests for the ``csfwctl status`` CLI command body.

The status engine itself is covered in ``test_status.py``; this file
exercises the CLI plumbing: exit codes, JSON output, error surfacing,
and the ``--all-envs`` pivot.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from csfwctl.cli import app
from csfwctl.differ import LiveState


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _signed(env: str, *, version: int = 1, sha: str = "abc1234") -> str:
    """Build a description with a canonical metadata trailer."""
    return (
        f"Managed by csfwctl | version: {version} | git_sha: {sha} "
        f"| applied: 2026-04-15T10:30:00Z | env: {env}"
    )


def _policy(name: str, description: str | None = None) -> dict[str, Any]:
    return {"id": f"p-{name}", "name": name, "description": description}


def _live_state_with_three_envs() -> LiveState:
    """A modest snapshot covering policy, rule-group, and location kinds."""
    return LiveState(
        policies=[
            _policy("Alpha-Test", _signed("test", version=2)),
            _policy("Alpha-Pilot", _signed("pilot", version=1)),
            _policy("Beta-Test", description=None),  # unmanaged
        ],
        rule_groups=[
            {"id": "rg-1", "name": "rg-baseline-Test", "description": _signed("test")},
        ],
        locations=[
            {"id": "loc-1", "name": "corp-vpn", "description": _signed("test", version=1)},
        ],
    )


# ---- run_status: programmatic invocation ---------------------------------


def test_run_status_returns_report_with_state_provider() -> None:
    """``run_status`` can be called directly with a stub state provider."""
    from csfwctl.status_cmd import run_status

    report = run_status(
        all_envs=False,
        output_format="table",
        state_provider=_live_state_with_three_envs,
    )
    # alpha (1) + beta (1) + rule-group (1) + location (1)
    assert report.total == 4
    assert report.managed == 3
    assert report.unmanaged == 1


def test_run_status_json_format_returns_report() -> None:
    """``--format json`` short-circuits the table renderer."""
    from csfwctl.status_cmd import run_status

    report = run_status(
        all_envs=False,
        output_format="json",
        state_provider=lambda: LiveState(),
    )
    assert report.total == 0


# ---- end-to-end Typer dispatch -------------------------------------------


def test_status_cli_dispatches_to_run_status(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end: ``csfwctl status`` runs to completion against stubbed live."""
    state = _live_state_with_three_envs()
    monkeypatch.setattr(
        "csfwctl.status_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: state,
    )
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0, result.output + result.stderr
    # The flat table header appears.
    assert "csfwctl status" in result.output
    # Both managed and unmanaged objects show up.
    assert "alpha" in result.output
    assert "beta" in result.output


def test_status_cli_all_envs_pivot_emits_per_env_columns(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--all-envs`` pivots into one row per logical object."""
    state = _live_state_with_three_envs()
    monkeypatch.setattr(
        "csfwctl.status_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: state,
    )
    result = runner.invoke(app, ["status", "--all-envs"])
    assert result.exit_code == 0
    # Pivot title includes the flag.
    assert "csfwctl status --all-envs" in result.output
    # The version is rendered for the managed object.
    assert "v2@" in result.output


def test_status_cli_json_output_is_valid_json(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--format json`` emits a parseable document with the expected shape."""
    state = _live_state_with_three_envs()
    monkeypatch.setattr(
        "csfwctl.status_cmd._default_state_provider",
        lambda profile, credentials_file: lambda: state,
    )
    result = runner.invoke(app, ["status", "--format", "json"])
    assert result.exit_code == 0
    # Rich's ``print_json`` writes the payload to stdout; parse it back.
    payload = json.loads(_first_json_object(result.output))
    assert payload["summary"]["total"] == 4
    assert payload["summary"]["managed"] == 3


def _first_json_object(text: str) -> str:
    """Extract the first balanced top-level JSON object from ``text``.

    Rich's ``print_json`` may wrap output with ANSI codes; this helper
    pulls out the JSON body for parsing.
    """
    start = text.find("{")
    if start < 0:
        raise AssertionError(f"no JSON object in output: {text!r}")
    depth = 0
    for index in range(start, len(text)):
        ch = text[index]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    raise AssertionError(f"unterminated JSON object: {text!r}")


# ---- error surfacing -----------------------------------------------------


def test_status_cli_surfaces_state_fetch_failure(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exception while fetching live state should exit 1 with a clear message."""

    def fail_provider(profile: Any, credentials_file: Any) -> Any:
        def _raise() -> LiveState:
            raise RuntimeError("boom")

        return _raise

    monkeypatch.setattr("csfwctl.status_cmd._default_state_provider", fail_provider)
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 1
    assert "failed to fetch live state" in result.stderr
