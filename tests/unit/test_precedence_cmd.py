"""Tests for the ``csfwctl precedence`` CLI command body.

The resolver itself is covered in ``test_precedence_resolver.py``;
this file exercises the CLI plumbing: exit codes, JSON output,
config-repo error surfacing, and the ``--env`` live comparison.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from csfwctl.cli import app
from csfwctl.loader import LoadError
from csfwctl.schema import Platform


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def realistic_repo_root(realistic_repo_path: Path) -> Path:
    return realistic_repo_path


def _live(name: str) -> dict[str, Any]:
    """Live policy record (only ``id`` and ``name`` are used downstream)."""
    return {"id": f"id-{name}", "name": name}


# ---- programmatic invocation --------------------------------------------


def test_run_precedence_returns_resolved_order_for_realistic_repo(
    realistic_repo_root: Path,
) -> None:
    """Realistic fixture: precedence resolves windows + mac, override moves research-lab."""
    from csfwctl.precedence_cmd import run_precedence

    resolved = run_precedence(realistic_repo_root, env=None)
    # Both platforms present.
    assert Platform.windows in resolved
    assert Platform.mac in resolved
    windows_slugs = [p.slug for p in resolved[Platform.windows]]
    # Realistic fixture has an override moving research-lab-7-windows ahead.
    assert windows_slugs.index("research-lab-7-windows") < windows_slugs.index(
        "abc01-endpoints-windows"
    )


def test_run_precedence_with_env_compares_against_live_via_provider(
    realistic_repo_root: Path,
) -> None:
    """``--env`` triggers the live comparison path with our stub provider."""
    from csfwctl.precedence_cmd import run_precedence

    captured: list[Platform] = []

    def provider(platform: Platform) -> list[dict[str, Any]]:
        captured.append(platform)
        if platform is Platform.windows:
            return [_live("Research-Lab-7-Windows-Test"), _live("ABC01-Endpoints-Windows-Test")]
        return [_live("ABC01-Endpoints-Mac-Test")]

    run_precedence(
        realistic_repo_root,
        env="test",
        live_provider=provider,
    )
    # Provider called once per platform that resolved policies.
    assert Platform.windows in captured
    assert Platform.mac in captured


# ---- end-to-end Typer dispatch ------------------------------------------


def test_precedence_cli_renders_resolved_table(
    realistic_repo_root: Path, runner: CliRunner
) -> None:
    """``csfwctl precedence`` (no --env) renders one table per platform."""
    result = runner.invoke(app, ["precedence", "--repo", str(realistic_repo_root)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "resolved precedence" in result.output
    assert "windows" in result.output
    assert "mac" in result.output
    # The realistic-fixture override should have research-lab-7 first.
    research_pos = result.output.find("research-lab-7-windows")
    abc_pos = result.output.find("abc01-endpoints-windows")
    assert 0 <= research_pos < abc_pos


def test_precedence_cli_json_format_emits_platform_block(
    realistic_repo_root: Path, runner: CliRunner
) -> None:
    """``--format json`` produces a parseable document keyed by platform."""
    result = runner.invoke(
        app,
        ["precedence", "--repo", str(realistic_repo_root), "--format", "json"],
    )
    assert result.exit_code == 0
    payload = json.loads(_first_json_object(result.output))
    assert "platforms" in payload
    assert "windows" in payload["platforms"]
    assert any(p["slug"] == "research-lab-7-windows" for p in payload["platforms"]["windows"])


def test_precedence_cli_surfaces_config_repo_errors(
    tmp_path: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid config repo exits 1 with the per-error list on stderr."""
    from csfwctl.loader import ConfigRepoError

    def fail_loader(_: Path) -> None:
        raise ConfigRepoError([LoadError(path=tmp_path / "broken.yaml", message="bad")])

    monkeypatch.setattr("csfwctl.precedence_cmd._load_config", fail_loader)
    result = runner.invoke(app, ["precedence", "--repo", str(tmp_path)])
    assert result.exit_code == 1
    assert "failed to validate" in result.stderr


def test_precedence_cli_dispatches_env_through_to_provider(
    realistic_repo_root: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``--env`` runs through to the default live provider; we stub the client."""

    def provider(platform: Platform) -> list[dict[str, Any]]:
        # Return live in the resolved order so the comparison reports match.
        if platform is Platform.windows:
            return [
                _live("Research-Lab-7-Windows-Test"),
                _live("ABC01-Endpoints-Windows-Test"),
            ]
        return [_live("ABC01-Endpoints-Mac-Test")]

    # Patch the default-provider builder so no real client is instantiated.
    monkeypatch.setattr(
        "csfwctl.precedence_cmd._default_live_provider",
        lambda *, profile, client_factory, err: provider,
    )
    result = runner.invoke(
        app,
        ["precedence", "--repo", str(realistic_repo_root), "--env", "test"],
    )
    assert result.exit_code == 0, result.output + result.stderr
    assert "matches resolved order" in result.output


def _first_json_object(text: str) -> str:
    """Extract the first balanced top-level JSON object from ``text``."""
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
