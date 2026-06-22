"""Tests for the ``csfwctl apply`` CLI command body.

Focuses on plumbing: argument wiring, exit codes, dry-run output. The
applier engine itself is covered by ``test_applier.py`` and the safety
rails by ``test_safety.py``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from csfwctl.apply_cmd import run_apply
from csfwctl.cli import app
from csfwctl.differ import LiveState
from csfwctl.loader import ConfigRepoError, LoadError


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


class _StubClient:
    """Minimal stand-in: no APIs are reached because state is provided."""

    class _Noop:
        def __getattr__(self, name: str) -> Any:
            def _missing(*_a: Any, **_kw: Any) -> Any:
                raise AssertionError(f"unexpected sub-client call: {name}")

            return _missing

    policies = _Noop()
    rule_groups = _Noop()
    host_groups = _Noop()
    locations = _Noop()


def test_run_apply_dry_run_against_realistic_repo(
    realistic_repo_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dry-run with an empty live state: every YAML object lands as a create."""
    # An unbootstrapped tenant is fine in bootstrap mode; here we use a
    # signed seed location so the normal-apply gate passes.
    from csfwctl.differ import METADATA_SIGNATURE_TOKEN

    seed = LiveState(
        locations=[
            {
                "id": "seed-id",
                "name": "seed-location",
                "description": (
                    f"{METADATA_SIGNATURE_TOKEN} | version: 1 | git_sha: x | "
                    "applied: 2026-01-01T00:00:00Z | env: any"
                ),
                "enabled": True,
                "addresses": [{"address": "10.255.255.255/32"}],
            }
        ],
    )

    report = run_apply(
        env="test",
        repo=realistic_repo_path,
        dry_run=True,
        enforce=True,  # realistic-repo fixture has managed updates; allow them
        allow_delete=False,
        strict_groups=False,
        create_groups=False,
        initial_bootstrap=False,
        max_deletes=100,
        max_changes=100,
        state_provider=lambda: seed,
        client_factory=lambda: _StubClient(),
        git_sha="dryrunsha",
    )
    assert report.dry_run is True
    # Realistic fixture has policies + rule groups + locations -> creates.
    assert report.count("create") > 0
    # And the report's environment matches the CLI argument.
    assert report.env == "test"


def test_run_apply_surfaces_config_repo_errors(
    tmp_path: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An invalid config repo exits 1 with the per-error listing."""
    bad = tmp_path / "broken"
    bad.mkdir()

    def fail_loader(_: Path) -> None:
        raise ConfigRepoError([LoadError(path=bad / "policies" / "broken.yaml", message="bad")])

    monkeypatch.setattr("csfwctl.apply_cmd.load_config_repo", fail_loader)

    result = runner.invoke(
        app,
        [
            "apply",
            "--env",
            "test",
            "--repo",
            str(bad),
            "--dry-run",
        ],
    )
    assert result.exit_code == 1
    assert "failed to validate" in result.stderr


def test_run_apply_writes_json_output(realistic_repo_path: Path, tmp_path: Path) -> None:
    """``--output`` writes diff + apply payload to disk."""
    from csfwctl.differ import METADATA_SIGNATURE_TOKEN

    seed = LiveState(
        locations=[
            {
                "id": "seed-id",
                "name": "seed",
                "description": f"{METADATA_SIGNATURE_TOKEN} | version: 1 | git_sha: x | applied: 2026-01-01T00:00:00Z | env: any",
                "enabled": True,
                "addresses": [{"address": "10.255.255.255/32"}],
            }
        ]
    )
    target = tmp_path / "apply.json"
    run_apply(
        env="test",
        repo=realistic_repo_path,
        dry_run=True,
        enforce=True,
        allow_delete=False,
        strict_groups=False,
        create_groups=False,
        initial_bootstrap=False,
        max_deletes=100,
        max_changes=100,
        state_provider=lambda: seed,
        client_factory=lambda: _StubClient(),
        git_sha="x",
        output=target,
    )
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert "diff" in payload
    assert "apply" in payload
    assert payload["apply"]["env"] == "test"


def test_run_apply_refuses_strict_and_create_groups(
    realistic_repo_path: Path,
) -> None:
    """Mutually-exclusive host-group flags surface as a BadParameter exit."""
    import typer

    seed = LiveState()
    with pytest.raises(typer.BadParameter):
        run_apply(
            env="test",
            repo=realistic_repo_path,
            dry_run=True,
            enforce=False,
            allow_delete=False,
            strict_groups=True,
            create_groups=True,
            initial_bootstrap=True,
            max_deletes=100,
            max_changes=100,
            state_provider=lambda: seed,
            client_factory=lambda: _StubClient(),
            git_sha="x",
        )


def test_apply_cli_dispatch_runs_to_completion(
    realistic_repo_path: Path, runner: CliRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End-to-end Typer dispatch: ``apply --env --dry-run`` exits 0."""
    from csfwctl.differ import METADATA_SIGNATURE_TOKEN

    seed = LiveState(
        locations=[
            {
                "id": "seed-id",
                "name": "seed",
                "description": (
                    f"{METADATA_SIGNATURE_TOKEN} | version: 1 | git_sha: x | "
                    "applied: 2026-01-01T00:00:00Z | env: any"
                ),
                "enabled": True,
                "addresses": [{"address": "10.255.255.255/32"}],
            }
        ]
    )
    monkeypatch.setattr(
        "csfwctl.apply_cmd._build_client",
        lambda factory, profile, credentials_file, err: _StubClient(),
    )
    monkeypatch.setattr(
        "csfwctl.apply_cmd._fetch_state",
        lambda provider, client, err: seed,
    )
    monkeypatch.setenv("CSFWCTL_GIT_SHA", "cli-test-sha")

    result = runner.invoke(
        app,
        [
            "apply",
            "--env",
            "test",
            "--repo",
            str(realistic_repo_path),
            "--dry-run",
            "--enforce",
            "--create-groups",
            "--max-changes",
            "100",
            "--max-deletes",
            "100",
        ],
    )
    assert result.exit_code == 0, result.output + result.stderr
    # Rich wraps the title across lines depending on terminal width.
    assert "csfwctl apply" in result.output
    assert "dry-run" in result.output


def test_change_detail_does_not_truncate_long_paths() -> None:
    """The apply change detail is an audit record — values render in full.

    A clipped executable path cannot be reconstructed after the fact, so the
    render must not truncate (regression for the old 60-char ``_short`` cap).
    """
    from csfwctl.apply_cmd import _summarise_field_change
    from csfwctl.differ import FieldChange

    long_path = r"C:\Program Files (x86)\Microsoft Office\root\Office16\lync.exe"
    assert len(long_path) > 60
    lines = _summarise_field_change(FieldChange(path="file_path", before=long_path, after=None))
    rendered = "\n".join(lines)
    assert repr(long_path) in rendered  # full value present
    assert "lync.exe" in rendered  # the tail survives — not clipped
    assert "…" not in rendered  # nothing truncated


def test_change_detail_does_not_truncate_nested_rule_field() -> None:
    """Modified-rule key deltas (the ``~ name: file_path: ...`` lines) are full too."""
    from csfwctl.apply_cmd import _summarise_field_change
    from csfwctl.differ import FieldChange

    long_path = r"C:\Program Files (x86)\Microsoft Office\root\Office16\lync.exe"
    before = [{"name": "Skype for Business", "file_path": long_path}]
    after = [{"name": "Skype for Business", "file_path": None}]
    lines = _summarise_field_change(FieldChange(path="rules", before=before, after=after))
    rendered = "\n".join(lines)
    assert repr(long_path) in rendered
    assert "lync.exe" in rendered
    assert "…" not in rendered
