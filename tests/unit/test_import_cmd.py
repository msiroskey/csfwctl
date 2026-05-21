"""Tests for the ``csfwctl import`` and ``record-fixtures`` command bodies.

These bypass Typer's runner and directly exercise the command modules
with a mocked ``FalconClient`` factory. The exporter logic itself has
its own coverage in ``test_exporter.py``; this file is about CLI plumbing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from csfwctl.cli import app
from csfwctl.exporter import (
    ImporterError,
    ImportResult,
)
from csfwctl.schema import Location, Platform, Policy, RuleGroup


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


# ---- import_cmd: argument plumbing ---------------------------------------


def test_import_policy_writes_to_default_subdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    """The CLI delegates to ``run_import_policy`` with the expected kwargs."""
    fake_model = Policy(name="ABC01-Endpoints-Windows", platform=Platform.windows)
    target_path = tmp_path / "policies" / "abc01-endpoints-windows.yaml"
    target_path.parent.mkdir(parents=True)
    target_path.write_text("name: ABC01-Endpoints-Windows\n", encoding="utf-8")

    seen: dict[str, Any] = {}

    def fake_import(client: Any, name_or_uuid: str, **kwargs: Any) -> ImportResult:
        seen["client"] = client
        seen["name_or_uuid"] = name_or_uuid
        seen["kwargs"] = kwargs
        return ImportResult(
            kind="policy", slug="abc01-endpoints-windows", model=fake_model, path=target_path
        )

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_policy", fake_import)

    result = runner.invoke(app, ["import", "policy", "ABC01-Endpoints-Windows-Test"])
    assert result.exit_code == 0, result.output + result.stderr
    assert seen["name_or_uuid"] == "ABC01-Endpoints-Windows-Test"
    assert seen["kwargs"]["strip_env_suffix"] is True
    assert "imported policy" in result.output


def test_import_policy_passes_no_strip_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    fake_model = Policy(name="ABC01-Endpoints-Windows", platform=Platform.windows)

    seen: dict[str, Any] = {}

    def fake_import(client: Any, name_or_uuid: str, **kwargs: Any) -> ImportResult:
        seen["kwargs"] = kwargs
        return ImportResult(kind="policy", slug="abc", model=fake_model, path=None)

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_policy", fake_import)

    result = runner.invoke(app, ["import", "policy", "Whatever", "--no-strip-env-suffix"])
    assert result.exit_code == 0, result.output + result.stderr
    assert seen["kwargs"]["strip_env_suffix"] is False


def test_import_policy_surfaces_importer_error(
    monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    def fake_import(*_args: Any, **_kwargs: Any) -> ImportResult:
        raise ImporterError("policy 'foo' not found")

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_policy", fake_import)

    result = runner.invoke(app, ["import", "policy", "foo"])
    assert result.exit_code == 1
    assert "not found" in result.stderr


def test_import_rule_group_writes_subdir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    fake_model = RuleGroup(name="windows-baseline", platform=Platform.windows)
    written = tmp_path / "rule_groups" / "windows-baseline.yaml"

    seen: dict[str, Any] = {}

    def fake_import(client: Any, name_or_uuid: str, **kwargs: Any) -> ImportResult:
        seen["kwargs"] = kwargs
        return ImportResult(
            kind="rule-group", slug="windows-baseline", model=fake_model, path=written
        )

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_rule_group", fake_import)

    result = runner.invoke(app, ["import", "rule-group", "windows-baseline"])
    assert result.exit_code == 0, result.output + result.stderr
    assert "rule-group" in result.output


def test_import_location_writes_subdir(monkeypatch: pytest.MonkeyPatch, runner: CliRunner) -> None:
    fake_model = Location(name="corp-vpn")

    def fake_import(client: Any, name_or_uuid: str, **kwargs: Any) -> ImportResult:
        return ImportResult(kind="location", slug="corp-vpn", model=fake_model, path=None)

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_location", fake_import)

    result = runner.invoke(app, ["import", "location", "corp-vpn"])
    assert result.exit_code == 0
    assert "imported location" in result.output


def test_import_all_tabulates_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    rg = RuleGroup(name="windows-baseline", platform=Platform.windows)
    loc = Location(name="corp-vpn")
    pol = Policy(name="ABC01-Endpoints-Windows", platform=Platform.windows)

    def fake_import_all(client: Any, output_dir: Path) -> list[ImportResult]:
        return [
            ImportResult(
                kind="rule-group", slug="windows-baseline", model=rg, path=output_dir / "x"
            ),
            ImportResult(kind="location", slug="corp-vpn", model=loc, path=output_dir / "y"),
            ImportResult(
                kind="policy", slug="abc01-endpoints-windows", model=pol, path=output_dir / "z"
            ),
        ]

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_all", fake_import_all)

    result = runner.invoke(app, ["import", "all", "--output-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "rule-group" in result.output
    assert "location" in result.output
    assert "policy" in result.output


def test_import_all_creates_target_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    target = tmp_path / "new-repo"

    captured: dict[str, Any] = {}

    def fake_import_all(client: Any, output_dir: Path) -> list[ImportResult]:
        captured["output_dir"] = output_dir
        return []

    monkeypatch.setattr(
        "csfwctl.import_cmd._build_client", lambda profile, credentials_file: "FAKE-CLIENT"
    )
    monkeypatch.setattr("csfwctl.import_cmd.import_all", fake_import_all)

    result = runner.invoke(app, ["import", "all", "--output-dir", str(target)])
    assert result.exit_code == 0
    assert captured["output_dir"] == target.resolve()
    assert target.is_dir()


# ---- record-fixtures ------------------------------------------------------


def test_record_fixtures_writes_to_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    """End-to-end smoke for the CLI command body."""
    from csfwctl.fixtures import Operation, RecordResult

    monkeypatch.setattr(
        "csfwctl.record_fixtures_cmd.load_credentials",
        lambda profile, credentials_path=None: __import__(
            "csfwctl.config", fromlist=["Credentials"]
        ).Credentials(
            client_id="x", client_secret="y", base_url="https://api", profile="env", source="env"
        ),
    )

    # Replace FalconClient so we don't hit auth.
    class _FakeClient:
        pass

    monkeypatch.setattr("csfwctl.record_fixtures_cmd.FalconClient", lambda creds: _FakeClient())

    def fake_record(
        client: Any, output_dir: Path, *, operations: Any, sanitizer: Any
    ) -> list[RecordResult]:
        # Pretend to write one fixture.
        path = output_dir / "ok.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}", encoding="utf-8")
        return [RecordResult(filename="ok.json", path=path, bytes_written=2)]

    monkeypatch.setattr("csfwctl.record_fixtures_cmd.record_fixtures", fake_record)
    monkeypatch.setattr(
        "csfwctl.record_fixtures_cmd.default_operations",
        lambda: [Operation(filename="ok.json", runner=lambda c: {})],
    )

    result = runner.invoke(app, ["record-fixtures", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output + result.stderr
    assert "ok.json" in result.output


def test_record_fixtures_unknown_operation_errors_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, runner: CliRunner
) -> None:
    monkeypatch.setattr(
        "csfwctl.record_fixtures_cmd.load_credentials",
        lambda profile, credentials_path=None: __import__(
            "csfwctl.config", fromlist=["Credentials"]
        ).Credentials(
            client_id="x", client_secret="y", base_url="https://api", profile="env", source="env"
        ),
    )
    monkeypatch.setattr("csfwctl.record_fixtures_cmd.FalconClient", lambda creds: object())

    result = runner.invoke(
        app, ["record-fixtures", "--operations", "no-such-op", "--output", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "no operations selected" in result.stderr
