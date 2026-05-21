"""Tests for the credentials loader."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

from csfwctl.config import (
    DEFAULT_BASE_URL,
    Credentials,
    CredentialsError,
    load_credentials,
)


def _write_creds(path: Path, content: str) -> Path:
    """Write a credentials file with 0o600 perms so the loader accepts it."""
    path.write_text(content)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def _restore_csfwctl_propagation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-enable propagation on the ``csfwctl`` logger so caplog can capture.

    ``configure_logging`` (used by other test modules and by the CLI)
    sets ``propagate = False`` on the package logger, which prevents
    ``caplog``'s root-attached handler from receiving child records.
    """
    monkeypatch.setattr(logging.getLogger("csfwctl"), "propagate", True)


def test_env_vars_take_precedence(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        '[profile.readonly]\nclient_id = "file-id"\nclient_secret = "file-secret"\n',
    )
    env = {
        "CSFWCTL_CLIENT_ID": "env-id",
        "CSFWCTL_CLIENT_SECRET": "env-secret",
        "CSFWCTL_BASE_URL": "https://api.us-2.crowdstrike.com",
    }
    creds = load_credentials("readonly", credentials_path=creds_file, env=env)
    assert creds.client_id == "env-id"
    assert creds.client_secret == "env-secret"
    assert creds.base_url == "https://api.us-2.crowdstrike.com"
    assert creds.source == "environment"


def test_file_profile_loaded_when_env_missing(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        "[profile.readwrite]\n"
        'client_id = "file-id"\n'
        'client_secret = "file-secret"\n'
        'base_url = "https://api.eu-1.crowdstrike.com"\n',
    )
    creds = load_credentials("readwrite", credentials_path=creds_file, env={})
    assert creds.client_id == "file-id"
    assert creds.client_secret == "file-secret"
    assert creds.base_url == "https://api.eu-1.crowdstrike.com"
    assert creds.profile == "readwrite"
    assert creds.source == str(creds_file)


def test_default_base_url_when_unset(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        '[profile.readonly]\nclient_id = "id"\nclient_secret = "secret"\n',
    )
    creds = load_credentials("readonly", credentials_path=creds_file, env={})
    assert creds.base_url == DEFAULT_BASE_URL


def test_missing_file_and_no_env_raises(tmp_path: Path) -> None:
    with pytest.raises(CredentialsError, match="No credentials found"):
        load_credentials("readonly", credentials_path=tmp_path / "missing.toml", env={})


def test_unknown_profile_lists_available(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        "[profile.alpha]\n"
        'client_id = "x"\n'
        'client_secret = "y"\n'
        "[profile.beta]\n"
        'client_id = "x"\n'
        'client_secret = "y"\n',
    )
    with pytest.raises(CredentialsError, match="alpha, beta"):
        load_credentials("gamma", credentials_path=creds_file, env={})


def test_profile_missing_required_field(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        '[profile.readonly]\nclient_id = "x"\n',
    )
    with pytest.raises(CredentialsError, match="client_secret"):
        load_credentials("readonly", credentials_path=creds_file, env={})


def test_invalid_toml(tmp_path: Path) -> None:
    creds_file = _write_creds(tmp_path / "credentials.toml", "not = valid = toml")
    with pytest.raises(CredentialsError, match="invalid TOML"):
        load_credentials("readonly", credentials_path=creds_file, env={})


def test_env_credentials_path_expands_user_and_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        '[profile.dev]\nclient_id = "dev-id"\nclient_secret = "dev-secret"\n',
    )
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CSFWCTL_CREDS_DIR", str(tmp_path))

    creds = load_credentials(
        "dev",
        env={"CSFWCTL_CREDENTIALS_PATH": "$CSFWCTL_CREDS_DIR/credentials.toml"},
    )
    assert creds.client_id == "dev-id"
    assert creds.source == str(creds_file)

    creds = load_credentials(
        "dev",
        env={"CSFWCTL_CREDENTIALS_PATH": "~/credentials.toml"},
    )
    assert creds.client_id == "dev-id"


def test_explicit_path_arg_overrides_env_credentials_path(tmp_path: Path) -> None:
    """The ``credentials_path=`` argument wins over $CSFWCTL_CREDENTIALS_PATH."""
    arg_file = _write_creds(
        tmp_path / "arg.toml",
        '[profile.readonly]\nclient_id = "arg-id"\nclient_secret = "arg-secret"\n',
    )
    env_file = _write_creds(
        tmp_path / "env.toml",
        '[profile.readonly]\nclient_id = "env-id"\nclient_secret = "env-secret"\n',
    )

    creds = load_credentials(
        "readonly",
        credentials_path=arg_file,
        env={"CSFWCTL_CREDENTIALS_PATH": str(env_file)},
    )
    assert creds.client_id == "arg-id"
    assert creds.source == str(arg_file)


def test_logs_warn_when_credentials_path_ignored_due_to_env_vars(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    _restore_csfwctl_propagation: None,
) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        '[profile.readonly]\nclient_id = "file-id"\nclient_secret = "file-secret"\n',
    )
    env = {
        "CSFWCTL_CLIENT_ID": "env-id",
        "CSFWCTL_CLIENT_SECRET": "env-secret",
        "CSFWCTL_CREDENTIALS_PATH": str(creds_file),
    }
    with caplog.at_level("INFO", logger="csfwctl.config"):
        creds = load_credentials("readonly", env=env)
    assert creds.source == "environment"
    messages = [r.getMessage() for r in caplog.records]
    assert any("ignored" in m and "CSFWCTL_CREDENTIALS_PATH" in m for m in messages)


def test_logs_source_when_loaded_from_file(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    _restore_csfwctl_propagation: None,
) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        '[profile.readonly]\nclient_id = "file-id"\nclient_secret = "file-secret"\n',
    )
    with caplog.at_level("INFO", logger="csfwctl.config"):
        load_credentials("readonly", credentials_path=creds_file, env={})
    messages = [r.getMessage() for r in caplog.records]
    assert any(str(creds_file) in m and "profile=readonly" in m for m in messages)


# ---- Hardening: permissions + scheme checks --------------------------------


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_world_readable_credentials_file_refused(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text('[profile.readonly]\nclient_id = "x"\nclient_secret = "y"\n')
    os.chmod(creds_file, 0o644)
    with pytest.raises(CredentialsError, match="group/world bits set"):
        load_credentials("readonly", credentials_path=creds_file, env={})


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_group_readable_credentials_file_refused(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text('[profile.readonly]\nclient_id = "x"\nclient_secret = "y"\n')
    os.chmod(creds_file, 0o640)
    with pytest.raises(CredentialsError, match="group/world bits set"):
        load_credentials("readonly", credentials_path=creds_file, env={})


def test_http_base_url_refused_via_env(tmp_path: Path) -> None:
    env = {
        "CSFWCTL_CLIENT_ID": "id",
        "CSFWCTL_CLIENT_SECRET": "secret",
        "CSFWCTL_BASE_URL": "http://api.crowdstrike.com",
    }
    with pytest.raises(CredentialsError, match="must use https://"):
        load_credentials("readonly", credentials_path=tmp_path / "x.toml", env=env)


def test_http_base_url_refused_via_file(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        "[profile.readonly]\n"
        'client_id = "x"\n'
        'client_secret = "y"\n'
        'base_url = "http://api.crowdstrike.com"\n',
    )
    with pytest.raises(CredentialsError, match="must use https://"):
        load_credentials("readonly", credentials_path=creds_file, env={})


def test_http_loopback_base_url_accepted_for_local_testing(tmp_path: Path) -> None:
    creds_file = _write_creds(
        tmp_path / "credentials.toml",
        "[profile.readonly]\n"
        'client_id = "x"\n'
        'client_secret = "y"\n'
        'base_url = "http://localhost:8080"\n',
    )
    creds = load_credentials("readonly", credentials_path=creds_file, env={})
    assert creds.base_url == "http://localhost:8080"


def test_credentials_redacted_hides_secret() -> None:
    creds = Credentials(
        client_id="abcdef123456",
        client_secret="super-secret-value",
        base_url="https://api.crowdstrike.com",
        profile="readonly",
        source="environment",
    )
    redacted = creds.redacted()
    assert "super-secret-value" not in str(redacted)
    assert redacted["client_id_prefix"].startswith("abcdef")
    assert redacted["profile"] == "readonly"
