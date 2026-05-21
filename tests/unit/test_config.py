"""Tests for the credentials loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from csfwctl.config import (
    DEFAULT_BASE_URL,
    Credentials,
    CredentialsError,
    load_credentials,
)


def test_env_vars_take_precedence(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text(
        '[profile.readonly]\nclient_id = "file-id"\nclient_secret = "file-secret"\n'
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
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text(
        "[profile.readwrite]\n"
        'client_id = "file-id"\n'
        'client_secret = "file-secret"\n'
        'base_url = "https://api.eu-1.crowdstrike.com"\n'
    )
    creds = load_credentials("readwrite", credentials_path=creds_file, env={})
    assert creds.client_id == "file-id"
    assert creds.client_secret == "file-secret"
    assert creds.base_url == "https://api.eu-1.crowdstrike.com"
    assert creds.profile == "readwrite"
    assert creds.source == str(creds_file)


def test_default_base_url_when_unset(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text('[profile.readonly]\nclient_id = "id"\nclient_secret = "secret"\n')
    creds = load_credentials("readonly", credentials_path=creds_file, env={})
    assert creds.base_url == DEFAULT_BASE_URL


def test_missing_file_and_no_env_raises(tmp_path: Path) -> None:
    with pytest.raises(CredentialsError, match="No credentials found"):
        load_credentials("readonly", credentials_path=tmp_path / "missing.toml", env={})


def test_unknown_profile_lists_available(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text(
        "[profile.alpha]\n"
        'client_id = "x"\n'
        'client_secret = "y"\n'
        "[profile.beta]\n"
        'client_id = "x"\n'
        'client_secret = "y"\n'
    )
    with pytest.raises(CredentialsError, match="alpha, beta"):
        load_credentials("gamma", credentials_path=creds_file, env={})


def test_profile_missing_required_field(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text('[profile.readonly]\nclient_id = "x"\n')
    with pytest.raises(CredentialsError, match="client_secret"):
        load_credentials("readonly", credentials_path=creds_file, env={})


def test_invalid_toml(tmp_path: Path) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text("not = valid = toml")
    with pytest.raises(CredentialsError, match="invalid TOML"):
        load_credentials("readonly", credentials_path=creds_file, env={})


def test_env_credentials_path_expands_user_and_vars(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    creds_file = tmp_path / "credentials.toml"
    creds_file.write_text('[profile.dev]\nclient_id = "dev-id"\nclient_secret = "dev-secret"\n')
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
