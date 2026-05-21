"""Credential and runtime configuration loading.

Credentials come from one of two sources, in order:

1. Environment variables ``CSFWCTL_CLIENT_ID`` / ``CSFWCTL_CLIENT_SECRET``
   (plus optional ``CSFWCTL_BASE_URL``). Used by CI.
2. A TOML file (default ``/etc/csfwctl/credentials.toml``) with one
   section per named profile::

       [profile.readonly]
       client_id = "..."
       client_secret = "..."
       # base_url optional; defaults to api.crowdstrike.com

       [profile.readwrite]
       client_id = "..."
       client_secret = "..."

Env vars take precedence over the file. Missing credentials raise
:class:`CredentialsError` rather than falling through to FalconPy's
runtime errors, so the CLI can surface a clear message.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from csfwctl.observability import get_logger

_logger = get_logger("config")

DEFAULT_CREDENTIALS_PATH = Path("/etc/csfwctl/credentials.toml")
DEFAULT_BASE_URL = "https://api.crowdstrike.com"
DEFAULT_PROFILE = "readonly"

ENV_CLIENT_ID = "CSFWCTL_CLIENT_ID"
ENV_CLIENT_SECRET = "CSFWCTL_CLIENT_SECRET"  # noqa: S105 — env-var name, not a secret
ENV_BASE_URL = "CSFWCTL_BASE_URL"
ENV_CREDENTIALS_PATH = "CSFWCTL_CREDENTIALS_PATH"


class CredentialsError(Exception):
    """Raised when credentials cannot be loaded or are malformed."""


@dataclass(frozen=True)
class Credentials:
    """An immutable set of CrowdStrike API credentials."""

    client_id: str
    client_secret: str
    base_url: str = DEFAULT_BASE_URL
    profile: str = "env"
    source: str = "environment"

    def redacted(self) -> dict[str, str]:
        """Mapping safe to log: secrets are reduced to a short prefix."""
        return {
            "client_id_prefix": self.client_id[:6] + "…" if self.client_id else "",
            "base_url": self.base_url,
            "profile": self.profile,
            "source": self.source,
        }


def load_credentials(
    profile: str | None = None,
    *,
    credentials_path: Path | None = None,
    env: dict[str, str] | None = None,
) -> Credentials:
    """Load credentials, preferring env vars, then the TOML file.

    ``profile`` defaults to ``readonly``. ``credentials_path`` defaults
    to ``$CSFWCTL_CREDENTIALS_PATH`` if set, otherwise
    ``/etc/csfwctl/credentials.toml``. When sourced from the env var,
    ``~`` and ``$VAR`` references are expanded. ``env`` is injectable
    for tests; defaults to ``os.environ``.
    """
    env_map = os.environ if env is None else env

    client_id_env = env_map.get(ENV_CLIENT_ID)
    client_secret_env = env_map.get(ENV_CLIENT_SECRET)
    env_id_set = bool(client_id_env)
    env_secret_set = bool(client_secret_env)
    credentials_path_env = env_map.get(ENV_CREDENTIALS_PATH)

    if client_id_env and client_secret_env:
        if credentials_path_env:
            _logger.info(
                "credentials resolved from environment variables; "
                "%s=%r is set but ignored because both %s and %s are also set",
                ENV_CREDENTIALS_PATH,
                credentials_path_env,
                ENV_CLIENT_ID,
                ENV_CLIENT_SECRET,
                extra={
                    "event": "credentials.resolve",
                    "selected_source": "environment",
                    "env_client_id_set": env_id_set,
                    "env_client_secret_set": env_secret_set,
                    "env_credentials_path": credentials_path_env,
                    "credentials_path_ignored": True,
                },
            )
        else:
            _logger.info(
                "credentials resolved from environment variables (%s, %s)",
                ENV_CLIENT_ID,
                ENV_CLIENT_SECRET,
                extra={
                    "event": "credentials.resolve",
                    "selected_source": "environment",
                    "env_client_id_set": env_id_set,
                    "env_client_secret_set": env_secret_set,
                },
            )
        return Credentials(
            client_id=client_id_env,
            client_secret=client_secret_env,
            base_url=env_map.get(ENV_BASE_URL, DEFAULT_BASE_URL),
            profile="env",
            source="environment",
        )

    profile_name = profile or DEFAULT_PROFILE
    if credentials_path is not None:
        path = credentials_path
        path_origin = "argument"
    elif credentials_path_env:
        path = Path(os.path.expandvars(credentials_path_env)).expanduser()
        path_origin = f"${ENV_CREDENTIALS_PATH}"
    else:
        path = DEFAULT_CREDENTIALS_PATH
        path_origin = "default"
    _logger.info(
        "credentials resolved from file %s (origin=%s, profile=%s); "
        "env vars considered: %s=%s, %s=%s",
        path,
        path_origin,
        profile_name,
        ENV_CLIENT_ID,
        "set" if env_id_set else "unset",
        ENV_CLIENT_SECRET,
        "set" if env_secret_set else "unset",
        extra={
            "event": "credentials.resolve",
            "selected_source": str(path),
            "path_origin": path_origin,
            "profile": profile_name,
            "env_client_id_set": env_id_set,
            "env_client_secret_set": env_secret_set,
        },
    )
    if not path.is_file():
        raise CredentialsError(
            f"No credentials found: env vars {ENV_CLIENT_ID}/{ENV_CLIENT_SECRET} "
            f"are unset and {path} does not exist."
        )

    try:
        with path.open("rb") as fp:
            data = tomllib.load(fp)
    except OSError as exc:
        raise CredentialsError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise CredentialsError(f"invalid TOML in {path}: {exc}") from exc

    profiles = data.get("profile", {})
    if not isinstance(profiles, dict) or profile_name not in profiles:
        available = ", ".join(sorted(profiles)) if isinstance(profiles, dict) else "(none)"
        raise CredentialsError(
            f"profile {profile_name!r} not found in {path}. Available: {available}"
        )

    entry = profiles[profile_name]
    if not isinstance(entry, dict):
        raise CredentialsError(f"profile {profile_name!r} in {path} is not a table")

    missing = [k for k in ("client_id", "client_secret") if not entry.get(k)]
    if missing:
        raise CredentialsError(
            f"profile {profile_name!r} in {path} is missing required fields: {', '.join(missing)}"
        )

    return Credentials(
        client_id=str(entry["client_id"]),
        client_secret=str(entry["client_secret"]),
        base_url=str(entry.get("base_url", DEFAULT_BASE_URL)),
        profile=profile_name,
        source=str(path),
    )


__all__ = [
    "Credentials",
    "CredentialsError",
    "DEFAULT_BASE_URL",
    "DEFAULT_CREDENTIALS_PATH",
    "DEFAULT_PROFILE",
    "ENV_BASE_URL",
    "ENV_CLIENT_ID",
    "ENV_CLIENT_SECRET",
    "ENV_CREDENTIALS_PATH",
    "load_credentials",
]
