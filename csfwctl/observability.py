"""Request-ID propagation and structured logger setup.

Each CLI invocation generates one request ID. Every API call logged
through this module's logger carries that ID, which makes correlating
logs across a single ``csfwctl`` run trivial.

Stdlib ``logging`` is used so downstream notifiers (Phase 8) can attach
handlers without depending on a third-party logging library.
"""

from __future__ import annotations

import contextvars
import json
import logging
import secrets
import sys
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "csfwctl_request_id", default=""
)
"""Per-invocation request ID. Empty string when unset (tests, library use)."""

ROOT_LOGGER_NAME = "csfwctl"


class LogFormat(StrEnum):
    """Output format for log records emitted by the CLI."""

    text = "text"
    json = "json"


def new_request_id() -> str:
    """Generate a fresh short request ID (``req_<12 hex>``)."""
    return f"req_{secrets.token_hex(6)}"


def set_request_id(request_id: str) -> None:
    """Bind ``request_id`` to the current context."""
    _request_id_var.set(request_id)


def current_request_id() -> str:
    """Return the request ID bound to the current context, or ``""``."""
    return _request_id_var.get()


class _TextFormatter(logging.Formatter):
    """Human-readable single-line text output with request-ID prefix."""

    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        rid = current_request_id() or "-"
        base = f"{ts} [{rid}] {record.levelname:5s} {record.name}: {record.getMessage()}"
        extras = _record_extras(record)
        if extras:
            tail = " ".join(f"{k}={v!r}" for k, v in sorted(extras.items()))
            base = f"{base} {tail}"
        if record.exc_info:
            base = f"{base}\n{self.formatException(record.exc_info)}"
        return base


class _JsonFormatter(logging.Formatter):
    """One JSON object per log record (newline-delimited)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": current_request_id(),
        }
        payload.update(_record_extras(record))
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_RESERVED_RECORD_ATTRS = frozenset(
    logging.LogRecord("", logging.INFO, "", 0, "", None, None).__dict__.keys()
) | {"message", "asctime"}


def _record_extras(record: logging.LogRecord) -> dict[str, Any]:
    """Pull caller-supplied ``extra=`` keys off a log record."""
    return {k: v for k, v in record.__dict__.items() if k not in _RESERVED_RECORD_ATTRS}


def configure_logging(
    log_format: LogFormat = LogFormat.text,
    level: int = logging.INFO,
    *,
    quiet: bool = False,
    stream: Any = None,
) -> logging.Logger:
    """Install one stderr handler on the ``csfwctl`` root logger.

    Idempotent: replaces any handlers we previously installed so that
    repeated calls (e.g. across tests) don't double-emit. ``quiet=True``
    raises the level to WARNING regardless of ``level``.
    """
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    for existing in list(logger.handlers):
        if getattr(existing, "_csfwctl_handler", False):
            logger.removeHandler(existing)

    handler = logging.StreamHandler(stream or sys.stderr)
    handler._csfwctl_handler = True  # type: ignore[attr-defined]
    formatter: logging.Formatter
    if log_format is LogFormat.json:
        formatter = _JsonFormatter()
    else:
        formatter = _TextFormatter()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.WARNING if quiet else level)
    logger.propagate = False
    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Get a child logger under the ``csfwctl`` root."""
    if not name:
        return logging.getLogger(ROOT_LOGGER_NAME)
    return logging.getLogger(f"{ROOT_LOGGER_NAME}.{name}")


__all__ = [
    "LogFormat",
    "ROOT_LOGGER_NAME",
    "configure_logging",
    "current_request_id",
    "get_logger",
    "new_request_id",
    "set_request_id",
]
