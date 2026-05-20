"""Tests for request-ID propagation and structured logger setup."""

from __future__ import annotations

import io
import json
import logging

from csfwctl.observability import (
    LogFormat,
    configure_logging,
    current_request_id,
    get_logger,
    new_request_id,
    set_request_id,
)


def test_new_request_id_format() -> None:
    rid = new_request_id()
    assert rid.startswith("req_")
    assert len(rid) == 16  # "req_" + 12 hex


def test_request_id_round_trips() -> None:
    set_request_id("req_test123456")
    assert current_request_id() == "req_test123456"


def test_text_formatter_emits_request_id() -> None:
    buf = io.StringIO()
    configure_logging(LogFormat.text, level=logging.INFO, stream=buf)
    set_request_id("req_abc123")

    get_logger("test").info("hello", extra={"event": "demo", "value": 7})

    output = buf.getvalue()
    assert "req_abc123" in output
    assert "csfwctl.test" in output
    assert "hello" in output
    assert "event='demo'" in output
    assert "value=7" in output


def test_json_formatter_is_valid_jsonl() -> None:
    buf = io.StringIO()
    configure_logging(LogFormat.json, level=logging.INFO, stream=buf)
    set_request_id("req_json01")

    get_logger("test").info("hello", extra={"event": "demo", "value": 7})

    line = buf.getvalue().strip().splitlines()[-1]
    payload = json.loads(line)
    assert payload["request_id"] == "req_json01"
    assert payload["message"] == "hello"
    assert payload["event"] == "demo"
    assert payload["value"] == 7
    assert payload["level"] == "INFO"
    assert payload["logger"] == "csfwctl.test"


def test_configure_logging_is_idempotent() -> None:
    buf = io.StringIO()
    configure_logging(LogFormat.text, stream=buf)
    configure_logging(LogFormat.text, stream=buf)
    handlers = [
        h for h in logging.getLogger("csfwctl").handlers if getattr(h, "_csfwctl_handler", False)
    ]
    assert len(handlers) == 1


def test_quiet_raises_level_to_warning() -> None:
    buf = io.StringIO()
    configure_logging(LogFormat.text, level=logging.INFO, quiet=True, stream=buf)
    get_logger("test").info("should not appear")
    get_logger("test").warning("should appear")
    output = buf.getvalue()
    assert "should not appear" not in output
    assert "should appear" in output
