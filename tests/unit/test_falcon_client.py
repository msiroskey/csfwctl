"""Tests for the FalconClient wrapper (retry + logging behavior)."""

from __future__ import annotations

from typing import Any

import pytest

from csfwctl.config import Credentials
from csfwctl.falcon.client import FalconAPIError, FalconClient


def _creds() -> Credentials:
    return Credentials(
        client_id="cid",
        client_secret="secret",
        base_url="https://api.crowdstrike.com",
        profile="test",
        source="test",
    )


def _make_client(**overrides: Any) -> tuple[FalconClient, list[float]]:
    """Build a client whose ``sleep`` is recorded rather than executed."""
    sleeps: list[float] = []

    defaults = dict(
        max_attempts=4,
        base_backoff_seconds=0.01,
        max_backoff_seconds=1.0,
        sleep=sleeps.append,
    )
    defaults.update(overrides)
    client = FalconClient(_creds(), **defaults)  # type: ignore[arg-type]
    return client, sleeps


def test_call_returns_dict_on_success() -> None:
    client, sleeps = _make_client()

    def ok() -> dict[str, Any]:
        return {"status_code": 200, "headers": {}, "body": {"resources": [1, 2, 3]}}

    result = client.call("test.op", ok)
    assert result["status_code"] == 200
    assert result["body"] == {"resources": [1, 2, 3]}
    assert sleeps == []


def test_call_raises_on_non_retryable_client_error() -> None:
    client, sleeps = _make_client()

    def bad() -> dict[str, Any]:
        return {"status_code": 404, "headers": {}, "body": {"errors": ["not found"]}}

    with pytest.raises(FalconAPIError) as excinfo:
        client.call("test.op", bad)
    assert excinfo.value.status == 404
    assert sleeps == []


def test_call_retries_then_succeeds() -> None:
    client, sleeps = _make_client()
    responses_seq = [
        {"status_code": 503, "headers": {}, "body": {}},
        {"status_code": 502, "headers": {}, "body": {}},
        {"status_code": 200, "headers": {}, "body": {"ok": True}},
    ]

    def flaky() -> dict[str, Any]:
        return responses_seq.pop(0)

    result = client.call("test.op", flaky)
    assert result["status_code"] == 200
    assert len(sleeps) == 2
    assert sleeps[0] < sleeps[1]  # exponential


def test_call_eventually_raises_after_exhausting_retries() -> None:
    client, sleeps = _make_client()

    def always_503() -> dict[str, Any]:
        return {"status_code": 503, "headers": {}, "body": {}}

    with pytest.raises(FalconAPIError) as excinfo:
        client.call("test.op", always_503)
    assert excinfo.value.status == 503
    assert len(sleeps) == 3  # max_attempts=4 → 3 sleeps before final failure


def test_call_honors_retry_after_header_on_429() -> None:
    client, sleeps = _make_client()
    responses_seq = [
        {"status_code": 429, "headers": {"Retry-After": "0.5"}, "body": {}},
        {"status_code": 200, "headers": {}, "body": {}},
    ]

    def rate_limited() -> dict[str, Any]:
        return responses_seq.pop(0)

    client.call("test.op", rate_limited)
    assert sleeps == [0.5]


def test_call_caps_retry_after_at_max_backoff() -> None:
    client, sleeps = _make_client(max_backoff_seconds=2.0)
    responses_seq = [
        {"status_code": 429, "headers": {"X-Ratelimit-Retryafter": "9999"}, "body": {}},
        {"status_code": 200, "headers": {}, "body": {}},
    ]

    def rate_limited() -> dict[str, Any]:
        return responses_seq.pop(0)

    client.call("test.op", rate_limited)
    assert sleeps == [2.0]


def test_call_normalizes_pythonic_response() -> None:
    client, _ = _make_client()

    class FakeResponse:
        status_code = 200
        headers: dict[str, str] = {}
        body: dict[str, Any] = {"resources": []}

    def returns_object() -> FakeResponse:
        return FakeResponse()

    result = client.call("test.op", returns_object)
    assert result["status_code"] == 200
    assert result["body"] == {"resources": []}


def test_client_binds_request_id() -> None:
    client, _ = _make_client(request_id="req_explicit01")
    assert client.request_id == "req_explicit01"
