"""Tests for Location, Tombstones, PrecedenceOverrides, ToolConfig."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from csfwctl.schema import (
    Location,
    PrecedenceOverride,
    PrecedenceOverrides,
    Tombstones,
    ToolConfig,
)


def test_location_validates_ips() -> None:
    loc = Location(
        name="corp-vpn",
        addresses=["10.0.0.0/8", "192.168.1.1"],
        dns_servers=["10.1.1.53"],
    )
    assert loc.addresses == ["10.0.0.0/8", "192.168.1.1"]


def test_location_rejects_bad_ip() -> None:
    with pytest.raises(ValidationError):
        Location(name="corp-vpn", addresses=["not-an-ip"])


def test_tombstones_no_dupe_names_within_kind() -> None:
    with pytest.raises(ValidationError):
        Tombstones.model_validate(
            {
                "rule_groups": [
                    {"name": "x", "deleted_in_sha": "abc1234", "reason": "r"},
                    {"name": "x", "deleted_in_sha": "def5678", "reason": "r"},
                ]
            }
        )


def test_tombstone_sha_must_be_hex() -> None:
    with pytest.raises(ValidationError):
        Tombstones.model_validate(
            {"rule_groups": [{"name": "x", "deleted_in_sha": "zzzzzzz", "reason": "r"}]}
        )


def test_precedence_override_distinct() -> None:
    with pytest.raises(ValidationError):
        PrecedenceOverride(before="a", after="a")


def test_precedence_overrides_no_duplicate_pairs() -> None:
    with pytest.raises(ValidationError):
        PrecedenceOverrides.model_validate(
            {
                "overrides": [
                    {"before": "a", "after": "b"},
                    {"before": "a", "after": "b"},
                ]
            }
        )


def test_tool_config_defaults() -> None:
    cfg = ToolConfig()
    assert cfg.tool.metadata_signature == "Managed by csfwctl"
    assert cfg.safety.max_deletes == 1
    assert cfg.safety.max_changes == 10
    assert cfg.notifications == {}


def test_tool_config_accepts_notifier_section() -> None:
    cfg = ToolConfig.model_validate(
        {"notifications": {"teams": {"events": ["apply.*"], "url_env": "X"}}}
    )
    assert "teams" in cfg.notifications
    assert cfg.notifications["teams"].events == ["apply.*"]
