"""Tests for the Policy and RuleGroup models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from csfwctl.schema import (
    Action,
    Direction,
    Platform,
    Policy,
    PrecedenceBucket,
    Protocol,
    Rule,
    RuleGroup,
    Status,
)


def _sample_rule(name: str = "r") -> Rule:
    return Rule(
        name=name,
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
    )


def test_policy_defaults() -> None:
    p = Policy(name="abc01-endpoints-windows", platform=Platform.windows)
    assert p.priority is PrecedenceBucket.default
    assert p.status is Status.enabled
    assert p.host_groups == {}
    assert p.rules == []
    assert p.rule_groups == []


def test_policy_rejects_titlecase_name() -> None:
    with pytest.raises(ValidationError):
        Policy(name="ABC01-Endpoints-Windows", platform=Platform.windows)


def test_policy_rule_groups_must_be_slugs() -> None:
    with pytest.raises(ValidationError):
        Policy(
            name="abc01",
            platform=Platform.windows,
            rule_groups=["NotASlug"],
        )


def test_policy_rejects_duplicate_rule_group_refs() -> None:
    with pytest.raises(ValidationError):
        Policy(
            name="abc01",
            platform=Platform.windows,
            rule_groups=["windows-baseline", "windows-baseline"],
        )


def test_policy_rejects_duplicate_inline_rule_names() -> None:
    with pytest.raises(ValidationError):
        Policy(
            name="abc01",
            platform=Platform.windows,
            rules=[_sample_rule("dup"), _sample_rule("dup")],
        )


def test_policy_rejects_two_host_groups_in_same_env() -> None:
    with pytest.raises(ValidationError):
        Policy(
            name="abc01",
            platform=Platform.windows,
            host_groups={
                "Group-One-Test": "test",
                "Group-Two-Test": "test",
            },
        )


def test_policy_skip_unassigned_envs_defaults_off() -> None:
    p = Policy(name="abc01-endpoints-windows", platform=Platform.windows)
    assert p.skip_unassigned_envs is False
    assert p.tombstone_unassigned_envs is False


def test_policy_tombstone_requires_skip_flag() -> None:
    with pytest.raises(ValidationError, match="tombstone_unassigned_envs requires"):
        Policy(
            name="abc01",
            platform=Platform.windows,
            tombstone_unassigned_envs=True,
        )


def test_policy_tombstone_with_skip_is_valid() -> None:
    p = Policy(
        name="abc01",
        platform=Platform.windows,
        skip_unassigned_envs=True,
        tombstone_unassigned_envs=True,
    )
    assert p.skip_unassigned_envs is True
    assert p.tombstone_unassigned_envs is True


def test_rule_group_name_must_be_slug() -> None:
    with pytest.raises(ValidationError):
        RuleGroup(name="WindowsBaseline", platform=Platform.windows)


def test_rule_group_rejects_duplicate_rule_names() -> None:
    with pytest.raises(ValidationError):
        RuleGroup(
            name="windows-baseline",
            platform=Platform.windows,
            rules=[_sample_rule("dup"), _sample_rule("dup")],
        )


def test_extra_keys_forbidden() -> None:
    with pytest.raises(ValidationError):
        Policy.model_validate(
            {
                "name": "abc01",
                "platform": "windows",
                "unknown_field": True,
            }
        )
