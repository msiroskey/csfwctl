"""Tests for Rule and Endpoint models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from csfwctl.schema import Action, Direction, Endpoint, Protocol, Rule


def test_rule_minimum_fields() -> None:
    rule = Rule(
        name="allow https", action=Action.allow, direction=Direction.outbound, protocol=Protocol.tcp
    )
    assert rule.enabled is True
    assert rule.locations == ["any"]
    assert rule.local is None
    assert rule.remote is None


def test_rule_locations_must_be_slugs_or_any() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=Protocol.tcp,
            locations=["NotASlug"],
        )


def test_rule_locations_cannot_be_empty() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=Protocol.tcp,
            locations=[],
        )


def test_rule_state_only_for_tcp_or_any() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.inbound,
            protocol=Protocol.udp,
            state="established",
        )


def test_endpoint_validates_addresses() -> None:
    ep = Endpoint(addresses=["10.0.0.1", "192.168.0.0/16"])
    assert ep.addresses == ["10.0.0.1", "192.168.0.0/16"]


def test_endpoint_rejects_bad_address() -> None:
    with pytest.raises(ValidationError):
        Endpoint(addresses=["not-an-ip"])


@pytest.mark.parametrize("port", [1, 65535, 80, "1000-2000"])
def test_endpoint_accepts_valid_ports(port: int | str) -> None:
    ep = Endpoint(ports=[port])
    assert ep.ports == [port]


@pytest.mark.parametrize("port", [0, 65536, -1, "100-50", "abc", "1-2-3"])
def test_endpoint_rejects_invalid_ports(port: int | str) -> None:
    with pytest.raises(ValidationError):
        Endpoint(ports=[port])


def test_endpoint_negation_requires_values() -> None:
    with pytest.raises(ValidationError):
        Endpoint(addresses_negated=True)
    with pytest.raises(ValidationError):
        Endpoint(ports_negated=True)


def test_rule_referenced_locations_excludes_any() -> None:
    rule = Rule(
        name="r",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        locations=["any", "corp-vpn"],
    )
    assert rule.referenced_locations() == {"corp-vpn"}
