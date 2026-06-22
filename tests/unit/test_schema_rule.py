"""Tests for Rule and Endpoint models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from csfwctl.schema import Action, ConnectionState, Direction, Endpoint, Protocol, Rule


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


@pytest.mark.parametrize("proto", [Protocol.any, Protocol.icmp, Protocol.gre])
def test_rule_rejects_ports_without_tcp_or_udp(proto: Protocol) -> None:
    """CrowdStrike rejects ports unless the protocol is tcp or udp."""
    with pytest.raises(ValidationError, match="ports require protocol tcp or udp"):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=proto,
            remote=Endpoint(ports=[443]),
        )


@pytest.mark.parametrize("proto", [Protocol.tcp, Protocol.udp])
def test_rule_allows_ports_for_tcp_and_udp(proto: Protocol) -> None:
    rule = Rule(
        name="ok",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=proto,
        remote=Endpoint(ports=[443, "8000-8100"]),
    )
    assert rule.remote is not None
    assert rule.remote.ports == [443, "8000-8100"]


def test_rule_allows_ports_with_raw_protocol_number() -> None:
    """Raw-integer 'Advanced' protocols are left to the user (no port check)."""
    rule = Rule(
        name="advanced",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=6,  # raw TCP, Advanced mode
        remote=Endpoint(ports=[443]),
    )
    assert rule.remote is not None and rule.remote.ports == [443]


def test_rule_accepts_file_path_glob() -> None:
    rule = Rule(
        name="updater",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        file_path=r"C:\Program Files\app\*.exe",
    )
    assert rule.file_path == r"C:\Program Files\app\*.exe"


def test_rule_accepts_macos_file_path_glob() -> None:
    """file_path is platform-agnostic: macOS path format is accepted too."""
    rule = Rule(
        name="updater",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        file_path="/Applications/App.app/Contents/MacOS/*",
    )
    assert rule.file_path == "/Applications/App.app/Contents/MacOS/*"


def test_rule_file_path_defaults_to_none() -> None:
    rule = Rule(name="x", action=Action.allow, direction=Direction.outbound, protocol=Protocol.tcp)
    assert rule.file_path is None


def test_rule_rejects_empty_file_path() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=Protocol.tcp,
            file_path="   ",
        )


def test_rule_rejects_overlong_file_path() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=Protocol.tcp,
            file_path="C:\\" + "a" * 1000,
        )


def test_rule_accepts_service_name() -> None:
    rule = Rule(
        name="dhcp service",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.udp,
        file_path=r"%SystemRoot%\System32\svchost.exe",
        service_name="Dhcp",
    )
    assert rule.service_name == "Dhcp"


def test_rule_service_name_defaults_to_none() -> None:
    rule = Rule(name="x", action=Action.allow, direction=Direction.outbound, protocol=Protocol.tcp)
    assert rule.service_name is None


def test_rule_rejects_empty_service_name() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=Protocol.tcp,
            service_name="   ",
        )


def test_rule_rejects_overlong_service_name() -> None:
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            action=Action.allow,
            direction=Direction.outbound,
            protocol=Protocol.tcp,
            service_name="a" * 257,
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


@pytest.mark.parametrize(
    "addr",
    [
        "10.0.0.1",
        "192.168.0.0/16",
        "224.0.0.230-233",  # CS last-octet shorthand
        "10.0.0.1-10.0.0.254",  # full range
    ],
)
def test_endpoint_accepts_ip_range_addresses(addr: str) -> None:
    ep = Endpoint(addresses=[addr])
    assert ep.addresses == [addr]


@pytest.mark.parametrize(
    "addr",
    [
        "not-an-ip",
        "10.0.0.254-10.0.0.1",  # end before start
        "10.0.0.1-999",  # last octet out of range
    ],
)
def test_endpoint_rejects_bad_addresses(addr: str) -> None:
    with pytest.raises(ValidationError):
        Endpoint(addresses=[addr])


@pytest.mark.parametrize(
    "proto",
    [
        Protocol.igmp,
        Protocol.ipip,
        Protocol.ipv6,
        Protocol.gre,
        Protocol.icmpv6,
    ],
)
def test_rule_accepts_new_named_protocols(proto: Protocol) -> None:
    rule = Rule(name="test", action=Action.allow, direction=Direction.inbound, protocol=proto)
    assert rule.protocol is proto


@pytest.mark.parametrize("proto_num", [0, 89, 255])
def test_rule_accepts_raw_protocol_number(proto_num: int) -> None:
    rule = Rule(name="test", action=Action.allow, direction=Direction.outbound, protocol=proto_num)
    assert rule.protocol == proto_num


def test_rule_rejects_protocol_number_out_of_range() -> None:
    with pytest.raises(ValidationError):
        Rule(name="test", action=Action.allow, direction=Direction.outbound, protocol=256)


def test_rule_state_allowed_with_raw_protocol_number() -> None:
    # Raw int protocols bypass the tcp-only state check; user controls this.
    rule = Rule(
        name="test",
        action=Action.allow,
        direction=Direction.inbound,
        protocol=6,  # TCP by number
        state=ConnectionState.established,
    )
    assert rule.state is ConnectionState.established


def test_rule_referenced_locations_excludes_any() -> None:
    rule = Rule(
        name="r",
        action=Action.allow,
        direction=Direction.outbound,
        protocol=Protocol.tcp,
        locations=["any", "corp-vpn"],
    )
    assert rule.referenced_locations() == {"corp-vpn"}
