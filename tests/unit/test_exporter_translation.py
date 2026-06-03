"""Unit tests for individual translation helpers in ``csfwctl.exporter``.

These exercise the API-shape <-> model conversions in isolation, without
touching the Falcon client. End-to-end import behaviour lives in
``test_exporter.py``.
"""

from __future__ import annotations

import pytest

from csfwctl.exporter import (
    ImporterError,
    clean_description,
    display_name_to_slug,
    host_group_env,
    is_override_group_name,
    is_uuid,
    location_from_api,
    location_to_api_shape,
    policy_from_api,
    policy_to_api_shape,
    rule_from_api,
    rule_group_from_api,
    rule_group_to_api_shape,
    strip_env_suffix,
)
from csfwctl.schema import (
    Action,
    ConnectionState,
    Direction,
    Endpoint,
    HostGroupEnv,
    Location,
    Platform,
    Policy,
    PrecedenceBucket,
    Protocol,
    Rule,
    RuleGroup,
    Status,
)

# ---- strip_env_suffix / display_name_to_slug -------------------------------


@pytest.mark.parametrize(
    "name,expected_base,expected_env",
    [
        ("ABC01-Endpoints-Windows-Test", "ABC01-Endpoints-Windows", "test"),
        ("ABC01-Endpoints-Windows-Pilot", "ABC01-Endpoints-Windows", "pilot"),
        ("ABC01-Endpoints-Windows-Production", "ABC01-Endpoints-Windows", "production"),
        ("Research-Lab-7-Windows", "Research-Lab-7-Windows", None),
        ("not-suffixed", "not-suffixed", None),
    ],
)
def test_strip_env_suffix(name: str, expected_base: str, expected_env: str | None) -> None:
    assert strip_env_suffix(name) == (expected_base, expected_env)


def test_display_name_to_slug_strips_suffix_and_lowercases() -> None:
    assert display_name_to_slug("ABC01-Endpoints-Windows-Pilot") == "abc01-endpoints-windows"


def test_display_name_to_slug_normalises_spaces_and_underscores() -> None:
    assert display_name_to_slug("Has Spaces") == "has-spaces"
    assert display_name_to_slug("platform_default") == "platform-default"
    assert display_name_to_slug("cs default-Test") == "cs-default"


def test_display_name_to_slug_rejects_unrepresentable_names() -> None:
    with pytest.raises(ImporterError, match="cannot derive a valid slug"):
        display_name_to_slug("123-Starts-With-Digit")


def test_host_group_env_reads_suffix() -> None:
    assert host_group_env("ABC01-Endpoints-Windows-Test") is HostGroupEnv.test
    assert host_group_env("ABC01-Endpoints-Windows-Pilot") is HostGroupEnv.pilot
    assert host_group_env("ABC01-Endpoints-Windows-Production") is HostGroupEnv.production
    assert host_group_env("ABC01-Endpoints-Windows") is None


# ---- clean_description ----------------------------------------------------


def test_clean_description_strips_metadata_block() -> None:
    raw = (
        "Baseline policy for ABC01 Windows endpoints.\n"
        "Managed by csfwctl | version: 7 | git_sha: abc123 | "
        "applied: 2026-05-19T14:30Z | env: production"
    )
    assert clean_description(raw) == "Baseline policy for ABC01 Windows endpoints."


def test_clean_description_handles_no_signature() -> None:
    assert clean_description("just a description") == "just a description"
    assert clean_description("") == ""
    assert clean_description(None) == ""


# ---- is_uuid / is_override_group_name -------------------------------------


def test_is_uuid_detects_standard_form() -> None:
    assert is_uuid("12345678-1234-1234-1234-123456789abc")
    assert not is_uuid("abc01-endpoints-windows")
    assert not is_uuid("12345678-1234-1234-1234")


def test_is_override_group_name_extracts_policy_base_and_env() -> None:
    assert is_override_group_name("abc01-endpoints-windows-overrides-test") == (
        "abc01-endpoints-windows",
        "test",
    )
    assert is_override_group_name("abc01-endpoints-windows-overrides-production") == (
        "abc01-endpoints-windows",
        "production",
    )
    assert is_override_group_name("windows-baseline") == ("windows-baseline", None)


# ---- rule_from_api --------------------------------------------------------


def test_rule_from_api_minimal() -> None:
    record = {
        "name": "Allow corp DNS outbound",
        "enabled": True,
        "action": "ALLOW",
        "direction": "OUT",
        "protocol": "17",
        "remote": {"addresses": [{"address": "10.1.1.53"}], "ports": [{"start": 53, "end": 53}]},
    }
    rule = rule_from_api(record)
    assert rule.action is Action.allow
    assert rule.direction is Direction.outbound
    assert rule.protocol is Protocol.udp
    assert rule.remote is not None
    assert rule.remote.addresses == ["10.1.1.53"]
    assert rule.remote.ports == [53]
    assert rule.locations == ["any"]
    assert rule.local is None


def test_rule_from_api_with_state_and_port_range() -> None:
    record = {
        "name": "Allow inbound established",
        "action": "ALLOW",
        "direction": "IN",
        "protocol": "6",
        "fields": [{"name": "tcp_state", "value": "established"}],
        "remote": {"ports": [{"start": 1024, "end": 65535}]},
    }
    rule = rule_from_api(record)
    assert rule.state is ConnectionState.established
    assert rule.remote is not None
    assert rule.remote.ports == ["1024-65535"]


def test_rule_from_api_negated_endpoint() -> None:
    record = {
        "name": "Block SMB inbound from non-corp",
        "action": "DENY",
        "direction": "IN",
        "protocol": "6",
        "local": {"ports": [{"start": 445, "end": 445}]},
        "remote": {"addresses_negated": True, "addresses": [{"address": "10.0.0.0/8"}]},
    }
    rule = rule_from_api(record)
    assert rule.action is Action.block
    assert rule.remote is not None
    assert rule.remote.addresses_negated is True
    assert rule.remote.addresses == ["10.0.0.0/8"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("2", Protocol.igmp),
        ("4", Protocol.ipip),
        ("41", Protocol.ipv6),
        ("47", Protocol.gre),
        ("58", Protocol.icmpv6),
        ("ICMPV6", Protocol.icmpv6),
        ("GRE", Protocol.gre),
    ],
)
def test_rule_from_api_new_named_protocols(raw: str, expected: Protocol) -> None:
    record = {"name": "r", "action": "ALLOW", "direction": "IN", "protocol": raw}
    rule = rule_from_api(record)
    assert rule.protocol is expected


def test_rule_from_api_advanced_protocol_number() -> None:
    record = {"name": "r", "action": "ALLOW", "direction": "IN", "protocol": "89"}
    rule = rule_from_api(record)
    assert rule.protocol == 89


def test_rule_from_api_ip_range_address_passes_validation() -> None:
    record = {
        "name": "ICMPv6 Router Solicitation",
        "action": "ALLOW",
        "direction": "OUT",
        "protocol": "58",
        "remote": {"addresses": [{"address": "224.0.0.230-233"}]},
    }
    rule = rule_from_api(record)
    assert rule.protocol is Protocol.icmpv6
    assert rule.remote is not None
    assert rule.remote.addresses == ["224.0.0.230-233"]


def test_rule_from_api_direction_both() -> None:
    record = {
        "name": "Allow Airplay TCP",
        "action": "ALLOW",
        "direction": "BOTH",
        "protocol": "6",
    }
    rule = rule_from_api(record)
    assert rule.direction is Direction.both


def test_rule_from_api_wildcard_address_dropped() -> None:
    record = {
        "name": "Allow all outbound",
        "action": "ALLOW",
        "direction": "OUT",
        "protocol": "6",
        "remote": {"addresses": [{"address": "*"}], "ports": [{"start": 443, "end": 443}]},
    }
    rule = rule_from_api(record)
    assert rule.remote is not None
    assert rule.remote.addresses == []
    assert rule.remote.ports == [443]


def test_rule_from_api_port_end_zero_treated_as_single_port() -> None:
    record = {
        "name": "Allow SSH",
        "action": "ALLOW",
        "direction": "IN",
        "protocol": "6",
        "local": {"ports": [{"start": 22, "end": 0}]},
    }
    rule = rule_from_api(record)
    assert rule.local is not None
    assert rule.local.ports == [22]


def test_rule_from_api_port_both_zero_dropped() -> None:
    record = {
        "name": "Allow all TCP",
        "action": "ALLOW",
        "direction": "OUT",
        "protocol": "6",
        "remote": {"addresses": [{"address": "10.0.0.1"}], "ports": [{"start": 0, "end": 0}]},
    }
    rule = rule_from_api(record)
    assert rule.remote is not None
    assert rule.remote.ports == []


def test_rule_from_api_unknown_action_raises() -> None:
    with pytest.raises(ImporterError, match="unknown action"):
        rule_from_api({"name": "x", "action": "MAYBE", "direction": "IN", "protocol": "6"})


def test_rule_from_api_missing_required_field() -> None:
    with pytest.raises(ImporterError, match="missing required field 'action'"):
        rule_from_api({"name": "x", "direction": "IN", "protocol": "6"})


# ---- rule_group_from_api --------------------------------------------------


def test_rule_group_from_api_inlines_rules_from_lookup() -> None:
    rules_by_id = {
        "r1": {"name": "rule-a", "action": "ALLOW", "direction": "IN", "protocol": "6"},
        "r2": {"name": "rule-b", "action": "DENY", "direction": "OUT", "protocol": "17"},
    }
    record = {
        "name": "windows-baseline-Test",
        "platform": "0",
        "enabled": True,
        "rule_ids": ["r1", "r2"],
    }
    rg = rule_group_from_api(record, rules_by_id)
    assert rg.name == "windows-baseline"
    assert rg.platform is Platform.windows
    assert [r.name for r in rg.rules] == ["rule-a", "rule-b"]


def test_rule_group_from_api_accepts_embedded_rules() -> None:
    record = {
        "name": "windows-baseline",
        "platform": "windows",
        "rules": [{"name": "rule-a", "action": "ALLOW", "direction": "IN", "protocol": "6"}],
        "rule_ids": [],
    }
    rg = rule_group_from_api(record, {}, strip_suffix=False)
    assert [r.name for r in rg.rules] == ["rule-a"]


def test_rule_group_from_api_missing_rule_id_raises() -> None:
    record = {"name": "win", "platform": "windows", "rule_ids": ["missing"]}
    with pytest.raises(ImporterError, match="references rule 'missing'"):
        rule_group_from_api(record, {})


# ---- location_from_api ----------------------------------------------------


def test_location_from_api_normalises_nested_address_dicts() -> None:
    record = {
        "name": "corp-vpn",
        "description": "Corporate VPN address ranges",
        "enabled": True,
        "addresses": [{"address": "10.100.0.0/16"}, {"address": "10.101.0.0/16"}],
        "dns_servers": [{"address": "10.1.1.53"}],
        "dns_resolution_targets": {"targets": [{"hostname": "corp.example.edu"}]},
    }
    location = location_from_api(record)
    assert isinstance(location, Location)
    assert location.addresses == ["10.100.0.0/16", "10.101.0.0/16"]
    assert location.dns_servers == ["10.1.1.53"]
    assert location.dns_resolution_targets == ["corp.example.edu"]


def test_location_from_api_invalid_slug_raises() -> None:
    with pytest.raises(ImporterError, match="does not derive a valid slug"):
        location_from_api({"name": "123-Starts-With-Digit"})


# ---- policy_from_api ------------------------------------------------------


def _windows_policy(**overrides: object) -> dict[str, object]:
    base = {
        "id": "pol-1",
        "name": "ABC01-Endpoints-Windows-Test",
        "description": "Baseline.",
        "platform_name": "Windows",
        "enabled": True,
        "groups": [
            {"id": "hg-1", "name": "ABC01-Endpoints-Windows-Test"},
            {"id": "hg-2", "name": "ABC01-Endpoints-Windows-Pilot"},
            {"id": "hg-3", "name": "ABC01-Endpoints-Windows-Production"},
        ],
        "settings": {"rule_group_ids": ["rg-baseline"]},
    }
    base.update(overrides)
    return base


def test_policy_from_api_resolves_host_groups_and_rule_groups() -> None:
    rule_groups_by_id = {
        "rg-baseline": {"id": "rg-baseline", "name": "windows-baseline-Test"},
    }
    policy = policy_from_api(_windows_policy(), rule_groups_by_id=rule_groups_by_id)
    assert isinstance(policy, Policy)
    assert policy.name == "abc01-endpoints-windows"
    assert policy.display_name == "ABC01-Endpoints-Windows"
    assert policy.platform is Platform.windows
    assert policy.status is Status.enabled
    assert policy.priority is PrecedenceBucket.default
    assert policy.host_groups == {
        "ABC01-Endpoints-Windows-Test": HostGroupEnv.test,
        "ABC01-Endpoints-Windows-Pilot": HostGroupEnv.pilot,
        "ABC01-Endpoints-Windows-Production": HostGroupEnv.production,
    }
    assert policy.rule_groups == ["windows-baseline"]
    assert policy.rules == []


def test_policy_from_api_host_group_without_suffix_uses_policy_env() -> None:
    """A host group lacking an env suffix inherits the policy's own env.

    Bootstrapping a tenant whose host groups predate csfwctl's naming
    convention must not silently drop the assignment (the bug this guards
    against): such a policy would then look like it has no host groups.
    """
    record = _windows_policy(
        groups=[{"id": "hg-1", "name": "ASC-Endpoints-FW-FULL_DISABLE"}],
    )
    policy = policy_from_api(
        record,
        rule_groups_by_id={"rg-baseline": {"id": "rg-baseline", "name": "windows-baseline-Test"}},
    )
    # Policy name is "...-Test", so the suffix-less group binds to test.
    assert policy.host_groups == {"ASC-Endpoints-FW-FULL_DISABLE": HostGroupEnv.test}


def test_policy_from_api_suffixless_group_on_suffixless_policy_defaults_production() -> None:
    """With no env info anywhere, a host group defaults to production."""
    record = _windows_policy(
        name="ASC-Windows-Endpoints-FULL_DISABLE",
        groups=[{"id": "hg-1", "name": "ASC-Endpoints-FW-FULL_DISABLE"}],
    )
    policy = policy_from_api(
        record,
        rule_groups_by_id={"rg-baseline": {"id": "rg-baseline", "name": "windows-baseline"}},
    )
    assert policy.host_groups == {"ASC-Endpoints-FW-FULL_DISABLE": HostGroupEnv.production}


def test_policy_from_api_keeps_first_group_when_env_collides() -> None:
    """Two suffix-less groups can't share an env; keep the first, drop the rest."""
    record = _windows_policy(
        name="ASC-Windows-Endpoints-FULL_DISABLE",
        groups=[
            {"id": "hg-1", "name": "ASC-Endpoints-FW-FULL_DISABLE"},
            {"id": "hg-2", "name": "ASC-Servers-FW-FULL_DISABLE"},
        ],
    )
    policy = policy_from_api(
        record,
        rule_groups_by_id={"rg-baseline": {"id": "rg-baseline", "name": "windows-baseline"}},
    )
    assert policy.host_groups == {"ASC-Endpoints-FW-FULL_DISABLE": HostGroupEnv.production}


def test_policy_from_api_folds_override_group_into_inline_rules() -> None:
    override_rg = {
        "id": "rg-overrides",
        "name": "abc01-endpoints-windows-overrides-test",
        "platform": "windows",
        "enabled": True,
        "rule_ids": [],
        "rules": [
            {
                "name": "Allow corp DNS outbound",
                "action": "ALLOW",
                "direction": "OUT",
                "protocol": "17",
                "remote": {
                    "addresses": [{"address": "10.1.1.53"}],
                    "ports": [{"start": 53, "end": 53}],
                },
            }
        ],
    }
    baseline_rg = {"id": "rg-baseline", "name": "windows-baseline-Test"}
    record = _windows_policy(settings={"rule_group_ids": ["rg-overrides", "rg-baseline"]})
    folded = RuleGroup(
        name="abc01-endpoints-windows-overrides-test",
        platform=Platform.windows,
        status=Status.enabled,
        rules=[
            Rule(
                name="Allow corp DNS outbound",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.udp,
            )
        ],
    )
    policy = policy_from_api(
        record,
        rule_groups_by_id={"rg-overrides": override_rg, "rg-baseline": baseline_rg},
        rule_groups_by_slug={"abc01-endpoints-windows-overrides-test": folded},
    )
    assert policy.rule_groups == ["windows-baseline"]
    assert len(policy.rules) == 1
    assert policy.rules[0].name == "Allow corp DNS outbound"


def test_policy_from_api_unresolved_rule_group_raises() -> None:
    record = _windows_policy(settings={"rule_group_ids": ["unknown-id"]})
    with pytest.raises(ImporterError, match="no record was fetched"):
        policy_from_api(record, rule_groups_by_id={})


def test_policy_from_api_bad_base_name_raises() -> None:
    record = _windows_policy(name="123-Starts-With-Digit-Test")
    with pytest.raises(ImporterError, match="does not derive a valid slug"):
        policy_from_api(record)


# ---- model -> API shape (used by round-trip harness + Phase 5) ------------


def test_policy_to_api_shape_appends_env_suffix() -> None:
    policy = Policy(
        name="abc01-endpoints-windows",
        display_name="ABC01-Endpoints-Windows",
        platform=Platform.windows,
    )
    shape = policy_to_api_shape(policy, "test")
    assert shape["name"] == "ABC01-Endpoints-Windows-Test"
    assert shape["platform_name"] == "Windows"
    assert shape["enabled"] is True


def test_policy_to_api_shape_falls_back_to_slug_when_no_display_name() -> None:
    policy = Policy(name="abc01-endpoints-windows", platform=Platform.windows)
    shape = policy_to_api_shape(policy, "test")
    assert shape["name"] == "abc01-endpoints-windows-Test"


def test_rule_group_to_api_shape_emits_rule_ids_and_inline_rules() -> None:
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="r1", action=Action.allow, direction=Direction.inbound, protocol=Protocol.tcp
            ),
            Rule(
                name="r2", action=Action.block, direction=Direction.inbound, protocol=Protocol.tcp
            ),
        ],
    )
    shape = rule_group_to_api_shape(rg, "test")
    assert shape["name"] == "windows-baseline-Test"
    # CREATE/UPDATE endpoint uses lowercase platform ID, not numeric "0".
    assert shape["platform"] == "windows"
    assert len(shape["rule_ids"]) == 2
    assert {r["name"] for r in shape["rules"]} == {"r1", "r2"}
    # Every rule must carry address_family for the CREATE endpoint.
    assert all(r["address_family"] == "IP4" for r in shape["rules"])


def test_rule_group_to_api_shape_ipv6_address_family() -> None:
    """address_family is IP6 when any endpoint address is IPv6."""
    rg = RuleGroup(
        name="ipv6-rules",
        platform=Platform.windows,
        rules=[
            Rule(
                name="allow-ipv6",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
                remote=Endpoint(addresses=["2001:db8::/32"]),
            ),
        ],
    )
    shape = rule_group_to_api_shape(rg, "test")
    assert shape["rules"][0]["address_family"] == "IP6"


def test_rule_group_to_api_shape_single_port_uses_end_zero_sentinel() -> None:
    """Single ports must use end=0 (CS sentinel), not end=N (rejected as duplicate)."""
    rg = RuleGroup(
        name="port-test",
        platform=Platform.windows,
        rules=[
            Rule(
                name="dns",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.udp,
                remote=Endpoint(addresses=["10.1.1.53"], ports=[53]),
            ),
        ],
    )
    shape = rule_group_to_api_shape(rg, "test")
    rule = shape["rules"][0]
    assert rule["remote_port"] == [{"start": 53, "end": 0}]


def test_rule_group_to_api_shape_port_range_uses_explicit_end() -> None:
    """Port ranges keep both start and end."""
    rg = RuleGroup(
        name="range-test",
        platform=Platform.windows,
        rules=[
            Rule(
                name="ephemeral",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
                local=Endpoint(ports=["1024-65535"]),
            ),
        ],
    )
    shape = rule_group_to_api_shape(rg, "test")
    rule = shape["rules"][0]
    assert rule["local_port"] == [{"start": 1024, "end": 65535}]


def test_location_to_api_shape_wraps_addresses_in_dicts() -> None:
    loc = Location(name="corp-vpn", addresses=["10.100.0.0/16"], dns_servers=["10.1.1.53"])
    shape = location_to_api_shape(loc)
    assert shape["addresses"] == [{"address": "10.100.0.0/16"}]
    assert shape["dns_servers"] == [{"address": "10.1.1.53"}]
