"""End-to-end round-trip tests for ``csfwctl.exporter``.

Uses a hand-rolled fake ``FalconClient`` that returns API-shape records
synthesised from a hand-authored Pydantic model. The test then runs the
importer against the fake client and verifies it reproduces the original
model. This is the "import -> load -> diff should be empty" contract
that the Phase 3 plan calls out.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from csfwctl.exporter import (
    ImporterError,
    _fetch_rules_for_groups,
    dump_yaml,
    import_all,
    import_location,
    import_policy,
    import_rule_group,
    location_to_api_shape,
    policy_to_api_shape,
    rule_from_api,
    rule_group_to_api_shape,
)
from csfwctl.loader import load_config_repo
from csfwctl.schema import (
    Action,
    AddressFamily,
    ConnectionState,
    Direction,
    Endpoint,
    HostGroupEnv,
    Location,
    Platform,
    Policy,
    Protocol,
    Rule,
    RuleGroup,
)

# ---- fake Falcon client ---------------------------------------------------


@dataclass
class FakeSubclient:
    """Behaves like one of the falcon sub-clients for importer tests.

    The exporter only calls ``query``, ``get``/``get_details`` (and on
    rule groups, ``get_rules`` + ``list_all``). We model that surface
    here without needing FalconPy in the loop.
    """

    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    # ``rules`` is only used by the rule-groups sub-client.

    def query(self, *, filter: str | None = None, limit: int | None = None) -> list[str]:
        del limit
        if filter is None:
            return list(self.records)
        if filter.startswith("name:'") and filter.endswith("'"):
            target = filter[len("name:'") : -1]
            return [rid for rid, r in self.records.items() if r.get("name") == target]
        return list(self.records)

    def get(self, ids: list[str]) -> list[dict[str, Any]]:
        return [self.records[i] for i in ids if i in self.records]

    def get_details(self, ids: list[str]) -> list[dict[str, Any]]:
        return self.get(ids)

    def list_all(self, *, filter: str | None = None) -> list[dict[str, Any]]:
        del filter
        return list(self.records.values())

    def get_rules(self, ids: list[str]) -> list[dict[str, Any]]:
        return [self.rules[i] for i in ids if i in self.rules]

    def get_policy_containers(self, ids: list[str]) -> list[dict[str, Any]]:
        """Synthesize container records from stored policy records."""
        result = []
        for id_ in ids:
            record = self.records.get(id_)
            if record:
                settings = record.get("settings") or {}
                result.append(
                    {
                        "policy_id": id_,
                        "rule_group_ids": list(settings.get("rule_group_ids") or []),
                    }
                )
        return result


@dataclass
class FakeFalconClient:
    """Stand-in for :class:`FalconClient` with hand-supplied data."""

    policies: FakeSubclient = field(default_factory=FakeSubclient)
    rule_groups: FakeSubclient = field(default_factory=FakeSubclient)
    locations: FakeSubclient = field(default_factory=FakeSubclient)


# ---- harness: populate fake client from Pydantic models --------------------


def _populate(
    client: FakeFalconClient,
    *,
    policies: list[Policy] | None = None,
    rule_groups: list[RuleGroup] | None = None,
    locations: list[Location] | None = None,
    envs: tuple[str, ...] = ("test", "pilot", "production"),
) -> None:
    """Render the given models into API shapes and load them into the client.

    Each policy and rule group is emitted once per env (the trunk-style
    naming convention from the project plan); locations are env-agnostic.
    """
    for rg in rule_groups or []:
        for env in envs:
            shape = rule_group_to_api_shape(rg, env)
            client.rule_groups.records[str(shape["id"])] = shape
            for rule in shape.get("rules", []):
                client.rule_groups.rules[str(rule["id"])] = rule
    for policy in policies or []:
        for env in envs:
            shape = policy_to_api_shape(policy, env)
            # If the policy carries inline rules, the harness ALSO emits
            # a synthesised override rule group so the importer can fold.
            client.policies.records[str(shape["id"])] = shape
            if policy.rules:
                override_slug = f"{policy.name.lower()}-overrides-{env}"
                override_rg = RuleGroup(
                    name=override_slug,
                    platform=policy.platform,
                    rules=list(policy.rules),
                )
                shape_rg = rule_group_to_api_shape(override_rg, env)
                # Override-group names already carry the env in the slug;
                # avoid double-suffixing on the shape.
                shape_rg["name"] = f"{override_slug}-{env.title()}"
                client.rule_groups.records[str(shape_rg["id"])] = shape_rg
                for rule in shape_rg.get("rules", []):
                    client.rule_groups.rules[str(rule["id"])] = rule
    for loc in locations or []:
        shape = location_to_api_shape(loc)
        client.locations.records[str(shape["id"])] = shape


# ---- fixture: a hand-authored model set ------------------------------------


def _baseline_rg() -> RuleGroup:
    return RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        description="Baseline allow/deny rules for Windows endpoints.",
        rules=[
            Rule(
                name="Allow established inbound",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
                state=ConnectionState.established,
            ),
            Rule(
                name="Block SMB inbound from non-corp",
                action=Action.block,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
                local=Endpoint(ports=[445]),
                remote=Endpoint(addresses=["10.0.0.0/8"], addresses_negated=True),
            ),
        ],
    )


def _remote_rg() -> RuleGroup:
    return RuleGroup(
        name="windows-remote-access",
        platform=Platform.windows,
        description="Shared remote-access allow rules.",
        rules=[
            Rule(
                name="Allow RDP outbound to corp-vpn",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
                locations=["corp-vpn"],
                remote=Endpoint(ports=[3389]),
            )
        ],
    )


def _corp_vpn_location() -> Location:
    return Location(
        name="corp-vpn",
        description="Corporate VPN address ranges.",
        addresses=["10.100.0.0/16", "10.101.0.0/16"],
        dns_servers=["10.1.1.53"],
        dns_resolution_targets=["corp.example.edu"],
    )


def _abc01_policy() -> Policy:
    return Policy(
        name="abc01-endpoints-windows",
        display_name="ABC01-Endpoints-Windows",
        platform=Platform.windows,
        description="Baseline policy for ABC01 Windows endpoints.",
        host_groups={
            "ABC01-Endpoints-Windows-Test": HostGroupEnv.test,
            "ABC01-Endpoints-Windows-Pilot": HostGroupEnv.pilot,
            "ABC01-Endpoints-Windows-Production": HostGroupEnv.production,
        },
        rules=[
            Rule(
                name="Allow corp DNS outbound",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.udp,
                remote=Endpoint(addresses=["10.1.1.53", "10.1.1.54"], ports=[53]),
            )
        ],
        rule_groups=["windows-baseline", "windows-remote-access"],
    )


# ---- round-trip tests -----------------------------------------------------


def test_import_rule_group_round_trips_through_fake_client() -> None:
    client = FakeFalconClient()
    original = _baseline_rg()
    _populate(client, rule_groups=[original])

    result = import_rule_group(client, "windows-baseline")  # type: ignore[arg-type]

    assert result.kind == "rule-group"
    assert result.slug == "windows-baseline"
    assert isinstance(result.model, RuleGroup)
    assert result.model.model_dump() == original.model_dump()


def test_import_location_round_trips() -> None:
    client = FakeFalconClient()
    original = _corp_vpn_location()
    _populate(client, locations=[original])

    result = import_location(client, "corp-vpn")  # type: ignore[arg-type]
    assert isinstance(result.model, Location)
    assert result.model.model_dump() == original.model_dump()


def test_import_policy_folds_override_group_back_into_inline_rules() -> None:
    client = FakeFalconClient()
    policy = _abc01_policy()
    rule_groups = [_baseline_rg(), _remote_rg()]
    _populate(client, policies=[policy], rule_groups=rule_groups)

    result = import_policy(client, "ABC01-Endpoints-Windows")  # type: ignore[arg-type]

    assert isinstance(result.model, Policy)
    assert result.model.name == "abc01-endpoints-windows"
    assert result.model.display_name == "ABC01-Endpoints-Windows"
    assert result.model.rule_groups == ["windows-baseline", "windows-remote-access"]
    assert [r.name for r in result.model.rules] == ["Allow corp DNS outbound"]
    # Host groups carry across all three envs.
    assert set(result.model.host_groups.values()) == {
        HostGroupEnv.test,
        HostGroupEnv.pilot,
        HostGroupEnv.production,
    }


def test_import_policy_by_uuid_uses_id_lookup() -> None:
    client = FakeFalconClient()
    policy = _abc01_policy()
    _populate(client, policies=[policy], rule_groups=[_baseline_rg(), _remote_rg()])
    # Grab one record's UUID directly to exercise the id branch.
    some_id = next(iter(client.policies.records))

    result = import_policy(client, some_id)  # type: ignore[arg-type]
    assert isinstance(result.model, Policy)


def test_import_policy_missing_name_raises() -> None:
    client = FakeFalconClient()
    with pytest.raises(ImporterError, match="not found"):
        import_policy(client, "nonexistent-policy")  # type: ignore[arg-type]


# ---- writing + loader round-trip ------------------------------------------


def test_import_all_writes_loadable_repo(tmp_path: Path) -> None:
    """The headline guarantee: import -> load -> validate is clean."""
    client = FakeFalconClient()
    _populate(
        client,
        policies=[_abc01_policy()],
        rule_groups=[_baseline_rg(), _remote_rg()],
        locations=[_corp_vpn_location()],
    )
    target = tmp_path / "imported"

    results = import_all(client, target)  # type: ignore[arg-type]

    kinds = {r.kind for r in results}
    assert kinds == {"policy", "rule-group", "location"}
    assert (target / "policies" / "abc01-endpoints-windows.yaml").is_file()
    assert (target / "rule_groups" / "windows-baseline.yaml").is_file()
    assert (target / "rule_groups" / "windows-remote-access.yaml").is_file()
    assert (target / "locations" / "corp-vpn.yaml").is_file()
    # The folded override group is NOT written: its rules live inline.
    assert not (target / "rule_groups" / "abc01-endpoints-windows-overrides-test.yaml").exists()

    repo = load_config_repo(target)
    assert set(repo.policies) == {"abc01-endpoints-windows"}
    assert set(repo.rule_groups) == {"windows-baseline", "windows-remote-access"}
    assert set(repo.locations) == {"corp-vpn"}
    assert [r.name for r in repo.policies["abc01-endpoints-windows"].rules] == [
        "Allow corp DNS outbound"
    ]


def test_dump_yaml_omits_defaults() -> None:
    rg = RuleGroup(name="windows-baseline", platform=Platform.windows)
    yaml_text = dump_yaml(rg)
    # An empty rule group should NOT emit a ``rules: []`` line.
    assert "rules:" not in yaml_text
    # And no description either.
    assert "description" not in yaml_text


def test_dump_yaml_writes_locations_only_when_non_any() -> None:
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="r1",
                action=Action.allow,
                direction=Direction.inbound,
                protocol=Protocol.tcp,
            )
        ],
    )
    yaml_text = dump_yaml(rg)
    assert "locations:" in yaml_text  # default [any] is still emitted; loader expects it


def test_dump_yaml_emits_file_path_and_service_name() -> None:
    """Regression: the importer's YAML dump must preserve file_path/service_name.

    ``_trim_rule`` previously dropped both, so ``import`` silently lost the
    application-aware match (and re-importing could not backfill it).
    """
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="dhcp",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.udp,
                file_path=r"%SystemRoot%\System32\svchost.exe",
                service_name="Dhcp",
            )
        ],
    )
    yaml_text = dump_yaml(rg)
    assert r"file_path: '%SystemRoot%\System32\svchost.exe'" in yaml_text
    assert "service_name: Dhcp" in yaml_text


def test_dump_yaml_emits_address_family_type_and_watch_mode() -> None:
    """The importer's YAML dump must preserve the new top-level rule qualifiers.

    ``_trim_rule`` is an allowlist; an omitted field is silently dropped, so a
    regression here would make ``import`` lose an explicit address_family
    override, address_type, or watch_mode flag.
    """
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="app-rule",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
                address_family=AddressFamily.ip4,
                address_type="NetworkAddressIPv4",
                watch_mode=True,
            )
        ],
    )
    yaml_text = dump_yaml(rg)
    assert "address_family: ip4" in yaml_text
    assert "address_type: NetworkAddressIPv4" in yaml_text
    assert "watch_mode: true" in yaml_text


def test_dump_yaml_omits_unset_watch_mode_and_inferred_family() -> None:
    """watch_mode=false and an omitted address_family stay out of the YAML."""
    rg = RuleGroup(
        name="windows-baseline",
        platform=Platform.windows,
        rules=[
            Rule(
                name="plain",
                action=Action.allow,
                direction=Direction.outbound,
                protocol=Protocol.tcp,
            )
        ],
    )
    yaml_text = dump_yaml(rg)
    assert "watch_mode" not in yaml_text
    assert "address_family" not in yaml_text
    assert "address_type" not in yaml_text


def test_round_trip_realistic_repo(tmp_path: Path) -> None:
    """Round-trip the realistic fixture repo through the importer."""
    from tests.conftest import FIXTURES_ROOT

    source_root = FIXTURES_ROOT / "realistic"
    # Load the hand-authored repo so we know what to expect back.
    source_repo = load_config_repo(source_root)

    client = FakeFalconClient()
    _populate(
        client,
        policies=list(source_repo.policies.values()),
        rule_groups=list(source_repo.rule_groups.values()),
        locations=list(source_repo.locations.values()),
    )
    target = tmp_path / "imported"
    import_all(client, target)  # type: ignore[arg-type]

    # The imported repo must load without errors and contain the same
    # set of policies / rule groups / locations.
    imported = load_config_repo(target)
    assert set(imported.policies) == set(source_repo.policies)
    assert set(imported.rule_groups) == set(source_repo.rule_groups)
    assert set(imported.locations) == set(source_repo.locations)

    # Spot-check that the override group folded correctly.
    abc = imported.policies["abc01-endpoints-windows"]
    assert [r.name for r in abc.rules] == ["Allow corp DNS outbound"]
    assert abc.rule_groups == ["windows-baseline", "windows-remote-access"]

    # The new top-level rule qualifiers survive import -> YAML -> reload.
    baseline = {r.name: r for r in imported.rule_groups["windows-baseline"].rules}
    assert baseline["Allow updater outbound"].address_family is AddressFamily.ip4
    assert baseline["Block SMB inbound from non-corp"].watch_mode is True


def test_import_all_idempotent_when_rerun(tmp_path: Path) -> None:
    """Re-running ``import all`` produces byte-identical YAML."""
    client = FakeFalconClient()
    _populate(
        client,
        policies=[_abc01_policy()],
        rule_groups=[_baseline_rg(), _remote_rg()],
        locations=[_corp_vpn_location()],
    )
    target1 = tmp_path / "run1"
    target2 = tmp_path / "run2"
    import_all(client, target1)  # type: ignore[arg-type]
    import_all(client, target2)  # type: ignore[arg-type]

    for sub in ("policies", "rule_groups", "locations"):
        files1 = sorted((target1 / sub).glob("*.yaml"))
        files2 = sorted((target2 / sub).glob("*.yaml"))
        assert [f.name for f in files1] == [f.name for f in files2]
        for a, b in zip(files1, files2, strict=False):
            assert a.read_text() == b.read_text()


# ---- output path handling ------------------------------------------------


def test_import_policy_writes_to_default_subdir(tmp_path: Path) -> None:
    client = FakeFalconClient()
    _populate(
        client,
        policies=[_abc01_policy()],
        rule_groups=[_baseline_rg(), _remote_rg()],
    )

    result = import_policy(  # type: ignore[arg-type]
        client,
        "ABC01-Endpoints-Windows",
        output_dir=tmp_path,
    )
    assert result.path == (tmp_path / "policies" / "abc01-endpoints-windows.yaml").resolve()
    assert result.path is not None and result.path.is_file()


def test_import_policy_no_output_dir_skips_write() -> None:
    client = FakeFalconClient()
    _populate(
        client,
        policies=[_abc01_policy()],
        rule_groups=[_baseline_rg(), _remote_rg()],
    )
    result = import_policy(client, "ABC01-Endpoints-Windows")  # type: ignore[arg-type]
    assert result.path is None
    assert isinstance(result.model, Policy)


# ---- minimal smoke against the loader on a tiny tree ---------------------


def test_imported_minimal_repo_loads(tmp_path: Path) -> None:
    client = FakeFalconClient()
    _populate(
        client,
        policies=[
            Policy(
                name="tiny-policy",
                platform=Platform.windows,
                rule_groups=["windows-baseline"],
            )
        ],
        rule_groups=[RuleGroup(name="windows-baseline", platform=Platform.windows)],
    )
    target = tmp_path / "tiny"
    import_all(client, target)  # type: ignore[arg-type]
    # Loader requires tombstones / csfwctl.toml to be optional; absence is fine.
    repo = load_config_repo(target)
    assert set(repo.policies) == {"tiny-policy"}
    assert set(repo.rule_groups) == {"windows-baseline"}


# ---- artefacts JSON support (defensive) -----------------------------------


def test_dump_yaml_is_valid_yaml(tmp_path: Path) -> None:
    """Sanity: emitted text parses as YAML and round-trips through json."""
    from ruamel.yaml import YAML

    rg = _baseline_rg()
    text = dump_yaml(rg)
    parsed = YAML(typ="safe").load(text)
    # Round-trip through JSON just to make sure all leaf values are simple.
    json.dumps(parsed)
    assert parsed["name"] == "windows-baseline"
    assert parsed["platform"] == "windows"


def test_round_trip_realistic_repo_does_not_mutate_source(realistic_repo_path: Path) -> None:
    """The importer must never write into the source repo."""
    snapshot = sorted(p.relative_to(realistic_repo_path) for p in realistic_repo_path.rglob("*"))
    # Use the fixture path read-only; if any code path tried to write
    # there, the test below would catch it.
    repo = load_config_repo(realistic_repo_path)
    client = FakeFalconClient()
    _populate(
        client,
        policies=list(repo.policies.values()),
        rule_groups=list(repo.rule_groups.values()),
        locations=list(repo.locations.values()),
    )
    # Drive import into a tmp dir so the source stays clean.
    tmp = realistic_repo_path.parent / "_round_trip_tmp"
    try:
        if tmp.exists():
            shutil.rmtree(tmp)
        import_all(client, tmp)  # type: ignore[arg-type]
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)
    assert (
        sorted(p.relative_to(realistic_repo_path) for p in realistic_repo_path.rglob("*"))
        == snapshot
    )


# ---- real-API shape compatibility tests ------------------------------------


def test_rule_from_api_handles_flat_endpoint_fields() -> None:
    """The real API returns local_address/local_port rather than nested local/remote."""
    record = {
        "name": "Allow DNS outbound",
        "action": "ALLOW",
        "direction": "OUT",
        "protocol": "17",
        "enabled": True,
        "fields": [],
        "local_address": [{"address": "10.0.0.0", "netmask": 8}],
        "local_port": [],
        "remote_address": [{"address": "8.8.8.8", "netmask": 32}],
        "remote_port": [{"start": 53, "end": 53}],
    }
    rule = rule_from_api(record)
    assert rule.name == "Allow DNS outbound"
    assert rule.local is not None
    assert rule.local.addresses == ["10.0.0.0/8"]
    assert rule.remote is not None
    assert rule.remote.addresses == ["8.8.8.8/32"]
    assert rule.remote.ports == [53]


def test_rule_from_api_flat_takes_precedence_when_nested_absent() -> None:
    """Flat fields are used when ``local``/``remote`` keys are not present."""
    record = {
        "name": "Block SMB",
        "action": "DENY",
        "direction": "IN",
        "protocol": "6",
        "remote_address": [{"address": "0.0.0.0", "netmask": 0}],
        "remote_port": [{"start": 445, "end": 445}],
    }
    rule = rule_from_api(record)
    assert rule.remote is not None
    assert rule.remote.ports == [445]
    # Zero netmask = no prefix appended
    assert rule.remote.addresses == ["0.0.0.0"]


def test_fetch_rules_for_groups_batches_large_id_lists() -> None:
    """_fetch_rules_for_groups splits large rule-ID lists into 100-ID batches."""
    from csfwctl.exporter import _RULE_FETCH_BATCH_SIZE

    call_batches: list[list[str]] = []

    @dataclass
    class BatchTrackingSubclient:
        records: dict[str, Any] = field(default_factory=dict)
        rules: dict[str, Any] = field(default_factory=dict)

        def get_rules(self, ids: list[str]) -> list[dict[str, Any]]:
            call_batches.append(list(ids))
            return [
                {
                    "id": i,
                    "name": f"rule-{i}",
                    "action": "ALLOW",
                    "direction": "OUT",
                    "protocol": "6",
                }
                for i in ids
            ]

    @dataclass
    class MinimalClient:
        rule_groups: Any

    total_ids = _RULE_FETCH_BATCH_SIZE * 2 + 5  # 205 IDs → 3 batches
    rg_records = [{"rule_ids": [str(i) for i in range(total_ids)]}]
    client = MinimalClient(rule_groups=BatchTrackingSubclient())

    result = _fetch_rules_for_groups(client, rg_records)  # type: ignore[arg-type]

    assert len(call_batches) == 3
    assert len(call_batches[0]) == _RULE_FETCH_BATCH_SIZE
    assert len(call_batches[1]) == _RULE_FETCH_BATCH_SIZE
    assert len(call_batches[2]) == 5
    assert len(result) == total_ids


def test_fetch_rules_for_groups_resolves_hex_family_id_via_value_scan() -> None:
    """rules_by_id resolves hex family IDs even when the returned record has no
    named family_id field — the value scan finds the match in any string field."""

    @dataclass
    class FamilyIdSubclient:
        records: dict[str, Any] = field(default_factory=dict)
        rules: dict[str, Any] = field(default_factory=dict)

        def get_rules(self, ids: list[str]) -> list[dict[str, Any]]:
            # Real API: returns only a numeric id, no family_id field at all.
            return [
                {
                    "id": "7629257022100668539",
                    "name": "r1",
                    "action": "ALLOW",
                    "direction": "IN",
                    "protocol": "6",
                }
            ]

    @dataclass
    class MinimalClient:
        rule_groups: Any

    family_id = "838b17a58aab40e59c9a952299fd0b00"  # real-world example from logs
    rg_records = [{"rule_ids": [family_id]}]
    client = MinimalClient(rule_groups=FamilyIdSubclient())

    result = _fetch_rules_for_groups(client, rg_records)  # type: ignore[arg-type]

    # Positional fallback must map the requested family_id to the returned record.
    assert family_id in result
    # Numeric id is also indexed.
    assert "7629257022100668539" in result


def test_fetch_rules_for_groups_resolves_hex_family_id_via_named_field() -> None:
    """When the record does include a family_id field the value scan picks it up."""

    @dataclass
    class FamilyIdFieldSubclient:
        records: dict[str, Any] = field(default_factory=dict)
        rules: dict[str, Any] = field(default_factory=dict)

        def get_rules(self, ids: list[str]) -> list[dict[str, Any]]:
            return [
                {
                    "id": "7629257022100668539",
                    "family_id": "abc123def456abc123def456abc12345",
                    "name": "r1",
                    "action": "ALLOW",
                    "direction": "IN",
                    "protocol": "6",
                }
            ]

    @dataclass
    class MinimalClient:
        rule_groups: Any

    rg_records = [{"rule_ids": ["abc123def456abc123def456abc12345"]}]
    client = MinimalClient(rule_groups=FamilyIdFieldSubclient())

    result = _fetch_rules_for_groups(client, rg_records)  # type: ignore[arg-type]

    assert "7629257022100668539" in result
    assert "abc123def456abc123def456abc12345" in result


def test_flatten_addresses_appends_nonzero_netmask() -> None:
    """CrowdStrike API address dicts with netmask > 0 produce CIDR notation."""
    from csfwctl.exporter import _flatten_addresses

    items = [
        {"address": "192.168.1.0", "netmask": 24},
        {"address": "10.0.0.0", "netmask": 8},
        {"address": "0.0.0.0", "netmask": 0},
        "172.16.0.0/12",
    ]
    result = _flatten_addresses(items)
    assert result == ["192.168.1.0/24", "10.0.0.0/8", "0.0.0.0", "172.16.0.0/12"]
