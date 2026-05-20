"""Loader and cross-reference validation tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from csfwctl.loader import ConfigRepoError, load_config_repo


def test_load_minimal_repo(minimal_repo_path: Path) -> None:
    repo = load_config_repo(minimal_repo_path)
    assert set(repo.policies) == {"abc01-endpoints-windows"}
    assert set(repo.rule_groups) == {"windows-baseline"}
    assert repo.locations == {}
    assert repo.tombstones.policies == []
    assert repo.tool_config.tool.metadata_signature == "Managed by csfwctl"


def test_load_realistic_repo(realistic_repo_path: Path) -> None:
    repo = load_config_repo(realistic_repo_path)
    assert set(repo.policies) == {
        "abc01-endpoints-windows",
        "abc01-endpoints-mac",
        "research-lab-7-windows",
    }
    assert set(repo.rule_groups) == {
        "windows-baseline",
        "windows-remote-access",
        "mac-baseline",
    }
    assert set(repo.locations) == {"corp-vpn"}
    assert len(repo.tombstones.rule_groups) == 1
    assert len(repo.precedence_overrides.overrides) == 1


def test_missing_rule_group_reference_is_caught(minimal_repo_copy: Path) -> None:
    policy_path = minimal_repo_copy / "policies" / "abc01-endpoints-windows.yaml"
    text = policy_path.read_text()
    policy_path.write_text(text + "  - does-not-exist\n")

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(minimal_repo_copy)
    msgs = " ".join(err.message for err in excinfo.value.errors)
    assert "does-not-exist" in msgs


def test_platform_mismatch_is_caught(realistic_repo_copy: Path) -> None:
    # Make the mac policy reference a windows rule group.
    mac_policy = realistic_repo_copy / "policies" / "abc01-endpoints-mac.yaml"
    text = mac_policy.read_text().replace("mac-baseline", "windows-baseline")
    mac_policy.write_text(text)

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(realistic_repo_copy)
    msgs = " ".join(err.message for err in excinfo.value.errors)
    assert "platform mismatch" in msgs


def test_missing_location_reference_is_caught(realistic_repo_copy: Path) -> None:
    (realistic_repo_copy / "locations" / "corp-vpn.yaml").unlink()

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(realistic_repo_copy)
    msgs = " ".join(err.message for err in excinfo.value.errors)
    assert "corp-vpn" in msgs
    assert "not found" in msgs


def test_filename_must_match_name_for_rule_groups(minimal_repo_copy: Path) -> None:
    rg = minimal_repo_copy / "rule_groups" / "windows-baseline.yaml"
    text = rg.read_text().replace("name: windows-baseline", "name: other-baseline")
    rg.write_text(text)

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(minimal_repo_copy)
    msgs = " ".join(err.message for err in excinfo.value.errors)
    assert "does not match filename slug" in msgs


def test_tombstone_referencing_live_object_is_caught(minimal_repo_copy: Path) -> None:
    tomb = minimal_repo_copy / "tombstones.yaml"
    tomb.write_text(
        "policies: []\n"
        "rule_groups:\n"
        "  - name: windows-baseline\n"
        "    deleted_in_sha: abcdefa\n"
        "    reason: testing tombstone check\n"
        "locations: []\n"
    )

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(minimal_repo_copy)
    msgs = " ".join(err.message for err in excinfo.value.errors)
    assert "still exists" in msgs


def test_precedence_override_to_unknown_policy_is_caught(realistic_repo_copy: Path) -> None:
    prec = realistic_repo_copy / "precedence.yaml"
    prec.write_text("overrides:\n  - before: does-not-exist\n    after: abc01-endpoints-windows\n")

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(realistic_repo_copy)
    msgs = " ".join(err.message for err in excinfo.value.errors)
    assert "unknown policy" in msgs


def test_yaml_parse_error_includes_line(minimal_repo_copy: Path) -> None:
    rg = minimal_repo_copy / "rule_groups" / "windows-baseline.yaml"
    rg.write_text("name: windows-baseline\nplatform: windows\n: invalid: : :\n")

    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(minimal_repo_copy)
    assert any("YAML parse error" in err.message for err in excinfo.value.errors)


def test_load_nonexistent_repo() -> None:
    with pytest.raises(ConfigRepoError) as excinfo:
        load_config_repo(Path("/this/should/not/exist/anywhere"))
    assert "not a directory" in excinfo.value.errors[0].message


def test_empty_repo_loads_clean(tmp_path: Path) -> None:
    repo = load_config_repo(tmp_path)
    assert repo.policies == {}
    assert repo.rule_groups == {}
    assert repo.locations == {}
