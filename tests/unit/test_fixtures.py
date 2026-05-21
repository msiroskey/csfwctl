"""Tests for the sanitiser and record-fixtures driver."""

from __future__ import annotations

import json
from pathlib import Path

from csfwctl.fixtures import (
    Operation,
    Sanitizer,
    default_operations,
    filter_operations,
    record_fixtures,
)

# ---- Sanitizer ------------------------------------------------------------


def test_sanitizer_replaces_uuids_deterministically() -> None:
    san = Sanitizer()
    a = san.sanitize("12345678-1234-1234-1234-123456789abc")
    b = san.sanitize("12345678-1234-1234-1234-123456789abc")
    assert a == b
    assert a.startswith("00000000-0000-0000-0000-")


def test_sanitizer_replaces_ipv4_with_reserved_ranges() -> None:
    san = Sanitizer()
    result = san.sanitize({"address": "10.1.2.3"})
    assert result["address"].startswith("192.0.2.")
    # Same input -> same output across calls.
    assert san.sanitize("10.1.2.3") == result["address"]


def test_sanitizer_preserves_cidr_prefix() -> None:
    san = Sanitizer()
    result = san.sanitize("10.100.0.0/16")
    assert result.endswith("/16")
    assert result != "10.100.0.0/16"


def test_sanitizer_replaces_hostnames() -> None:
    san = Sanitizer()
    result = san.sanitize("corp.example.edu")
    assert result.endswith(".example.test")
    assert "host-001" in result


def test_sanitizer_replaces_emails() -> None:
    san = Sanitizer()
    result = san.sanitize("alice@example.edu")
    # Email gets fake username; the trailing domain is then caught by the
    # hostname pass as well, which is fine — over-sanitising is safe.
    assert result.startswith("user-001@")
    assert "example.edu" not in result


def test_sanitizer_walks_nested_structures() -> None:
    san = Sanitizer()
    data = {
        "resources": [
            {
                "id": "12345678-1234-1234-1234-123456789abc",
                "addresses": [{"address": "10.0.0.1"}],
                "hostnames": ["corp.example.edu"],
            }
        ],
        "meta": {"trace_id": "abcdef12-3456-7890-1234-567890abcdef"},
    }
    out = san.sanitize(data)
    assert out["resources"][0]["id"].startswith("00000000-")
    assert out["resources"][0]["addresses"][0]["address"].startswith("192.0.2.")
    assert out["resources"][0]["hostnames"][0].endswith(".example.test")
    assert out["meta"]["trace_id"].startswith("00000000-")
    # Two distinct UUIDs map to two distinct fakes.
    assert out["resources"][0]["id"] != out["meta"]["trace_id"]


def test_sanitizer_preserve_substrings_skip_replacement() -> None:
    san = Sanitizer(preserve_substrings=("corp-vpn",))
    # The slug "corp-vpn" must be retained because Pydantic Slug validation
    # depends on it staying lowercase-kebab.
    assert san.sanitize("corp-vpn") == "corp-vpn"


def test_sanitizer_no_op_on_unrecognised_strings() -> None:
    san = Sanitizer()
    assert san.sanitize("just-a-slug") == "just-a-slug"
    assert san.sanitize(42) == 42
    assert san.sanitize(None) is None
    assert san.sanitize(True) is True


def test_sanitizer_replaces_mac_addresses_with_doc_oui() -> None:
    san = Sanitizer()
    a = san.sanitize("device aa:bb:cc:dd:ee:ff is online")
    # Replaced with the IANA documentation OUI (RFC 7042) — safe to publish.
    assert "aa:bb:cc:dd:ee:ff" not in a
    assert "00:00:5E" in a
    # Same input → same output across calls.
    b = san.sanitize("aa:bb:cc:dd:ee:ff")
    assert b in a


def test_sanitizer_preserves_mac_separator_style() -> None:
    san = Sanitizer()
    hyphen = san.sanitize("AA-BB-CC-DD-EE-FF")
    assert "-" in hyphen
    assert ":" not in hyphen
    colon = san.sanitize("11:22:33:44:55:66")
    assert ":" in colon
    assert "-" not in colon


def test_sanitizer_handles_empty_collections() -> None:
    san = Sanitizer()
    assert san.sanitize([]) == []
    assert san.sanitize({}) == {}
    assert san.sanitize("") == ""


# ---- filter_operations ----------------------------------------------------


def test_filter_operations_subsets_by_stem() -> None:
    ops = default_operations()
    subset = filter_operations(ops, ["policies-query", "locations-list"])
    assert {op.filename for op in subset} == {"policies-query.json", "locations-list.json"}


def test_filter_operations_empty_list_returns_all() -> None:
    ops = default_operations()
    assert filter_operations(ops, []) == ops


# ---- record_fixtures ------------------------------------------------------


def test_record_fixtures_writes_sanitized_json(tmp_path: Path) -> None:
    sentinel = {
        "resources": [
            {"id": "12345678-1234-1234-1234-123456789abc", "name": "ABC01-Endpoints-Windows"}
        ]
    }
    op = Operation(filename="policies-list.json", runner=lambda c: sentinel)
    results = record_fixtures(
        client=None,  # type: ignore[arg-type] — operation does not call the client
        output_dir=tmp_path,
        operations=[op],
    )
    assert len(results) == 1
    assert results[0].error is None
    path = tmp_path / "policies-list.json"
    assert path.is_file()
    data = json.loads(path.read_text())
    # UUID got sanitised; slug-ish name passed through.
    assert data["resources"][0]["id"].startswith("00000000-")
    assert data["resources"][0]["name"] == "ABC01-Endpoints-Windows"


def test_record_fixtures_captures_per_op_errors(tmp_path: Path) -> None:
    def boom(_c: object) -> object:
        raise RuntimeError("API exploded")

    good_op = Operation(filename="ok.json", runner=lambda c: {"hello": "world"})
    bad_op = Operation(filename="bad.json", runner=boom)
    results = record_fixtures(
        client=None,  # type: ignore[arg-type]
        output_dir=tmp_path,
        operations=[good_op, bad_op],
    )
    assert results[0].error is None
    assert results[0].path == tmp_path / "ok.json"
    assert results[1].error == "API exploded"
    assert results[1].path is None
    # The good op still wrote its file even though the bad one failed.
    assert (tmp_path / "ok.json").is_file()
    assert not (tmp_path / "bad.json").exists()


def test_record_fixtures_uses_shared_sanitizer_for_consistent_uuids(tmp_path: Path) -> None:
    san = Sanitizer()
    uuid = "12345678-1234-1234-1234-123456789abc"
    op_a = Operation(filename="a.json", runner=lambda c: {"id": uuid})
    op_b = Operation(filename="b.json", runner=lambda c: {"ref": uuid})
    record_fixtures(client=None, output_dir=tmp_path, operations=[op_a, op_b], sanitizer=san)  # type: ignore[arg-type]
    a = json.loads((tmp_path / "a.json").read_text())
    b = json.loads((tmp_path / "b.json").read_text())
    assert a["id"] == b["ref"]
    assert a["id"].startswith("00000000-")


def test_default_operations_covers_all_read_endpoints() -> None:
    names = {Path(op.filename).stem for op in default_operations()}
    # Each sub-client has a query + list_all pair.
    assert names >= {
        "policies-query",
        "policies-list",
        "rule-groups-query",
        "rule-groups-list",
        "locations-query",
        "locations-list",
        "host-groups-query",
        "host-groups-list",
    }
