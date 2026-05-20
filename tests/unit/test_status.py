"""Unit tests for :mod:`csfwctl.status`.

The status engine consumes a :class:`csfwctl.differ.LiveState` (the same
snapshot the differ uses) and groups every record by ``(kind, slug)``
with one :class:`EnvState` per environment. These tests exercise the
parsing and grouping logic; the CLI rendering lives in
``test_status_cmd.py``.
"""

from __future__ import annotations

from typing import Any

from csfwctl.differ import (
    KIND_LOCATION,
    KIND_POLICY,
    KIND_RULE_GROUP,
    LiveState,
)
from csfwctl.status import (
    ENV_ORDER,
    LOCATION_ENV,
    UNSUFFIXED_ENV,
    build_status_report,
)


def _signed(
    env: str, *, version: int = 1, sha: str = "abc1234", applied: str = "2026-05-01T00:00:00Z"
) -> str:
    """Build a description with a canonical metadata trailer."""
    return (
        f"some prior description\n\n"
        f"Managed by csfwctl | version: {version} | git_sha: {sha} "
        f"| applied: {applied} | env: {env}"
    )


def _policy_record(
    *,
    name: str,
    description: str | None,
    record_id: str = "p-id-1",
) -> dict[str, Any]:
    return {"id": record_id, "name": name, "description": description}


def _rule_group_record(
    *,
    name: str,
    description: str | None,
    record_id: str = "rg-id-1",
) -> dict[str, Any]:
    return {"id": record_id, "name": name, "description": description}


def _location_record(
    *,
    name: str,
    description: str | None,
    record_id: str = "loc-id-1",
) -> dict[str, Any]:
    return {"id": record_id, "name": name, "description": description}


def _state(
    *,
    policies: list[dict[str, Any]] | None = None,
    rule_groups: list[dict[str, Any]] | None = None,
    locations: list[dict[str, Any]] | None = None,
) -> LiveState:
    return LiveState(
        policies=list(policies or []),
        rule_groups=list(rule_groups or []),
        locations=list(locations or []),
    )


# ---- basic grouping -------------------------------------------------------


def test_status_groups_policy_records_by_env_stripped_slug() -> None:
    """Three env-suffixed policies for the same base name collapse into one entry."""
    state = _state(
        policies=[
            _policy_record(
                name="ABC01-Endpoints-Windows-Test",
                description=_signed("test", version=2),
                record_id="p-test",
            ),
            _policy_record(
                name="ABC01-Endpoints-Windows-Pilot",
                description=_signed("pilot", version=2),
                record_id="p-pilot",
            ),
            _policy_record(
                name="ABC01-Endpoints-Windows-Production",
                description=_signed("production", version=2),
                record_id="p-prod",
            ),
        ],
    )
    report = build_status_report(state)
    assert report.total == 1
    entry = report.entries[0]
    assert entry.kind == KIND_POLICY
    assert entry.slug == "abc01-endpoints-windows"
    assert set(entry.envs) == {"test", "pilot", "production"}
    assert entry.envs["test"].object_id == "p-test"
    assert entry.envs["pilot"].object_id == "p-pilot"
    assert entry.envs["production"].object_id == "p-prod"
    assert entry.is_managed


def test_status_distinguishes_managed_vs_unmanaged_by_description_only() -> None:
    """The ``Managed by csfwctl`` token alone decides managed status."""
    state = _state(
        policies=[
            _policy_record(name="Foo-Test", description="Managed by csfwctl | bogus trailer"),
            _policy_record(name="Bar-Test", description="some other description"),
            _policy_record(name="Baz-Test", description=None),
        ],
    )
    report = build_status_report(state)
    slugs = {entry.slug: entry for entry in report.entries}
    assert slugs["foo"].envs["test"].managed is True
    # Malformed trailer → managed=True but signature=None
    assert slugs["foo"].envs["test"].signature is None
    assert slugs["bar"].envs["test"].managed is False
    assert slugs["baz"].envs["test"].managed is False


def test_status_parses_signature_fields_into_envstate() -> None:
    """Every signature field round-trips into the :class:`MetadataSignature`."""
    state = _state(
        policies=[
            _policy_record(
                name="Foo-Pilot",
                description=_signed(
                    env="pilot", version=7, sha="deadbee", applied="2026-04-15T10:30:00Z"
                ),
            )
        ],
    )
    report = build_status_report(state)
    sig = report.entries[0].envs["pilot"].signature
    assert sig is not None
    assert sig.version == 7
    assert sig.git_sha == "deadbee"
    assert sig.applied == "2026-04-15T10:30:00Z"
    assert sig.env == "pilot"


# ---- env-suffix handling --------------------------------------------------


def test_status_unsuffixed_records_land_in_no_env_bucket() -> None:
    """Console-created objects without a -Test/-Pilot/-Production suffix."""
    state = _state(
        policies=[_policy_record(name="LegacyHandRolledPolicy", description=None)],
    )
    report = build_status_report(state)
    assert report.total == 1
    assert UNSUFFIXED_ENV in report.entries[0].envs


def test_status_skips_records_without_a_name() -> None:
    """Empty/missing names are dropped on the floor rather than crashing."""
    state = _state(
        policies=[
            {"id": "no-name", "description": None},  # no ``name`` key
            _policy_record(name="", description=None),
            _policy_record(name="Real-Test", description=_signed("test")),
        ],
    )
    report = build_status_report(state)
    assert report.total == 1
    assert report.entries[0].slug == "real"


def test_status_handles_non_dict_records_gracefully() -> None:
    """A garbled live state shouldn't kill the report (mirrors differ behaviour)."""
    state = LiveState(
        policies=["not-a-dict", _policy_record(name="Foo-Test", description=None)],  # type: ignore[list-item]
        rule_groups=[None],  # type: ignore[list-item]
        locations=[42],  # type: ignore[list-item]
    )
    report = build_status_report(state)
    assert report.total == 1
    assert report.entries[0].kind == KIND_POLICY


# ---- locations are tenant-global -----------------------------------------


def test_status_location_with_signature_uses_signature_env() -> None:
    """Locations don't carry env suffixes; the trailer is the source of truth."""
    state = _state(
        locations=[
            _location_record(
                name="corp-vpn",
                description=_signed(env="pilot"),
            )
        ],
    )
    report = build_status_report(state)
    entry = report.entries[0]
    assert entry.kind == KIND_LOCATION
    assert entry.slug == "corp-vpn"
    assert "pilot" in entry.envs


def test_status_location_without_signature_uses_any_env() -> None:
    """An unmanaged location appears under the ``LOCATION_ENV`` pseudo-tag."""
    state = _state(
        locations=[_location_record(name="HQ", description="hand-rolled")],
    )
    report = build_status_report(state)
    entry = report.entries[0]
    assert entry.kind == KIND_LOCATION
    assert LOCATION_ENV in entry.envs
    assert entry.envs[LOCATION_ENV].managed is False


# ---- ordering / summary --------------------------------------------------


def test_status_entries_sorted_by_kind_then_slug() -> None:
    """Apply-order (location → rule-group → policy) then slug alphabetic."""
    state = _state(
        policies=[_policy_record(name="Zeta-Test", description=None)],
        rule_groups=[_rule_group_record(name="aaaa-Test", description=None)],
        locations=[_location_record(name="middle", description=None)],
    )
    report = build_status_report(state)
    kinds = [entry.kind for entry in report.entries]
    assert kinds == [KIND_LOCATION, KIND_RULE_GROUP, KIND_POLICY]


def test_status_summary_counts_managed_vs_unmanaged() -> None:
    """``managed`` + ``unmanaged`` always sum to ``total``."""
    state = _state(
        policies=[
            _policy_record(name="A-Test", description=_signed("test")),
            _policy_record(name="B-Test", description=None),
        ],
        rule_groups=[
            _rule_group_record(name="rg1-Test", description=_signed("test")),
            _rule_group_record(name="rg2-Test", description="random text"),
        ],
        locations=[_location_record(name="loc1", description=_signed("test"))],
    )
    report = build_status_report(state)
    assert report.total == 5
    assert report.managed == 3
    assert report.unmanaged == 2


def test_status_managed_envs_property_lists_managed_envs_in_canonical_order() -> None:
    """``managed_envs`` preserves test/pilot/production ordering."""
    state = _state(
        policies=[
            _policy_record(name="Foo-Production", description=_signed("production")),
            _policy_record(name="Foo-Test", description=_signed("test")),
            _policy_record(name="Foo-Pilot", description=None),  # unmanaged
        ]
    )
    report = build_status_report(state)
    entry = report.entries[0]
    assert entry.managed_envs == ["test", "production"]


# ---- JSON serialization ---------------------------------------------------


def test_status_report_to_json_is_serialisable_shape() -> None:
    """``to_json`` produces a dict suitable for ``json.dumps`` with summary."""
    state = _state(
        policies=[
            _policy_record(name="Foo-Test", description=_signed("test", version=3)),
        ]
    )
    report = build_status_report(state)
    payload = report.to_json()
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["managed"] == 1
    assert payload["summary"]["unmanaged"] == 0
    assert payload["summary"]["by_kind"][KIND_POLICY] == 1
    entries = payload["entries"]
    assert entries[0]["slug"] == "foo"
    env_payload = entries[0]["envs"]["test"]
    assert env_payload["managed"] is True
    assert env_payload["signature"]["version"] == 3
    assert env_payload["signature"]["env"] == "test"


def test_status_report_unmanaged_section_when_no_signature() -> None:
    """JSON shape stays valid when an env has ``signature=None``."""
    state = _state(
        policies=[_policy_record(name="Foo-Test", description=None)],
    )
    payload = build_status_report(state).to_json()
    assert payload["entries"][0]["envs"]["test"]["signature"] is None


# ---- display name handling -----------------------------------------------


def test_status_display_name_strips_env_suffix() -> None:
    """``StatusEntry.display_name`` shows the env-stripped name."""
    state = _state(
        policies=[
            _policy_record(name="ABC01-Endpoints-Windows-Test", description=None),
            _policy_record(name="ABC01-Endpoints-Windows-Production", description=None),
        ]
    )
    entry = build_status_report(state).entries[0]
    assert entry.display_name == "ABC01-Endpoints-Windows"


def test_status_env_order_constant_is_canonical_apply_order() -> None:
    """``ENV_ORDER`` matches the project's test → pilot → production flow."""
    assert ENV_ORDER == ("test", "pilot", "production")
