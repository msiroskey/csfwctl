"""Unit tests for :mod:`csfwctl.precedence_resolver`.

The resolver turns a config repo's policies plus ``precedence.yaml``
overrides into a deterministic per-platform ordering. These tests
cover the base sort, override application, cycle detection, and the
live-state comparison helper.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from csfwctl.loader import ConfigRepo
from csfwctl.precedence_resolver import (
    BUCKET_ORDER,
    BUCKET_RANK,
    PrecedenceComparison,
    PrecedenceError,
    compare_to_live,
    resolve_precedence,
)
from csfwctl.schema import (
    HostGroupEnv,
    Platform,
    Policy,
    PrecedenceBucket,
    PrecedenceOverride,
    PrecedenceOverrides,
    Status,
)


def _policy(
    *,
    name: str,
    platform: Platform = Platform.windows,
    bucket: PrecedenceBucket = PrecedenceBucket.default,
    status: Status = Status.enabled,
) -> Policy:
    """Build a minimal Policy good enough for precedence resolution.

    ``name`` is the display name (TitleCase). The slug is derived via
    ``to_slug`` so the Policy model's ``name`` field gets a valid slug.
    """
    from csfwctl.exporter import to_slug as _to_slug

    slug = _to_slug(name)
    return Policy(
        name=slug,
        display_name=name if name != slug else None,
        platform=platform,
        priority=bucket,
        status=status,
        host_groups={f"{name}-Test": HostGroupEnv.test},
    )


def _repo(
    *,
    policies: dict[str, Policy] | None = None,
    overrides: list[PrecedenceOverride] | None = None,
) -> ConfigRepo:
    """Repo built from in-memory policies plus optional overrides."""
    repo = ConfigRepo(root=Path("/tmp/fake-repo"))
    repo.policies = dict(policies or {})
    repo.precedence_overrides = PrecedenceOverrides(overrides=overrides or [])
    return repo


# ---- bucket ordering & alphabetical tie-break ----------------------------


def test_bucket_order_matches_project_plan_order() -> None:
    """Highest precedence first: emergency, high, medium, default, low."""
    assert BUCKET_ORDER == (
        PrecedenceBucket.emergency,
        PrecedenceBucket.high,
        PrecedenceBucket.medium,
        PrecedenceBucket.default,
        PrecedenceBucket.low,
    )


def test_resolves_policies_by_bucket_then_alphabetic() -> None:
    """Within a platform: bucket rank then policy name alphabetic."""
    repo = _repo(
        policies={
            "zeta": _policy(name="Zeta", bucket=PrecedenceBucket.low),
            "alpha": _policy(name="Alpha", bucket=PrecedenceBucket.default),
            "incident": _policy(name="Incident", bucket=PrecedenceBucket.emergency),
            "high-priority": _policy(name="HighPriority", bucket=PrecedenceBucket.high),
        }
    )
    resolved = resolve_precedence(repo)
    windows = resolved[Platform.windows]
    assert [p.slug for p in windows] == ["incident", "high-priority", "alpha", "zeta"]
    assert [p.ordinal for p in windows] == [0, 1, 2, 3]


def test_resolves_per_platform_independently() -> None:
    """Windows and Mac policies are sorted into separate lists."""
    repo = _repo(
        policies={
            "win-1": _policy(name="WinOne", platform=Platform.windows),
            "win-2": _policy(name="WinTwo", platform=Platform.windows),
            "mac-1": _policy(name="MacOne", platform=Platform.mac),
        }
    )
    resolved = resolve_precedence(repo)
    assert Platform.windows in resolved
    assert Platform.mac in resolved
    assert [p.slug for p in resolved[Platform.windows]] == ["win-1", "win-2"]
    assert [p.slug for p in resolved[Platform.mac]] == ["mac-1"]


def test_resolve_excludes_deleted_status_policies() -> None:
    """``status: deleted`` is treated as 'do not include in precedence'."""
    repo = _repo(
        policies={
            "alive": _policy(name="Alive"),
            "dead": _policy(name="Dead", status=Status.deleted),
        }
    )
    resolved = resolve_precedence(repo)
    slugs = [p.slug for p in resolved[Platform.windows]]
    assert slugs == ["alive"]


def test_resolve_empty_repo_returns_empty_dict() -> None:
    """No policies → no platforms in the result."""
    resolved = resolve_precedence(_repo())
    assert resolved == {}


def test_bucket_rank_dense_and_monotonic() -> None:
    """Ranks are 0..4 dense and match :data:`BUCKET_ORDER` index."""
    assert sorted(BUCKET_RANK.values()) == [0, 1, 2, 3, 4]
    for index, bucket in enumerate(BUCKET_ORDER):
        assert BUCKET_RANK[bucket] == index


# ---- override application ------------------------------------------------


def test_override_moves_before_ahead_of_after_in_same_bucket() -> None:
    """``research → abc`` raises research-lab-7 ahead of abc-endpoints."""
    repo = _repo(
        policies={
            "abc-endpoints": _policy(name="AbcEndpoints"),
            "research-lab-7": _policy(name="ResearchLab7"),
        },
        overrides=[
            PrecedenceOverride(before="research-lab-7", after="abc-endpoints"),
        ],
    )
    resolved = resolve_precedence(repo)
    slugs = [p.slug for p in resolved[Platform.windows]]
    assert slugs == ["research-lab-7", "abc-endpoints"]


def test_override_is_noop_when_already_in_target_order() -> None:
    """Base sort already has ``before`` ahead → override leaves order unchanged."""
    repo = _repo(
        policies={
            "alpha": _policy(name="Alpha"),
            "beta": _policy(name="Beta"),
        },
        overrides=[
            PrecedenceOverride(before="alpha", after="beta"),
        ],
    )
    slugs = [p.slug for p in resolve_precedence(repo)[Platform.windows]]
    assert slugs == ["alpha", "beta"]


def test_override_silently_skips_when_slug_outside_platform() -> None:
    """An override spanning platforms doesn't kick a KeyError."""
    repo = _repo(
        policies={
            "win-1": _policy(name="WinOne", platform=Platform.windows),
            "mac-1": _policy(name="MacOne", platform=Platform.mac),
        },
        overrides=[
            PrecedenceOverride(before="mac-1", after="win-1"),
        ],
    )
    # Windows and Mac platforms each have a single policy; the override
    # references slugs in different platforms and is simply ignored.
    resolved = resolve_precedence(repo)
    assert [p.slug for p in resolved[Platform.windows]] == ["win-1"]
    assert [p.slug for p in resolved[Platform.mac]] == ["mac-1"]


def test_multiple_overrides_apply_in_declaration_order() -> None:
    """Override aa → bb, then bb → cc gives final order aa, bb, cc."""
    # Buckets pre-arrange aa/bb/cc into reverse order; overrides restore it.
    repo = _repo(
        policies={
            "aa": _policy(name="Alpha", bucket=PrecedenceBucket.low),
            "bb": _policy(name="Beta", bucket=PrecedenceBucket.default),
            "cc": _policy(name="Gamma", bucket=PrecedenceBucket.high),
        },
        overrides=[
            PrecedenceOverride(before="bb", after="cc"),
            PrecedenceOverride(before="aa", after="bb"),
        ],
    )
    slugs = [p.slug for p in resolve_precedence(repo)[Platform.windows]]
    assert slugs == ["aa", "bb", "cc"]


def test_override_cycle_raises_precedence_error() -> None:
    """A → B then B → A within the same platform is unsatisfiable."""
    repo = _repo(
        policies={
            "alpha": _policy(name="Alpha"),
            "beta": _policy(name="Beta"),
        },
        overrides=[
            PrecedenceOverride(before="beta", after="alpha"),
            PrecedenceOverride(before="alpha", after="beta"),
        ],
    )
    with pytest.raises(PrecedenceError):
        resolve_precedence(repo)


# ---- live comparison -----------------------------------------------------


def _live_record(name: str, *, record_id: str | None = None) -> dict[str, Any]:
    return {"id": record_id or f"id-{name}", "name": name}


def test_compare_matches_when_live_matches_resolved_order() -> None:
    """Live records env-suffixed and in resolved order → ``matches=True``."""
    repo = _repo(
        policies={
            "alpha": _policy(name="Alpha", bucket=PrecedenceBucket.high),
            "beta": _policy(name="Beta", bucket=PrecedenceBucket.default),
        }
    )
    resolved = resolve_precedence(repo)[Platform.windows]
    live = [
        _live_record("Alpha-Test"),
        _live_record("Beta-Test"),
    ]
    comparison = compare_to_live(resolved, live, env="test")
    assert comparison.matches is True
    assert comparison.resolved_slugs == ["alpha", "beta"]
    assert comparison.live_slugs == ["alpha", "beta"]


def test_compare_flags_mismatch_when_live_order_differs() -> None:
    """Same slugs in different order → ``matches=False``."""
    repo = _repo(
        policies={
            "alpha": _policy(name="Alpha", bucket=PrecedenceBucket.high),
            "beta": _policy(name="Beta", bucket=PrecedenceBucket.default),
        }
    )
    resolved = resolve_precedence(repo)[Platform.windows]
    live = [
        _live_record("Beta-Test"),
        _live_record("Alpha-Test"),
    ]
    comparison = compare_to_live(resolved, live, env="test")
    assert comparison.matches is False
    assert comparison.live_slugs == ["beta", "alpha"]


def test_compare_filters_live_records_by_env() -> None:
    """Records whose suffix doesn't match ``env`` are excluded."""
    repo = _repo(
        policies={"alpha": _policy(name="Alpha")},
    )
    resolved = resolve_precedence(repo)[Platform.windows]
    live = [
        _live_record("Alpha-Pilot"),
        _live_record("Alpha-Test"),
        _live_record("Alpha-Production"),
    ]
    comparison = compare_to_live(resolved, live, env="test")
    assert comparison.live_slugs == ["alpha"]
    assert comparison.matches is True


def test_compare_ignores_live_only_extras() -> None:
    """Live slugs not in resolved are filtered out (e.g., unmanaged policy)."""
    repo = _repo(policies={"alpha": _policy(name="Alpha")})
    resolved = resolve_precedence(repo)[Platform.windows]
    live = [
        _live_record("LegacyConsoleOnly-Test"),
        _live_record("Alpha-Test"),
    ]
    comparison = compare_to_live(resolved, live, env="test")
    assert comparison.live_slugs == ["alpha"]
    assert comparison.matches is True


def test_compare_empty_resolved_returns_no_match() -> None:
    """No resolved policies → no comparison can match."""
    comparison = compare_to_live([], [_live_record("Alpha-Test")], env="test")
    assert isinstance(comparison, PrecedenceComparison)
    assert comparison.matches is False
    assert comparison.resolved_slugs == []


# ---- JSON serialisation -------------------------------------------------


def test_resolved_policy_json_roundtrip() -> None:
    """``ResolvedPolicy.to_json`` carries slug/name/platform/bucket/ordinal."""
    repo = _repo(
        policies={"alpha": _policy(name="Alpha", bucket=PrecedenceBucket.high)},
    )
    policy = resolve_precedence(repo)[Platform.windows][0]
    payload = policy.to_json()
    assert payload == {
        "slug": "alpha",
        "name": "Alpha",
        "platform": "windows",
        "bucket": "high",
        "ordinal": 0,
    }


def test_comparison_json_includes_all_fields() -> None:
    """JSON shape exposes platform/resolved/live/matches."""
    repo = _repo(policies={"alpha": _policy(name="Alpha")})
    resolved = resolve_precedence(repo)[Platform.windows]
    payload = compare_to_live(resolved, [_live_record("Alpha-Test")], env="test").to_json()
    assert payload["platform"] == "windows"
    assert payload["resolved"] == ["alpha"]
    assert payload["live"] == ["alpha"]
    assert payload["matches"] is True
