"""Bucket-to-ordinal precedence resolver — the engine behind ``csfwctl precedence``.

Each policy declares a coarse :class:`csfwctl.schema.PrecedenceBucket`
(``emergency`` / ``high`` / ``medium`` / ``default`` / ``low``). The
resolver expands that into a deterministic per-platform ordering:

1. Sort by bucket (emergency wins).
2. Break ties alphabetically by the policy's TitleCase ``name``.
3. Apply :class:`csfwctl.schema.PrecedenceOverride` entries from
   ``precedence.yaml``: each ``before/after`` pair lifts ``before``
   ahead of ``after`` if it isn't already.

The applier's step-4 hook in :func:`csfwctl.applier.apply_change_set`
will eventually call :func:`apply_precedence_to_tenant` with the
resolved order to converge live state.

The override loop is intentionally simple: each override is processed
in declaration order, moving ``before`` to the slot immediately ahead
of ``after`` if needed. Conflicting overrides therefore resolve in
favour of the *last* one to fire. Cycles are detected and surfaced as
:class:`PrecedenceError` so the operator notices.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from csfwctl.exporter import strip_env_suffix
from csfwctl.loader import ConfigRepo
from csfwctl.schema import Platform, Policy, PrecedenceBucket, PrecedenceOverride

BUCKET_ORDER: tuple[PrecedenceBucket, ...] = (
    PrecedenceBucket.emergency,
    PrecedenceBucket.high,
    PrecedenceBucket.medium,
    PrecedenceBucket.default,
    PrecedenceBucket.low,
)
"""Highest-precedence first. Matches the project plan's bucket list."""

BUCKET_RANK: dict[PrecedenceBucket, int] = {
    bucket: index for index, bucket in enumerate(BUCKET_ORDER)
}


class PrecedenceError(Exception):
    """Raised when overrides cannot be applied (e.g., a cycle)."""


@dataclass(frozen=True)
class ResolvedPolicy:
    """One policy's place in the resolved per-platform order."""

    slug: str
    name: str
    platform: Platform
    bucket: PrecedenceBucket
    ordinal: int

    def to_json(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "name": self.name,
            "platform": self.platform.value,
            "bucket": self.bucket.value,
            "ordinal": self.ordinal,
        }


@dataclass(frozen=True)
class PrecedenceComparison:
    """Result of comparing a resolved order against live tenant order.

    ``matches`` is true only when every entry's position lines up. The
    ``moves`` list records, in resolved order, the previous live
    position for each policy slug (or ``None`` when the live tenant has
    no matching policy).
    """

    platform: Platform
    resolved_slugs: list[str]
    live_slugs: list[str]
    matches: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "platform": self.platform.value,
            "resolved": list(self.resolved_slugs),
            "live": list(self.live_slugs),
            "matches": self.matches,
        }


# ---- core resolution ------------------------------------------------------


def resolve_precedence(repo: ConfigRepo) -> dict[Platform, list[ResolvedPolicy]]:
    """Compute the per-platform resolved precedence order.

    Returns a mapping keyed by :class:`Platform`. Platforms with no
    policies are omitted. Skipped (``deleted`` status) policies are
    excluded so the result reflects what the applier would actually
    push.
    """
    by_platform: dict[Platform, list[tuple[str, Policy]]] = defaultdict(list)
    for slug, policy in repo.policies.items():
        if policy.status.value == "deleted":
            continue
        by_platform[policy.platform].append((slug, policy))

    overrides = list(repo.precedence_overrides.overrides)
    result: dict[Platform, list[ResolvedPolicy]] = {}
    for platform, slugs_policies in by_platform.items():
        order = _base_order(slugs_policies)
        order = _apply_overrides(order, overrides)
        by_slug: dict[str, Policy] = {slug: policy for slug, policy in slugs_policies}
        result[platform] = [
            ResolvedPolicy(
                slug=slug,
                name=by_slug[slug].name,
                platform=platform,
                bucket=by_slug[slug].priority,
                ordinal=index,
            )
            for index, slug in enumerate(order)
        ]
    return result


def _base_order(slugs_policies: list[tuple[str, Policy]]) -> list[str]:
    """Stable sort: bucket rank then alphabetical by display name."""
    sorted_pairs = sorted(
        slugs_policies, key=lambda sp: (BUCKET_RANK[sp[1].priority], sp[1].name, sp[0])
    )
    return [slug for slug, _ in sorted_pairs]


def _apply_overrides(order: list[str], overrides: list[PrecedenceOverride]) -> list[str]:
    """Apply each override in declaration order.

    ``before`` is moved to the slot immediately ahead of ``after`` if it
    is not already ahead. Overrides referencing slugs outside ``order``
    are silently skipped — they may belong to the other platform.

    Cycles (A→B and B→A both within the same platform) are detected and
    raised as :class:`PrecedenceError` so the operator can fix the YAML.
    """
    out = list(order)
    seen_pairs: set[tuple[str, str]] = set()
    for override in overrides:
        forward = (override.before, override.after)
        reverse = (override.after, override.before)
        if reverse in seen_pairs and forward[0] in out and forward[1] in out:
            raise PrecedenceError(
                "precedence overrides form a cycle involving "
                f"{override.before!r} and {override.after!r}"
            )
        seen_pairs.add(forward)
        if override.before not in out or override.after not in out:
            continue
        before_index = out.index(override.before)
        after_index = out.index(override.after)
        if before_index < after_index:
            continue
        slug = out.pop(before_index)
        # after_index may have shifted left by the pop; recompute.
        new_after_index = out.index(override.after)
        out.insert(new_after_index, slug)
    return out


# ---- live comparison ------------------------------------------------------


def compare_to_live(
    resolved: list[ResolvedPolicy],
    live_records: list[dict[str, Any]],
    *,
    env: str | None = None,
) -> PrecedenceComparison:
    """Compare a per-platform resolved order against live tenant records.

    ``live_records`` is the platform-filtered policy list from the
    tenant in precedence order (FalconPy returns ``query_policies`` in
    that order). When ``env`` is given, only live records whose display
    name carries the matching env suffix are considered; that keeps the
    comparison apples-to-apples with what the applier will write.
    """
    if not resolved:
        return PrecedenceComparison(
            platform=Platform.windows,  # dummy; never used downstream
            resolved_slugs=[],
            live_slugs=_live_slugs(live_records, env=env),
            matches=False,
        )
    platform = resolved[0].platform
    resolved_slugs = [r.slug for r in resolved]
    live_slugs = _live_slugs(live_records, env=env)
    # Restrict the live view to slugs we know about so a live-only entry
    # doesn't dominate the comparison.
    filtered_live = [slug for slug in live_slugs if slug in set(resolved_slugs)]
    return PrecedenceComparison(
        platform=platform,
        resolved_slugs=resolved_slugs,
        live_slugs=filtered_live,
        matches=resolved_slugs == filtered_live,
    )


def _live_slugs(records: list[dict[str, Any]], *, env: str | None) -> list[str]:
    """Translate live policy records into env-stripped slug order.

    Records whose display name lacks the expected env suffix are
    skipped when ``env`` is passed; otherwise the suffix is stripped
    permissively (matching the differ's slug derivation).
    """
    out: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        name = str(record.get("name", "")).strip()
        if not name:
            continue
        base, suffix_env = strip_env_suffix(name)
        if env is not None and suffix_env != env:
            continue
        out.append(base.lower())
    return out


__all__ = [
    "BUCKET_ORDER",
    "BUCKET_RANK",
    "PrecedenceComparison",
    "PrecedenceError",
    "ResolvedPolicy",
    "compare_to_live",
    "resolve_precedence",
]
