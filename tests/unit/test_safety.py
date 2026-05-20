"""Unit tests for :mod:`csfwctl.safety`.

Each safety rail has its own focused test set: signature parsing /
rendering / merging, bootstrap detection, blast-radius limits,
drift/enforce, and the git-sha resolver.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime

import pytest

from csfwctl.differ import (
    ChangeSet,
    DiffOp,
    ManagedStatus,
    ObjectChange,
)
from csfwctl.safety import (
    ENV_GIT_SHA,
    BlastRadiusExceeded,
    DriftBlocked,
    MetadataSignature,
    SafetyError,
    SafetyOptions,
    UnbootstrappedTenantError,
    check_blast_radius,
    check_bootstrap,
    check_deletes,
    check_drift,
    current_git_sha,
    inject_signature,
    is_tenant_bootstrapped,
    next_signature,
    parse_signature,
    render_signature,
    strip_signature,
)

# ---- signature rendering / parsing ---------------------------------------


def _sig(version: int = 1, env: str = "test") -> MetadataSignature:
    return MetadataSignature(
        version=version, git_sha="abc1234", applied="2026-05-19T14:30:00Z", env=env
    )


def test_render_signature_uses_fixed_format() -> None:
    sig = _sig(version=7, env="production")
    line = render_signature(sig)
    assert line == (
        "Managed by csfwctl | version: 7 | git_sha: abc1234 | "
        "applied: 2026-05-19T14:30:00Z | env: production"
    )


def test_parse_signature_round_trips() -> None:
    sig = _sig(version=5)
    parsed = parse_signature(render_signature(sig))
    assert parsed == sig


def test_parse_signature_returns_latest_when_multiple_lines() -> None:
    older = render_signature(_sig(version=3))
    newer = render_signature(_sig(version=4))
    body = f"Free text\n{older}\n{newer}"
    parsed = parse_signature(body)
    assert parsed is not None
    assert parsed.version == 4


def test_parse_signature_returns_none_for_empty_or_unsigned() -> None:
    assert parse_signature(None) is None
    assert parse_signature("") is None
    assert parse_signature("just free text here") is None


def test_strip_signature_drops_block_only() -> None:
    body = f"Baseline policy.\n\n{render_signature(_sig())}"
    assert strip_signature(body) == "Baseline policy."


def test_inject_signature_preserves_free_text() -> None:
    existing = "Free text body.\n\nManaged by csfwctl | version: 1 | git_sha: deadbeef | applied: 2026-01-01T00:00:00Z | env: test"
    sig = _sig(version=2)
    merged = inject_signature(existing, sig)
    assert "Free text body." in merged
    assert render_signature(sig) in merged
    # Old trailer is gone.
    assert "version: 1" not in merged


def test_inject_signature_on_empty_description() -> None:
    merged = inject_signature(None, _sig())
    assert merged == render_signature(_sig())


def test_next_signature_increments_version() -> None:
    previous = _sig(version=4)
    out = next_signature(previous, git_sha="newsha", env="test")
    assert out.version == 5
    assert out.git_sha == "newsha"


def test_next_signature_starts_at_one_when_no_previous() -> None:
    out = next_signature(None, git_sha="sha1", env="pilot")
    assert out.version == 1
    assert out.env == "pilot"


def test_next_signature_uses_passed_clock() -> None:
    out = next_signature(
        None, git_sha="x", env="test", now=datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
    )
    assert out.applied == "2030-01-02T03:04:05Z"


# ---- tenant bootstrap detection ------------------------------------------


def test_is_tenant_bootstrapped_true_when_any_signature_present() -> None:
    descs = ["no signature here", render_signature(_sig())]
    assert is_tenant_bootstrapped(descs) is True


def test_is_tenant_bootstrapped_false_otherwise() -> None:
    assert is_tenant_bootstrapped(["plain", "more plain", None, ""]) is False


def test_check_bootstrap_passes_when_initial_bootstrap_set() -> None:
    options = SafetyOptions(initial_bootstrap=True)
    check_bootstrap(live_descriptions=["nothing"], options=options)


def test_check_bootstrap_raises_on_unbootstrapped_normal_apply() -> None:
    with pytest.raises(UnbootstrappedTenantError):
        check_bootstrap(live_descriptions=["no signature"], options=SafetyOptions())


def test_check_bootstrap_ok_when_tenant_has_signature() -> None:
    descs = [render_signature(_sig())]
    check_bootstrap(live_descriptions=descs, options=SafetyOptions())


# ---- helpers for the safety checks below --------------------------------


def _change(
    *,
    kind: str = "policy",
    op: DiffOp = DiffOp.update,
    slug: str = "p1",
    managed: ManagedStatus = ManagedStatus.managed,
) -> ObjectChange:
    return ObjectChange(
        kind=kind, op=op, slug=slug, display_name=slug, managed=managed
    )


def _cs(
    *,
    creates: int = 0,
    updates: int = 0,
    deletes: int = 0,
    updates_managed: bool = True,
) -> ChangeSet:
    cs = ChangeSet(env="test")
    for i in range(creates):
        cs.creates.append(_change(slug=f"c{i}", op=DiffOp.create, managed=ManagedStatus.new))
    for i in range(updates):
        cs.updates.append(
            _change(
                slug=f"u{i}",
                op=DiffOp.update,
                managed=ManagedStatus.managed if updates_managed else ManagedStatus.unmanaged,
            )
        )
    for i in range(deletes):
        cs.deletes.append(_change(slug=f"d{i}", op=DiffOp.delete))
    return cs


# ---- blast-radius ---------------------------------------------------------


def test_check_blast_radius_ok_within_limits() -> None:
    cs = _cs(creates=2, updates=2, deletes=0)
    report = check_blast_radius(cs, SafetyOptions(max_changes=10, max_deletes=1))
    assert report.total_changes == 4
    assert report.deletes == 0


def test_check_blast_radius_exceeds_changes() -> None:
    cs = _cs(creates=11)
    with pytest.raises(BlastRadiusExceeded, match="changes? exceed|11 change|11 change\\(s\\)"):
        check_blast_radius(cs, SafetyOptions(max_changes=10))


def test_check_blast_radius_exceeds_deletes() -> None:
    cs = _cs(deletes=3)
    with pytest.raises(BlastRadiusExceeded, match="delete"):
        check_blast_radius(cs, SafetyOptions(max_deletes=1, max_changes=100))


def test_check_blast_radius_bootstrap_skips_change_cap_but_not_delete_cap() -> None:
    cs = _cs(updates=50, deletes=0)
    # Bootstrap touches every live object's description, which can easily
    # blow past max_changes; we exempt it from that limit.
    check_blast_radius(cs, SafetyOptions(max_changes=10, initial_bootstrap=True))
    # Delete cap still applies.
    cs_with_delete = _cs(deletes=2)
    with pytest.raises(BlastRadiusExceeded):
        check_blast_radius(
            cs_with_delete, SafetyOptions(max_deletes=1, initial_bootstrap=True)
        )


# ---- drift / enforce -----------------------------------------------------


def test_check_drift_raises_for_managed_update_without_enforce() -> None:
    cs = _cs(updates=1, updates_managed=True)
    with pytest.raises(DriftBlocked):
        check_drift(cs, SafetyOptions())


def test_check_drift_passes_with_enforce() -> None:
    cs = _cs(updates=2, updates_managed=True)
    check_drift(cs, SafetyOptions(enforce=True))


def test_check_drift_skips_unmanaged_updates() -> None:
    cs = _cs(updates=1, updates_managed=False)
    check_drift(cs, SafetyOptions())


def test_check_drift_skipped_in_bootstrap() -> None:
    cs = _cs(updates=1)
    check_drift(cs, SafetyOptions(initial_bootstrap=True))


# ---- deletes -------------------------------------------------------------


def test_check_deletes_passes_when_no_deletes() -> None:
    check_deletes(_cs(), SafetyOptions())


def test_check_deletes_requires_allow_delete_flag() -> None:
    cs = _cs(deletes=1)
    with pytest.raises(SafetyError, match="allow-delete"):
        check_deletes(cs, SafetyOptions(allow_delete=False))


def test_check_deletes_passes_with_allow_delete() -> None:
    cs = _cs(deletes=1)
    check_deletes(cs, SafetyOptions(allow_delete=True))


def test_check_deletes_forbidden_in_bootstrap_mode() -> None:
    cs = _cs(deletes=1)
    with pytest.raises(SafetyError, match="bootstrap"):
        check_deletes(cs, SafetyOptions(initial_bootstrap=True, allow_delete=True))


# ---- git sha resolver ----------------------------------------------------


def test_current_git_sha_prefers_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ENV_GIT_SHA, "fromenv123")
    assert current_git_sha() == "fromenv123"


def test_current_git_sha_falls_back_to_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ENV_GIT_SHA, raising=False)

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=0, stdout="abc1234\n", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert current_git_sha() == "abc1234"


def test_current_git_sha_returns_unknown_on_subprocess_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(ENV_GIT_SHA, raising=False)

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=[], returncode=128, stdout="", stderr="bad")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert current_git_sha() == "unknown"


def test_current_git_sha_handles_oserror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_GIT_SHA, raising=False)

    def fake_run(*_args: object, **_kwargs: object) -> None:
        raise OSError("git not on PATH")

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert current_git_sha() == "unknown"
