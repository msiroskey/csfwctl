"""Load and validate a csfwctl-config repository.

Walks the on-disk directory layout (``policies/``, ``rule_groups/``,
``locations/``, plus the root files ``tombstones.yaml``,
``precedence.yaml``, ``csfwctl.toml``), parses each document with
:mod:`ruamel.yaml` for round-trip preservation, runs Pydantic v2 schema
validation, and performs cross-reference checks across the loaded set.

The public entrypoint is :func:`load_config_repo`, which raises
:class:`ConfigRepoError` aggregating every problem found. The caller —
typically ``csfwctl validate`` — renders those errors for the operator.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from csfwctl.schema import (
    ANY_LOCATION,
    Location,
    Platform,
    Policy,
    PrecedenceOverrides,
    RuleGroup,
    Tombstones,
    ToolConfig,
)

POLICIES_DIR = "policies"
RULE_GROUPS_DIR = "rule_groups"
LOCATIONS_DIR = "locations"
TOMBSTONES_FILE = "tombstones.yaml"
PRECEDENCE_FILE = "precedence.yaml"
TOOL_CONFIG_FILE = "csfwctl.toml"


@dataclass(frozen=True)
class LoadError:
    """A single problem detected while loading a config repo.

    ``path`` is the offending file; ``line`` may be ``None`` when no
    line information is available (e.g., a cross-reference check or a
    Pydantic field error whose location is structural rather than
    textual).
    """

    path: Path
    message: str
    line: int | None = None
    field_path: str | None = None

    def format(self) -> str:
        """Human-readable single-line representation for CLI output."""
        loc_parts: list[str] = [str(self.path)]
        if self.line is not None:
            loc_parts.append(str(self.line))
        if self.field_path:
            loc_parts.append(self.field_path)
        return f"{':'.join(loc_parts)}: {self.message}"


class ConfigRepoError(Exception):
    """Aggregate error raised when one or more :class:`LoadError` are found."""

    def __init__(self, errors: list[LoadError]) -> None:
        self.errors = errors
        super().__init__(f"{len(errors)} error(s) loading config repo")


@dataclass
class ConfigRepo:
    """In-memory representation of a parsed and validated config repo.

    Maps are keyed by filename slug (the kebab-case stem of the YAML
    file). For rule groups and locations the slug matches the document's
    ``name`` field; for policies the slug is independent of the
    TitleCase ``name`` field, which is the CrowdStrike display name.
    """

    root: Path
    policies: dict[str, Policy] = field(default_factory=dict)
    rule_groups: dict[str, RuleGroup] = field(default_factory=dict)
    locations: dict[str, Location] = field(default_factory=dict)
    tombstones: Tombstones = field(default_factory=Tombstones)
    precedence_overrides: PrecedenceOverrides = field(default_factory=PrecedenceOverrides)
    tool_config: ToolConfig = field(default_factory=ToolConfig)


def _yaml() -> YAML:
    """Round-trip YAML reader/writer with comment preservation."""
    yaml = YAML(typ="rt")
    yaml.preserve_quotes = True
    return yaml


def _parse_yaml_file(path: Path, errors: list[LoadError]) -> Any | None:
    """Parse a YAML file. Append a :class:`LoadError` on failure."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(LoadError(path=path, message=f"cannot read file: {exc}"))
        return None
    try:
        return _yaml().load(text)
    except YAMLError as exc:
        line: int | None = None
        problem_mark = getattr(exc, "problem_mark", None)
        if problem_mark is not None:
            line = problem_mark.line + 1
        errors.append(LoadError(path=path, line=line, message=f"YAML parse error: {exc}"))
        return None


def _coerce_for_pydantic(data: Any) -> Any:
    """Convert ruamel round-trip containers to plain Python types.

    Pydantic 2 handles dicts/lists/scalars; ruamel's
    ``CommentedMap``/``CommentedSeq`` subclass those, but converting
    keeps validation error paths tidy.
    """
    if isinstance(data, dict):
        return {str(k): _coerce_for_pydantic(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_coerce_for_pydantic(item) for item in data]
    return data


def _format_pydantic_loc(loc: tuple[Any, ...]) -> str:
    """Render a Pydantic error ``loc`` as a dotted path."""
    return ".".join(str(part) for part in loc)


def _validate_model(
    model_cls: type[BaseModel],
    raw: Any,
    path: Path,
    errors: list[LoadError],
) -> Any | None:
    """Run schema validation, appending one :class:`LoadError` per problem."""
    try:
        return model_cls.model_validate(_coerce_for_pydantic(raw))
    except ValidationError as exc:
        for err in exc.errors():
            errors.append(
                LoadError(
                    path=path,
                    field_path=_format_pydantic_loc(err["loc"]),
                    message=err["msg"],
                )
            )
        return None


def _load_kind(
    kind_dir: Path,
    model_cls: type[BaseModel],
    errors: list[LoadError],
) -> dict[str, Any]:
    """Load every ``*.yaml`` under ``kind_dir`` keyed by filename slug."""
    out: dict[str, Any] = {}
    if not kind_dir.is_dir():
        return out
    for path in sorted(kind_dir.glob("*.yaml")):
        slug = path.stem
        raw = _parse_yaml_file(path, errors)
        if raw is None:
            continue
        if not isinstance(raw, dict):
            errors.append(LoadError(path=path, message="top-level YAML document must be a mapping"))
            continue
        model = _validate_model(model_cls, raw, path, errors)
        if model is None:
            continue
        # The filename stem must equal the in-document ``name`` for all
        # object kinds so cross-references resolve correctly.
        doc_name = getattr(model, "name", None)
        if doc_name is not None and doc_name != slug:
            errors.append(
                LoadError(
                    path=path,
                    field_path="name",
                    message=(
                        f"name {doc_name!r} does not match filename slug {slug!r}; "
                        "they must agree for cross-references to work"
                    ),
                )
            )
            continue
        if slug in out:
            errors.append(LoadError(path=path, message=f"duplicate slug {slug!r} within this kind"))
            continue
        out[slug] = model
    return out


def _load_top_level_yaml(
    path: Path,
    model_cls: type[BaseModel],
    errors: list[LoadError],
) -> Any | None:
    """Load an optional top-level YAML file (tombstones, precedence)."""
    if not path.is_file():
        return model_cls()
    raw = _parse_yaml_file(path, errors)
    if raw is None:
        return None
    if raw is None or raw == {}:
        return model_cls()
    if not isinstance(raw, dict):
        errors.append(LoadError(path=path, message="top-level YAML document must be a mapping"))
        return None
    return _validate_model(model_cls, raw, path, errors)


def _load_tool_config(path: Path, errors: list[LoadError]) -> ToolConfig | None:
    """Parse ``csfwctl.toml`` if present; return a default ``ToolConfig`` otherwise."""
    if not path.is_file():
        return ToolConfig()
    try:
        with path.open("rb") as fp:
            raw = tomllib.load(fp)
    except OSError as exc:
        errors.append(LoadError(path=path, message=f"cannot read file: {exc}"))
        return None
    except tomllib.TOMLDecodeError as exc:
        errors.append(LoadError(path=path, message=f"TOML parse error: {exc}"))
        return None
    return _validate_model(ToolConfig, raw, path, errors)


def _check_cross_refs(repo: ConfigRepo, errors: list[LoadError]) -> None:
    """Cross-reference checks across the loaded set."""
    policies_dir = repo.root / POLICIES_DIR
    rg_dir = repo.root / RULE_GROUPS_DIR

    # Rule-group references and platform consistency.
    for slug, policy in repo.policies.items():
        policy_path = policies_dir / f"{slug}.yaml"
        for ref in policy.rule_groups:
            target = repo.rule_groups.get(ref)
            if target is None:
                errors.append(
                    LoadError(
                        path=policy_path,
                        field_path=f"rule_groups.{ref}",
                        message=f"rule group {ref!r} referenced but not found",
                    )
                )
                continue
            if target.platform is not policy.platform:
                errors.append(
                    LoadError(
                        path=policy_path,
                        field_path=f"rule_groups.{ref}",
                        message=(
                            f"platform mismatch: policy is {policy.platform.value}, "
                            f"rule group {ref!r} is {target.platform.value}"
                        ),
                    )
                )

    # Location references in inline policy rules.
    for slug, policy in repo.policies.items():
        policy_path = policies_dir / f"{slug}.yaml"
        for ref in policy.referenced_locations():
            if ref == ANY_LOCATION:
                continue
            if ref not in repo.locations:
                errors.append(
                    LoadError(
                        path=policy_path,
                        field_path=f"rules.locations.{ref}",
                        message=f"location {ref!r} referenced but not found",
                    )
                )

    # Location references in shared rule groups.
    for slug, rg in repo.rule_groups.items():
        rg_path = rg_dir / f"{slug}.yaml"
        for ref in rg.referenced_locations():
            if ref not in repo.locations:
                errors.append(
                    LoadError(
                        path=rg_path,
                        field_path=f"rules.locations.{ref}",
                        message=f"location {ref!r} referenced but not found",
                    )
                )

    # Tombstones must not match a still-present object.
    tomb_path = repo.root / TOMBSTONES_FILE
    for entry in repo.tombstones.policies:
        if entry.name in repo.policies:
            errors.append(
                LoadError(
                    path=tomb_path,
                    field_path=f"policies.{entry.name}",
                    message=f"tombstoned policy {entry.name!r} still exists in policies/",
                )
            )
    for entry in repo.tombstones.rule_groups:
        if entry.name in repo.rule_groups:
            errors.append(
                LoadError(
                    path=tomb_path,
                    field_path=f"rule_groups.{entry.name}",
                    message=f"tombstoned rule group {entry.name!r} still exists in rule_groups/",
                )
            )
    for entry in repo.tombstones.locations:
        if entry.name in repo.locations:
            errors.append(
                LoadError(
                    path=tomb_path,
                    field_path=f"locations.{entry.name}",
                    message=f"tombstoned location {entry.name!r} still exists in locations/",
                )
            )

    # Precedence overrides must reference known policies.
    prec_path = repo.root / PRECEDENCE_FILE
    for override in repo.precedence_overrides.overrides:
        for which, slug in (("before", override.before), ("after", override.after)):
            if slug not in repo.policies:
                errors.append(
                    LoadError(
                        path=prec_path,
                        field_path=f"overrides.{which}",
                        message=f"precedence override references unknown policy {slug!r}",
                    )
                )


def _check_platform_invariants(repo: ConfigRepo, errors: list[LoadError]) -> None:
    """Sanity checks that depend only on per-kind contents."""
    policies_dir = repo.root / POLICIES_DIR
    for slug, policy in repo.policies.items():
        policy_path = policies_dir / f"{slug}.yaml"
        for rule in policy.rules:
            if not _platform_supports_protocol(policy.platform, rule):
                errors.append(
                    LoadError(
                        path=policy_path,
                        field_path=f"rules.{rule.name}",
                        message=(
                            f"protocol {rule.protocol.value} is not valid on "
                            f"{policy.platform.value}"
                        ),
                    )
                )


def _platform_supports_protocol(platform: Platform, rule: Any) -> bool:
    """Stub for per-platform protocol whitelists.

    Phase 1 accepts every protocol on every platform. Tightening this is
    a Phase 7 linter concern; the hook exists here so the cross-ref
    pass already covers the call site.
    """
    del platform, rule
    return True


def load_config_repo(root: Path) -> ConfigRepo:
    """Load and validate a csfwctl-config repository.

    Raises :class:`ConfigRepoError` aggregating every problem found. On
    success returns a :class:`ConfigRepo` whose maps are non-empty for
    whichever kinds were present on disk.
    """
    root = root.expanduser().resolve()
    if not root.is_dir():
        raise ConfigRepoError(
            [LoadError(path=root, message=f"config repo path {root} is not a directory")]
        )

    errors: list[LoadError] = []
    repo = ConfigRepo(root=root)

    repo.policies = _load_kind(root / POLICIES_DIR, Policy, errors)
    repo.rule_groups = _load_kind(root / RULE_GROUPS_DIR, RuleGroup, errors)
    repo.locations = _load_kind(root / LOCATIONS_DIR, Location, errors)

    tomb = _load_top_level_yaml(root / TOMBSTONES_FILE, Tombstones, errors)
    if isinstance(tomb, Tombstones):
        repo.tombstones = tomb

    prec = _load_top_level_yaml(root / PRECEDENCE_FILE, PrecedenceOverrides, errors)
    if isinstance(prec, PrecedenceOverrides):
        repo.precedence_overrides = prec

    cfg = _load_tool_config(root / TOOL_CONFIG_FILE, errors)
    if isinstance(cfg, ToolConfig):
        repo.tool_config = cfg

    _check_cross_refs(repo, errors)
    _check_platform_invariants(repo, errors)

    if errors:
        raise ConfigRepoError(errors)
    return repo


__all__ = [
    "ConfigRepo",
    "ConfigRepoError",
    "LoadError",
    "load_config_repo",
    "POLICIES_DIR",
    "RULE_GROUPS_DIR",
    "LOCATIONS_DIR",
    "TOMBSTONES_FILE",
    "PRECEDENCE_FILE",
    "TOOL_CONFIG_FILE",
]
