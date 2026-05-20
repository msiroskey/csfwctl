"""Tool configuration model (``csfwctl.toml`` in the config repo).

Loaded from TOML rather than YAML. The structure mirrors
``csfwctl-project-plan.md`` section 3, "Tool config".
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ToolSection(BaseModel):
    """The ``[tool]`` section."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    metadata_signature: str = Field(default="Managed by csfwctl", min_length=1)


class SafetySection(BaseModel):
    """The ``[safety]`` section: blast-radius and bootstrap defaults."""

    model_config = ConfigDict(extra="forbid")

    max_deletes: int = Field(default=1, ge=0, le=10_000)
    max_changes: int = Field(default=10, ge=0, le=10_000)
    require_bootstrap_for_unmanaged: bool = True


class NotifierConfig(BaseModel):
    """Base notifier config. Each channel may add its own fields."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    events: list[str] = Field(default_factory=list)


class ToolConfig(BaseModel):
    """Top-level ``csfwctl.toml`` model."""

    model_config = ConfigDict(extra="forbid")

    tool: ToolSection = Field(default_factory=ToolSection)
    safety: SafetySection = Field(default_factory=SafetySection)
    notifications: dict[str, NotifierConfig] = Field(default_factory=dict)


__all__ = ["NotifierConfig", "SafetySection", "ToolConfig", "ToolSection"]
