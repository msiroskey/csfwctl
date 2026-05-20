"""Rule-group schema model."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from csfwctl.schema._common import Platform, Slug, Status
from csfwctl.schema.rule import Rule


class RuleGroup(BaseModel):
    """A reusable, named collection of firewall rules.

    Rule groups are shared across policy families within a single
    environment. The base ``name`` is the slug used for cross-references
    in policy YAML; the environment suffix (``-Test``/``-Pilot``/
    ``-Production``) is appended at apply time and is never stored here.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Slug
    platform: Platform
    status: Status = Status.enabled
    description: str = Field(default="", max_length=2000)
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _rule_names_unique(self) -> RuleGroup:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                duplicates.add(rule.name)
            seen.add(rule.name)
        if duplicates:
            joined = ", ".join(sorted(duplicates))
            raise ValueError(f"duplicate rule names within rule group: {joined}")
        return self

    def referenced_locations(self) -> set[str]:
        """Union of non-``any`` location slugs referenced by this group's rules."""
        result: set[str] = set()
        for rule in self.rules:
            result.update(rule.referenced_locations())
        return result


__all__ = ["RuleGroup"]
