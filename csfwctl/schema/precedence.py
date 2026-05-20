"""Optional precedence-override schema."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from csfwctl.schema._common import Slug


class PrecedenceOverride(BaseModel):
    """Place one policy ahead of another within the same bucket.

    ``before`` is the policy whose precedence should be raised; ``after``
    is the one it should outrank. Slugs refer to policy filenames.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    before: Slug
    after: Slug

    @model_validator(mode="after")
    def _distinct(self) -> PrecedenceOverride:
        if self.before == self.after:
            raise ValueError(f"override before/after must differ: both {self.before!r}")
        return self


class PrecedenceOverrides(BaseModel):
    """Top-level ``precedence.yaml`` document."""

    model_config = ConfigDict(extra="forbid")

    overrides: list[PrecedenceOverride] = Field(default_factory=list)

    @model_validator(mode="after")
    def _no_duplicate_pairs(self) -> PrecedenceOverrides:
        seen: set[tuple[str, str]] = set()
        for entry in self.overrides:
            pair = (entry.before, entry.after)
            if pair in seen:
                raise ValueError(
                    f"duplicate precedence override: {entry.before!r} -> {entry.after!r}"
                )
            seen.add(pair)
        return self


__all__ = ["PrecedenceOverride", "PrecedenceOverrides"]
