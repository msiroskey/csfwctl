"""Tombstones — explicit deletion markers.

Deleting an object requires:

1. A matching tombstone entry in ``tombstones.yaml``, and
2. The ``--allow-delete`` flag on ``csfwctl apply``.

The applier refuses to delete an object without both. See
``csfwctl-project-plan.md`` section 3 and CLAUDE.md "Hard rules".
"""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from csfwctl.schema._common import Slug

_SHORT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")


class TombstoneEntry(BaseModel):
    """A single tombstone marker for an object that was removed."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Slug
    deleted_in_sha: str = Field(min_length=7, max_length=40)
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("deleted_in_sha")
    @classmethod
    def _check_sha(cls, value: str) -> str:
        if not _SHORT_SHA_RE.match(value):
            raise ValueError(f"deleted_in_sha must be a hex git SHA, got {value!r}")
        return value


class Tombstones(BaseModel):
    """Top-level tombstones file: ``tombstones.yaml`` at the repo root."""

    model_config = ConfigDict(extra="forbid")

    policies: list[TombstoneEntry] = Field(default_factory=list)
    rule_groups: list[TombstoneEntry] = Field(default_factory=list)
    locations: list[TombstoneEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _no_dupes_within_kind(self) -> Tombstones:
        for kind, entries in (
            ("policies", self.policies),
            ("rule_groups", self.rule_groups),
            ("locations", self.locations),
        ):
            seen: set[str] = set()
            duplicates: set[str] = set()
            for entry in entries:
                if entry.name in seen:
                    duplicates.add(entry.name)
                seen.add(entry.name)
            if duplicates:
                joined = ", ".join(sorted(duplicates))
                raise ValueError(f"duplicate tombstone names in {kind}: {joined}")
        return self


__all__ = ["TombstoneEntry", "Tombstones"]
