"""Shared schema primitives.

Enums, regex patterns, and lightweight type aliases used across the
Pydantic models in this package.

Naming conventions (see CLAUDE.md):

- **Slugs** — filenames and cross-references. ``lowercase-kebab-case``:
  a leading lowercase letter, then lowercase letters / digits / single
  hyphens. No trailing hyphen, no consecutive hyphens.
- **Display names** — what CrowdStrike sees. ``TitleCase-With-Hyphens``.
  Validated separately by :class:`DisplayName`.
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Final

from pydantic import Field

SLUG_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
"""Lowercase-kebab-case slug. Used for filenames and cross-references."""

DISPLAY_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Z][A-Za-z0-9]*(?:-[A-Z0-9][A-Za-z0-9]*)*$"
)
"""TitleCase-With-Hyphens display name (CrowdStrike-visible name)."""

Slug = Annotated[
    str,
    Field(
        pattern=SLUG_RE.pattern,
        min_length=2,
        max_length=80,
        description="lowercase-kebab-case identifier",
    ),
]

DisplayName = Annotated[
    str,
    Field(
        pattern=DISPLAY_NAME_RE.pattern,
        min_length=2,
        max_length=80,
        description="TitleCase-With-Hyphens display name as it appears in CrowdStrike",
    ),
]

CrowdStrikeName = Annotated[
    str,
    Field(
        min_length=1,
        max_length=200,
        description=(
            "Verbatim CrowdStrike object name. Used when the natural name "
            "does not conform to slug or TitleCase conventions (e.g. contains "
            "spaces or underscores). Takes precedence over ``name`` at apply time."
        ),
    ),
]


class Platform(StrEnum):
    """Operating-system platform a policy or rule group applies to."""

    windows = "windows"
    mac = "mac"


class Status(StrEnum):
    """Lifecycle status for a managed object.

    Maps directly to the CrowdStrike ``enabled`` attribute. ``deleted``
    requires a matching tombstone entry and the ``--allow-delete`` flag
    at apply time.
    """

    enabled = "enabled"
    disabled = "disabled"
    deleted = "deleted"


class PrecedenceBucket(StrEnum):
    """Coarse precedence bucket assigned to each policy.

    Resolved to an ordinal precedence at apply time, with ties broken
    alphabetically by policy name.
    """

    emergency = "emergency"
    high = "high"
    medium = "medium"
    default = "default"
    low = "low"


class Action(StrEnum):
    """Rule action."""

    allow = "allow"
    block = "block"
    monitor = "monitor"


class Direction(StrEnum):
    """Rule direction."""

    inbound = "inbound"
    outbound = "outbound"
    both = "both"


class Protocol(StrEnum):
    """Network-layer protocol a rule matches.

    Named values cover the protocols available in the CrowdStrike UI.
    For protocols not listed here use ``Rule.protocol`` as a raw integer
    (0-255) — this corresponds to the CrowdStrike "Advanced" protocol
    entry. IPv6-family protocols (``ipv6``, ``icmpv6``) should be paired
    with IPv6 addresses.
    """

    any = "any"
    tcp = "tcp"
    udp = "udp"
    icmp = "icmp"
    igmp = "igmp"
    ipip = "ipip"
    ipv6 = "ipv6"
    gre = "gre"
    icmpv6 = "icmpv6"


class AddressFamily(StrEnum):
    """Explicit IP address family override for a rule.

    Maps to the CrowdStrike rule ``address_family`` wire field: ``ip4`` →
    ``IP4``, ``ip6`` → ``IP6``, ``any`` → ``NONE`` (the family-agnostic
    value CrowdStrike uses for application-based rules that match no
    address). The field is optional in YAML: when omitted the exporter
    derives the family from the protocol and configured addresses, falling
    back to ``any`` when it cannot determine one. Set it explicitly only to
    override that inference. In YAML the ``ipv4``/``ipv6`` spellings are
    accepted as input aliases and normalized to ``ip4``/``ip6`` (see
    :meth:`csfwctl.schema.rule.Rule._normalize_address_family`).
    """

    any = "any"
    ip4 = "ip4"
    ip6 = "ip6"


class ConnectionState(StrEnum):
    """Optional TCP connection-state qualifier on a rule."""

    new = "new"
    established = "established"
    related = "related"


class HostGroupEnv(StrEnum):
    """Environment a host group is bound to inside a policy."""

    test = "test"
    pilot = "pilot"
    production = "production"


__all__ = [
    "SLUG_RE",
    "DISPLAY_NAME_RE",
    "Slug",
    "DisplayName",
    "CrowdStrikeName",
    "Platform",
    "Status",
    "PrecedenceBucket",
    "Action",
    "Direction",
    "Protocol",
    "AddressFamily",
    "ConnectionState",
    "HostGroupEnv",
]
