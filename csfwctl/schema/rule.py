"""Rule and endpoint schema models."""

from __future__ import annotations

import ipaddress
import re
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from csfwctl.schema._common import (
    Action,
    ConnectionState,
    Direction,
    Protocol,
)

ANY_LOCATION: str = "any"
"""Reserved location slug meaning 'apply everywhere'."""

_PORT_RANGE_RE = re.compile(r"^(\d{1,5})-(\d{1,5})$")
_MIN_PORT = 1
_MAX_PORT = 65535


def _validate_address(value: str) -> str:
    """Accept either a bare IP or a CIDR; raise ``ValueError`` otherwise."""
    if "/" in value:
        ipaddress.ip_network(value, strict=False)
    else:
        ipaddress.ip_address(value)
    return value


def _validate_port(value: int | str) -> int | str:
    """Accept an int 1-65535 or an inclusive ``N-M`` range string."""
    if isinstance(value, int):
        if not _MIN_PORT <= value <= _MAX_PORT:
            raise ValueError(f"port {value} out of range 1-65535")
        return value
    match = _PORT_RANGE_RE.match(value)
    if not match:
        raise ValueError(f"port {value!r} is not an int or 'N-M' range")
    low, high = int(match.group(1)), int(match.group(2))
    if not (_MIN_PORT <= low <= high <= _MAX_PORT):
        raise ValueError(f"port range {value!r} is invalid (need 1 <= low <= high <= 65535)")
    return value


Address = Annotated[str, Field(min_length=1)]
Port = int | str


class Endpoint(BaseModel):
    """Local or remote endpoint targeted by a rule.

    All fields are optional; an absent field means "no constraint on this
    dimension". ``addresses_negated`` and ``ports_negated`` invert the
    match for their respective lists (matching everything *except* the
    listed values).
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    addresses: list[Address] = Field(default_factory=list)
    addresses_negated: bool = False
    ports: list[Port] = Field(default_factory=list)
    ports_negated: bool = False

    @field_validator("addresses")
    @classmethod
    def _check_addresses(cls, value: list[str]) -> list[str]:
        return [_validate_address(addr) for addr in value]

    @field_validator("ports")
    @classmethod
    def _check_ports(cls, value: list[int | str]) -> list[int | str]:
        return [_validate_port(port) for port in value]

    @model_validator(mode="after")
    def _negation_requires_values(self) -> Endpoint:
        if self.addresses_negated and not self.addresses:
            raise ValueError("addresses_negated=true requires a non-empty addresses list")
        if self.ports_negated and not self.ports:
            raise ValueError("ports_negated=true requires a non-empty ports list")
        return self


class Rule(BaseModel):
    """A single firewall rule.

    Either inline in a policy's ``rules:`` list (becoming part of an
    anonymous per-policy override group at apply time) or part of a
    rule group's ``rules:`` list.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    action: Action
    direction: Direction
    protocol: Protocol
    state: ConnectionState | None = None
    locations: list[str] = Field(default_factory=lambda: [ANY_LOCATION])
    local: Endpoint | None = None
    remote: Endpoint | None = None

    @field_validator("locations")
    @classmethod
    def _check_locations(cls, value: list[str]) -> list[str]:
        from csfwctl.schema._common import SLUG_RE

        if not value:
            raise ValueError("locations must contain at least one entry (use ['any'] for default)")
        for slug in value:
            if slug == ANY_LOCATION:
                continue
            if not SLUG_RE.match(slug):
                raise ValueError(f"location reference {slug!r} is not a valid slug")
        return value

    @model_validator(mode="after")
    def _state_only_for_tcp(self) -> Rule:
        if self.state is not None and self.protocol not in (Protocol.tcp, Protocol.any):
            raise ValueError(
                f"connection state qualifier is only valid for tcp or any protocol, "
                f"not {self.protocol.value}"
            )
        return self

    def referenced_locations(self) -> set[str]:
        """Return the set of non-``any`` location slugs this rule references."""
        return {loc for loc in self.locations if loc != ANY_LOCATION}


__all__ = ["ANY_LOCATION", "Endpoint", "Rule", "Address", "Port"]
