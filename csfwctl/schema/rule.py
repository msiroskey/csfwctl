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

# Matches "A.B.C.D-E.F.G.H" (full range) or "A.B.C.D-N" (last-octet shorthand).
_IP_RANGE_RE = re.compile(
    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3})$"
)


def _validate_address(value: str) -> str:
    """Accept an IP, CIDR, or CrowdStrike IP-range; raise ``ValueError`` otherwise.

    Supported forms:
    - ``10.0.0.1`` — plain IPv4 or IPv6 address
    - ``10.0.0.0/8`` — CIDR notation
    - ``224.0.0.230-233`` — last-octet range shorthand (CS notation)
    - ``10.0.0.1-10.0.0.254`` — full start-end range
    """
    if "/" in value:
        ipaddress.ip_network(value, strict=False)
        return value
    m = _IP_RANGE_RE.match(value)
    if m:
        start_str, end_str = m.group(1), m.group(2)
        start_ip = ipaddress.ip_address(start_str)
        if "." in end_str:
            end_ip = ipaddress.ip_address(end_str)
        else:
            # Short form: only last octet of end is given; share the prefix.
            prefix = start_str.rsplit(".", 1)[0]
            end_ip = ipaddress.ip_address(f"{prefix}.{end_str}")
        if int(end_ip) < int(start_ip):
            raise ValueError(f"IP range {value!r}: end address is before start")
        return value
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

    ``protocol`` accepts either a named :class:`Protocol` value (e.g.
    ``tcp``) or a raw IANA protocol number (0-255) for protocols not
    covered by the named enum ("Advanced" mode in the CrowdStrike UI).

    ``file_path`` is an optional executable-filepath glob: the rule then
    only matches traffic originating from a process whose image path
    matches the pattern (CrowdStrike's application-aware firewall match).
    It is platform-agnostic — use the native path format for the target
    platform (Windows ``C:\\...`` or macOS ``/Applications/...``). It
    rides in the API ``fields`` array alongside the connection-state
    qualifier.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    enabled: bool = True
    action: Action
    direction: Direction
    protocol: Protocol | int
    state: ConnectionState | None = None
    file_path: str | None = Field(default=None, max_length=999)
    locations: list[str] = Field(default_factory=lambda: [ANY_LOCATION])
    local: Endpoint | None = None
    remote: Endpoint | None = None

    @field_validator("protocol")
    @classmethod
    def _check_protocol(cls, value: Protocol | int) -> Protocol | int:
        if isinstance(value, int) and not (0 <= value <= 255):
            raise ValueError(f"raw protocol number {value} out of range 0-255")
        return value

    @field_validator("file_path")
    @classmethod
    def _check_file_path(cls, value: str | None) -> str | None:
        """Sanity-check the executable filepath glob (local check only).

        CrowdStrike matches the rule against the originating executable's
        path using a glob pattern (e.g. ``C:\\Program Files\\app\\*.exe``).
        We do not call CrowdStrike's ``validate_filepath_pattern`` endpoint
        here — there is no test tenant — so this is a structural check
        only: non-empty after whitespace stripping and no embedded NUL.
        """
        if value is None:
            return value
        if not value:
            raise ValueError("file_path must be a non-empty glob pattern (or omitted)")
        if "\x00" in value:
            raise ValueError("file_path must not contain a NUL character")
        return value

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
        # Only enforce the constraint when a named protocol is given; raw
        # integers are the "Advanced" case where the user controls the match.
        if (
            self.state is not None
            and isinstance(self.protocol, Protocol)
            and self.protocol not in (Protocol.tcp, Protocol.any)
        ):
            raise ValueError(
                f"connection state qualifier is only valid for tcp or any protocol, "
                f"not {self.protocol.value}"
            )
        return self

    @model_validator(mode="after")
    def _ports_require_tcp_or_udp(self) -> Rule:
        """Ports are only meaningful for TCP/UDP; reject them otherwise.

        CrowdStrike returns HTTP 400 ``"Ports not allowed without a specific
        Protocol"`` if a rule carries local/remote ports with any protocol
        other than TCP or UDP (the ``any`` wildcard included). Enforce locally
        so ``validate`` and the apply load step catch it with an actionable
        message before reaching the tenant. Raw-integer ("Advanced") protocols
        are left to the user, matching ``_state_only_for_tcp``.
        """
        has_ports = bool(
            (self.local is not None and self.local.ports)
            or (self.remote is not None and self.remote.ports)
        )
        if (
            has_ports
            and isinstance(self.protocol, Protocol)
            and self.protocol not in (Protocol.tcp, Protocol.udp)
        ):
            raise ValueError(
                f"ports require protocol tcp or udp, not {self.protocol.value}; "
                "remove the ports or set a specific protocol"
            )
        return self

    def referenced_locations(self) -> set[str]:
        """Return the set of non-``any`` location slugs this rule references."""
        return {loc for loc in self.locations if loc != ANY_LOCATION}


__all__ = ["ANY_LOCATION", "Endpoint", "Rule", "Address", "Port"]
