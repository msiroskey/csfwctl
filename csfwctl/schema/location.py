"""Location schema model."""

from __future__ import annotations

import ipaddress

from pydantic import BaseModel, ConfigDict, Field, field_validator

from csfwctl.schema._common import CrowdStrikeName, Slug, Status


def _validate_address(value: str) -> str:
    """Accept either a bare IP or a CIDR; raise ``ValueError`` otherwise."""
    if "/" in value:
        ipaddress.ip_network(value, strict=False)
    else:
        ipaddress.ip_address(value)
    return value


class Location(BaseModel):
    """A named network location ("where the host currently is").

    The reserved location ``any`` is auto-managed by CrowdStrike and is
    not represented as a YAML file. Named locations live under
    ``locations/<slug>.yaml``.

    Multi-location policy scenarios are explicitly out of scope for v1
    (see CLAUDE.md); a location object is supported but most policies
    will just use ``any``.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    name: Slug
    display_name: CrowdStrikeName | None = None
    status: Status = Status.enabled
    description: str = Field(default="", max_length=2000)
    addresses: list[str] = Field(default_factory=list)
    dns_servers: list[str] = Field(default_factory=list)
    dns_resolution_targets: list[str] = Field(default_factory=list)
    default_gateways: list[str] = Field(default_factory=list)

    @field_validator("addresses", "dns_servers", "default_gateways")
    @classmethod
    def _check_ip_lists(cls, value: list[str]) -> list[str]:
        return [_validate_address(addr) for addr in value]


__all__ = ["Location"]
