"""Policy-level enforcement and default-traffic settings."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class EnforcementMode(StrEnum):
    """CrowdStrike firewall policy enforcement posture.

    ``enforce`` — rules are enforced; traffic is blocked or allowed per rule.
    ``monitor`` — block rules demoted to monitor; no traffic is dropped but
    block events are recorded as "would be blocked."
    ``local_logging`` — like monitor but events are only logged on the host.
    """

    enforce = "enforce"
    monitor = "monitor"
    local_logging = "local_logging"


class DefaultTrafficAction(StrEnum):
    """Default action for traffic that matches no explicit rule."""

    allow = "allow"
    deny = "deny"


class PolicySettings(BaseModel):
    """Enforcement and default-traffic settings for a firewall policy.

    All fields are optional. An absent field means "leave the tenant's
    current value unchanged" at apply time.

    .. note::
       The CrowdStrike API payload field names (``enforce``,
       ``local_logging``, ``inbound``, ``outbound``) are the assumed
       mapping; see ``docs/architecture.md`` for items pending real-tenant
       confirmation.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enforcement_mode: EnforcementMode | None = None
    default_inbound: DefaultTrafficAction | None = None
    default_outbound: DefaultTrafficAction | None = None


__all__ = ["DefaultTrafficAction", "EnforcementMode", "PolicySettings"]
