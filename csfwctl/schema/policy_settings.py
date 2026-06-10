"""Policy-level enforcement and default-traffic settings."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict


class EnforcementMode(StrEnum):
    """CrowdStrike firewall policy enforcement posture.

    ``enforce`` — rules are enforced; traffic is blocked or allowed per rule.
    ``monitor`` — rules are evaluated but no traffic is dropped; block events
    are recorded as "would be blocked." The console requires enforcement to be
    enabled for monitor mode, so this maps to ``enforce: true`` with the
    monitor (``test_mode``) flag set.
    ``disabled`` — the firewall policy does not enforce any rules.

    These map onto the CrowdStrike container booleans as follows:

    ====================  ===========  =============
    ``enforcement_mode``  ``enforce``  ``test_mode``
    ====================  ===========  =============
    ``enforce``           ``True``     ``False``
    ``monitor``           ``True``     ``True``
    ``disabled``          ``False``    ``False``
    ====================  ===========  =============

    Local logging is **not** an enforcement mode; it is an independent
    setting (see :attr:`PolicySettings.local_logging`).
    """

    enforce = "enforce"
    monitor = "monitor"
    disabled = "disabled"


class DefaultTrafficAction(StrEnum):
    """Default action for traffic that matches no explicit rule."""

    allow = "allow"
    deny = "deny"


class PolicySettings(BaseModel):
    """Enforcement and default-traffic settings for a firewall policy.

    All fields are optional. An absent field means "leave the tenant's
    current value unchanged" at apply time.

    ``enforcement_mode`` drives the ``enforce`` / ``test_mode`` container
    booleans (see :class:`EnforcementMode`). ``local_logging`` is an
    independent toggle: local event logging can be enabled even when
    enforcement is ``disabled``.

    .. note::
       The CrowdStrike API payload field names (``enforce``, ``test_mode``,
       ``local_logging``, ``inbound``, ``outbound``) are the assumed
       mapping; see ``docs/architecture.md`` for items pending real-tenant
       confirmation.
    """

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    enforcement_mode: EnforcementMode | None = None
    local_logging: bool | None = None
    default_inbound: DefaultTrafficAction | None = None
    default_outbound: DefaultTrafficAction | None = None


__all__ = ["DefaultTrafficAction", "EnforcementMode", "PolicySettings"]
