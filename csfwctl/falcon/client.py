"""Falcon API client wrapper.

CLAUDE.md hard rule: every CrowdStrike API call passes through this
module. No direct ``falconpy`` imports anywhere else in the codebase.

Responsibilities:

- OAuth2 token lifecycle (delegated to FalconPy ``OAuth2``).
- Retry with exponential backoff on 5xx; honor ``Retry-After`` /
  ``X-Ratelimit-Retryafter`` on 429.
- One ``INFO`` log line per API call carrying the current request ID,
  operation name, HTTP status, attempt count, and elapsed milliseconds.
- Lazy construction of the per-API sub-clients (policies, rule groups,
  host groups, locations).

Sub-clients are instantiated against this wrapper and call back into
:meth:`FalconClient.call` so retry + logging happen in exactly one
place.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, cast

from falconpy import (
    FirewallManagement,
    FirewallPolicies,
    HostGroup,
    OAuth2,
)

from csfwctl.config import Credentials
from csfwctl.observability import (
    current_request_id,
    get_logger,
    new_request_id,
    set_request_id,
)

if TYPE_CHECKING:
    from csfwctl.falcon.host_groups import HostGroupsAPI
    from csfwctl.falcon.locations import LocationsAPI
    from csfwctl.falcon.policies import PoliciesAPI
    from csfwctl.falcon.rule_groups import RuleGroupsAPI

_logger = get_logger("falcon")

RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})
DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_BASE_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_BACKOFF_SECONDS = 30.0


class FalconAPIError(Exception):
    """Raised when an API call ultimately fails after retries."""

    def __init__(self, op_name: str, status: int, body: Any) -> None:
        self.op_name = op_name
        self.status = status
        self.body = body
        super().__init__(f"{op_name} failed with HTTP {status}: {body!r}")


class FalconClient:
    """Authenticated, retrying wrapper around FalconPy service classes.

    The wrapper holds one shared :class:`falconpy.OAuth2` instance and
    derives every service-specific client from it, which means the
    access token is cached and reused across every API call in the
    invocation.
    """

    def __init__(
        self,
        credentials: Credentials,
        *,
        request_id: str | None = None,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS,
        max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        user_agent: str = "csfwctl/0.0.1",
    ) -> None:
        self._credentials = credentials
        self._max_attempts = max_attempts
        self._base_backoff_seconds = base_backoff_seconds
        self._max_backoff_seconds = max_backoff_seconds
        self._sleep = sleep
        self._auth = OAuth2(
            client_id=credentials.client_id,
            client_secret=credentials.client_secret,
            base_url=credentials.base_url,
            user_agent=user_agent,
        )
        self._firewall_policies: FirewallPolicies | None = None
        self._firewall_management: FirewallManagement | None = None
        self._host_group: HostGroup | None = None
        self._policies_api: PoliciesAPI | None = None
        self._rule_groups_api: RuleGroupsAPI | None = None
        self._host_groups_api: HostGroupsAPI | None = None
        self._locations_api: LocationsAPI | None = None

        rid = request_id or current_request_id() or new_request_id()
        set_request_id(rid)
        self._request_id = rid
        _logger.info(
            "falcon client ready",
            extra={"event": "client.init", **credentials.redacted()},
        )

    @property
    def request_id(self) -> str:
        """The request ID bound when this client was created."""
        return self._request_id

    @property
    def credentials(self) -> Credentials:
        """The credentials used to construct this client."""
        return self._credentials

    @property
    def auth(self) -> OAuth2:
        """The shared FalconPy ``OAuth2`` instance."""
        return self._auth

    # ---- sub-client accessors --------------------------------------------------

    @property
    def policies(self) -> PoliciesAPI:
        """Firewall-policy sub-client."""
        from csfwctl.falcon.policies import PoliciesAPI

        if self._policies_api is None:
            self._policies_api = PoliciesAPI(self)
        return self._policies_api

    @property
    def rule_groups(self) -> RuleGroupsAPI:
        """Firewall rule-group sub-client."""
        from csfwctl.falcon.rule_groups import RuleGroupsAPI

        if self._rule_groups_api is None:
            self._rule_groups_api = RuleGroupsAPI(self)
        return self._rule_groups_api

    @property
    def host_groups(self) -> HostGroupsAPI:
        """Host-group sub-client."""
        from csfwctl.falcon.host_groups import HostGroupsAPI

        if self._host_groups_api is None:
            self._host_groups_api = HostGroupsAPI(self)
        return self._host_groups_api

    @property
    def locations(self) -> LocationsAPI:
        """Firewall network-location sub-client."""
        from csfwctl.falcon.locations import LocationsAPI

        if self._locations_api is None:
            self._locations_api = LocationsAPI(self)
        return self._locations_api

    # ---- internal FalconPy service accessors ----------------------------------

    def _firewall_policies_service(self) -> FirewallPolicies:
        if self._firewall_policies is None:
            self._firewall_policies = FirewallPolicies(auth_object=self._auth)
        return self._firewall_policies

    def _firewall_management_service(self) -> FirewallManagement:
        if self._firewall_management is None:
            self._firewall_management = FirewallManagement(auth_object=self._auth)
        return self._firewall_management

    def _host_group_service(self) -> HostGroup:
        if self._host_group is None:
            self._host_group = HostGroup(auth_object=self._auth)
        return self._host_group

    # ---- retry + logging ------------------------------------------------------

    def call(
        self,
        op_name: str,
        fn: Callable[[], Any],
        *,
        retry_statuses: frozenset[int] = RETRYABLE_STATUSES,
    ) -> dict[str, Any]:
        """Invoke ``fn``, retrying transient failures and logging the outcome.

        ``fn`` is a zero-arg callable that returns the FalconPy response
        dict (``{"status_code", "headers", "body"}``). Raises
        :class:`FalconAPIError` if every attempt fails or returns a
        non-retryable error status (>= 400).
        """
        last: dict[str, Any] = {}
        for attempt in range(1, self._max_attempts + 1):
            started = time.monotonic()
            result = self._normalize(fn())
            elapsed_ms = int((time.monotonic() - started) * 1000)
            status = int(result.get("status_code", 0))
            last = result
            if status not in retry_statuses:
                self._log_outcome(op_name, status, attempt, elapsed_ms)
                if status >= 400:
                    raise FalconAPIError(op_name, status, result.get("body"))
                return result

            if attempt >= self._max_attempts:
                self._log_outcome(op_name, status, attempt, elapsed_ms, retried_out=True)
                raise FalconAPIError(op_name, status, result.get("body"))

            sleep_for = self._compute_backoff(status, result, attempt)
            _logger.warning(
                "falcon api retry",
                extra={
                    "event": "api.retry",
                    "op": op_name,
                    "status": status,
                    "attempt": attempt,
                    "sleep_s": round(sleep_for, 3),
                },
            )
            self._sleep(sleep_for)

        return last  # unreachable, but quiets mypy

    @staticmethod
    def _normalize(response: Any) -> dict[str, Any]:
        """Coerce FalconPy responses into a plain dict."""
        if isinstance(response, dict):
            return cast("dict[str, Any]", response)
        # Newer FalconPy "pythonic" responses expose status_code/body attrs.
        return {
            "status_code": getattr(response, "status_code", 0),
            "headers": getattr(response, "headers", {}),
            "body": getattr(response, "body", response),
        }

    def _compute_backoff(self, status: int, result: dict[str, Any], attempt: int) -> float:
        """Backoff seconds. Respects ``Retry-After``-style headers on 429."""
        if status == 429:
            headers = result.get("headers") or {}
            for key in ("Retry-After", "retry-after", "X-Ratelimit-Retryafter"):
                value = headers.get(key) if isinstance(headers, dict) else None
                if value is None:
                    continue
                try:
                    return min(float(value), self._max_backoff_seconds)
                except (TypeError, ValueError):
                    continue
        backoff: float = self._base_backoff_seconds * float(2 ** (attempt - 1))
        return min(backoff, self._max_backoff_seconds)

    @staticmethod
    def _log_outcome(
        op_name: str,
        status: int,
        attempt: int,
        elapsed_ms: int,
        *,
        retried_out: bool = False,
    ) -> None:
        level = "info" if status < 400 else "error"
        getattr(_logger, level)(
            "falcon api call",
            extra={
                "event": "api.call",
                "op": op_name,
                "status": status,
                "attempt": attempt,
                "elapsed_ms": elapsed_ms,
                "retried_out": retried_out,
            },
        )


__all__ = [
    "DEFAULT_BASE_BACKOFF_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_BACKOFF_SECONDS",
    "FalconAPIError",
    "FalconClient",
    "RETRYABLE_STATUSES",
]
