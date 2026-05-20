"""Falcon API client layer.

All Falcon API calls go through this package. No direct ``falconpy``
imports elsewhere in the codebase (CLAUDE.md hard rule).
"""

from csfwctl.falcon.client import (
    DEFAULT_BASE_BACKOFF_SECONDS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MAX_BACKOFF_SECONDS,
    RETRYABLE_STATUSES,
    FalconAPIError,
    FalconClient,
)

__all__ = [
    "DEFAULT_BASE_BACKOFF_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_BACKOFF_SECONDS",
    "FalconAPIError",
    "FalconClient",
    "RETRYABLE_STATUSES",
]
