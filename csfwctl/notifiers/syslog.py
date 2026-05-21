"""Syslog (RFC 5424) notifier.

Sends RFC 5424-formatted syslog datagrams over UDP to a remote syslog
daemon. Python's built-in :class:`logging.handlers.SysLogHandler` emits
RFC 3164 format; this notifier formats the frame manually to comply with
the newer standard.

Config table (``csfwctl.toml``):

.. code-block:: toml

    [notifications.syslog]
    host     = "syslog.example.edu"
    port     = 514
    facility = "local3"    # any standard facility name
    events   = ["apply.*", "drift.*"]
"""

from __future__ import annotations

import socket

from csfwctl.notifiers import Event, event_matches
from csfwctl.schema.tool_config import NotifierConfig

_FACILITIES: dict[str, int] = {
    "kern": 0,
    "user": 1,
    "mail": 2,
    "daemon": 3,
    "auth": 4,
    "syslog": 5,
    "lpr": 6,
    "news": 7,
    "uucp": 8,
    "cron": 9,
    "local0": 16,
    "local1": 17,
    "local2": 18,
    "local3": 19,
    "local4": 20,
    "local5": 21,
    "local6": 22,
    "local7": 23,
}

_SEVERITY_CODES: dict[str, int] = {
    "error": 3,  # RFC 5424 ERR
    "warn": 4,  # RFC 5424 WARNING
    "info": 6,  # RFC 5424 INFORMATIONAL
}

_NILVALUE = "-"
_APP_NAME = "csfwctl"


class SyslogNotifier:
    """Sends RFC 5424 syslog datagrams over UDP."""

    name = "syslog"

    def __init__(self, config: NotifierConfig) -> None:
        """Initialise the syslog notifier from ``config``."""
        extra = config.model_extra or {}
        host = extra.get("host")
        if not host:
            raise ValueError("syslog notifier requires 'host' in [notifications.syslog]")
        self._host = str(host)
        self._port = int(str(extra.get("port", 514)))
        facility_name = str(extra.get("facility", "user"))
        facility = _FACILITIES.get(facility_name)
        if facility is None:
            valid = ", ".join(sorted(_FACILITIES))
            raise ValueError(
                f"syslog notifier: unknown facility {facility_name!r}. Valid values: {valid}"
            )
        self._facility = facility
        self._patterns: list[str] = config.events if config.events else ["*"]

    def supports(self, event_type: str) -> bool:
        """Return True if ``event_type`` matches any configured pattern."""
        return event_matches(event_type, self._patterns)

    def send(self, event: Event) -> None:
        """Send a single RFC 5424 UDP datagram."""
        severity = _SEVERITY_CODES.get(event.severity, 6)
        priority = self._facility * 8 + severity
        ts = event.timestamp.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        hostname = _local_hostname()
        msg_text = f"{event.type}: {event.summary}"
        frame = (
            f"<{priority}>1 {ts} {hostname} {_APP_NAME}"
            f" {_NILVALUE} {_NILVALUE} {_NILVALUE} {msg_text}"
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(frame.encode("utf-8"), (self._host, self._port))


def _local_hostname() -> str:
    """Return the local hostname for the syslog HOSTNAME field."""
    try:
        return socket.gethostname() or _NILVALUE
    except OSError:
        return _NILVALUE
