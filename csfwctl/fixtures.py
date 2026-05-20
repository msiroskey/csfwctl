"""Record and sanitise CrowdStrike API responses for offline tests.

``csfwctl record-fixtures`` calls a fixed set of read-only operations
against a live tenant and writes one JSON file per operation under
``tests/fixtures/api_responses/``. Sensitive content — UUIDs, internal
hostnames, IP addresses — is replaced with deterministic fake values so
the fixtures are safe to commit to a public repo.

The same sanitiser runs in two places:

- ``record-fixtures`` writes sanitised JSON to disk.
- ``import`` (when ``--sanitize`` is passed) sanitises the in-memory
  records before they ever reach the loader, so the imported YAML can
  also be committed without tenant detail.

A :class:`Sanitizer` instance carries its mapping table across an entire
recording session so that ``policy-detail.json`` and
``policy-list.json`` agree on the same fake UUIDs.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from csfwctl.falcon.client import FalconClient

UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

HOSTNAME_RE = re.compile(
    r"\b(?=[A-Za-z0-9-]{1,63}\.)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}\b"
)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# RFC 5737 / 3849 / 5156 reserved test ranges; safe to emit publicly.
_FAKE_IPV4_NETS: tuple[str, ...] = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
_FAKE_HOST_DOMAIN = "example.test"


@dataclass
class Sanitizer:
    """Deterministic UUID / IP / hostname / email substitution.

    Calling :meth:`sanitize` on the same input multiple times produces
    the same output, which keeps fixture diffs minimal between
    re-recordings. The mapping tables are exposed on the instance so
    tests can inspect them.
    """

    uuid_map: dict[str, str] = field(default_factory=dict)
    ipv4_map: dict[str, str] = field(default_factory=dict)
    ipv6_map: dict[str, str] = field(default_factory=dict)
    cidr_map: dict[str, str] = field(default_factory=dict)
    hostname_map: dict[str, str] = field(default_factory=dict)
    email_map: dict[str, str] = field(default_factory=dict)
    preserve_substrings: tuple[str, ...] = field(default_factory=tuple)
    # ``preserve_substrings`` lets callers keep certain names (e.g.
    # ``corp-vpn``) unchanged so the imported YAML stays readable.

    def sanitize(self, value: Any) -> Any:
        """Walk ``value`` recursively, replacing sensitive tokens."""
        if isinstance(value, dict):
            return {k: self.sanitize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.sanitize(item) for item in value]
        if isinstance(value, str):
            return self._sanitize_string(value)
        return value

    # ---- string handling -------------------------------------------------

    def _sanitize_string(self, value: str) -> str:
        if not value:
            return value
        if any(sub in value for sub in self.preserve_substrings):
            return value
        # CIDR networks need to be handled before bare IPs so that the
        # mask is preserved.
        value = self._replace_cidrs(value)
        value = self._replace_ips(value)
        value = UUID_RE.sub(lambda m: self._fake_uuid(m.group(0)), value)
        value = EMAIL_RE.sub(lambda m: self._fake_email(m.group(0)), value)
        value = HOSTNAME_RE.sub(lambda m: self._fake_hostname(m.group(0)), value)
        return value

    def _replace_cidrs(self, value: str) -> str:
        # CIDR pattern: either v4 or v6 followed by /N.
        cidr_re = re.compile(
            r"(?:\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})"
            r"|(?:[0-9A-Fa-f:]+/\d{1,3})"
        )

        def repl(match: re.Match[str]) -> str:
            token = match.group(0)
            try:
                ipaddress.ip_network(token, strict=False)
            except ValueError:
                return token
            return self._fake_cidr(token)

        return cidr_re.sub(repl, value)

    def _replace_ips(self, value: str) -> str:
        ipv4_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

        def repl4(match: re.Match[str]) -> str:
            token = match.group(0)
            try:
                ipaddress.IPv4Address(token)
            except ValueError:
                return token
            return self._fake_ipv4(token)

        value = ipv4_re.sub(repl4, value)

        # v6 is harder to detect without false positives; match obvious
        # forms ``XXXX:XXXX:...`` with at least one colon and a hex run.
        ipv6_re = re.compile(r"(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:]+")

        def repl6(match: re.Match[str]) -> str:
            token = match.group(0)
            try:
                ipaddress.IPv6Address(token)
            except ValueError:
                return token
            return self._fake_ipv6(token)

        return ipv6_re.sub(repl6, value)

    # ---- fake-value generation -------------------------------------------

    def _fake_uuid(self, original: str) -> str:
        key = original.lower()
        if key in self.uuid_map:
            return self.uuid_map[key]
        index = len(self.uuid_map) + 1
        fake = f"00000000-0000-0000-0000-{index:012x}"
        self.uuid_map[key] = fake
        return fake

    def _fake_ipv4(self, original: str) -> str:
        if original in self.ipv4_map:
            return self.ipv4_map[original]
        net_index = len(self.ipv4_map) % len(_FAKE_IPV4_NETS)
        net = ipaddress.IPv4Network(_FAKE_IPV4_NETS[net_index])
        host_index = (len(self.ipv4_map) // len(_FAKE_IPV4_NETS)) + 1
        host = list(net.hosts())[host_index % (net.num_addresses - 2)]
        fake = str(host)
        self.ipv4_map[original] = fake
        return fake

    def _fake_ipv6(self, original: str) -> str:
        if original in self.ipv6_map:
            return self.ipv6_map[original]
        index = len(self.ipv6_map) + 1
        fake = f"2001:db8::{index:x}"
        self.ipv6_map[original] = fake
        return fake

    def _fake_cidr(self, original: str) -> str:
        if original in self.cidr_map:
            return self.cidr_map[original]
        net = ipaddress.ip_network(original, strict=False)
        if net.version == 4:
            base = _FAKE_IPV4_NETS[len(self.cidr_map) % len(_FAKE_IPV4_NETS)]
            base_net = ipaddress.IPv4Network(base)
            fake = f"{base_net.network_address}/{net.prefixlen}"
        else:
            fake = f"2001:db8::/{net.prefixlen}"
        self.cidr_map[original] = fake
        return fake

    def _fake_hostname(self, original: str) -> str:
        key = original.lower()
        if key in self.hostname_map:
            return self.hostname_map[key]
        index = len(self.hostname_map) + 1
        fake = f"host-{index:03d}.{_FAKE_HOST_DOMAIN}"
        self.hostname_map[key] = fake
        return fake

    def _fake_email(self, original: str) -> str:
        key = original.lower()
        if key in self.email_map:
            return self.email_map[key]
        index = len(self.email_map) + 1
        fake = f"user-{index:03d}@{_FAKE_HOST_DOMAIN}"
        self.email_map[key] = fake
        return fake


# ---- recording driver -----------------------------------------------------


@dataclass(frozen=True)
class Operation:
    """One read-only API call captured into a fixture file.

    ``runner`` returns the raw FalconPy response dict (or any
    JSON-serialisable structure). ``filename`` is the relative path
    under the output directory.
    """

    filename: str
    runner: Callable[[FalconClient], Any]


def default_operations() -> list[Operation]:
    """Read-only operations recorded by ``csfwctl record-fixtures``."""
    return [
        Operation("policies-query.json", lambda c: c.policies.query()),
        Operation("policies-list.json", lambda c: c.policies.list_all()),
        Operation("rule-groups-query.json", lambda c: c.rule_groups.query()),
        Operation("rule-groups-list.json", lambda c: c.rule_groups.list_all()),
        Operation("locations-query.json", lambda c: c.locations.query()),
        Operation("locations-list.json", lambda c: c.locations.list_all()),
        Operation("host-groups-query.json", lambda c: c.host_groups.query()),
        Operation("host-groups-list.json", lambda c: c.host_groups.list_all()),
    ]


@dataclass(frozen=True)
class RecordResult:
    """Per-operation outcome for ``record-fixtures``."""

    filename: str
    path: Path | None
    bytes_written: int
    error: str | None = None


def record_fixtures(
    client: FalconClient,
    output_dir: Path,
    *,
    operations: list[Operation] | None = None,
    sanitizer: Sanitizer | None = None,
) -> list[RecordResult]:
    """Run each operation, sanitise the response, write JSON to ``output_dir``.

    Failing operations do not stop the run: the error is captured on the
    :class:`RecordResult` for the caller to surface.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    ops = operations or default_operations()
    san = sanitizer or Sanitizer()
    results: list[RecordResult] = []
    for op in ops:
        try:
            data = op.runner(client)
        except Exception as exc:
            results.append(
                RecordResult(filename=op.filename, path=None, bytes_written=0, error=str(exc))
            )
            continue
        sanitized = san.sanitize(data)
        path = output_dir / op.filename
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(sanitized, indent=2, sort_keys=True) + "\n"
        path.write_text(payload, encoding="utf-8")
        results.append(
            RecordResult(
                filename=op.filename, path=path, bytes_written=len(payload.encode("utf-8"))
            )
        )
    return results


def filter_operations(operations: list[Operation], names: list[str]) -> list[Operation]:
    """Subset ``operations`` to those whose filename stem matches ``names``.

    ``--operations`` is a comma-separated list of filename stems
    (``policies-query``, etc.). Order is preserved from the original
    operation list so the JSON output is reproducible.
    """
    wanted = {name.strip() for name in names if name.strip()}
    if not wanted:
        return list(operations)
    return [op for op in operations if Path(op.filename).stem in wanted]


__all__ = [
    "Operation",
    "RecordResult",
    "Sanitizer",
    "default_operations",
    "filter_operations",
    "record_fixtures",
]
