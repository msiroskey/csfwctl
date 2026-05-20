# Architecture

Technical findings accumulated during implementation. This document
captures decisions and discoveries that affect how the code is
structured.

## Layering

- `csfwctl.cli` is the only entrypoint operators touch.
- `csfwctl.falcon.*` is the only module that talks to CrowdStrike. Every
  call funnels through `FalconClient.call`, which is where retry and
  per-call logging live (CLAUDE.md hard rule).
- `csfwctl.loader` and `csfwctl.schema.*` own the desired-state side.
- `csfwctl.differ` consumes both and produces a structured change set
  (Phase 4, pending).
- `csfwctl.applier` is the only module that performs writes, gated by
  `csfwctl.safety` (Phase 5, pending).

## Request IDs and logging

- One request ID per CLI invocation. Generated in the Typer callback
  (`cli.main`), bound on a `contextvars.ContextVar` in
  `csfwctl.observability`, and emitted on every log line.
- `FalconClient` re-binds the request ID at construction time so
  programmatic callers (tests, future library use) get a deterministic
  ID even without going through the CLI.
- `--log-format=json` switches to newline-delimited JSON records.
- One INFO log per API call (`api.call`) with `op`, `status`,
  `attempt`, `elapsed_ms`. One WARNING per retry (`api.retry`).

## Retry policy

`FalconClient.call` retries:

- Up to `DEFAULT_MAX_ATTEMPTS` (5) total tries.
- On HTTP 5xx and 429.
- 429 honors `Retry-After` / `X-Ratelimit-Retryafter` when present;
  otherwise exponential backoff `1s, 2s, 4s, 8s, …` capped at 30s.
- Final failure surfaces as `FalconAPIError`, carrying the operation
  name, status, and body for the notifier/runbook to consume.

## Location API spike — Phase 2 findings

Drove the `csfwctl/falcon/locations.py` wrapper. Captured here so the
team doesn't re-discover this during apply work.

**FalconPy surface.** What CrowdStrike's API and FalconPy call
"firewall locations" are exposed under `FirewallManagement` as
`network_locations`. The endpoints used by csfwctl:

| Operation                                | FalconPy method                  | HTTP                                                       |
|------------------------------------------|----------------------------------|------------------------------------------------------------|
| List IDs matching filter                 | `query_network_locations`        | `GET /fwmgr/queries/network-locations/v1`                  |
| Fetch details for a list of IDs          | `get_network_locations_details`  | `GET /fwmgr/entities/network-locations-details/v1`         |
| Create or update                         | `upsert_network_locations`       | `PUT /fwmgr/entities/network-locations/v1`                 |
| Delete                                   | `delete_network_locations`       | `DELETE /fwmgr/entities/network-locations/v1`              |
| Reorder                                  | `update_network_locations_precedence` | `POST /fwmgr/entities/network-locations-precedence/v1` |

We expose `query`, `get_details`, `list_all`, `upsert`, `delete`.
Reorder lands when multi-location scenarios become first-class (out of
scope for v1).

**The `any` location.** csfwctl reserves the slug `any` as a sentinel
meaning "no location constraint", and the loader excludes it from
cross-reference checks (`Rule.referenced_locations()`). On the
CrowdStrike side, the default location is auto-managed by the tenant
and does not appear in custom-location queries; rules whose location
list is empty (or that target the system default) are equivalent to
csfwctl's `any`.

**What still needs tenant confirmation.** Cannot be validated against a
sandbox tenant (CLAUDE.md — no test tenant). The first
`--initial-bootstrap` apply against real infrastructure must verify:

1. `query_network_locations` with no filter returns only
   *custom* locations (not the system default). Expected behavior; the
   importer drops anything matching the system default by ID.
2. A rule with `locations: [any]` round-trips to a CrowdStrike rule
   with an empty location-ID list — not to a rule that names the
   default location explicitly.
3. The system default location's ID is stable per tenant; if it ever
   surfaces in responses (e.g. through `get_details`), the importer
   must drop it consistently.

Once confirmed, fold the verified behavior into this section and remove
the "still needs confirmation" list. If any assumption is wrong, the
`LocationsAPI` wrapper is the only place that needs to change — the
loader/differ already treat `any` as a sentinel.

## Exporter / API shape assumptions (Phase 3)

The importer converts CrowdStrike API records into our Pydantic schema
and back. ``csfwctl/exporter.py`` carries both directions: the
``*_from_api`` functions consume the API shape, and the ``*_to_api_shape``
functions render a model into the shape we expect to see. Phase 5's
applier will reuse the renderers verbatim.

The API shapes below are inferred from CrowdStrike's Falcon Firewall
documentation and FalconPy method signatures. We have no test tenant
(see CLAUDE.md), so first-tenant interaction must verify each shape;
discrepancies are localised to the translation helpers.

**Firewall policy (FirewallPolicies.get_policies):**

```python
{
  "id": "<uuid>",
  "name": "ABC01-Endpoints-Windows-Test",
  "description": "...",
  "platform_name": "Windows",          # "Windows" | "Mac"
  "enabled": True,
  "groups": [{"id": "<uuid>", "name": "ABC01-Endpoints-Windows-Test"}],
  "settings": {
    "rule_group_ids": ["<uuid>", "<uuid>"],
    # default_inbound/default_outbound surfaces on the apply side; the
    # importer ignores them in v1.
  },
}
```

**Rule group (FirewallManagement.get_rule_groups):**

```python
{
  "id": "<uuid>",
  "name": "windows-baseline-Test",
  "description": "...",
  "platform": "0",                     # "0" Windows | "1" Mac
  "enabled": True,
  "rule_ids": ["<uuid>", "<uuid>"],
}
```

**Rule (FirewallManagement.get_rules):**

```python
{
  "id": "<uuid>",
  "name": "Allow corp DNS outbound",
  "enabled": True,
  "action": "ALLOW",                   # "ALLOW" | "DENY" | "MONITOR"
  "direction": "OUT",                  # "IN" | "OUT"
  "protocol": "17",                    # "0"/"*" any, "1" icmp, "6" tcp, "17" udp
  "fields": [{"name": "tcp_state", "value": "established"}],   # optional state
  "local": {"addresses": [...], "ports": [{"start": N, "end": M}]},
  "remote": {...},
  "locations": [...],                  # slug list (csfwctl convention)
}
```

**Network location (FirewallManagement.get_network_locations_details):**

```python
{
  "id": "<uuid>",
  "name": "corp-vpn",
  "enabled": True,
  "addresses": [{"address": "10.100.0.0/16"}],
  "dns_servers": [{"address": "10.1.1.53"}],
  "dns_resolution_targets": {"targets": [{"hostname": "corp.example.edu"}]},
  "default_gateways": [],
}
```

**Override rule-group folding.** The applier renders a policy's inline
``rules`` field as an anonymous rule group named
``<policy-slug>-overrides-<env>``. The importer detects that name shape
and folds the group's rules back into the policy YAML's ``rules:``
field; the override-group YAML itself is not written. Detection is in
``exporter.is_override_group_name`` and the folding logic is in
``policy_from_api``.

**Round-trip contract.** The unit tests in ``test_exporter.py`` start
with a hand-authored Pydantic model, render it into the API shapes
above (via the ``*_to_api_shape`` helpers), drive the importer against
a hand-rolled fake ``FalconClient``, and assert that the imported model
equals the original. This is the "import → load → diff should be empty"
guarantee from the project plan.

## Fixture sanitisation (Phase 3)

``csfwctl/fixtures.py`` ships a :class:`Sanitizer` that walks an API
response and replaces sensitive tokens with deterministic fakes:

| Token kind | Replacement                                                   |
|------------|---------------------------------------------------------------|
| UUID       | ``00000000-0000-0000-0000-XXXXXXXXXXXX`` counter              |
| IPv4       | RFC 5737 ranges ``192.0.2.0/24`` / ``198.51.100.0/24`` / ``203.0.113.0/24`` |
| IPv4 CIDR  | Same base ranges with the original prefix length preserved    |
| IPv6       | ``2001:db8::N`` (RFC 3849)                                    |
| Hostname   | ``host-NNN.example.test``                                     |
| Email      | ``user-NNN@example.test``                                     |

Mappings are stable for the lifetime of a :class:`Sanitizer` instance,
so cross-references between fixture files (e.g. a UUID appearing in
both ``policies-list.json`` and ``policies-query.json``) stay
consistent. ``record-fixtures`` uses one sanitiser per invocation.

The sanitiser is intentionally aggressive: when in doubt about whether
a token is sensitive it replaces it. Tests can opt slugs out via
``preserve_substrings``.

## Credentials and profiles

- Env vars (`CSFWCTL_CLIENT_ID` / `CSFWCTL_CLIENT_SECRET`) take
  precedence so CI can inject scoped tokens per job (the GitLab
  config-repo pipeline binds the read-only or read/write client per
  stage).
- File fallback at `/etc/csfwctl/credentials.toml` with
  `[profile.<name>]` tables. `--profile` selects which.
- The CLI's `--profile {prod|dev}` from the project plan maps directly
  to a TOML profile name; ``readonly``/``readwrite`` is the convention
  for production CI.
