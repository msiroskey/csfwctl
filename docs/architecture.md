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
