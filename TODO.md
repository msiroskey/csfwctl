# csfwctl — Build TODO

Cross-session handoff for Claude Code. Update as work progresses.
Project plan: ./csfwctl-project-plan.md

## Current phase

Phase 2: Falcon client layer

## Phase 2 tasks

- [x] `observability.py`: per-invocation request ID (contextvar) plus
      structured logger setup (text + JSON formatters).
- [x] `config.py`: `Credentials` model and loader. Env vars override
      profiles from `credentials.toml`. Clear error on missing creds.
- [x] `falcon/client.py`: `FalconClient` wrapper over FalconPy `OAuth2`.
      Retry with exponential backoff on 5xx; honor Retry-After on 429.
      Every API call logs at INFO with the current request ID.
- [x] Thin sub-clients: `policies.py`, `rule_groups.py`,
      `host_groups.py`, `locations.py` (FalconPy `network_locations`).
- [x] Location API spike findings in `docs/architecture.md`: FalconPy
      surface table, `any`-sentinel semantics, three items still
      pending tenant confirmation during initial bootstrap.
- [x] Wire global `--log-format` and `--quiet` flags through
      `observability.configure_logging` in the Typer callback.
- [x] Unit tests: 108 passing — observability (text + JSON formatters,
      idempotent setup, quiet level), config (env override, profile
      lookup, error paths), FalconClient retry (success / non-retry /
      retry-then-OK / exhaust / Retry-After / pythonic response /
      request-ID binding), one happy-path per sub-client via
      `responses`-mocked HTTP, and a meta-test enforcing "only
      `csfwctl/falcon/` may import `falconpy`".

## Phase 1 tasks (complete)

- [x] Shared schema types: `Platform`, `Status`, `PrecedenceBucket`,
      `Action`, `Direction`, `Protocol`, slug/display-name patterns,
      host-group env, connection state.
- [x] Pydantic v2 models: `Rule`, `RuleGroup`, `Policy`, `Location`,
      `Tombstones`, `PrecedenceOverrides`, `ToolConfig`.
- [x] Strict slug validation on object names. Cross-platform reference
      validation (Windows policy cannot reference a Mac rule group).
      No duplicate names within a kind. No duplicate inline rule names.
- [x] `ruamel.yaml` loader. Round-trip comment preservation. YAML
      parse errors carry file path and line number. Pydantic errors
      carry file path and dotted field path.
- [x] `ConfigRepo` aggregate: loads policies/, rule_groups/, locations/,
      tombstones.yaml, precedence.yaml, csfwctl.toml.
- [x] Cross-ref resolution: rule-group slugs in policies, location
      slugs in rules, tombstones don't match live objects, precedence
      overrides reference known policies.
- [x] Wire `csfwctl validate` end-to-end. Rich table summary on
      success, per-error stderr listing, exit 1 on any error.
- [x] Fixture config repos under `tests/fixtures/config_repos/minimal/`
      and `.../realistic/`.
- [x] Unit tests for every model and for the loader / cross-ref checks
      (80 tests, all passing).
- [x] `docs/schema_reference.md` reflects the models.
- [x] `docs/cli_reference.md` documents the `validate` command.

## Phase 0 tasks (complete)

- [x] Initialize git repo, MIT license, .gitignore for Python
- [x] Author pyproject.toml with project metadata and dependencies
- [x] Author Makefile with targets
- [x] Create directory skeleton matching project plan section 2
- [x] Author .github/workflows/ci.yml: ruff, mypy, pytest
- [x] Author csfwctl/cli.py with Typer app and stubbed subcommands
- [x] Author csfwctl/__main__.py so `python -m csfwctl` works
- [x] Author README.md
- [x] Add docs/ skeleton
- [x] Verify `make dev` then `make test` runs green
- [ ] Tag v0.0.1 (deferred — tag from maintainer machine after review)

## Open questions

(None at this time.)

## Notes for next session

- **Next phase: Phase 3 — Exporter and fixture recorder.**
  - `csfwctl import {policy|rule-group|location} <name|uuid>` reads
    live objects through `FalconClient` sub-clients and round-trips
    them through the Pydantic models / loader. Should produce YAML
    identical to a hand-authored file (round-trip test).
  - `csfwctl import all` bulk-imports an entire tenant into a fresh
    directory. Used for initial repo population.
  - `csfwctl record-fixtures` captures sanitized API responses for the
    integration test suite. Sanitization (UUIDs, hostnames, IPs) will
    need a small transform table.
  - Strips environment suffixes (`-Test`/`-Pilot`/`-Production`) from
    imported names. Keep the importer's slug-derivation logic close to
    the loader's filename ↔ name agreement check.
- **Location API spike** has three confirmation items pending the first
  real-tenant interaction; see `docs/architecture.md`. The
  `LocationsAPI` wrapper is the only place that needs to change if any
  of those assumptions turn out wrong, because the loader/differ treat
  `any` as a sentinel.
- The `FalconClient.call(op_name, fn)` pattern keeps retry + logging
  in one place. New sub-client methods should always go through it
  rather than calling FalconPy directly.
- `Credentials.redacted()` is what to put in logs / notifier payloads
  — never log a `Credentials` instance unredacted.
- The meta-test `test_only_falcon_subpackage_imports_falconpy` makes
  the no-direct-`falconpy` rule a CI failure. If a later phase needs
  FalconPy types elsewhere, re-export them from `csfwctl.falcon`
  rather than importing the library directly.
- `csfwctl/validate_cmd.py` holds the `validate` body; pattern of
  putting command bodies in their own module (kept out of `cli.py`)
  scales well — apply the same shape for `import`, `diff`, `apply`.
- v0.0.1 tag intentionally left for a maintainer to apply locally; CI
  release workflow is not configured yet (lands in a later phase).
