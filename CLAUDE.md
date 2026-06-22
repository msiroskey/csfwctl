# CLAUDE.md — csfwctl

Guidance for Claude Code working in this repository.

## What this is

csfwctl is a Python CLI that manages CrowdStrike Falcon firewall policies,
rule groups, and locations as code. It is one of two repositories:

- **This repo (`csfwctl`)** — the Python package and CLI. Public on
  GitHub, mirrored to internal GitLab. No tenant data.
- **`csfwctl-config`** — YAML data describing the desired state of a
  specific tenant. Internal GitLab only. Calls `csfwctl` from CI.

Three environments per logical policy: Test → Pilot → Production. Trunk-
based development, manual promotion gates. See `csfwctl-project-plan.md`
for the full design.

## Operating constraint

**The default test suite is hermetic.** All unit/integration tests run
against mocked or recorded API responses, and that is the bar every PR
must meet. The safety rails in `csfwctl/safety.py` exist because the
first apply against real infrastructure has to be correct.

A **gated live-validation path now exists** for the narrow set of
wire-contract questions mocks cannot answer (e.g. the diff-based
`update_rule_group` payload). It is opt-in and isolated, not a license to
"just try it against the tenant":

- `tests/integration/test_live_rule_group.py` — marked `live`, skipped
  unless `CSFWCTL_LIVE_TEST=1` + credentials. Provisions a throwaway
  `csfwctl-live-*` rule group and deletes it in `finally`.
- `.github/workflows/live-validation.yml` — manual (`workflow_dispatch`)
  or `live-validation` PR label only; reads creds from the `test-tenant`
  GitHub environment.

Do not add live tenant calls to the default suite, and do not widen the
live test's blast radius beyond its own throwaway objects.

## Where to start each session

1. Read `TODO.md`. It reflects current phase and open tasks.
2. Re-read the relevant phase section of `csfwctl-project-plan.md`
   before starting work on a new phase.
3. After completing a task, update `TODO.md`: check the box, add notes
   under "Notes for next session" if anything needs handoff.

## Hard rules

These are not negotiable. Violations break the design.

- **All Falcon API calls go through `csfwctl/falcon/client.py`.** No
  direct `falconpy` imports elsewhere in the codebase. The client layer
  owns auth, retry, rate limiting, and request-ID logging.
- **CrowdStrike object names never change once set.** The environment
  suffix (`-Test`, `-Pilot`, `-Production`) is appended at apply time
  and never stored in YAML.
- **The metadata signature format is fixed.** Object descriptions
  managed by csfwctl carry:
  ```
  Managed by csfwctl | version: N | git_sha: X | applied: TS | env: E
  ```
  Do not reformat. The importer and status command parse this string.
- **Safety rails are non-negotiable:**
  - `--initial-bootstrap` mode only adds metadata. Never modifies rule
    content.
  - Blast-radius limits (`--max-deletes`, `--max-changes`) are checked
    *before* any write operation.
  - Drift detection always fails loudly. `--enforce` is the only way to
    overwrite drifted state.
  - Apply refuses to run against an unbootstrapped tenant unless
    `--initial-bootstrap` is passed.
- **Pydantic v2 syntax throughout.** Not v1. Use `model_validator`,
  `field_validator`, `ConfigDict`.
- **`ruamel.yaml` for YAML I/O.** Not PyYAML. Round-trip comment
  preservation matters for the importer and for hand-edited config
  files.
- **Tombstones are required for deletions.** The applier refuses to
  delete an object without a matching tombstone entry and the
  `--allow-delete` flag.

## Conventions

Choices rather than rules, but stay consistent.

- **CLI framework:** Typer. Not click, not argparse.
- **Human output:** `rich`. Suppressed in CI (detect via `CI` env var or
  `--quiet`).
- **Machine output:** plain JSON, selected via `--log-format json`.
- **Logging:** structured, request-ID correlated. Every API call logs
  with the current request ID. One request ID per CLI invocation.
- **HTTP mocking in tests:** `responses` library. Fixtures live under
  `tests/fixtures/api_responses/`.
- **Slugs (filenames, cross-refs):** `lowercase-kebab-case`.
- **Display names (in CrowdStrike):** `TitleCase-With-Hyphens`.
- **Imports:** stdlib first, third-party second, local third. `ruff`
  enforces this.
- **Type hints:** required on all public functions and methods. `mypy`
  runs in CI.
- **Docstrings:** required on all public functions, modules, and
  classes. One-line summary minimum.

## What not to do

- **Don't add dependencies without flagging it.** The dep list in
  `pyproject.toml` is deliberate. If you think a new one is needed,
  surface the suggestion explicitly before adding it.
- **Don't write integration tests that hit a real tenant.** All
  integration tests replay recorded fixtures. If you need new fixtures,
  document what they should contain and surface the request.
- **Don't reformat existing code for style.** `ruff` enforces what we
  care about. Mass reformats add noise to diffs.
- **Don't expand scope into deferred items** without checking. The
  following are explicitly out of v1: Linux platform support,
  "universal" rule groups, multi-location policy scenarios, Slack
  notifier, email notifier, PagerDuty notifier, generic JSON webhook,
  Prometheus metrics, pip package distribution. See the plan's "Later
  sprints" section.
- **Don't put tenant-specific data in this repo.** Real policy names,
  host group names, IP ranges, and similar belong in `csfwctl-config`
  or in sanitized test fixtures. Fixtures under
  `tests/fixtures/config_repos/` use deliberately fake names like
  `abc01-endpoints-windows`.
- **Don't change the schema lightly.** Pydantic model changes ripple
  into example YAML, `docs/schema_reference.md`, the importer, and the
  applier. If you change a model, update all four.

## Before declaring a task done

- `make lint` passes (ruff + mypy).
- `make test` passes (pytest, coverage threshold met).
- If you changed schema: `docs/schema_reference.md` and example YAML
  under `tests/fixtures/config_repos/` are updated to match.
- If you changed CLI surface: `docs/cli_reference.md` is updated.
- `TODO.md` reflects the new state.

## Reference files

- `csfwctl-project-plan.md` — design decisions, schema specifications,
  phase plan, success criteria. The authoritative source.
- `TODO.md` — current phase and open tasks.
- `docs/architecture.md` — accumulated technical findings. Especially
  the location API spike outcome from Phase 2.
- `docs/schema_reference.md` — YAML schema documentation, kept in sync
  with Pydantic models.
- `docs/cli_reference.md` — command-line interface documentation.
- `docs/operations.md` — runbooks: rollback, drift response, onboarding.
- `docs/notifications.md` — notifier configuration reference.

## Updating this file

When you learn something new about the project that future sessions need
to know — especially results of the location API spike, or any
constraint discovered during implementation — update this file. Keep it
under 200 lines. Push detail into the linked reference docs and keep
this document focused on rules and pointers.
