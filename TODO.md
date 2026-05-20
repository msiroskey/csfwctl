# csfwctl — Build TODO

Cross-session handoff for Claude Code. Update as work progresses.
Project plan: ./csfwctl-project-plan.md

## Current phase

Phase 4: Differ

## Phase 4 tasks

- [x] `differ.py`: core engine. `LiveState` snapshot dataclass,
      `ChangeSet` aggregate with `creates` / `updates` / `deletes` /
      `no_changes` / `unmanaged` / `warnings` buckets, plus
      `ObjectChange`, `FieldChange`, `HostGroupChange` records. JSON
      and apply-ordered iteration on the change set.
- [x] Schema-domain comparison: translate live records via
      `exporter.*_from_api` (with `strip_suffix=True`), then compare
      `model_dump` dicts. `_diff_dicts` walks leaves and emits one
      `FieldChange` per difference (lists treated as scalars).
- [x] Per-env projection: `project_policy_for_env` filters
      `host_groups` to the env's group, prepends the synthesised
      override-RG slug to `rule_groups`, and empties inline `rules`
      so the desired shape matches what the applier will render.
- [x] Override-RG synthesis: `synthesise_override_rule_groups` emits
      `<policy-slug>-overrides-<env>` rule groups from every policy's
      inline rules. Mirrored on the live side by passing
      `fold_overrides=False` to `policy_from_api` (new parameter,
      defaults `True` for the importer).
- [x] Managed-vs-unmanaged classification from the
      `Managed by csfwctl` description trailer; live-only objects
      become `unmanaged` entries unless a matching tombstone queues a
      delete. Description excluded from comparison so the applier owns it.
- [x] `fetch_live_state(client)` convenience that walks every sub-client
      (policies, rule groups + their rules, locations) so the diff
      command body only owes credentials.
- [x] `diff_cmd.py`: command body following the `validate_cmd` /
      `import_cmd` pattern. Renders the rich text summary to stdout,
      writes JSON to `--output` when given, exits 1 only on repo-load
      or live-fetch failure. Accepts a `state_provider` callable so
      tests bypass the real Falcon client.
- [x] Wire `csfwctl diff --env` through `cli.py` (was previously a stub).
- [x] Docs: `docs/cli_reference.md` documents the `diff` command;
      `docs/architecture.md` carries the Phase 4 design notes (schema
      comparison, override-RG synthesis, host-group projection,
      managed-status rules).
- [x] Unit tests: 203 passing total (27 new):
      22 differ tests (`test_differ.py`) covering signature detection,
      override-RG synthesis, per-env policy projection, no-change /
      create / update / delete / unmanaged paths, env-suffix filtering,
      override round-trip, orphan-override warning, JSON serialization,
      unknown-env rejection, and a realistic-fixture integration test.
      5 CLI command-body tests (`test_diff_cmd.py`) for stub-provider
      flow, JSON output, repo-error surfacing, end-to-end Typer
      dispatch, and the no-changes path.

## Phase 3 tasks

- [x] `exporter.py`: name normalisation helpers (`strip_env_suffix`,
      `display_name_to_slug`, `clean_description`, override-group
      detection), API → Pydantic translators for rules / endpoints /
      rule groups / policies / locations, and inverse `*_to_api_shape`
      renderers used by tests + Phase 5 applier.
- [x] `exporter.import_policy` / `import_rule_group` / `import_location`
      / `import_all`: high-level entry points that drive the
      `FalconClient` sub-clients, validate via Pydantic, and write
      round-trippable YAML through a custom `dump_yaml` that strips
      defaults so emitted files match hand-authored shape.
- [x] Override-rule-group folding: when a policy references a rule
      group named `<policy-slug>-overrides-<env>`, fold its rules back
      into the policy YAML's inline `rules:` field instead of writing
      the override group as a separate file.
- [x] `falcon/rule_groups.py`: added `get_rules(ids)` so the importer
      can fetch rule contents (`get_rule_groups` only returns
      `rule_ids`).
- [x] `fixtures.py`: deterministic `Sanitizer` (UUIDs → counter UUIDs,
      IPv4/IPv6 → RFC 5737/3849 ranges, hostnames → `host-NNN.example.test`,
      emails → `user-NNN@example.test`, CIDRs preserve prefix length),
      `record_fixtures` driver that walks default read-only operations
      and writes per-op JSON, plus `filter_operations` for the
      `--operations` flag.
- [x] `import_cmd.py` + `record_fixtures_cmd.py`: command bodies
      (matching `validate_cmd.py` pattern) wired into `cli.py`. CLI
      now passes `--profile` through `ctx.obj` for sub-commands that
      need credentials.
- [x] API shape assumptions documented in `docs/architecture.md` —
      policy / rule-group / rule / location record layouts plus the
      override-folding contract and round-trip test design.
- [x] `docs/cli_reference.md` updated for `import` and `record-fixtures`.
- [x] Unit tests: 176 passing total (68 new):
      29 translation tests (`test_exporter_translation.py`),
      15 end-to-end round-trip tests (`test_exporter.py`) including the
      "import → load → validate is clean" contract against a fake
      `FalconClient` and the realistic fixture repo,
      15 sanitiser / record-fixtures tests (`test_fixtures.py`), and
      9 CLI command-body tests (`test_import_cmd.py`).

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

- **Next phase: Phase 5 — Applier.**
  - Consume a `ChangeSet` produced by `csfwctl.differ.compute_diff`
    and execute the creates / updates / deletes against the tenant.
    Order: locations → rule groups → policies → host-group reassignments
    → precedence ordering. Deletes last and only with `--allow-delete`
    + matching tombstone.
  - Reuse `exporter.*_to_api_shape` to render desired state into API
    payloads (the differ already proves they round-trip through
    `*_from_api`). The applier writes the metadata signature trailer
    into each touched object's description (`Managed by csfwctl |
    version: N | git_sha: X | applied: TS | env: E`).
  - `--initial-bootstrap` mode only writes the metadata trailer; it
    never modifies rule content. Refuses to run a normal apply against
    an unbootstrapped tenant.
  - Safety rails (`csfwctl.safety`): blast-radius limits
    (`--max-deletes`, `--max-changes`) checked before any write.
    `--enforce` is the only way to overwrite drifted state.
  - `--dry-run` runs the differ + safety checks but skips writes,
    printing the same change set the live apply would produce.
- **Differ contract reminders for Phase 5:**
  - Override-RGs are synthesised on the desired side as
    `<policy-slug>-overrides-<env>` and prepended to `rule_groups`;
    the applier must materialise them when applying policies with
    inline rules. See `synthesise_override_rule_groups` and
    `project_policy_for_env`.
  - `policy_from_api` now takes `fold_overrides=False`; the differ
    uses it so live override-RG references stay visible during
    comparison. The importer still defaults to `True`.
  - The `description` field is excluded from differ comparisons
    because the applier owns the metadata trailer. The applier must
    preserve any pre-existing free-text in the description while
    rewriting the trailer.
  - `ChangeSet.unmanaged` lists live objects without a YAML
    counterpart and without a tombstone. The applier must not touch
    these unless `--enforce` is passed and a tombstone is added.
- **API shape assumptions** (recorded in `docs/architecture.md`) are
  the contract Phase 5 writes against. If real-tenant interaction
  reveals discrepancies, all translation is localised to
  `csfwctl/exporter.py`'s `*_from_api` / `*_to_api_shape` helpers —
  the differ and applier do not parse API shapes directly.
- **Round-trip test pattern** in `tests/unit/test_exporter.py` and
  `tests/unit/test_differ.py` is the template Phase 5 should reuse:
  hand-author a model, drive through translation, assert results.
  Build a `FakeFalconClient` (see `test_exporter.py`) plus a
  recording fake that captures write calls for assertion.
- **Location API spike** still has three confirmation items pending
  the first real-tenant interaction; see `docs/architecture.md`.
- `Credentials.redacted()` is what to put in logs / notifier payloads
  — never log a `Credentials` instance unredacted.
- The meta-test `test_only_falcon_subpackage_imports_falconpy` makes
  the no-direct-`falconpy` rule a CI failure. New imports of FalconPy
  types must re-export from `csfwctl.falcon`.
- Command-body pattern (one module per command, kept out of `cli.py`)
  is now used by `validate_cmd.py`, `import_cmd.py`, and
  `record_fixtures_cmd.py`. Apply the same shape for `diff`, `apply`,
  `status`, `precedence`.
- v0.0.1 tag intentionally left for a maintainer to apply locally; CI
  release workflow is not configured yet (lands in a later phase).
