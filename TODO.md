# csfwctl — Build TODO

Cross-session handoff for Claude Code. Update as work progresses.
Project plan: ./csfwctl-project-plan.md

## Current phase

Phase 1: Schema and loader

## Phase 1 tasks

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

- **Next phase: Phase 2 — Falcon client layer.** All CrowdStrike API
  calls go through `csfwctl/falcon/client.py`; no direct `falconpy`
  imports anywhere else. Includes the location API spike — record
  findings in `docs/architecture.md`.
- The `Location` model may need adjustment after the spike (default
  `any` representation, ID stability per tenant, FalconPy surface).
- `csfwctl/validate_cmd.py` holds the `validate` body; pattern of
  putting command bodies in their own module (kept out of `cli.py`)
  scales well — apply the same shape for `diff` and `apply` later.
- `csfwctl/loader.py` exposes `_check_platform_invariants` with a
  stub `_platform_supports_protocol` helper. Phase 7 lints tighten
  this without changing the cross-ref pass shape.
- `tomllib` requires Python ≥ 3.11. `pyproject.toml` already pins
  that; the loader uses `import tomllib` directly.
- v0.0.1 tag intentionally left for a maintainer to apply locally; CI
  release workflow is not configured yet (lands in a later phase).
