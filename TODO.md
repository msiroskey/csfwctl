# csfwctl — Build TODO

Cross-session handoff for Claude Code. Update as work progresses.
Project plan: ./csfwctl-project-plan.md

## Current phase

Phase 0: Scaffolding

## Phase 0 tasks

- [x] Initialize git repo, MIT license, .gitignore for Python
- [x] Author pyproject.toml with project metadata and dependencies:
      crowdstrike-falconpy, pydantic>=2, ruamel.yaml, typer, rich,
      tomli; dev: pytest, pytest-mock, responses, ruff, mypy
- [x] Author Makefile with targets: dev, test, lint, wheel, clean,
      install, uninstall (install/uninstall stubs OK for now)
- [x] Create directory skeleton matching project plan section 2
- [x] Author .github/workflows/ci.yml: ruff, mypy, pytest on push and PR
- [x] Author csfwctl/cli.py with Typer app and all subcommands stubbed
      to print "not implemented" and exit 2
- [x] Author csfwctl/__main__.py so `python -m csfwctl` works
- [x] Author README.md with project overview, split-repo note, install
      placeholder
- [x] Add docs/ skeleton: architecture.md, schema_reference.md,
      cli_reference.md, operations.md, notifications.md (headers only)
- [x] Verify `make dev` then `make test` runs green with zero tests
- [ ] Tag v0.0.1 (deferred — tag from maintainer machine after review)

## Open questions

(None at this time.)

## Notes for next session

- Phase 1 starts with Pydantic schema modules in `csfwctl/schema/`.
- The location API spike in Phase 2 may surface schema changes; expect
  to iterate on `Location` model after Phase 2 begins.
- Fixtures live in `tests/fixtures/`. Two starter config repos:
  `minimal/` (one policy, one rule group) and `realistic/` (several of
  each, including one-off policies and platform mix).
- v0.0.1 tag intentionally left for a maintainer to apply locally; CI
  release workflow is not configured yet (lands in a later phase).
