# csfwctl

Config-as-code management for CrowdStrike Falcon firewall policies,
rule groups, and locations.

> Status: **Phase 0 — scaffolding.** The CLI surface is in place but every
> subcommand is stubbed.

## Two repositories

csfwctl is one of two repositories:

- **`csfwctl`** (this repo) — the Python package and CLI. Public on
  GitHub, mirrored to internal GitLab. Contains no tenant data.
- **`csfwctl-config`** — YAML data describing the desired state of a
  specific tenant. Internal GitLab only. Calls `csfwctl` from CI.

Real policy names, host group names, IP ranges, and similar tenant data
live in `csfwctl-config`. Anything checked into this repository is
either code or sanitized test fixtures.

## Model

Three environments per logical policy and rule group: **Test → Pilot →
Production**. Object names never change once set; the environment
suffix (`-Test`, `-Pilot`, `-Production`) is appended at apply time.
Version history lives in Git, surfaced through a metadata signature
written into each managed object's description on every apply:

```
Managed by csfwctl | version: N | git_sha: X | applied: TS | env: E
```

Promotion is trunk-based with manual gates between environments. See
[`csfwctl-project-plan.md`](./csfwctl-project-plan.md) for the full
design.

## Safety constraint

There is no test tenant. Every test in this repository runs against
mocked or recorded API responses. Safety rails in `csfwctl/safety.py`
exist because the first apply against real infrastructure has to be
correct:

- `--initial-bootstrap` only adds metadata; never modifies rule content.
- `--max-deletes` and `--max-changes` are checked before any write.
- Drift fails loudly; `--enforce` is the only way to overwrite it.
- Deletions require a matching tombstone and `--allow-delete`.

## Quick start (development)

```sh
make dev      # create .venv, editable-install with dev extras
make test     # run pytest with coverage
make lint     # ruff + mypy
```

## Install (production)

Production install is `make install` to a system path. Layout: venv at
`/opt/csfwctl`, wrapper at `/usr/local/bin/csfwctl`, config at
`/etc/csfwctl/`. The Makefile target is a stub in Phase 0; full
install support lands in a later phase.

## Documentation

- [`csfwctl-project-plan.md`](./csfwctl-project-plan.md) — authoritative
  design document.
- [`TODO.md`](./TODO.md) — current phase and open tasks.
- [`docs/architecture.md`](./docs/architecture.md) — technical findings.
- [`docs/schema_reference.md`](./docs/schema_reference.md) — YAML schema.
- [`docs/cli_reference.md`](./docs/cli_reference.md) — command reference.
- [`docs/operations.md`](./docs/operations.md) — runbooks.
- [`docs/notifications.md`](./docs/notifications.md) — notifier configuration.

## License

MIT. See [`LICENSE`](./LICENSE).
