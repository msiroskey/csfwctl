# csfwctl

Config-as-code management for CrowdStrike Falcon firewall policies,
rule groups, and locations.

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

## Install

Development install (editable, into `.venv`):

```sh
make dev
make test   # pytest with coverage
make lint   # ruff + mypy
```

Production install (venv at `/opt/csfwctl`, wrapper at
`/usr/local/bin/csfwctl`):

```sh
sudo make install
```

Credentials live in `/etc/csfwctl/credentials.toml` (mode `0600`):

```toml
[prod]
client_id     = "YOUR_FALCON_CLIENT_ID"
client_secret = "YOUR_FALCON_CLIENT_SECRET"

[dev]
client_id     = "DEV_CLIENT_ID"
client_secret = "DEV_CLIENT_SECRET"
```

For CI, set `CSFWCTL_CLIENT_ID` / `CSFWCTL_CLIENT_SECRET` instead. Full
resolution order is in [`docs/cli_reference.md`](./docs/cli_reference.md).

## Using the tool

The CLI is always pointed at a config repo (`--repo PATH`, or the
current directory by default) and, for any command that touches the
tenant, an environment (`--env test|pilot|production`). See
[`docs/cli_reference.md`](./docs/cli_reference.md) for every flag.

### 1. Bootstrap YAML from an existing tenant

The first time you bring a tenant under csfwctl management, populate
the config repo by importing every existing object:

```sh
# Pull every policy, rule group, and location into the current repo.
csfwctl import all --output-dir .

# Or import individual objects by display name or UUID.
csfwctl import policy     "ABC01-Endpoints-Windows-Test"
csfwctl import rule-group "Windows-Baseline-Test"
csfwctl import location   "Corp-VPN"
```

What `import` does:

- Writes round-trippable YAML under `policies/`, `rule_groups/`, and
  `locations/`.
- Strips the `-Test` / `-Pilot` / `-Production` suffix from the name
  (toggle with `--no-strip-env-suffix`) so a single YAML file describes
  the object across all three environments.
- Picks `-Test` when multiple env variants exist, so the YAML reflects
  trunk state.
- Folds inline override rule groups
  (`<policy-slug>-overrides-<env>`) back into the policy YAML's
  `rules:` field — see the override-policy example below.

Import is read-only; nothing is written to CrowdStrike. After importing,
validate, commit, and open an MR.

### 2. Validate and preview

Every change starts with a local validate + diff:

```sh
csfwctl validate --repo .                    # schema + cross-ref + lint
csfwctl validate --repo . --strict           # promote lint warnings to fatal
csfwctl diff     --repo . --env test         # vs. live Test state
csfwctl status   --repo . --all-envs         # per-object version per env
csfwctl precedence --repo . --env production # resolved policy order
```

`validate` runs offline. `diff`, `status`, and `precedence` only read
from the tenant.

### 3. Initial tenant bootstrap

Before the first normal apply against a freshly-imported tenant, stamp
the csfwctl metadata signature on every matching live object:

```sh
csfwctl apply --env test --initial-bootstrap --dry-run --repo .
csfwctl apply --env test --initial-bootstrap --repo .
# repeat for --env pilot and --env production
```

Bootstrap only writes the `description` trailer. It does not create,
delete, or modify rule content. Normal `apply` refuses to run until the
tenant is bootstrapped.

### 4. Promote a change through Test → Pilot → Production

The same Git SHA flows through all three environments. Nothing is
recomputed between them.

```sh
# Edit a YAML file, then locally:
csfwctl validate --repo .
csfwctl diff --env test --repo .

# Open an MR. CI runs validate + diff and posts the diff as an MR comment.
# After merge, the apply-test CI job runs automatically:
csfwctl apply --env test --repo .

# Manual gate (1 approver) before Pilot, then:
csfwctl apply --env pilot --repo .

# Manual gate (2 approvers) before Production, then:
csfwctl apply --env production --repo .
```

A few useful apply flags for promotion scenarios:

- `--dry-run` — plan + safety checks; no writes.
- `--enforce` — required when the live state has drifted from the
  previous apply (e.g. a console edit). Re-asserts YAML as the source
  of truth.
- `--allow-delete` — required, alongside a matching `tombstones.yaml`
  entry, to delete a managed object.
- `--max-changes N`, `--max-deletes N` — raise the blast-radius limits
  for a one-off larger change.

Drift between scheduled runs surfaces via `csfwctl drift-check`,
typically wired into a cron / CI schedule against Production. See
[`docs/operations.md`](./docs/operations.md) for the rollback and
drift-response runbooks.

## Naming conventions

csfwctl distinguishes three names for every object. Following the
conventions below keeps slugs, display names, and host-group references
aligned, and keeps the env-suffix machinery working.

| Name           | Style                  | Where it appears                                                       | Example                                |
|----------------|------------------------|------------------------------------------------------------------------|----------------------------------------|
| Slug           | `lowercase-kebab-case` | YAML filename stem and in-document `name:`; cross-references.          | `abc01-endpoints-windows`              |
| Display name   | `TitleCase-With-Hyphens` | Optional `display_name:` field; what CrowdStrike shows.               | `ABC01-Endpoints-Windows`              |
| Live name      | display name + env suffix | Appended by csfwctl at apply time. Never typed into YAML.            | `ABC01-Endpoints-Windows-Production`   |

### Platform suffix on slugs

Policies and rule groups are platform-scoped (`windows` or `mac`).
Always include the platform as the trailing token of the slug so the
file is self-describing and so a mac-equivalent can sit next to it
without colliding:

- `abc01-endpoints-windows` / `abc01-endpoints-mac`
- `windows-baseline` / `mac-baseline`
- `windows-remote-access`

Locations are tenant-global and do not take a platform suffix
(e.g. `corp-vpn`).

### Rollout-phase suffix

The environment suffix is **appended by csfwctl at apply time** and
must never appear in YAML:

| Environment   | Suffix          |
|---------------|-----------------|
| Test          | `-Test`         |
| Pilot         | `-Pilot`        |
| Production    | `-Production`   |

So a slug `abc01-endpoints-windows` with `display_name:
ABC01-Endpoints-Windows` materialises in CrowdStrike as three objects:
`ABC01-Endpoints-Windows-Test`, `ABC01-Endpoints-Windows-Pilot`, and
`ABC01-Endpoints-Windows-Production`. The same Git SHA produces all
three; the only difference is the suffix.

### Host groups

Pre-create host groups in the Falcon console using the same pattern —
display name plus env suffix — and reference each one in the policy
under the matching env key:

```yaml
host_groups:
  ABC01-Endpoints-Windows-Test:       test
  ABC01-Endpoints-Windows-Pilot:      pilot
  ABC01-Endpoints-Windows-Production: production
```

Each env (`test` / `pilot` / `production`) may appear at most once.
`csfwctl apply` will refuse a referenced host group that doesn't exist
unless you pass `--create-groups` (creates it empty) or
`--strict-groups` (hard fail).

### When the display name has to break the pattern

If a CrowdStrike object name predates csfwctl and can't be renamed
(remember: names never change once set), keep the slug in the canonical
style and set `display_name:` to the verbatim console name. The
importer does this automatically when it encounters a non-conforming
name. The slug still drives the filename and all cross-references; the
display name is the only thing csfwctl pushes to the tenant.

## Sample config repo

A minimal repo looks like this:

```
my-csfwctl-config/
├── csfwctl.toml
├── policies/
│   └── abc01-endpoints-windows.yaml
├── rule_groups/
│   ├── windows-baseline.yaml
│   └── windows-remote-access.yaml
├── locations/
│   └── corp-vpn.yaml
├── precedence.yaml      # optional
└── tombstones.yaml      # optional
```

The full schema reference lives in
[`docs/schema_reference.md`](./docs/schema_reference.md). The sections
below show the most common shapes; complete fixtures live under
[`tests/fixtures/config_repos/realistic/`](./tests/fixtures/config_repos/realistic/).

### Override policy (inline `rules:`)

An "override policy" is a regular policy that carries policy-specific
rules inline under a top-level `rules:` field, in addition to the shared
`rule_groups:` it references. The applier materialises these inline
rules as an anonymous rule group named
`<policy-slug>-overrides-<env>` and inserts it at the top of the
policy's rule list — so policy-specific overrides always win against
the shared baseline:

```yaml
# policies/abc01-endpoints-windows.yaml
name: abc01-endpoints-windows
display_name: ABC01-Endpoints-Windows
platform: windows
priority: default
status: enabled
description: Baseline policy for ABC01 Windows endpoints.

host_groups:
  ABC01-Endpoints-Windows-Test: test
  ABC01-Endpoints-Windows-Pilot: pilot
  ABC01-Endpoints-Windows-Production: production

# Inline override rules. Rendered as an anonymous rule group named
# "abc01-endpoints-windows-overrides-<env>", inserted ahead of the
# shared rule groups below.
rules:
  - name: Allow corp DNS outbound
    enabled: true
    action: allow
    direction: outbound
    protocol: udp
    locations: [any]
    remote:
      addresses: [10.1.1.53, 10.1.1.54]
      ports: [53]

# Shared rule groups, evaluated after the inline overrides.
rule_groups:
  - windows-baseline
  - windows-remote-access
```

### Shared rule group

```yaml
# rule_groups/windows-baseline.yaml
name: windows-baseline
platform: windows
status: enabled
description: Baseline allow/deny rules for Windows endpoints.

rules:
  - name: Allow established inbound
    enabled: true
    action: allow
    direction: inbound
    protocol: tcp
    state: established
    locations: [any]

  - name: Block SMB inbound from non-corp
    enabled: true
    action: block
    direction: inbound
    protocol: tcp
    local:
      ports: [445]
    remote:
      addresses_negated: true
      addresses: [10.0.0.0/8]
    locations: [any]
```

### Named location

```yaml
# locations/corp-vpn.yaml
name: corp-vpn
status: enabled
description: Corporate VPN address ranges.

addresses:
  - 10.100.0.0/16
  - 10.101.0.0/16

dns_servers:
  - 10.1.1.53

dns_resolution_targets:
  - corp.example.edu
```

### Precedence overrides

Rarely needed. By default policies are ordered by their `priority`
bucket (`emergency` → `high` → `medium` → `default` → `low`) and then
alphabetically. Use `precedence.yaml` to force one policy ahead of
another within the same bucket:

```yaml
# precedence.yaml
overrides:
  - before: research-lab-7-windows
    after: abc01-endpoints-windows
```

### Tombstones

Required to delete a managed object. The applier refuses a delete
without a matching tombstone entry and the `--allow-delete` flag.

```yaml
# tombstones.yaml
policies: []
rule_groups:
  - name: legacy-rdp-allow
    deleted_in_sha: def5678
    reason: Folded into windows-remote-access.
locations: []
```

### Tool config

```toml
# csfwctl.toml
[tool]
metadata_signature = "Managed by csfwctl"

[safety]
max_deletes = 1
max_changes = 10
require_bootstrap_for_unmanaged = true

[notifications.teams]
url_env = "TEAMS_WEBHOOK_URL"
events  = ["apply.failed", "drift.detected"]
```

## Documentation

- [`csfwctl-project-plan.md`](./csfwctl-project-plan.md) — authoritative
  design document.
- [`docs/cli_reference.md`](./docs/cli_reference.md) — every command and flag.
- [`docs/schema_reference.md`](./docs/schema_reference.md) — full YAML
  and TOML schema.
- [`docs/operations.md`](./docs/operations.md) — onboarding, promotion,
  rollback, and drift-response runbooks.
- [`docs/architecture.md`](./docs/architecture.md) — technical findings.
- [`docs/notifications.md`](./docs/notifications.md) — notifier
  configuration.
- [`TODO.md`](./TODO.md) — current phase and open tasks.

## License

MIT. See [`LICENSE`](./LICENSE).
