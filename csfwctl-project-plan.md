# csfwctl — Project Plan

Config-as-code management for CrowdStrike Falcon firewall policies, rule
groups, and locations. Two repositories: **`csfwctl`** (Python CLI, public)
and **`csfwctl-config`** (YAML data, internal-only).

---

## 1. Design decisions (locked)

### Object model

- Three stable CrowdStrike objects per logical policy and per logical rule
  group, suffixed `-Test`, `-Pilot`, `-Production`. Names never change once
  set. Host group assignments per environment never change. Apply updates
  rule content in place.
- One YAML file per logical object. Filename stem is the slug used for
  cross-references. Environment suffix is appended at apply time, never in
  the filename.
- Rule groups can be reused across policy families within a single
  environment (e.g., `windows-baseline-Test` is shared by multiple `-Test`
  policies).
- Locations included in v1. Default location is `any`, resolved at apply
  time. Named locations supported but multi-location policy scenarios are
  not the v1 focus.

### Version history

- Lives in Git. Not in object names.
- Each managed object's `description` field carries a metadata block,
  rewritten on every apply:
  ```
  Managed by csfwctl | version: 7 | git_sha: abc123 |
  applied: 2026-05-19T14:30Z | env: production
  ```
- `csfwctl status` reads these to show what SHA is deployed in each
  environment.

### Promotion workflow

- Trunk-based on `main` in the config repo.
- Merge to `main` auto-applies to Test.
- Manual GitLab jobs apply Pilot, then Production. Same commit SHA flows
  through all three; nothing is recomputed between stages.
- Approval gates: Pilot requires one approver, Production requires two.

### Status field

`enabled` | `disabled` | `deleted`. Maps directly to the CrowdStrike
`enabled` attribute. `deleted` requires a matching tombstone entry and the
`--allow-delete` flag at apply time.

### Drift handling

Fail loudly by default. `--enforce` overrides console edits and reasserts
YAML state. Scheduled drift-check job runs against Production.

### Precedence

Bucket-based: `emergency` | `high` | `medium` | `default` | `low`. Tool
resolves to ordinal precedence at apply time, ties broken alphabetically
by policy name. `csfwctl precedence` prints the resolved order.

### Rule ordering within a policy

YAML list order. Inline `rules:` (per-policy override block) first,
synthesized as an anonymous rule group named `<policy-name>-overrides-<env>`
and inserted at the top. Then `rule_groups:` in listed order.

### Platforms

`windows` and `mac` in v1. Linux deferred. "Universal" rule groups
(platform-agnostic with per-rule platform flags) deferred. Platform is a
required field on every policy and rule group YAML.

### Host groups

`host_groups:` dict in policy YAML keyed by group name, value is
environment. Missing groups produce a warning by default; `--strict-groups`
fails instead; `--create-groups` creates them as empty.

### Authentication

FalconPy with `client_id` + `client_secret`. Two API clients per tenant:
read-only (used by `diff`, `status`, `validate`) and read/write (used only
by `apply` jobs). Credentials per environment via CI variables.

### Safety rails (no test tenant available)

- `--initial-bootstrap`: first run only adds metadata to existing objects;
  never modifies rule content. One-time use during initial rollout.
- `--record-fixtures`: captures sanitized API responses for offline test
  fixtures.
- Blast-radius limits: `--max-deletes N` (default 1), `--max-changes N`
  (default 10). Apply refuses to proceed if exceeded without override.
- All apply operations support `--dry-run` and produce a written diff
  report.

### Distribution (v1)

Local install via `make install` on a small number of hosts. Wrapper
script at `/usr/local/bin/csfwctl`, config under `/etc/csfwctl/`, venv
under `/opt/csfwctl/`. Formal pip packaging deferred to a later sprint.

### Notifications

Pluggable notifier system. v1 channels: structured log (JSON), rich
console, Microsoft Teams webhook, GitLab MR comments, syslog. Deferred:
Slack, email, PagerDuty, generic JSON webhook, Prometheus push gateway.

Event types: `validate.failed`, `diff.changes_detected`, `apply.started`,
`apply.succeeded`, `apply.failed`, `drift.detected`, `drift.cleared`.

---

## 2. Repository layouts

### `csfwctl` (code repo, public on GitHub, mirrored to internal GitLab)

```
csfwctl/
├── pyproject.toml
├── Makefile
├── README.md
├── LICENSE
├── .github/
│   └── workflows/
│       ├── ci.yml                  # lint, type-check, unit tests
│       └── release.yml             # build wheel on tag
├── .gitlab-ci.yml                  # same plus upload wheel to internal host
├── csfwctl/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                      # Typer entrypoint
│   ├── config.py                   # env vars, credential loading
│   ├── schema/
│   │   ├── __init__.py
│   │   ├── policy.py
│   │   ├── rule_group.py
│   │   ├── rule.py
│   │   ├── location.py
│   │   ├── tombstone.py
│   │   └── precedence.py
│   ├── falcon/
│   │   ├── __init__.py
│   │   ├── client.py               # auth, retry, rate limit, request IDs
│   │   ├── policies.py
│   │   ├── rule_groups.py
│   │   ├── host_groups.py
│   │   └── locations.py
│   ├── loader.py                   # YAML → schema, cross-ref resolution
│   ├── differ.py                   # desired vs. live state
│   ├── applier.py                  # idempotent apply
│   ├── exporter.py                 # CrowdStrike → YAML (import command)
│   ├── linter.py                   # schema + semantic validation
│   ├── status.py                   # version/SHA introspection
│   ├── precedence_resolver.py      # bucket → ordinal
│   ├── safety.py                   # blast-radius checks, bootstrap mode
│   ├── notifiers/
│   │   ├── __init__.py             # plugin interface
│   │   ├── log.py
│   │   ├── console.py
│   │   ├── teams.py
│   │   ├── gitlab.py
│   │   └── syslog.py
│   └── fixtures.py                 # record/replay for tests
├── tests/
│   ├── unit/
│   ├── integration/                # against recorded fixtures only
│   └── fixtures/
│       ├── api_responses/          # recorded FalconPy responses
│       └── config_repos/           # sample YAML data repos
└── docs/
    ├── architecture.md
    ├── schema_reference.md
    ├── cli_reference.md
    ├── operations.md               # runbooks, rollback, onboarding
    └── notifications.md
```

### `csfwctl-config` (data repo, internal GitLab only)

```
csfwctl-config/
├── .gitlab-ci.yml
├── README.md
├── csfwctl.toml                    # tool config: notification routes,
│                                   # safety rail overrides, etc.
├── precedence.yaml                 # optional global precedence overrides
├── tombstones.yaml                 # explicit deletion markers
├── policies/
│   ├── abc01-endpoints-windows.yaml
│   ├── abc01-endpoints-mac.yaml
│   ├── research-lab-7-windows.yaml
│   └── ...
├── rule_groups/
│   ├── windows-baseline.yaml
│   ├── mac-baseline.yaml
│   ├── windows-remote-access.yaml
│   └── ...
├── locations/
│   └── ...                         # any-only initially
└── host_groups/
    └── manifest.yaml               # documents expected groups
```

---

## 3. Schema specifications

### Policy

```yaml
# policies/abc01-endpoints-windows.yaml
name: ABC01-Endpoints-Windows       # base name; -Test/-Pilot/-Production
                                    # appended at apply time
platform: windows                   # windows | mac
priority: default                   # emergency | high | medium | default | low
status: enabled                     # enabled | disabled | deleted
description: >
  Baseline firewall policy for ABC01-managed Windows endpoints.

host_groups:
  ABC01-Endpoints-Windows-Test: test
  ABC01-Endpoints-Windows-Pilot: pilot
  ABC01-Endpoints-Windows-Production: production

# Inline policy-specific override rules. Rendered as an anonymous rule
# group named "<policy-name>-overrides-<env>", inserted at top of the
# policy's rule group list.
rules:
  - name: Allow corp DNS outbound
    enabled: true
    action: allow
    direction: outbound
    protocol: udp
    locations: [any]                # default; may be omitted
    remote:
      addresses: [10.1.1.53, 10.1.1.54]
      ports: [53]

# Shared rule groups, in precedence order within the policy.
rule_groups:
  - windows-baseline
  - windows-remote-access
```

### Rule group

```yaml
# rule_groups/windows-baseline.yaml
name: windows-baseline
platform: windows                   # must match policies that reference it
status: enabled
description: Baseline allow/deny rules for Windows endpoints.

rules:
  - name: Allow established inbound
    enabled: true
    action: allow
    direction: inbound
    protocol: any
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

### Location

```yaml
# locations/any.yaml — special; auto-managed, generally not committed.
# Named locations look like this:
# locations/corp-vpn.yaml
name: corp-vpn
status: enabled
description: Corporate VPN address ranges
addresses:
  - 10.100.0.0/16
  - 10.101.0.0/16
dns_servers:
  - 10.1.1.53
dns_resolution_targets:
  - corp.example.edu
default_gateways: []
```

### Tombstones

```yaml
# tombstones.yaml
policies:
  - name: legacy-vpn-policy
    deleted_in_sha: abc1234
    reason: Replaced by remote-access-windows
rule_groups:
  - name: legacy-rdp-allow
    deleted_in_sha: def5678
    reason: Folded into windows-remote-access
locations: []
```

### Precedence overrides (optional)

```yaml
# precedence.yaml — only used to override the default bucket-based ordering
# in rare cases. Most installations leave this empty.
overrides:
  # Force one policy ahead of another within the same bucket
  - before: emergency-incident-response-windows
    after: research-lab-7-windows
```

### Tool config

```toml
# csfwctl.toml in the config repo
[tool]
metadata_signature = "Managed by csfwctl"

[safety]
max_deletes = 1
max_changes = 10
require_bootstrap_for_unmanaged = true

[notifications.teams]
url_env = "TEAMS_WEBHOOK_URL"
events = ["apply.failed", "drift.detected"]

[notifications.syslog]
host = "syslog.example.edu"
port = 514
facility = "local3"
events = ["apply.*", "drift.*"]

[notifications.log]
path = "/var/log/csfwctl/events.jsonl"
events = ["*"]
```

---

## 4. CLI surface

```
csfwctl validate [--repo PATH]
    Schema + semantic lint. No API calls. Exit 1 on any error.

csfwctl diff --env {test|pilot|production} [--repo PATH] [--output FILE]
    YAML vs. live state for the named environment. Human-readable to
    stdout, JSON to --output if given.

csfwctl apply --env {test|pilot|production}
    [--dry-run] [--enforce] [--allow-delete]
    [--strict-groups] [--create-groups]
    [--initial-bootstrap]
    [--max-deletes N] [--max-changes N]
    [--repo PATH]
    Idempotent apply. Refuses destructive ops without explicit flags.

csfwctl status [--all-envs] [--format {table|json}]
    Shows all policies, rule groups, and locations in the tenant.
    Marks each as [M]anaged or [U]nmanaged based on metadata signature.

csfwctl precedence [--env ENV]
    Prints the resolved policy precedence order.

csfwctl import {policy|rule-group|location} <name-or-uuid>
    [--strip-env-suffix] [--output PATH]
    Bootstraps a YAML file from a live CrowdStrike object.

csfwctl import all [--output-dir PATH]
    Bulk import of every object in the tenant. Used for initial repo
    population.

csfwctl record-fixtures [--operations OPS] [--output PATH]
    Captures sanitized API responses for offline tests.

csfwctl promote --from {test|pilot} --to {pilot|production}
    Convenience wrapper that triggers the corresponding GitLab CI job.

csfwctl notify-test [--channel CHANNEL]
    Sends a test notification to verify channel configuration.
```

Global flags: `--repo PATH`, `--profile {prod|dev}`, `--log-format {text|json}`,
`--verbose`, `--quiet`.

---

## 5. Safety rails

### Initial bootstrap mode

First-ever apply against a tenant uses `--initial-bootstrap`. In this mode:

- The applier reads every object in the tenant.
- For each object that matches a YAML file by name (after appending env
  suffix), it adds the `csfwctl` metadata block to the description. No
  other fields are touched.
- For each object that does NOT match a YAML file, it logs a warning and
  takes no action.
- For each YAML file that does NOT match an object, it logs a warning and
  takes no action (creation requires a subsequent normal apply).
- After bootstrap, every subsequent apply uses normal logic.

A tenant is considered "bootstrapped" once at least one object carries the
metadata signature. Normal apply refuses to run against an unbootstrapped
tenant unless `--initial-bootstrap` is passed.

### Blast-radius limits

Each apply tracks counts of: creates, updates, deletes, host group
reassignments. Limits are checked before any write. If exceeded:

- The tool prints the planned changes and the violated limit.
- It refuses to proceed.
- The operator must rerun with `--max-deletes N` or `--max-changes N` to
  authorize the larger change.

Defaults are deliberately conservative (1 delete, 10 changes per run).
For initial bootstrap or planned migrations, set them higher explicitly.

### Recorded fixtures

`csfwctl record-fixtures` runs a sequence of read-only API calls and
saves the responses to `tests/fixtures/api_responses/`. Secrets and
identifying information (UUIDs, hostnames) are sanitized via a
configurable transform. The integration test suite replays these
responses via `responses` or `pytest-httpserver`, giving us realistic
test data without a sandbox tenant.

Fixtures are version-controlled in the code repo. Re-record periodically
to catch API changes.

---

## 6. Makefile-based installation

```makefile
# Targets:

make install           # Production install: venv in /opt/csfwctl,
                       # wrapper script in /usr/local/bin, config in
                       # /etc/csfwctl. Requires root.

make uninstall         # Remove all of the above. Preserves /etc/csfwctl
                       # unless PURGE=1.

make dev               # Local development: venv in .venv, editable
                       # install, pre-commit hooks.

make test              # Run pytest with coverage.
make lint              # ruff + mypy.
make fixtures          # Re-record API fixtures (requires credentials).
make wheel             # Build distributable wheel into dist/.
make clean             # Remove build artifacts and caches.
```

Install layout:

```
/opt/csfwctl/                # venv root
  bin/
  lib/python3.x/site-packages/csfwctl/
/usr/local/bin/csfwctl       # wrapper: exec /opt/csfwctl/bin/csfwctl "$@"
/etc/csfwctl/
  credentials.toml           # client_id, client_secret (mode 0600)
  csfwctl.toml -> /path/to/config-repo/csfwctl.toml   # symlink
/var/log/csfwctl/
  events.jsonl
```

---

## 7. CI/CD pipelines

### Code repo (`csfwctl`)

**GitHub Actions (`.github/workflows/ci.yml`)**: lint, type-check, unit
tests, integration tests against fixtures, on every push and PR.

**GitHub Actions (`.github/workflows/release.yml`)**: on tag matching
`v*`, build the wheel and attach to a GitHub release.

**GitLab CI (`.gitlab-ci.yml`)**: same lint/test stages. On tag, build the
wheel and `scp` it to the internal static web server. Job is manual to
prevent accidental publishes.

### Config repo (`csfwctl-config`)

Stages:

- **validate** (every push and MR): `csfwctl validate` + `csfwctl diff
  --env test`. Diff posted as MR comment via the GitLab notifier.
- **apply-test** (merge to `main`, automatic): `csfwctl apply --env test`.
- **apply-pilot** (manual, GitLab `pilot` environment, 1 approver):
  `csfwctl apply --env pilot`.
- **apply-prod** (manual, GitLab `production` environment, 2 approvers):
  `csfwctl apply --env production`.
- **drift-check** (scheduled hourly): `csfwctl diff --env production`
  against current `main`. Notifies on any drift.

Read-only credentials are used in `validate` and `drift-check`.
Read/write credentials are used only in `apply-*` jobs, scoped to the
appropriate GitLab environment.

---

## 8. Notifier interface

```python
class Notifier(Protocol):
    name: str
    def supports(self, event_type: str) -> bool: ...
    def send(self, event: Event) -> None: ...

@dataclass
class Event:
    type: str                       # e.g. "apply.succeeded"
    severity: Literal["info", "warn", "error"]
    timestamp: datetime
    env: str | None                 # test/pilot/production
    git_sha: str | None
    summary: str                    # one-line human summary
    details: dict                   # structured payload
    request_id: str                 # for log correlation
```

Each notifier is a small class that reads its config from `csfwctl.toml`
and registers via entry points. Adding a new channel (Slack, email, etc.)
later is a new file in `csfwctl/notifiers/` and an entry-points line.

Routing: each notifier declares the events it cares about (glob patterns
like `apply.*` or `drift.detected`). The applier emits events to a bus;
the bus dispatches to all interested notifiers. Failures in one notifier
never block others or the apply itself.

---

## 9. Phased build plan

Each phase ends with green tests and (where applicable) a tagged release.

### Phase 0 — Scaffolding

- Initialize `csfwctl` repo on GitHub.
- `pyproject.toml` with deps: `crowdstrike-falconpy`, `pydantic>=2`,
  `ruamel.yaml`, `typer`, `rich`, `tomli`, `httpx` (transitive via
  FalconPy), `pytest`, `pytest-mock`, `responses`, `ruff`, `mypy`.
- Makefile with `dev`, `test`, `lint`, `wheel`, `clean`.
- GitHub Actions CI workflow (lint + test).
- Empty CLI module with all subcommands stubbed (each prints "not
  implemented" and exits 2).
- `TODO.md` for cross-session handoff (see section 10).
- README with project overview and split-repo note.

### Phase 1 — Schema and loader

- Pydantic v2 models for `Policy`, `RuleGroup`, `Rule`, `Location`,
  `Tombstones`, `PrecedenceOverrides`, `ToolConfig`.
- Strict slug validation on names. Cross-platform reference validation
  (a Windows policy cannot reference a Mac rule group). No duplicate
  names within a kind.
- YAML loader using `ruamel.yaml` for round-trip comment preservation.
  Resolves slug references across files. Surfaces errors with file path
  and approximate line number.
- Fixture data repo under `tests/fixtures/config_repos/minimal/` and
  `.../realistic/` for tests.
- `csfwctl validate` works end-to-end.

### Phase 2 — Falcon client layer

- FalconPy auth wrapper reading from `/etc/csfwctl/credentials.toml` or
  environment variables.
- Retry with exponential backoff on 5xx and 429.
- Request ID generated per CLI invocation; logged on every API call.
- Thin client modules for policies, rule groups, host groups, locations.
- **Spike: confirm location API behavior.** Determine how the default
  `any` location is represented, whether its ID is stable per tenant,
  and how FalconPy exposes it. Document findings in
  `docs/architecture.md`.
- All API interactions go through the wrapper. No direct FalconPy calls
  elsewhere in the codebase.
- Unit tests with mocked HTTP responses.

### Phase 3 — Exporter and fixture recorder

- `csfwctl import policy <name|uuid>`, `csfwctl import rule-group
  <name|uuid>`, `csfwctl import location <name|uuid>`.
- `csfwctl import all`: bulk import of an entire tenant into a fresh
  config repo directory.
- Strips environment suffixes from imported names.
- Sanitizes IDs and identifying info during import.
- `csfwctl record-fixtures`: captures read-only API responses for the
  integration test suite. Sanitizes secrets.
- Round-trip test: import → load → diff should be empty.

### Phase 4 — Differ

- Given loaded YAML and live state for one environment, produces a
  structured change set.
- Handles inline-rules-to-anonymous-rule-group expansion.
- Human-readable summary suitable for MR comments.
- JSON output for programmatic use.
- Distinguishes managed vs. unmanaged objects (used by `status`).

### Phase 5 — Applier with safety rails

- Idempotent apply for one environment.
- Operation order: locations first, then rule groups, then policies,
  then host group assignments, then precedence ordering. Deletes last,
  and only with `--allow-delete` + matching tombstone.
- Writes metadata block to description on every touched object.
- `--initial-bootstrap` mode: only adds metadata, never modifies rules.
- `--dry-run` produces the diff report and exits without writes.
- Blast-radius checks before any write.
- Refuses to run against unbootstrapped tenant.
- `--enforce` is the only way to overwrite drifted state.

### Phase 6 — Status and precedence

- `csfwctl status` reads all policies, rule groups, locations in the
  tenant. Groups them by logical name. Shows version/SHA per env.
  Marks managed vs. unmanaged. Optional `--all-envs` shows all three;
  default is current `--env` only.
- `csfwctl precedence` resolves buckets to ordinals, applies overrides,
  prints the resulting order. Read-only against tenant for current
  precedence comparison.

### Phase 7 — Linter and validators

Beyond schema:
- Precedence bucket conflicts and ambiguities.
- Rule groups referenced by no policy.
- Policies with no host groups in any environment.
- Tombstones without matching deletion in YAML.
- Rules with overly broad allow patterns (warn, configurable).
- Platform mismatches (already caught at schema layer; this adds
  cross-file checks).
- Pluggable rule architecture so site-specific lints can be added.

### Phase 8 — Notifiers

- Notifier protocol and registry.
- Log notifier (JSON Lines to file).
- Console notifier (rich, suppressed in CI).
- Teams notifier (incoming webhook, MessageCard format).
- GitLab notifier (MR comments via API).
- Syslog notifier (RFC 5424, configurable facility/host).
- `csfwctl notify-test` command for verifying channel config.

### Phase 9 — Config repo bootstrap

- Initialize `csfwctl-config` repo on internal GitLab.
- Run `csfwctl import all` against live tenant.
- Hand-review imported YAML; clean up names, descriptions, statuses.
- Author `csfwctl.toml` with notification routes.
- Author `.gitlab-ci.yml` with all four stages plus drift-check.
- Configure GitLab CI variables: read-only and read/write credentials
  for each environment.
- Configure GitLab environments: `test`, `pilot`, `production` with
  appropriate approver groups.
- First end-to-end exercise: `--initial-bootstrap` apply to Test,
  verify in console, normal apply with a trivial change, promote
  through Pilot to Production.

### Phase 10 — Operational hardening

- Drift-check job tuned for noise (deduplicate alerts within window).
- Rollback runbook: `git revert <sha>` + manual apply.
- Onboarding doc for new admins: how to write a new policy, how to
  promote, how to handle drift alerts.
- First production migration: pick a low-risk existing policy, fold
  into the system end-to-end, observe behavior for a week.

### Later sprints (post-v1)

- Linux platform support.
- Universal rule groups (platform-agnostic with per-rule platform flags).
- Multi-location policy scenarios.
- Slack, email, PagerDuty, generic webhook notifiers.
- Prometheus metrics endpoint.
- Pip package distribution via internal index or PyPI.
- Read-only public dashboard summarizing managed-policy state.

---

## 10. Initial TODO.md for Claude Code

The following is the content for `TODO.md` in the `csfwctl` repo, used
for cross-session handoff while Claude Code builds out Phases 0–2.

```markdown
# csfwctl — Build TODO

Cross-session handoff for Claude Code. Update as work progresses.
Project plan: ../csfwctl-project-plan.md

## Current phase

Phase 0: Scaffolding

## Phase 0 tasks

- [ ] Initialize git repo, MIT license, .gitignore for Python
- [ ] Author pyproject.toml with project metadata and dependencies:
      crowdstrike-falconpy, pydantic>=2, ruamel.yaml, typer, rich,
      tomli; dev: pytest, pytest-mock, responses, ruff, mypy
- [ ] Author Makefile with targets: dev, test, lint, wheel, clean,
      install, uninstall (install/uninstall stubs OK for now)
- [ ] Create directory skeleton matching project plan section 2
- [ ] Author .github/workflows/ci.yml: ruff, mypy, pytest on push and PR
- [ ] Author csfwctl/cli.py with Typer app and all subcommands stubbed
      to print "not implemented" and exit 2
- [ ] Author csfwctl/__main__.py so `python -m csfwctl` works
- [ ] Author README.md with project overview, split-repo note, install
      placeholder
- [ ] Add docs/ skeleton: architecture.md, schema_reference.md,
      cli_reference.md, operations.md, notifications.md (headers only)
- [ ] Verify `make dev` then `make test` runs green with zero tests
- [ ] Tag v0.0.1

## Open questions

(None at this time.)

## Notes for next session

- Phase 1 starts with Pydantic schema modules in csfwctl/schema/.
- The location API spike in Phase 2 may surface schema changes; expect
  to iterate on Location model after Phase 2 begins.
- Fixtures live in tests/fixtures/. Two starter config repos:
  minimal/ (one policy, one rule group) and realistic/ (several of
  each, including one-off policies and platform mix).
```

---

## 11. Open items before Phase 0 starts

None blocking. Things to verify or decide as work progresses:

1. **Location API spike outcome** (Phase 2). May require minor schema
   adjustments to the Location model.
2. **Teams MessageCard vs. Adaptive Card** format for the Teams notifier.
   MessageCard is older but universally supported; Adaptive Cards are
   richer but require a newer connector. Decide during Phase 8.
3. **Drift-check frequency.** Plan says hourly; adjust based on tenant
   API rate limits observed during Phase 2.
4. **Approver groups in GitLab.** Identify the actual user groups that
   will gate Pilot and Production apply jobs. Plan accordingly during
   Phase 9.

---

## 12. Success criteria for v1

- All existing firewall policies and rule groups in the tenant are
  represented as YAML in the config repo.
- Every managed object carries the csfwctl metadata signature.
- A trivial rule change can be promoted Test → Pilot → Production
  entirely through MR + GitLab CI jobs, with no console interaction.
- Drift introduced in the console is detected within one drift-check
  cycle and surfaces as a notification.
- `csfwctl status` accurately reflects what is deployed where.
- The most recent successful apply per environment can be rolled back
  via `git revert <sha>` plus a re-apply job within 15 minutes.
- Onboarding doc allows a new admin to make their first MR within 30
  minutes of reading it.
