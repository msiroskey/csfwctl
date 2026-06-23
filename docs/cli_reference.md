# CLI reference

Per-command documentation for `csfwctl`. The CLI surface is defined in
`csfwctl-project-plan.md` section 4. Commands not yet implemented exit
with status 2 and a `not implemented` message.

## Global options

These apply to every subcommand:

| Option            | Type                    | Default | Notes                                    |
|-------------------|-------------------------|---------|------------------------------------------|
| `--repo PATH`     | path                    | cwd     | Path to a csfwctl-config repository.     |
| `--profile`       | `prod` \| `dev`         | `prod`  | Credential profile selector.             |
| `--credentials-file PATH` | path            | unset   | Overrides `$CSFWCTL_CREDENTIALS_PATH` and the `/etc/csfwctl/credentials.toml` default. |
| `--log-format`    | `text` \| `json`        | `text`  | Output format for logs / machine output. |
| `--verbose`       | bool                    | off     |                                          |
| `--quiet`         | bool                    | off     |                                          |

Credential resolution order, highest precedence first:

1. `CSFWCTL_CLIENT_ID` + `CSFWCTL_CLIENT_SECRET` env vars (intended for CI).
2. The TOML file pointed at by `--credentials-file PATH`.
3. The TOML file pointed at by `$CSFWCTL_CREDENTIALS_PATH`.
4. `/etc/csfwctl/credentials.toml`.

`load_credentials` logs the selected source at INFO; if env vars
override a configured file the log line calls that out so it is not
silent.

## `csfwctl validate`

**Implemented (Phase 1, extended in Phase 7).** Schema, cross-reference,
and semantic lint of a config repo. No API calls.

```
csfwctl validate [--repo PATH] [--strict]
```

What it checks:

1. Every YAML file in `policies/`, `rule_groups/`, `locations/` parses
   and matches its Pydantic schema. Errors include file path and a
   dotted field path; YAML parse errors include the line number.
2. `tombstones.yaml`, `precedence.yaml`, `csfwctl.toml` parse and
   validate if present.
3. Cross-references: rule-group slugs in policies resolve to rule
   groups with matching platforms; non-`any` location references
   resolve to locations; tombstones do not match still-present objects;
   precedence overrides reference known policies.
4. Semantic linter (Phase 7): pluggable rules implemented in
   `csfwctl.linter`. Built-ins are documented below under "Lint rules".

The first three are fatal — any failure aborts with exit 1. The fourth
emits findings with a severity (`error` / `warning` / `info`); only
`error` findings (or any finding with `--strict`) fail the command.

Exit codes:

- `0` — repository is valid; a summary table is written to stdout
  (with a yellow `with N warning(s)` suffix when non-fatal lint
  findings were emitted).
- `1` — one or more validation errors, a lint error-severity finding,
  or any lint finding when `--strict` was passed. Per-error / per-lint
  listings are written to stderr.

### Lint rules

Built-in rules are registered at import time in
`csfwctl.linter.LINT_REGISTRY`. Each has a stable `rule_id`:

| Rule id                      | Severity | What it flags                                                              |
|------------------------------|----------|----------------------------------------------------------------------------|
| `precedence-cycle`           | warning  | Overrides in `precedence.yaml` resolve into a cycle on one platform.       |
| `orphan-rule-group`          | warning  | A rule group is defined but no active policy lists it in `rule_groups`.    |
| `policy-without-host-groups` | warning  | A policy's `host_groups` map is empty — it cannot apply to any host.       |
| `deleted-without-tombstone`  | warning  | A YAML object with `status: deleted` has no matching tombstone entry.      |
| `broad-allow`                | warning  | An `action: allow` rule is world-open (`0.0.0.0/0` / `::/0`) or has no address or port constraints. |

Disabling rules: list rule ids in `csfwctl.toml`:

```toml
[lint]
disabled = ["broad-allow"]

[lint.options.broad-allow]
unconstrained = false       # only flag world-open allow rules
```

Plug-in rules: import a module that calls
`csfwctl.linter.register_lint(MyLint())` at load time; the lint runs in
registration order alongside the built-ins.

## `csfwctl diff`

**Implemented (Phase 4).** Compares the loaded config repo against
CrowdStrike's live state and prints a structured change set. Read-only
against the tenant.

```
csfwctl diff [--env {test|pilot|production}] [--repo PATH] [--output FILE]
             [--fail-on-env-drift]
```

Two modes:

- **Single env** (`--env test`): diffs the config repo against the named
  environment only.
- **All envs** (`--env` omitted): fetches live state once and diffs it
  against all three environments. The live fetch is env-agnostic, so this
  is a single round-trip to CrowdStrike plus three in-memory passes — no
  extra API cost. Renders a combined per-env summary table followed by a
  per-env detail log, and surfaces a **cross-env ripple warning** when a
  downstream env (pilot/production) carries more pending changes than test.

What it produces (single env):

- A summary table on stdout listing the counts of creates, updates,
  deletes, no-change objects, unmanaged live-only objects, and any
  warnings.
- Per-change detail blocks for each create / update / delete, with
  field-level diffs (`path: before -> after`) and host-group add/remove
  lines for policies. List-valued fields (notably a rule group's
  `rules`) are expanded down to the individual element and leaf that
  changed — e.g. `rules[Airdrop: Any Inbound].file_path: None ->
  '/usr/libexec/sharingd'` — rather than printing the whole before/after
  list. Rules are matched by name, so an added/removed rule shows as a
  single `rules[<name>]` entry and a pure reorder as one compact
  `rules (order)` line.
- A "no changes" line when desired and live converge.
- The same change set as JSON written to ``--output PATH`` if given,
  ready for MR comments and the applier to consume.

What it produces (all envs):

- A combined table with one row per environment.
- A `⚠ cross-env ripple detected` callout listing each downstream env
  whose pending-change count exceeds test's, followed by per-env detail
  logs.
- A multi-env JSON document to ``--output PATH`` (keys: `summary`,
  `env_drift`, `env_drift_warnings`, `change_sets`).

### Cross-env ripple warning

Because all three environments read the same config-repo YAML but apply on
independent gates (Test auto on merge, Pilot/Production manual), a change
that was merged and applied to Test but **not yet promoted** shows up as a
pending change downstream. If a *second* change then merges, an operator
approving a Pilot/Production apply would unknowingly advance the
still-in-testing change alongside the new one.

The all-envs diff detects this: a downstream env with more *env-scoped*
pending changes than Test (tenant-global locations are excluded from the
comparison, since they appear identically in every env) is reported as a
ripple. With `--fail-on-env-drift`, the command exits `2` when a ripple is
detected so a pipeline can block on it; without the flag it warns and
exits `0`.

Behaviour notes:

- Comparison is in schema space: live API records are translated into
  the same Pydantic models the loader produces, with env-suffixes
  stripped from names before matching by slug.
- Policy ``rules:`` inline overrides are synthesised on the desired
  side into a rule group named ``<policy-slug>-overrides-<env>`` so the
  comparison matches the applier's planned shape.
- The ``description`` field is excluded from comparison — that's where
  the applier writes the ``Managed by csfwctl | …`` metadata trailer,
  and the differ does not race the applier on it.
- Live objects without a matching YAML entry are reported as
  ``unmanaged`` (no change queued). A live object can be queued for
  deletion only by adding a matching tombstone in ``tombstones.yaml``.
- Records that fail translation (corrupt or unexpected shape) are
  skipped silently rather than aborting the whole diff; surviving
  objects still get compared.

Exit codes: ``0`` on success regardless of whether changes were
detected. ``1`` if the config repo fails to load or if the live-state
fetch errors out. ``2`` in all-envs mode when ``--fail-on-env-drift`` is
set and a cross-env ripple is detected.

### Notifier payload

When the diff finds changes it emits a `diff.changes_detected` event. In
single-env mode the event's `details` carries the full change set under
`change_set`; in all-envs mode it carries every env's change set under
`change_sets` plus `env_drift` / `env_drift_warnings`. The GitLab notifier
renders this into an MR comment — a per-env summary table at the top, the
ripple warning (if any) as a callout, and a per-object detail log below —
so the planned changes are visible on the merge request without opening the
pipeline. See [docs/notifications.md](notifications.md).

## `csfwctl drift-check`

**Implemented (Phase 9, extended in Phase 10).** Scheduled drift monitor.
Same engine as `diff` but with persistent per-env state so the command can
recognise the transition from "drifted" to "clean" and emit a `drift.cleared`
event in addition to `drift.detected`. Read-only against the tenant.

```
csfwctl drift-check --env {test|pilot|production}
                    [--repo PATH]
                    [--state-file PATH] [--no-state]
                    [--fail-on-drift]
                    [--alert-window N]
                    [--output PATH]
```

### What it does

1. Loads and validates the config repo.
2. Pulls live tenant state.
3. Computes a diff for `--env` (same logic as `csfwctl diff --env`).
4. Reads the prior drift verdict from the state file (if any).
5. Emits one notifier event per transition (subject to alert-window):
   - `drift.detected` (severity `warn`) — when drift exists and either
     no previous alert was sent or the alert window has expired.
   - `drift.cleared` (severity `info`) — when the prior run had drift
     and this run does not.
6. Writes the new verdict to the state file (unless `--no-state`).

### State file

Default path: `<repo>/.csfwctl/drift-state-<env>.json`. Override with
`--state-file PATH`. One file per environment so independent schedules
don't trample each other. The file holds:

```json
{
  "env":          "production",
  "has_drift":    true,
  "last_run":     "2026-05-21T14:00:00+00:00",
  "last_alerted": "2026-05-21T14:00:00+00:00",
  "summary":      { "creates": 0, "updates": 1, "deletes": 0, "unmanaged": 0 }
}
```

`last_alerted` is `null` when no `drift.detected` alert has been emitted
for the current drift incident (either because the last run was clean, or
because the state was created before Phase 10). It is reset to `null`
whenever `drift.cleared` fires so the next occurrence always pages.

Missing or malformed state files are treated as "no prior run" so a
corrupted file never blocks the monitor; the next save replaces it.

### Flags

| Flag                 | Purpose                                                                                                                                |
|----------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| `--state-file PATH`  | Override the per-env state-file path.                                                                                                  |
| `--no-state`         | Skip the read+write. `drift.cleared` will never fire; suitable for ad-hoc runs.                                                        |
| `--fail-on-drift`    | Exit `2` when drift was detected. Default exits `0` to keep cron quiet.                                                                |
| `--alert-window N`   | Suppress repeated `drift.detected` events while drift is ongoing, for N minutes after the last alert. Default `60`. `0` = always alert. |
| `--output PATH`      | Write the drift report (transition + change set) as JSON for dashboards or downstream tools.                                           |

### Exit codes

- `0` — drift-check ran to completion (no drift, or drift detected but
  `--fail-on-drift` not passed; also `0` when alert is suppressed by
  `--alert-window`).
- `1` — config repo failed to load, or the live-state fetch errored.
- `2` — drift was detected and `--fail-on-drift` was passed.

### Alert deduplication

By default, `drift.detected` fires once per drift incident and then is
suppressed for 60 minutes while the incident is ongoing. After the window
expires, the alert fires again to remind the operator. This keeps channels
quiet during remediation without dropping pages entirely.

To force an immediate re-alert (e.g., after a shift handoff), delete the
state file or set `--alert-window 0`.

### Notes

- The events follow the standard payload shape documented in
  `docs/notifications.md`. Routing patterns like `drift.*` match both
  `drift.detected` and `drift.cleared`.
- The state file is per-environment. Running `drift-check --env test`
  and `--env production` against the same repo keeps independent state.
- State files written by Phase 9 (no `last_alerted` key) deserialise
  correctly; `last_alerted` defaults to `null` so the first Phase 10 run
  will emit normally.

## `csfwctl apply`

**Implemented (Phase 5).** Converges one environment's live state to the
loaded YAML config. Every safety rail from CLAUDE.md fires before any
write.

```
csfwctl apply --env {test|pilot|production}
              [--dry-run] [--enforce] [--allow-delete]
              [--strict-groups] [--create-groups]
              [--initial-bootstrap]
              [--max-deletes N] [--max-changes N]
              [--repo PATH] [--output FILE]
```

### What it does

1. Loads and validates the config repo (same path as `validate`).
2. Pulls live tenant state.
3. Computes a diff for the named environment.
4. Runs the safety rails (`safety.check_*`) — refuses to proceed on any
   failure.
5. Applies the change set in fixed order:
   1. **Locations** (creates, then updates).
   2. **Rule groups** (creates, then updates). Override rule groups
      (`<policy-slug>-overrides-<env>`) materialise here so the policy
      payload can reference real IDs.
   3. **Policies** (creates, then updates) — host-group membership is
      written on the policy payload itself.
   4. **Host-group reassignments** appear as explicit report rows even
      though they ride on the policy update payload.
   5. **Precedence ordering** — Phase 6 stub.
   6. **Deletes** — policies, then rule groups, then locations.
6. Rewrites the metadata trailer on every touched object's description:
   `Managed by csfwctl | version: N | git_sha: X | applied: TS | env: E`.
   The previous version is read off the live record and incremented;
   pre-existing free-text in the description is preserved verbatim.

### Safety flags

| Flag                  | Purpose                                                                                                     |
|-----------------------|-------------------------------------------------------------------------------------------------------------|
| `--dry-run`           | Plan + safety checks; no API writes.                                                                        |
| `--enforce`           | Permit updates against managed-but-drifted live objects. Without it, drift aborts the apply.                |
| `--allow-delete`      | Required (in addition to a tombstone) to delete an object.                                                  |
| `--strict-groups`     | Fail if a policy references a host group that is absent in the tenant.                                      |
| `--create-groups`     | Create missing host groups as empty static groups before the policy write. Mutually exclusive with `--strict-groups`. |
| `--initial-bootstrap` | First-run mode. Refuses unless run against an unbootstrapped tenant; only rewrites metadata trailers.        |
| `--max-deletes N`     | Refuse to proceed if the plan has more than `N` deletes (default: from `csfwctl.toml`).                     |
| `--max-changes N`     | Refuse to proceed if creates + updates + deletes exceeds `N` (default: from `csfwctl.toml`). Bootstrap mode is exempt. |
| `--output PATH`       | Persist the diff + apply payload as JSON to `PATH`.                                                         |

### Per-action change detail

Every action recorded on the `ApplyReport` carries the diff that produced
it, so the operator-facing render, the structured log records, the
`apply.succeeded` notifier payload, and the `--output` JSON all surface
*what* changed — not just *which object* changed.

Three structured fields appear on each `AppliedAction`:

- `field_changes` — one entry per leaf-level difference (e.g. a
  rule-group's `status` flipped, a policy's `priority` changed). For
  list-typed leaves such as `rules`, the JSON payload carries the full
  before/after lists and the console renderer prints a compact
  `N added, M removed, K modified` summary with one nested line per
  added/removed/modified rule (modified rules list only the keys that
  differ — direction, IP range, protocol, etc.).
- `host_group_changes` — `(op, group_name, env)` triples on policy
  updates, mirroring the standalone `host-group` action rows.
- `managed_group_changes` — `(op, group_name, env, desired_fql,
  live_fql)` rows for csfwctl-managed dynamic host groups.

Each action is also emitted as one structured `INFO` log record on the
`csfwctl.applier` logger, so `--log-format json` produces one JSON line
per action carrying the same fields, correlated by the request ID.

Field values in the change detail are rendered **in full** — never
truncated. The change detail is an audit record, and a clipped executable
path or address list cannot be reconstructed after the fact. Strings are
shown via `repr` (quoted, with backslashes escaped) so an empty string is
visible and `None` is distinguishable from the literal `"None"`.

### Initial bootstrap

First-ever apply against a tenant uses `--initial-bootstrap`. In this
mode the applier writes only the `description` field on each live
object whose name matches a YAML file (after appending the env suffix);
rule content, status, and assignments are left alone. Live objects
without a YAML counterpart and YAML objects without a live counterpart
are reported as warnings. A subsequent normal apply will then converge
content the usual way. Normal apply refuses to run against an
unbootstrapped tenant (a tenant counts as bootstrapped once *any* live
object carries the `Managed by csfwctl` signature).

### Exit codes

- `0` — apply (or dry-run) completed.
- `1` — config repo failed to validate, the live-state fetch errored,
  a safety rail refused, an API call failed, or an apply-time invariant
  was violated. Errors are written to stderr.

## `csfwctl status`

**Implemented (Phase 6).** Reads every policy, rule group, and location
in the tenant, parses the `Managed by csfwctl` metadata trailer off
each description, and prints a per-`(kind, slug, env)` summary.
Read-only.

```
csfwctl status [--all-envs] [--format {table|json}]
```

### Output modes

- **Default (flat table)** — one row per `(kind, slug, env)` triple,
  with `Managed`, version, short `git_sha`, and `applied` timestamp
  columns. Easy to grep for "what's the version on the rule group
  named X in env Y?".
- **`--all-envs`** — pivots into one row per logical object with one
  column per env (`test` / `pilot` / `production`). Cell value is
  `vN@sha` for managed objects, `U` for present-but-unmanaged, blank
  when the env has no matching live record. Quick way to spot version
  drift across the three environments.
- **`--format json`** — emits the same data as a structured JSON
  document (suitable for dashboards, drift-check alerts, and the
  Phase 8 notifiers). Schema:

  ```json
  {
    "summary": {"total": 12, "managed": 9, "unmanaged": 3,
                "by_kind": {"policy": 4, "rule-group": 6, "location": 2}},
    "entries": [
      {
        "kind": "policy", "slug": "abc01-endpoints-windows",
        "display_name": "ABC01-Endpoints-Windows", "managed": true,
        "envs": {
          "test": {
            "env": "test", "object_id": "…uuid…",
            "display_name": "ABC01-Endpoints-Windows-Test",
            "managed": true,
            "signature": {"version": 7, "git_sha": "abc1234",
                          "applied": "2026-05-19T14:30:00Z", "env": "test"}
          }
        }
      }
    ]
  }
  ```

### Behaviour notes

- Env labels come from the live display-name suffix
  (`-Test` / `-Pilot` / `-Production`) for policies and rule groups.
  Locations are tenant-global; their env tag is whatever the
  signature most recently recorded (or the literal `any` when no
  signature is present).
- Hand-rolled console objects without an env suffix appear in the
  pseudo-env column `(no-env)` so they remain visible.
- A description carrying the `Managed by csfwctl` token but a
  malformed trailer counts as `managed=true` with `signature=null`;
  the pivot view shows that as `M (unparseable)`.

### Exit codes

- `0` — snapshot rendered.
- `1` — live-state fetch failed.

## `csfwctl precedence`

**Implemented (Phase 6).** Resolves bucket-based precedence to an
ordinal order using `precedence.yaml` overrides and prints the
result per platform. Optionally compares against the live tenant
order. Read-only.

```
csfwctl precedence [--repo PATH] [--env {test|pilot|production}] [--format {table|json}]
```

### What it does

1. Loads and validates the config repo.
2. For each platform (`windows`, `mac`), sorts policies by bucket
   (`emergency` → `high` → `medium` → `default` → `low`) and then
   alphabetically by display name.
3. Applies each `precedence.yaml` override in declaration order:
   `before: X, after: Y` raises `X` immediately ahead of `Y` if it
   isn't already. Cycles surface as `1`-exit with an error.
4. With `--env`, fetches the env-filtered live policy list (in current
   precedence order) and compares against the resolved order. The
   comparison strips env suffixes and skips live-only entries so the
   diff is apples-to-apples with what the applier will eventually
   push via `set_precedence`.

### Behaviour notes

- `status: deleted` policies are excluded — the resolver reflects what
  the applier would actually write.
- Overrides that reference slugs outside the current platform are
  silently ignored (an override `mac-policy → win-policy` is a no-op
  on both platforms).
- The applier's Phase 5 precedence hook will consume the same
  resolver output once it lands; this command exists so operators
  can preview what that step will do.

### Exit codes

- `0` — resolved order rendered.
- `1` — config repo failed to validate, override cycle detected, or
  live fetch errored when `--env` was used.

## `csfwctl import`

**Implemented (Phase 3).** Bootstraps round-trippable YAML from live
CrowdStrike objects. Read-only — never writes to CrowdStrike.

```
csfwctl import policy     <name-or-uuid> [--strip-env-suffix/--no-strip-env-suffix] [--output PATH]
csfwctl import rule-group <name-or-uuid> [--strip-env-suffix/--no-strip-env-suffix] [--output PATH]
csfwctl import location   <name-or-uuid>                                            [--output PATH]
csfwctl import all                                                                  [--output-dir PATH]
```

Lookup: ``<name-or-uuid>`` is treated as a UUID when it matches the
standard ``8-4-4-4-12`` hex form, otherwise as a CrowdStrike display
name. Name lookup tries the literal string first and then each of
``<name>-Test`` / ``<name>-Pilot`` / ``<name>-Production``; if multiple
env variants exist, the importer picks ``-Test`` so the YAML reflects
trunk state.

Env suffix stripping: ``--strip-env-suffix`` (default) drops the
``-Test`` / ``-Pilot`` / ``-Production`` suffix from the imported name
so the saved slug is environment-agnostic. The applier re-appends the
suffix at apply time.

Override-rule-group folding: when a policy references a rule group
named ``<policy-slug>-overrides-<env>``, the importer folds that
group's rules back into the policy YAML's ``rules:`` field instead of
writing the override group as a separate file. The applier
re-synthesises the override group at apply time.

``import all`` walks rule groups, locations, then policies (in that
order) and writes one YAML per logical object under ``<output-dir>/``.
Duplicate env variants reduce to a single shared YAML.

Exit codes: ``0`` on success, ``1`` on any lookup or translation error.

## `csfwctl record-fixtures`

**Implemented (Phase 3).** Captures sanitised API responses to disk for
the offline integration test suite.

```
csfwctl record-fixtures [--operations OPS] [--output PATH]
```

``--operations`` is a comma-separated list of operation filename stems
(``policies-list``, ``rule-groups-query``, ``locations-list``, etc.).
With the flag omitted, every read-only operation is recorded.

``--output`` defaults to ``./tests/fixtures/api_responses``. Each
operation writes one JSON file there.

Sanitisation is unconditional: UUIDs, IPv4/IPv6 addresses and CIDR
networks, hostnames, and email addresses are replaced with deterministic
fakes drawn from RFC 5737 / 3849 reserved ranges and the ``example.test``
domain. Mappings are stable within a single run, so cross-references
between fixture files remain consistent.

Exit codes: ``0`` if every operation succeeded; ``1`` if any operation
failed (other operations still write their output).

## `csfwctl promote` *(stub)*

```
csfwctl promote --from {test|pilot} --to {pilot|production}
```

Convenience wrapper around the GitLab CI promotion jobs.

## `csfwctl notify-test` *(stub)*

```
csfwctl notify-test [--channel CHANNEL]
```

Phase 8. Verifies notifier-channel configuration.
