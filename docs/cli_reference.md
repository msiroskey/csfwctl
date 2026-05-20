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
| `--log-format`    | `text` \| `json`        | `text`  | Output format for logs / machine output. |
| `--verbose`       | bool                    | off     |                                          |
| `--quiet`         | bool                    | off     |                                          |

## `csfwctl validate`

**Implemented (Phase 1).** Schema and semantic lint of a config repo.
No API calls.

```
csfwctl validate [--repo PATH]
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

Exit codes:

- `0` — repository is valid; a summary table is written to stdout.
- `1` — one or more validation errors; each is written to stderr.

## `csfwctl diff`

**Implemented (Phase 4).** Compares the loaded config repo against one
environment's live CrowdStrike state and prints a structured change set.
Read-only against the tenant.

```
csfwctl diff --env {test|pilot|production} [--repo PATH] [--output FILE]
```

What it produces:

- A summary table on stdout listing the counts of creates, updates,
  deletes, no-change objects, unmanaged live-only objects, and any
  warnings.
- Per-change detail blocks for each create / update / delete, with
  field-level diffs (`path: before -> after`) and host-group add/remove
  lines for policies.
- A "no changes" line when desired and live converge.
- The same change set as JSON written to ``--output PATH`` if given,
  ready for MR comments and (in Phase 5) the applier to consume.

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
fetch errors out.

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

## `csfwctl status` *(stub)*

```
csfwctl status [--all-envs] [--format {table|json}]
```

Phase 6. Reads metadata signatures from each tenant object.

## `csfwctl precedence` *(stub)*

```
csfwctl precedence [--env ENV]
```

Phase 6. Resolves bucket-based precedence to an ordinal order.

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
