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

## `csfwctl diff` *(stub)*

```
csfwctl diff --env {test|pilot|production} [--repo PATH] [--output FILE]
```

Will compute YAML-vs-live diff for the named environment. Phase 4.

## `csfwctl apply` *(stub)*

```
csfwctl apply --env {test|pilot|production}
              [--dry-run] [--enforce] [--allow-delete]
              [--strict-groups] [--create-groups]
              [--initial-bootstrap]
              [--max-deletes N] [--max-changes N]
              [--repo PATH]
```

Phase 5. Safety rails (`--initial-bootstrap`, blast-radius limits,
tombstones+`--allow-delete` for deletions) are non-negotiable.

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
