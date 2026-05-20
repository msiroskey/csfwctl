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

## `csfwctl import` *(stub)*

```
csfwctl import policy <name-or-uuid>     [--strip-env-suffix] [--output PATH]
csfwctl import rule-group <name-or-uuid> [--strip-env-suffix] [--output PATH]
csfwctl import location <name-or-uuid>   [--output PATH]
csfwctl import all                       [--output-dir PATH]
```

Phase 3. Bootstraps YAML from live CrowdStrike objects.

## `csfwctl record-fixtures` *(stub)*

```
csfwctl record-fixtures [--operations OPS] [--output PATH]
```

Phase 3. Captures sanitized API responses for offline tests.

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
