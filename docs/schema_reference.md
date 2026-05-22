# Schema reference

YAML and TOML schemas accepted by csfwctl, kept in sync with the
Pydantic v2 models in `csfwctl/schema/`. If you change a model, update
this file and the example YAML under `tests/fixtures/config_repos/`.

## Naming conventions

- **Slugs** — filenames and cross-references. `lowercase-kebab-case`:
  must start with `[a-z]`, may contain `[a-z0-9-]`, no consecutive or
  trailing hyphens. All three kinds (`Policy`, `RuleGroup`, `Location`)
  use their slug as both the filename stem and the `name` field.
- **Display names** (`display_name`) — optional verbatim CrowdStrike
  object name. Use this when the CrowdStrike name does not conform to
  slug conventions (e.g. contains spaces, underscores, or mixed case).
  If set, takes precedence over `name` at apply time for the
  CrowdStrike-visible name (`-Test`/`-Pilot`/`-Production` is appended
  at apply time). The importer sets this field automatically when the
  imported name doesn't match its slug.

All three kinds enforce that the YAML `name` field matches the filename
stem (slug). Extra characters are rejected at load time.

## Policy (`policies/<slug>.yaml`)

| Field         | Type                          | Required | Notes                                     |
|---------------|-------------------------------|----------|-------------------------------------------|
| `name`        | `Slug`                        | yes      | `lowercase-kebab-case`. Must match filename stem. |
| `display_name`| string (1-200)                | no       | Verbatim CrowdStrike name. Overrides `name` at apply time. Set by importer when needed. |
| `platform`    | `windows` \| `mac`            | yes      | Linux deferred to a later sprint.         |
| `priority`    | precedence bucket             | no       | Default `default`.                        |
| `status`      | `enabled` \| `disabled` \| `deleted` | no | Default `enabled`.                        |
| `description` | string (≤ 2000)               | no       |                                           |
| `host_groups` | `{DisplayName: env}`          | no       | Each env (`test`/`pilot`/`production`) may appear at most once. |
| `rules`       | list of inline `Rule`         | no       | Becomes anonymous override group at apply. |
| `rule_groups` | list of slug references       | no       | Precedence order. No duplicates.          |

Precedence buckets: `emergency` `high` `medium` `default` `low`.

## RuleGroup (`rule_groups/<slug>.yaml`)

| Field         | Type                  | Required | Notes                                |
|---------------|-----------------------|----------|--------------------------------------|
| `name`        | `Slug`                | yes      | Must equal the filename stem.        |
| `display_name`| string (1-200)        | no       | Verbatim CrowdStrike name. Overrides `name` at apply time. Set by importer when needed. |
| `platform`    | `windows` \| `mac`    | yes      | Must match every referencing policy. |
| `status`      | status                | no       | Default `enabled`.                   |
| `description` | string                | no       |                                      |
| `rules`       | list of `Rule`        | no       | No duplicate rule names.             |

## Rule (inline in policies or inside a rule group)

| Field       | Type                              | Required | Notes                                              |
|-------------|-----------------------------------|----------|----------------------------------------------------|
| `name`      | string (1-120)                    | yes      | Free-form; shown in CrowdStrike.                   |
| `enabled`   | bool                              | no       | Default `true`.                                    |
| `action`    | `allow` \| `block` \| `monitor`   | yes      |                                                    |
| `direction` | `inbound` \| `outbound` \| `both` | yes      | `both` matches traffic in either direction.        |
| `protocol`  | `any` \| `tcp` \| `udp` \| `icmp` | yes      |                                                    |
| `state`     | `new` \| `established` \| `related` | no    | Only valid when `protocol` is `tcp` or `any`.       |
| `locations` | list of slugs (or `any`)          | no       | Default `[any]`. Must be non-empty.                |
| `local`     | `Endpoint`                        | no       |                                                    |
| `remote`    | `Endpoint`                        | no       |                                                    |

## Endpoint (sub-object of `Rule.local` / `Rule.remote`)

| Field                | Type                | Notes                                       |
|----------------------|---------------------|---------------------------------------------|
| `addresses`          | list of IP or CIDR  | IPv4 or IPv6 accepted.                      |
| `addresses_negated`  | bool                | Requires non-empty `addresses`.             |
| `ports`              | list of `int` or `"N-M"` | 1-65535. Range strings inclusive.       |
| `ports_negated`      | bool                | Requires non-empty `ports`.                 |

## Location (`locations/<slug>.yaml`)

| Field                    | Type     | Notes                          |
|--------------------------|----------|--------------------------------|
| `name`                   | `Slug`   | Must match filename stem.      |
| `display_name`           | string (1-200) | Verbatim CrowdStrike name. Overrides `name` at apply time. Set by importer when needed. |
| `status`                 | status   | Default `enabled`.             |
| `description`            | string   |                                |
| `addresses`              | list IP/CIDR |                            |
| `dns_servers`            | list IP  |                                |
| `dns_resolution_targets` | list str | DNS names; not IP-validated.   |
| `default_gateways`       | list IP  |                                |

The reserved location `any` is auto-managed by CrowdStrike and is not
represented as a YAML file.

## Tombstones (`tombstones.yaml`)

```yaml
policies: []
rule_groups:
  - name: legacy-rdp-allow
    deleted_in_sha: def5678
    reason: Folded into windows-remote-access.
locations: []
```

`deleted_in_sha` must be a 7-40 character hex SHA. Names must be unique
within each kind. A tombstone whose `name` still has a matching YAML
file is a validation error.

## Precedence overrides (`precedence.yaml`)

```yaml
overrides:
  - before: research-lab-7-windows
    after: abc01-endpoints-windows
```

Both fields must be slugs of existing policies. `before` and `after`
must differ. Duplicate `(before, after)` pairs are rejected.

## Tool configuration (`csfwctl.toml`)

```toml
[tool]
metadata_signature = "Managed by csfwctl"

[safety]
max_deletes = 1
max_changes = 10
require_bootstrap_for_unmanaged = true

[lint]
disabled = ["broad-allow"]              # list of rule ids to skip

[lint.options.broad-allow]
unconstrained = false                   # per-rule config; see CLI reference

[notifications.teams]
url_env = "TEAMS_WEBHOOK_URL"
events = ["apply.failed", "drift.detected"]
```

The `[lint]` section is optional. `disabled` lists `rule_id` strings
matched against `csfwctl.linter.LINT_REGISTRY`. `[lint.options.<rule>]`
sub-tables are passed verbatim to the matching rule's `check` method;
the rule itself defines the accepted keys.

Notifier sections under `[notifications.<channel>]` accept arbitrary
extra fields (channel-specific). The `events` list uses glob patterns
like `apply.*` or `drift.detected`.

## Cross-reference checks

`csfwctl validate` enforces, in addition to per-model validation:

1. Each `rule_groups` slug in a policy must reference an existing rule
   group whose `platform` matches the policy's platform.
2. Each non-`any` location slug referenced by an inline rule or a rule
   group's rules must reference an existing location.
3. Filename stem and the in-document `name` must agree for rule groups
   and locations.
4. Tombstone entries must not match a still-present object.
5. `precedence.yaml` overrides must reference known policy slugs.
