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

| Field                 | Type                                    | Required | Notes                                                                                      |
|-----------------------|-----------------------------------------|----------|--------------------------------------------------------------------------------------------|
| `name`                | `Slug`                                  | yes      | `lowercase-kebab-case`. Must match filename stem.                                          |
| `display_name`        | string (1-200)                          | no       | Verbatim CrowdStrike name. Overrides `name` at apply time. Set by importer when needed.   |
| `platform`            | `windows` \| `mac`                      | yes      | Linux deferred to a later sprint.                                                          |
| `priority`            | precedence bucket                       | no       | Default `default`.                                                                         |
| `status`              | `enabled` \| `disabled` \| `deleted`    | no       | Default `enabled`.                                                                         |
| `description`         | string (≤ 2000)                         | no       |                                                                                            |
| `host_groups`         | `{CrowdStrike name: env}`               | no       | Keys are verbatim CrowdStrike host-group names (may contain spaces/underscores). Each env (`test`/`pilot`/`production`) may appear at most once. |
| `managed_host_groups` | `{env: [hostname, …]}`                  | no       | Auto-creates a dynamic CrowdStrike host group per env. See [Managed host groups](#managed-host-groups-managed_host_groups). |
| `rules`               | list of inline `Rule`                   | no       | Becomes anonymous override group at apply.                                                 |
| `rule_groups`         | list of slug references                 | no       | Precedence order. No duplicates.                                                           |
| `settings`            | `PolicySettings`                        | no       | Enforcement mode and default traffic actions. See [Policy settings](#policy-settings-settings). |
| `inherits`            | slug of parent policy                   | no       | Inherit all unset fields from the named policy. Depth-1 only. See [Policy inheritance](#policy-inheritance). |
| `append_rule_groups`  | bool                                    | no       | Default `false`. When `true` and `inherits` is set, prepends parent `rule_groups` before child's. |
| `append_rules`        | bool                                    | no       | Default `false`. When `true` and `inherits` is set, prepends parent inline `rules` before child's. |
| `skip_unassigned_envs`     | bool | no | Default `false`. When `true`, the policy (and its synthesised `<slug>-overrides-<env>` rule group) is only created for envs that carry a host-group binding — an entry in `host_groups` or `managed_host_groups`. Intended for override-style policies scoped to a single environment. |
| `tombstone_unassigned_envs` | bool | no | Default `false`. When `true` (requires `skip_unassigned_envs: true`), a live *managed* object for this policy in an env that has since become unassigned is queued for deletion instead of being reported as drift. The `--allow-delete` gate on `apply` still applies. |

Precedence buckets: `emergency` `high` `medium` `default` `low`.

## PolicySettings (`settings` block inside a policy)

| Field              | Type                                      | Notes                                                                              |
|--------------------|-------------------------------------------|------------------------------------------------------------------------------------|
| `enforcement_mode` | `enforce` \| `monitor` \| `disabled`      | Maps to CrowdStrike's `enforce`/`test_mode` booleans. Default: API default.        |
| `local_logging`    | bool                                      | Independent of `enforcement_mode`. Default: API default.                           |
| `default_inbound`  | `allow` \| `deny`                         | Default action for inbound traffic not matched by any rule.                        |
| `default_outbound` | `allow` \| `deny`                         | Default action for outbound traffic not matched by any rule.                       |

All four fields are optional. If `settings` is omitted the policy inherits the
tenant's global defaults.

`enforcement_mode` values:

- `enforce` — policy is fully enforced; block rules block traffic.
  (`enforce: true, test_mode: false`)
- `monitor` — rules are evaluated but no traffic is dropped; block events are
  recorded as "would be blocked". The console requires enforcement to be
  enabled for monitor mode, so this maps to `enforce: true, test_mode: true`.
- `disabled` — the firewall policy does not enforce any rules.
  (`enforce: false`)

`local_logging` is **not** part of the enforcement mode. It toggles
CrowdStrike's `local_logging` boolean independently — local event logging can
be enabled even when `enforcement_mode` is `disabled`.

## Policy inheritance

A policy may declare `inherits: <parent-slug>` to use another policy as a
baseline. At materialise time (diff / apply) the resolver produces a flat
`Policy` with no `inherits` field:

- **Scalar fields** — the child's value wins for every field it explicitly
  sets; unset fields fall back to the parent's value.
- **`rule_groups`** — replaced by the child's list (default). Set
  `append_rule_groups: true` to prepend the parent's list before the child's.
- **`rules`** — replaced by the child's list (default). Set
  `append_rules: true` to prepend the parent's rules before the child's.
- **`host_groups` / `managed_host_groups`** — always replaced (no append).
  If the resolved policy would have both `host_groups` and `managed_host_groups`
  covering the same env, `managed_host_groups` wins and the inherited
  `host_groups` entry for that env is dropped.

Inheritance is **depth-1 only**: a parent policy must not itself have an
`inherits` field. The `inheritance-depth` lint rule enforces this statically.

## Managed host groups (`managed_host_groups`)

```yaml
managed_host_groups:
  test:
    - machine-a
    - machine-b
  production:
    - machine-c
```

Each entry creates or updates a **dynamic** CrowdStrike host group with an FQL
filter `hostname:'machine-a' or hostname:'machine-b'`. The group is
automatically named `{display_name or name.title()}-Managed-{Env}` (e.g.
`ABC01-Endpoints-Managed-Test`).

Restrictions:

- An env may not appear in both `host_groups` and `managed_host_groups` on the
  same policy (validated at load time).
- An empty hostname list is allowed in YAML but produces no host group and no
  assignment (equivalent to omitting the env key).

## Restricting a policy to assigned envs (`skip_unassigned_envs`)

Override-style policies often bind to a single environment. By default
csfwctl creates a per-env CrowdStrike policy object (and, if the policy
has inline `rules`, a synthesised `<slug>-overrides-<env>` rule group)
for **every** environment — Test, Pilot, and Production — regardless of
whether any hosts are assigned in that env.

Setting `skip_unassigned_envs: true` restricts the policy to the envs
that carry a host-group binding — an entry in either `host_groups` or
`managed_host_groups` for that env. In envs where the policy is
unassigned it is omitted from the desired state entirely and the applier
creates no per-env objects for it.

```yaml
name: abc01-adhoc-override
platform: windows
skip_unassigned_envs: true
host_groups:
  ABC01-AdHoc-Test: test
rules:
  - name: Allow local ssh
    action: allow
    direction: inbound
    protocol: tcp
    remote:
      ports: [22]
```

The example above produces objects only in the Test environment;
`csfwctl apply --env pilot` and `--env production` treat the policy as
non-existent for those envs.

### Auto-tombstoning stale envs (`tombstone_unassigned_envs`)

`skip_unassigned_envs` alone will not remove a policy object that was
already applied to an env before the flag was flipped or the binding was
moved. The lingering CrowdStrike object surfaces as **unmanaged** on the
next diff so an operator has to notice it and either add a tombstone
entry or restore the binding.

Setting `tombstone_unassigned_envs: true` (which requires
`skip_unassigned_envs: true`) lets the policy consent to its own
targeted deletion: a live *managed* object matching the policy in an
env where the policy is now unassigned is queued for delete instead of
being reported as drift. The `--allow-delete` gate on `apply` still
applies; no separate tombstone entry is needed.

Unmanaged live objects (records that predate csfwctl or that were
created outside it) are never auto-deleted even with the flag on.

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
| `description` | string (≤ 2000)                 | no       | Free-form rule description, round-tripped to/from the CrowdStrike rule `description` field. |
| `enabled`   | bool                              | no       | Default `true`.                                    |
| `action`    | `allow` \| `block` \| `monitor`   | yes      |                                                    |
| `direction` | `inbound` \| `outbound` \| `both` | yes      | `both` matches traffic in either direction.        |
| `protocol`  | named value or integer (0-255)    | yes      | Named: `any` `tcp` `udp` `icmp` `igmp` `ipip` `ipv6` `gre` `icmpv6`. Integer for unlisted protocols ("Advanced" mode). IPv6-family protocols (`ipv6`, `icmpv6`) emit `address_family: IP6` on apply regardless of whether explicit IPv6 addresses are configured (an ICMPv6 wildcard rule is valid and supported). |
| `state`     | `new` \| `established` \| `related` | no    | Only valid when `protocol` is `tcp` or `any`.       |
| `file_path` | string (glob, ≤999 chars)         | no       | Executable-filepath glob. Rule matches only traffic from a process whose image path matches (CrowdStrike's application-aware match). Platform-agnostic — use the native path format for the platform: Windows `C:\Program Files\app\*.exe` or macOS `/Applications/App.app/Contents/MacOS/*`. On the wire this is the `image_name` field in the rule's `fields` array, with a `type` of `windows_path` / `unix_path` derived from the rule group's platform. |
| `service_name` | string (≤256 chars)            | no       | **Windows-only.** Windows service-name qualifier (e.g. `Dhcp`). Rule matches only traffic from the named Windows service — typically paired with a `file_path` of `%SystemRoot%\System32\svchost.exe`. On the wire this is the `service_name` field in the rule's `fields` array with `type: string`. macOS has no equivalent; setting it on a macOS rule is a no-op on the wire. |
| `address_family` | `ip4` \| `ip6` \| `any`       | no       | Override for the top-level CrowdStrike `address_family` wire field (`ip4`→`IP4`, `ip6`→`IP6`, `any`→`NONE`). The `ipv4`/`ipv6` spellings are accepted as input aliases and normalized to `ip4`/`ip6`. **Omit to infer:** IPv6-family protocol or any IPv6 address → `ip6`; any IPv4 address → `ip4`; otherwise (e.g. an application-based rule matching no address) → `any`. An explicit `ip4` with an IPv6-family protocol (`ipv6`/`icmpv6`) is rejected. |
| `address_type` | string (≤256 chars)            | no       | Passed through verbatim to the top-level `address_type` wire field. Value domain is **not** validated locally (no test tenant); only emitted on the wire when set. |
| `watch_mode` | bool                             | no       | Default `false`. Toggles the top-level `watch_mode` wire flag — observe matching traffic in addition to the rule's allow/block action. Distinct from the `monitor` action. Only emitted on the wire when `true`. |
| `locations` | list of slugs (or `any`)          | no       | Default `[any]`. Must be non-empty.                |
| `local`     | `Endpoint`                        | no       |                                                    |
| `remote`    | `Endpoint`                        | no       |                                                    |

## Endpoint (sub-object of `Rule.local` / `Rule.remote`)

| Field                | Type                | Notes                                       |
|----------------------|---------------------|---------------------------------------------|
| `addresses`          | list of IP, CIDR, or range | IPv4 or IPv6. Range forms: `10.0.0.1-10.0.0.254` (full) or `10.0.0.1-254` (last-octet shorthand). |
| `addresses_negated`  | bool                | Requires non-empty `addresses`.             |
| `ports`              | list of `int` or `"N-M"` | 1-65535. Range strings inclusive. Only allowed when the rule's `protocol` is `tcp` or `udp` (CrowdStrike rejects ports on any other protocol, including `any`). |
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
