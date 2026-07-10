# csfwctl — Build TODO

Cross-session handoff for Claude Code. Update as work progresses.
Project plan: ./csfwctl-project-plan.md

## Current phase

Sprint 12: Cross-env diff + richer MR comments — complete.
Sprint 11: Policy inheritance, policy settings, and managed host groups — complete.

### Policy env-restriction flags (post Sprint 12)

- [x] `Policy.skip_unassigned_envs` (bool, default `false`). Filters
      out the policy and its synthesised `<slug>-overrides-<env>` rule
      group in `build_desired_state` for envs where the policy has no
      entry in `host_groups` or `managed_host_groups`. Aimed at
      override-style policies scoped to a single environment.
- [x] `Policy.tombstone_unassigned_envs` (bool, default `false`;
      requires `skip_unassigned_envs`). When a live *managed* object
      exists in an env that skip has removed from the desired state,
      the differ emits a delete (reason
      `unassigned in env; tombstone_unassigned_envs=true`) instead of
      reporting it as unmanaged. Unmanaged live records are never
      auto-deleted. Still gated by `--allow-delete` on apply.
- [x] `docs/schema_reference.md` — new section
      "Restricting a policy to assigned envs" plus rows in the Policy
      field table.
- [x] Unit tests: schema validators, `build_desired_state` skip
      behaviour, `compute_diff` auto-tombstone (managed vs unmanaged),
      flag-off passthrough. `tests/unit/test_differ.py` +
      `tests/unit/test_schema_policy.py`.
- [x] **Inheritance leak fix for override policies.** Previously a
      child that set only ``managed_host_groups: {test: [...]}`` would
      silently inherit the parent's Pilot / Production ``host_groups``
      entries — the resolver only dropped inherited ``host_groups`` for
      envs the child's ``managed_host_groups`` explicitly covered. Now
      when the child sets *either* map, the parent's contribution to
      **both** maps is dropped before the child's declaration is applied,
      so the child's binding scope is authoritative. If the child sets
      neither, both are inherited from the parent unchanged. Behaviour
      change documented in `docs/schema_reference.md` §Policy
      inheritance; regression tests in `tests/unit/test_sprint11.py`
      cover the four combinations (child sets managed only, host_groups
      only, both, neither).

## Rule schema extension: address family / address type / watch mode (post Sprint 12)

- [x] **`Rule.address_family` (override, infer when omitted).** New optional
      `AddressFamily` enum (`ip4`/`ip6`/`any`). `exporter._resolve_address_family`
      honours an explicit value (`ip4`→`IP4`, `ip6`→`IP6`, `any`→`NONE`) and
      otherwise falls back to `_infer_address_family`. **Behaviour change:**
      address-less rules now infer `NONE` (was unconditional `IP4`). A
      `model_validator` rejects explicit `ip4` with an IPv6-family protocol.
      The importer pins it explicitly only when the wire value diverges from
      inference, so omitted families round-trip clean.
- [x] **`Rule.address_type` (top-level passthrough).** Optional string emitted
      as the top-level `address_type` wire field only when set; read back by
      `rule_from_api`. Value domain not validated locally (no test tenant) —
      structural check only, mirroring `file_path`/`service_name`.
- [x] **`Rule.watch_mode` (top-level flag).** Bool, default `false`; emitted as
      top-level `watch_mode` only when `true`. Distinct from the `monitor`
      action. Round-tripped by the importer.
- [x] Updated `docs/schema_reference.md`, `docs/architecture.md`, the realistic
      config-repo fixture (`windows-baseline.yaml`), and added unit tests in
      `test_schema_rule.py` / `test_exporter_translation.py`.
- [ ] **Wire-contract confirmation (deferred — needs tenant).** The exact
      `address_type` value domain and the `watch_mode` field name/semantics are
      modelled from intent, not confirmed against a tenant. Emit-when-set keeps
      the blast radius to rules that opt in. Confirm via the gated
      live-validation path before relying on them in production config.
- [x] **Diff false-positive `address_family: None -> 'ip4'/'ip6'/'any'` on
      every rule when the YAML pinned the family redundantly.** `rule_from_api`
      only pins `address_family` on the live side when the wire value diverges
      from inference, but the desired side kept whatever the YAML said. A YAML
      rule with `address_family: ip4` on an already-IPv4 rule (inference IP4)
      therefore produced a spurious `None -> 'ip4'` field change on every
      diff. Surfaced most visibly when a new inherited policy pulled the
      parent's redundantly-pinned rules into the child's synthesised override
      rule group — the noise multiplied across every affected policy. Fix:
      new `exporter.canonicalize_rule_address_family(rule)` mirrors the
      importer decision (drop the explicit override when it matches
      inference); `differ.build_desired_state` runs every rule (inline
      policy rules after inheritance resolution, base and override rule
      groups) through it so both sides carry symmetric shapes. Divergent
      overrides (e.g. `address_family: ip4` on an application-based rule
      with no addresses) are preserved. Regression tests in
      `test_differ.py`.

## Diff-format follow-up fixes (post Sprint 12)

Three bugs surfaced by the per-leaf diff output:

- [x] **Live policy settings polled as `None`.** Enforcement mode,
      local-logging, and default inbound/outbound live on the policy
      *container*, not the `get_policies` record.
      `exporter._enrich_policy_records_with_containers` now lifts them onto the
      record's `settings` (remapping `default_inbound`/`default_outbound` →
      `inbound`/`outbound`) so the differ/importer see live settings instead of
      a spurious `settings: None -> {...}` update every run.
- [x] **Rule reorder not applied.** `applier._rule_content_diff_ops` matched
      rules by name and only emitted add/remove/modify ops, leaving `rule_ids`
      in live order — a pure reorder changed nothing on the wire. `rule_ids` is
      now emitted in the *desired* order (the authoritative final ordering),
      so reorders (alone or combined with adds/removes) land.
- [x] **Rule had no `description` field.** Added `Rule.description`
      (round-tripped to/from the CrowdStrike rule `description`); wired through
      `rule_from_api`, `_rule_to_api_shape`, `_trim_rule`. Updated
      `docs/schema_reference.md`, `docs/architecture.md`, and the realistic
      config-repo fixture.
- [x] **Per-object env matrix in `diff` all-envs output.** Added a second
      table after the summary in `_render_multi_env_text` (columns
      Type / Name / Change on / Test / Pilot / Production). Updates emit one
      row per changed field path with `before -> after` in each env cell;
      creates and deletes emit a single `(new)` / `(deleted)` summary row.
      Cells for envs with no matching change render an em-dash. Only appears
      in all-envs mode; single-env output is unchanged. Tests in
      `tests/unit/test_diff_cmd.py`.
- [x] **Data-driven width for the env matrix.** `_optimal_matrix_width`
      walks header + body to find each column's longest visible line
      (stripping rich `[tag]` markup via `Text.from_markup`), sums with
      Rich's per-column overhead, and caps at `_MATRIX_MAX_WIDTH = 140`.
      Below the cap the table renders at its natural width — no forced
      wrapping; at the cap Rich shrinks the widest columns. Keeps narrow
      change sets compact and gives long `before -> after` cells enough
      room in typical PR reviews.
- [x] **One matrix table per object with shared column widths.** Dropped
      the Type / Name columns and moved those values into each table's
      title (`kind: display_name`). Every changed object now gets its
      own titled table with columns Change on / Test / Pilot / Production.
      `_shared_column_widths` computes per-column widths across every
      object's data once and applies them uniformly, so tables line up
      down the page. Over-budget totals shrink proportionally with a
      header-label floor, then the widest column absorbs any remaining
      overrun. Long cells wrap via `overflow="fold"`.

## Sprint 12 tasks

- [x] **All-envs `diff` mode.** `--env` is now optional on `csfwctl diff`;
      omitting it runs the diff against test/pilot/production from a single
      live fetch (the fetch is env-agnostic, so no extra API calls). New
      `differ.MultiEnvDiff` aggregate + `compute_all_envs_diff(repo, state)`
      hold the three `ChangeSet`s and derive the cross-env ripple warning.
- [x] **Cross-env ripple warning.** `ChangeSet.env_scoped_change_count`
      (locations excluded, since they are tenant-global and appear in every
      env) drives `MultiEnvDiff.env_drift_warnings`: a downstream env
      (pilot/production) with more pending changes than test means an
      un-promoted change would ride along on the next downstream apply.
      `--fail-on-env-drift` exits `2` when detected (warn + exit 0 by
      default). Exit code `2` parallels `drift-check --fail-on-drift`.
- [x] **Richer GitLab MR comment.** `diff.changes_detected` now carries the
      full change set(s) in `details` (single-env: `change_set`; all-envs:
      `change_sets` + `env_drift` / `env_drift_warnings`). The gitlab
      notifier's `_build_markdown` renders a per-env summary table at the
      top, a ripple callout, and a per-object detail log below — capped at
      `MAX_DETAIL_LINES` for GitLab's note size limit. Makes planned
      changes visible on the MR without opening the pipeline.
- [x] **Docs:** `docs/cli_reference.md` (diff modes, ripple section, exit
      codes, notifier payload), `docs/notifications.md` (enriched gitlab
      comment), `docs/config-repo-ci.md` (`diff-test` → `diff-all` job),
      `README.md` (all-envs example).
- [x] Unit tests: 579 passing total. New differ tests cover
      `compute_all_envs_diff` env ordering, no-drift-when-equal, downstream
      ripple detection, `env_scoped_change_count` location exclusion, and
      `MultiEnvDiff.to_json`. New diff_cmd tests cover all-envs render,
      multi-env JSON output, `--fail-on-env-drift` exit code, and single-env
      backward compatibility. New notifier tests cover single-env and
      multi-env markdown rendering, the ripple callout, and the non-diff
      event shape staying unchanged.

## Sprint 11 tasks

- [x] **`csfwctl/schema/policy_settings.py`** (new): `EnforcementMode`
      enum (`enforce`/`monitor`/`local_logging`), `DefaultTrafficAction`
      enum (`allow`/`deny`), `PolicySettings` Pydantic model with
      optional `enforcement_mode`, `default_inbound`, `default_outbound`.
- [x] **`csfwctl/schema/policy.py`**: added `inherits: Slug | None`,
      `append_rule_groups: bool`, `append_rules: bool`,
      `settings: PolicySettings | None`, `managed_host_groups:
      dict[HostGroupEnv, list[str]]`; validators for self-inheritance
      and managed/host_groups env overlap.
- [x] **`csfwctl/schema/__init__.py`**: exports for `DefaultTrafficAction`,
      `EnforcementMode`, `PolicySettings`.
- [x] **`csfwctl/resolver.py`** (new): `resolve_inheritance` (depth-1,
      scalar override + append flags + managed-env priority);
      `managed_host_group_cs_name`; `managed_host_group_fql`.
- [x] **`csfwctl/linter.py`**: three new lint rules — `orphan-inherits`
      (parent slug not found), `inheritance-depth` (parent also inherits),
      `cross-platform-inheritance` (platforms differ). Updated
      `policy-without-host-groups` to accept `managed_host_groups`.
- [x] **`csfwctl/exporter.py`**: `policy_from_api` reads `enforce`,
      `local_logging`, `inbound`, `outbound` into `PolicySettings`;
      `policy_to_api_shape` writes them back.
- [x] **`csfwctl/falcon/host_groups.py`**: `create_dynamic` and
      `update_fql` for dynamic host group lifecycle.
- [x] **`csfwctl/differ.py`**: `ManagedGroupChange` dataclass; inheritance
      resolution at `build_desired_state`; `_managed_group_changes` per
      policy; `managed_group_changes` on `ObjectChange`; `host_groups`
      added to `LiveState`.
- [x] **`csfwctl/applier.py`**: `_apply_managed_host_groups` handles
      create/update/no-change; `_build_policy_payload` injects settings
      fields.
- [x] **`docs/schema_reference.md`**: documents all new fields,
      `PolicySettings`, inheritance semantics, managed host groups.
- [x] Unit tests: 528 passing total (57 new in `test_sprint11.py`)
      covering `PolicySettings` validation, `Policy` new-field validation,
      resolver helpers + inheritance materialisation (scalar/append/managed-
      env priority), all three new lint rules + updated `policy-without-
      host-groups`, exporter settings round-trip, project_policy_for_env
      with managed groups, differ managed-group-change detection, applier
      create/update/dry-run for managed host groups, and
      build_desired_state inheritance materialisation.

## Enhancements

- [x] **Precedence-preview section in `csfwctl diff`.** All-envs diff
      now surfaces the per-platform `set_precedence` moves that an
      apply will push. `fetch_live_state` adds a `precedence.asc`
      `query_policies` per platform and threads the ids through the
      new `LiveState.precedence_ids_by_platform`; the differ's
      `compute_precedence_diff` maps those ids to family slugs (dedupe
      by first live appearance so env-clustered instances count once)
      and produces a `PrecedenceDelta` per platform.
      `MultiEnvDiff.precedence_deltas` / `precedence_warnings` carry
      the result; `diff_cmd._render_precedence_deltas` renders a per-
      platform table listing only the families whose ordinal moves
      (`Live #`, `New #`, and a signed `Δ`; families new to the tenant
      show `(new)` in the Live column). JSON output grows
      `precedence_deltas` / `precedence_warnings` alongside the
      existing `change_sets`. Single-env diff intentionally skips the
      section — precedence is cross-env by construction and would
      repeat across envs. Tests in
      `tests/unit/test_precedence_resolver.py` (delta computation,
      dedup, JSON) and `tests/unit/test_diff_cmd.py` (table render,
      new-family marker, warning surfacing).
- [x] **Gated live tenant validation.** A real test environment is now
      available for the wire-contract questions mocks can't answer (the
      diff-based `update_rule_group` payload; the `image_name` filepath
      shape). Added `tests/integration/test_live_rule_group.py` (marked
      `live`, skipped unless `CSFWCTL_LIVE_TEST=1` + creds): provisions a
      throwaway `csfwctl-live-*` rule group, drives create → update
      (add/modify/remove) → re-fetch → assert → delete (cleanup in
      `finally`). New `.github/workflows/live-validation.yml` runs it
      only on `workflow_dispatch` or a `live-validation` PR label, reading
      creds from a `test-tenant` GitHub environment; serialised via
      `concurrency`. Default CI stays hermetic. `live` marker registered in
      `pyproject.toml`. Docs: `docs/operations.md` § "Live tenant
      validation"; `CLAUDE.md` operating-constraint section updated to
      reflect the gated path (still: no live calls in the default suite).
      **Next:** run it against the tenant to confirm the `update_rule_group`
      add payload (`rule_ids` handling for new rules) — the one part still
      flagged unverified in `_build_rule_group_update_payload`.
- [x] **`file_path` rule field (executable-filepath glob match).** `Rule`
      gained an optional `file_path: str` (≤999 chars) carrying a CrowdStrike
      application-aware filepath glob; the rule then only matches traffic from a
      process whose image path matches. Platform-agnostic — use the native path
      format for the platform (Windows `C:\Program Files\app\*.exe` or macOS
      `/Applications/App.app/Contents/MacOS/*`).
      On the wire it rides in the rule's `fields` array under the **`image_name`**
      name (confirmed against a tenant export — NOT `file_path`), carrying a
      platform-derived `type` token: `_rule_to_api_shape` emits
      `{"name": "image_name", "value": <glob>, "type": "windows_path"|"unix_path"}`
      and `exporter._filepath_from_fields` reads `image_name` back (empty value
      → None; the sibling `network_location` field is ignored). Schema validator
      does a local-only sanity check (non-empty, no NUL). Updated
      `csfwctl/schema/rule.py`, `csfwctl/exporter.py`,
      `docs/schema_reference.md`, `docs/architecture.md`, the realistic
      `windows-baseline` + `mac-baseline` fixtures, and tests
      (`test_schema_rule.py`, `test_exporter_translation.py`).
      **First cut shipped the wrong field name** (`file_path` instead of
      `image_name`, no `type`); CrowdStrike silently ignored it, so an applied
      filepath never took effect. Fixed once a tenant export confirmed the
      shape.
- [x] **`service_name` rule field (Windows service qualifier).** `Rule`
      gained an optional `service_name: str` (≤256 chars) carrying the
      CrowdStrike Windows service-name match (e.g. `Dhcp`), typically paired
      with a `file_path` of `%SystemRoot%\System32\svchost.exe`. Windows-only
      on the wire; the rule is platform-agnostic so platform appropriateness is
      left to the containing rule group / policy (mirrors `file_path`). It rides
      in the rule's `fields` array as
      `{"name": "service_name", "value": <name>, "type": "string"}` (confirmed
      against a tenant export). `exporter._rule_to_api_shape` emits it,
      `exporter._service_name_from_fields` reads it back (empty value → None),
      and the schema validator does a local-only check (non-empty, no NUL).
      Updated `csfwctl/schema/rule.py`, `csfwctl/exporter.py`,
      `docs/schema_reference.md`, `docs/architecture.md`, the realistic
      `windows-baseline` fixture, and tests (`test_schema_rule.py`,
      `test_exporter_translation.py`, `test_exporter.py`).
      **Also fixed a latent bug:** `exporter._trim_rule` (the importer's YAML
      writer) silently dropped both `file_path` and `service_name`, so
      `import` lost the application-aware match and the Bug-fixes-section advice
      to "re-import to backfill `file_path`" could not actually work. `_trim_rule`
      now emits both. Confirmed `type: windows_path` is already set for Windows
      `image_name` rules (it was — no change needed there).
- [x] **Per-action change detail in apply logs.** `AppliedAction` now
      carries the `field_changes` / `host_group_changes` /
      `managed_group_changes` tuples threaded off the originating
      `ObjectChange`, so the operator-facing render, the
      `apply.succeeded` notifier payload, the `--output` JSON, and the
      structured `csfwctl.applier` log records all surface *what*
      changed (rule edits, host-group adds/removes, FQL updates), not
      just *which object* changed. Rule-list edits show a per-rule
      add/remove/modify summary with key-level deltas on modified rules.
      See `docs/cli_reference.md` § "Per-action change detail".
- [x] **Readable `diff` output for list-valued fields.** The `diff`
      renderer printed a rule-group `rules` change as the entire
      before/after list on one line (`rules: [..] -> [..]`), so an
      operator could not see *what* changed. The structured `ChangeSet`
      must keep the whole list intact (the applier consumes it to build
      the JSON-Patch payload — the live-tested `update_rule_group`
      contract), so the fix is display-only: new
      `differ.expand_field_change` projects an opaque list change into
      per-element / per-leaf entries at render time. Lists of dicts are
      matched by `name` (rules' stable identity), so a changed field
      shows as `rules[<name>].<field>: before -> after`, an added/removed
      rule as one `rules[<name>]` entry, and a pure reorder as one
      compact `rules (order)` line; scalar lists fall back to positional
      `[i]` paths. `_diff_dicts` gained a `recurse_lists` flag (default
      `False` preserves the structured/JSON/applier contract; the display
      path passes `True`). Wired into `diff_cmd._render_change`. Updated
      `docs/cli_reference.md`; tests in `test_differ.py`
      (`test_expand_field_change_*`).

## Bug fixes

- [x] **Phantom `rule_groups[i]` slug diff on a policy that hadn't
      changed.** Follow-on to the "Rule-group create rejected with
      `Duplicate rule group name`" fix. `_diff_rule_groups` already
      reconciles a lossy `to_slug` on the live side by falling back to
      display-name matching, but `_diff_policies` still diffed the
      policy's `rule_groups` list as opaque slugs — so a YAML slug
      `asc-mac-endpoints` paired with display name `ASC-MacEndpoints`
      produced a spurious `rule_groups[0]: 'asc-macendpoints' ->
      'asc-mac-endpoints'` field change on every diff for the policy
      referencing it. Fix: new `differ._rule_group_slug_aliases`
      builds a `live_slug -> desired_slug` map from the same
      display-name reconciliation, and `_apply_rg_slug_aliases`
      remaps the live policy's `rule_groups` list through it before
      `_compare_models` runs. Overrides (already same on both sides)
      and matching slugs are no-ops. The applier already resolved the
      slug → id lookup via display-name fallback, so this is a
      display-only cleanup. Regression test:
      `tests/unit/test_differ.py::test_compute_diff_does_not_report_phantom_rule_groups_slug_change`.
- [x] **Phantom `priority: 'default' -> '<bucket>'` field change on a
      policy whose YAML sets a non-default `PrecedenceBucket`.** The
      CrowdStrike firewall-policy API record has no priority field —
      per-platform precedence is converged separately via
      `set_precedence`. `policy_from_api` hardcodes
      `priority=PrecedenceBucket.default` on every imported live record
      and `policy_to_api_shape` never sends the field, so comparing
      `priority` in the policy body diff always fired a spurious
      `priority: 'default' -> 'high'` (etc.) on policies like
      `Exception-Mac: Monitor Only`. Fix: `priority` added to
      `differ._POLICY_DIFF_EXCLUDE` so `_model_dump` drops it before
      `_compare_models` runs; precedence changes still surface via the
      dedicated `csfwctl precedence` output. Regression test:
      `tests/unit/test_differ.py::test_compute_diff_does_not_report_phantom_priority_change`.
- [x] **`enforcement_mode` conflated local logging with enforcement and
      lacked a `disabled` mode.** The enum was `enforce | monitor |
      local_logging`, with `monitor` wrongly mapped to `enforce: false`.
      In the console, `monitor` requires enforcement *enabled* and local
      logging is an independent toggle. Fix: enum is now `enforce |
      monitor | disabled`; `monitor` maps to `enforce: true, test_mode:
      true`, `disabled` to `enforce: false`. Added an independent
      `local_logging: bool` field on `PolicySettings` (maps straight to
      the container `local_logging` boolean, can be set even when
      enforcement is disabled). Updated applier, exporter importer +
      `policy_to_api_shape`, `docs/schema_reference.md`, README, and
      tests.
- [x] **Bootstrap rule-group update rejected with HTTP 400.** The
      `firewall_rule_groups.update` endpoint is diff-based: it has no
      top-level `description` field and requires `diff_type`
      (`application/json-patch+json`), `tracking`, and `rule_ids`.
      Bootstrap was sending `{id, description}`, which the API rejected.
      Fix: `applier._rule_group_metadata_payload` now builds a
      `replace /description` JSON Patch, copying `rule_ids`/`tracking`
      from the live record so rule content is preserved. Documented in
      `docs/architecture.md`.
      - [x] **Follow-up done:** the *normal* (non-bootstrap) rule-group
        update path silently dropped all rule add/remove/modify changes —
        it sent only a `replace /description` patch and copied `rule_ids`
        verbatim, so an applied rule change returned HTTP 200 while
        persisting nothing (confirmed against a real tenant: a new rule
        showed as "1 added" in the apply summary but never appeared in the
        export). Fix: `_build_rule_group_update_payload` now builds real
        JSON-Patch `diff_operations` on `/rules` from the change's
        before/after rule lists — `remove /rules/<i>` (descending index,
        dropped from `rule_ids`) and `add /rules/-` (new rule, id assigned
        server-side). `_rule_content_diff_ops` raises `SafetyError` if the
        live rule count and `rule_ids` length disagree (ambiguous mapping).
        Tests: `test_apply_update_rule_group_{adds_new_rule,removes_rule,
        modified_rule_becomes_remove_add}`.
        **Also:** pure rule *reorders* (same names + content) emit no
        ops and are not yet applied — documented limitation.
      - [x] **Follow-up confirmed against tenant (2026-06-22):** a content
        change to an existing rule was emitted as `replace /rules/<i>`,
        which the API rejects with HTTP 400 `"error updating rule group:
        unhandled replace operation in payload"` — only the scalar
        `replace /description` is a handled `replace`. Fix: a modified rule
        is now a **remove + add** pair (rules are matched by name, so the
        re-added rule taking a fresh server id is harmless), leaving only
        `add`/`remove` on `/rules`. `_rule_content_diff_ops` rewritten;
        ops ordered removes(desc) → adds. `docs/architecture.md` updated
        with the confirmed contract.
      - [x] **Second tenant follow-up (2026-06-22):** with the remove+add
        fix the `add` op then failed with HTTP 400 `"Rule 'temp_id' cannot
        be empty."`. An added rule must carry a non-empty client-supplied
        `temp_id`, and the same token must appear in `rule_ids` at the
        rule's final position; the server maps each `temp_id` to the real id
        it assigns. Fix: `_rule_content_diff_ops` sets `temp_id` (`temp_1`,
        `temp_2`, …) on each added rule and appends it to `rule_ids`. This
        also resolves the previously-unverified `rule_ids` placeholder
        question — it carries the temp_id, not an omission.
      - [x] **Third tenant follow-up (2026-06-22):** with the rule create
        path working, the apply then failed with HTTP 400 `"Ports not
        allowed without a specific Protocol"` — a config rule carried ports
        with `protocol: any` (CrowdStrike only allows ports on tcp/udp).
        This is a config-validity issue, not a wire-shape one. Fix: new
        `Rule._ports_require_tcp_or_udp` model validator rejects ports
        unless the protocol is tcp or udp (raw-int "Advanced" protocols
        left to the user, matching `_state_only_for_tcp`), so `validate`
        and the apply load step fail with an actionable message before
        reaching the tenant. `docs/schema_reference.md` updated.
- [x] **Apply change detail truncated field values (broke auditability).**
      The operator-facing per-action render clipped every before/after
      value to 60 chars with an ellipsis (`_short`), so a long executable
      path showed as `'C:\Program Files (x86)\…' -> None` and could not be
      reconstructed from the log. Fix: `_render_value` renders values in
      full (no cap); the structured-log / `--output` JSON path was already
      full-fidelity via `FieldChange.to_json`. Strings still use `repr`
      (quoted, backslashes escaped) so `None` ≠ `"None"` and empties are
      visible. `docs/cli_reference.md` notes the no-truncation guarantee.
      Tests assert a long path renders in full with no `…`.
- [x] **Not a bug: created/edited rules "missing" `file_path`.** Operator
      saw a re-apply diff show `file_path: '<live path>' -> None` and rules
      created without the executable-path match. Root cause: the config YAML
      was imported by a csfwctl predating the `file_path` feature, so it
      never captured the live `image_name` field — the YAML has no
      `file_path`, and apply correctly treats that as "remove it". The
      *current* importer does capture it (`_rule_from_api` →
      `_filepath_from_fields`, exporter.py), so the fix is to **re-import the
      affected rule groups to backfill `file_path` into the YAML** before the
      next apply.
      **⚠ Footgun:** until the YAML is backfilled, applying the stale config
      will strip the live `file_path` from every rule that has one (the apply
      summary shows them as modified `… -> None`). Re-import (or hand-add the
      paths) first. Consider an operations.md note + possibly a lint/diff
      warning when an apply would clear a live `file_path` — surfaced for a
      future session, not done here.
- [x] **Import dropped host groups without an env suffix.**
      `policy_from_api` inferred a host group's env solely from its name
      suffix and silently skipped any group lacking one, so bootstrapping
      a tenant whose host groups predate csfwctl's naming convention
      produced policies that looked like they had no host groups (false
      `policy-without-host-groups` warning on `validate`). Two fixes:
      (1) suffix-less groups now fall back to the policy's own env, then
      to `production`; (2) `Policy.host_groups` keys are now
      `CrowdStrikeName` (was `DisplayName`) so verbatim CrowdStrike names
      containing underscores/spaces are representable. Tests in
      `test_exporter_translation.py`; `docs/schema_reference.md` updated.
- [x] **Rule create rejected with `Address family IPv4 is not allowed with
      protocol ICMPv6`.** `_infer_address_family` derived the address
      family only from configured endpoint addresses, so an ICMPv6
      wildcard rule (no explicit IPv6 address) fell back to `IP4` and the
      CrowdStrike rule-create endpoint rejected the payload. Surfaced
      during a Test → Pilot promotion when the pilot rule group was
      being created for the first time. Fix: when the protocol is
      `Protocol.ipv6` or `Protocol.icmpv6`, `_infer_address_family`
      returns `"IP6"` unconditionally; address-based inference still
      applies for protocol-agnostic cases (TCP/UDP/etc.) and the
      raw-integer "Advanced" path is unchanged. Regression test in
      `tests/unit/test_exporter_translation.py`
      (`test_rule_group_to_api_shape_icmpv6_forces_ip6_without_addresses`);
      `docs/schema_reference.md` updated.
- [x] **Rule-group create rejected with `Duplicate rule group name`.**
      The differ and applier both keyed live rule groups by
      `to_slug(strip_env_suffix(live_name))`. `to_slug` normalises
      whitespace and underscores but does **not** insert hyphens at
      camel-case boundaries, so a live record named
      `ASC-MacEndpoints-Pilot` collapsed to slug `asc-macendpoints`
      while the YAML carried `asc-mac-endpoints`. The slug-only lookup
      missed the live record, the applier issued a create, and
      CrowdStrike rejected the payload. Three coordinated fixes:
      (1) `differ._diff_rule_groups` now falls back to matching by the
      full env-suffixed display name when the slug lookup misses;
      matched live slugs are excluded from the orphan loop so they are
      not also flagged as unmanaged. (2) `applier._build_live_index`
      additionally indexes rule groups by their raw env-suffixed
      display name, and the new `_rule_group_live_lookup` helper drives
      the update path through either key. (3) `_apply_policies` seeds
      `rule_group_ids` with desired-slug → live-id entries via the same
      display-name fallback so `_build_policy_payload` can resolve the
      RG id regardless of slug canonicalisation. Also dropped `name` /
      `display_name` from `_model_dump` because they are identity, not
      state, and inflated the diff with phantom field changes whenever
      slug canonicalisation was lossy. Regression tests:
      `tests/unit/test_differ.py::test_compute_diff_matches_rule_group_by_display_name_when_slug_collapses`
      and `tests/unit/test_applier.py::test_apply_updates_rule_group_with_camelcase_display_name`.
- [x] **Policy create rejected with `Duplicate policy name ... for <Platform> platform`.**
      Two compounding causes:
      (1) `policy_from_api` raised `ImporterError` when the live
      policy's `rule_group_ids` referenced an id that was not in the
      env-filtered fetched map (e.g. a suffixless or cross-env rule
      group). `differ._translate_live_state` then silently swallowed
      the exception, dropping the entire live policy from view. The
      diff therefore emitted a create, which CrowdStrike rejected as a
      duplicate. (2) Even after the policy was visible, the same
      slug-vs-display-name mismatch fixed for rule groups in the
      previous PR also applied to policies (e.g. YAML slug
      `asc-mac-endpoints` paired with display `ASC-MacEndpoints`
      produced live name `ASC-MacEndpoints-Pilot`, whose re-slug
      `asc-macendpoints` did not match).
      Fix: added a `tolerant_rule_group_refs` parameter to
      `policy_from_api` that logs and skips unresolved RG references
      instead of raising; the differ now passes it `True` and also
      records translation exceptions as `ChangeSet.warnings` so a
      dropped record is no longer invisible. Mirrored the rule-group
      display-name fallback in `_diff_policies`, and added
      `policies_by_display_name` plus `_policy_live_lookup` in the
      applier so the update path resolves the live id by display name
      when slug normalisation is lossy. Regression tests:
      `tests/unit/test_differ.py::test_compute_diff_does_not_drop_live_policy_with_unresolved_rule_group_ref`,
      `tests/unit/test_differ.py::test_compute_diff_matches_policy_by_display_name_when_slug_collapses`,
      and `tests/unit/test_applier.py::test_apply_updates_policy_with_camelcase_display_name`.
- [x] **Host-group `create` rejected with `409 Duplicate group name`.**
      With `--create-groups` enabled in CI, the applier called
      `host_groups.find_by_name` (which uses the FQL filter
      `name:'X'`); when that came back empty it issued
      `host_groups.create`, which CrowdStrike then rejected because
      the group did, in fact, exist. The `name:` filter is not
      uniformly reliable across tenants — some return an empty
      resource list for an exact-match name — and the unfiltered
      `query_host_groups` default page size silently truncated the
      list. Two fixes in `csfwctl/falcon/host_groups.py`:
      (1) `query` now defaults `limit=5000` (matches the rule-groups
      sub-client) so the unfiltered list cannot be silently
      truncated; `find_by_name` falls back to enumerating every host
      group and matching by exact name client-side when the FQL
      filter returns empty. (2) `create` (and `create_dynamic`) now
      catch a `409 Duplicate group name` `FalconAPIError`,
      re-resolve the group via `find_by_name`, and return the
      existing record — making both creates idempotent so a
      misfiring lookup no longer aborts the apply. Regression tests:
      `tests/unit/test_falcon_subclients.py::test_host_groups_find_by_name_falls_back_to_list_all`
      and `tests/unit/test_falcon_subclients.py::test_host_groups_create_returns_existing_on_duplicate_409`.
- [x] **`host_groups.query` rejected with `400 5000 is an invalid page
      size, must be between 1 and 500`.** The previous fix set the
      default `limit` on the unfiltered host-group query to `5000` to
      match the rule-groups sub-client, but the host-groups endpoint
      caps a single page at `500`. Apply now failed at the live-state
      fetch stage. Two changes in `csfwctl/falcon/host_groups.py`:
      (1) Added `_MAX_PAGE_SIZE = 500` constant. (2) `query()` now
      paginates by offset when no explicit `limit` is supplied: each
      page is `limit=500`, and the loop terminates on an empty page,
      when `meta.pagination.total` is reached, or when the page is
      shorter than the requested limit (so missing-`total` responses
      still terminate). Explicit `limit` from a caller still fetches
      a single page (the caller is responsible for keeping it in
      `1..500`). Regression tests:
      `tests/unit/test_falcon_subclients.py::test_host_groups_query_sends_limit_500_by_default`
      and
      `tests/unit/test_falcon_subclients.py::test_host_groups_query_paginates_to_collect_all_ids`.
- [x] **Apply reported success but rule groups, host groups, and
      enabled state were silently dropped.** ``apply`` logged
      ``update policy ... rule_groups: list changed (0 -> 3 items),
      status: 'disabled' -> 'enabled'`` yet the live policy stayed
      empty and disabled. ``firewall_policies.update`` (PATCH) only
      honours ``id``/``name``/``description``; ``firewall_policies.create``
      (POST) only honours ``name``/``description``/``platform_name``.
      Rule-group assignments live on the **policy container**
      (``PUT /fwmgr/entities/policies/v1`` →
      ``update_policy_container``), host-group membership goes through
      ``perform_action add-host-group`` /
      ``remove-host-group``, and the enabled flag toggles via
      ``perform_action enable`` / ``disable``.
      Fix:
      (1) ``csfwctl/falcon/policies.py`` gained ``update_policy_container``,
      and convenience ``enable``/``disable``/``add_host_group``/
      ``remove_host_group`` wrappers around ``perform_action``;
      ``perform_action`` signature now takes an
      ``action_parameters: list[dict[str, str]] | None`` instead of a
      single ``value: str`` that hard-coded ``name="filter"``.
      (2) ``csfwctl/applier.py`` introduces ``_apply_policy_relations``
      which is called after every policy create and update: it sets
      ``rule_group_ids`` and the default-traffic / enforcement /
      local-logging settings via ``update_policy_container``;
      attaches the desired host groups (for creates) or applies each
      ``HostGroupChange`` (for updates); and toggles the enabled
      flag when the ``status`` field changed (updates) or the new
      policy should be enabled (creates).
      Regression tests in ``tests/unit/test_applier.py``:
      ``test_apply_policy_update_routes_rule_groups_to_container_endpoint``,
      ``test_apply_policy_update_toggles_enabled_state_via_perform_action``,
      ``test_apply_policy_update_routes_host_group_changes_to_perform_action``,
      ``test_apply_policy_create_applies_container_and_host_groups``.
- [x] **`update_policy_container` rejected with `"... attribute cannot
      be empty"` for `default_inbound`/`default_outbound`/`enforce`/
      `test_mode`.** The previous fix omitted those fields whenever
      the YAML's `settings` block did not specify them — but the API
      treats omission as "empty" and returns HTTP 400. Fix: the
      applier now fetches the existing container via
      `get_policy_containers` and uses **PUT semantics**: every required
      field is sent on every update, with the value resolved
      desired → existing → safe default (`ALLOW` / `False`). The
      live container's `tracking` token, when present, is threaded
      through for optimistic concurrency. Two small helpers
      (`_resolve_container_str`, `_resolve_container_bool`) make the
      overlay explicit. Regression tests:
      `tests/unit/test_applier.py::test_apply_policy_container_always_sends_required_fields`
      (asserts existing live values flow through when the YAML has no
      `settings`) and
      `tests/unit/test_applier.py::test_apply_policy_container_uses_defaults_when_no_live_container`
      (asserts safe defaults are emitted for a fresh create with no
      container yet).
- [x] **Cross-env host-group drift on a policy was silently retained.**
      A live ``-Test`` policy with a stray ``-Pilot`` host group
      attached produced a ``host_groups.<group>: 'pilot' -> None``
      field-level diff entry in the change log but no
      ``HostGroupChange(remove)``. The applier acts only on the
      ``HostGroupChange`` tuple, so ``perform_action remove-host-group``
      never fired and the stray group stayed on every apply. Root
      cause in ``csfwctl/differ.py::_host_group_changes``: both sides
      were filtered by the current env, hiding cross-env strays on
      the live record. Fix:
      (1) ``_host_group_changes`` now compares the full host-group
      set on both sides (no env filter on live). ``desired`` is
      already projected by ``project_policy_for_env`` so its keys are
      the only groups that should remain attached; everything else on
      live is drift and gets a remove. The remove record preserves
      the live env when known.
      (2) ``csfwctl/applier.py`` gained ``_lookup_host_group_ids``,
      a find-by-name-only resolver used for the remove side of the
      churn so ``--create-groups`` does not accidentally create the
      very group we are about to detach. Regression tests:
      ``tests/unit/test_differ.py::test_compute_diff_emits_remove_for_cross_env_host_group_drift``,
      ``tests/unit/test_applier.py::test_apply_policy_update_removes_cross_env_host_group_drift``,
      ``tests/unit/test_applier.py::test_apply_policy_update_remove_lookup_does_not_create_target``.

## Phase 10 tasks

- [x] Alert deduplication for `drift.detected`: `last_alerted: str | None`
      added to `DriftState`; `_should_alert(prior, alert_window_minutes)`
      helper; `--alert-window N` CLI flag (default 60, 0 = always alert).
      `drift.cleared` resets `last_alerted` to `None`. Phase 9 state files
      deserialise without error (`last_alerted` defaults to `None`).
- [x] `docs/operations.md`: full runbook covering onboarding, writing and
      promoting a policy change, rollback (`git revert` + re-apply,
      fast-path Production-only revert), drift response (investigate,
      re-apply with `--enforce`, import console change as authoritative),
      initial bootstrap, credential rotation, and troubleshooting.
- [x] `docs/cli_reference.md`: updated drift-check section documents
      `--alert-window`, updated state-file JSON shape with `last_alerted`,
      updated exit-code note (alert suppression exits 0), new "Alert
      deduplication" subsection.
- [x] `docs/architecture.md`: Phase 9 transition-model paragraph updated
      to reference Phase 10 windowing; new "Alert deduplication (Phase 10)"
      section explains design, state-file compat, test pattern.
- [x] Unit tests: 412 passing total (13 new in `test_drift_cmd.py`)
      covering `last_alerted=None` JSON round-trip, `null` round-trip,
      Phase 9 compat (missing key → None), save/load with None,
      ongoing drift within window suppresses alert, outside window
      re-emits, `alert_window=0` always emits, state saves `last_alerted`
      on emit, state carries `last_alerted` forward when suppressed,
      cleared resets `last_alerted` to None, constant value assertion.

## Phase 9 tasks

- [x] `drift_cmd.py`: `DriftState` dataclass (env, has_drift, last_run,
      summary) with JSON round-trip helpers; `load_drift_state` /
      `save_drift_state` (atomic .tmp+rename, malformed → None);
      `default_state_path` under `<repo>/.csfwctl/drift-state-<env>.json`;
      `change_set_summary` / `has_drift` summary helpers; `run_drift_check`
      mirrors `run_diff` but adds the prior-state read, the four-way
      transition model (`stable` / `detected` / `ongoing` / `cleared`),
      and the post-run state write.
- [x] Notifier events: `drift.detected` (severity `warn`) on every
      drifted run; `drift.cleared` (severity `info`) only on the
      drift→clean transition. `drift.detected` carries the full
      `ChangeSet.to_json()` under `details.change_set`; `drift.cleared`
      carries `previous_summary` + `previous_run`. No emit on a stable
      run (no prior drift, no current drift) — healthy monitor stays
      quiet.
- [x] CLI: `csfwctl drift-check --env` wired through `cli.py` with
      `--state-file`, `--no-state`, `--fail-on-drift`, `--output`,
      `--repo` options. `--fail-on-drift` exits `2` to distinguish from
      `1` (infra failure).
- [x] `--output`: writes a JSON report with the transition label, the
      summary counts, and the full change set — same shape downstream
      MR comments and dashboards already consume.
- [x] Docs: `docs/cli_reference.md` documents the command, state-file
      shape, and exit codes; `docs/architecture.md` carries the Phase 9
      design notes (state file, transition model, payload shape, test
      pattern); `docs/notifications.md` now lists drift events as
      implemented and documents the `details` shape.
- [x] Unit tests: 399 passing total (22 new in `test_drift_cmd.py`)
      covering DriftState JSON round-trip, save/load round-trip,
      missing/malformed/wrong-shape state-file handling, default state
      path, summary + has_drift on empty / realistic repos, all four
      transitions (first run clean → no emit, first run drifted →
      `detected`, drift→clear → `cleared`, stable → no emit, repeated
      drift → `detected` again), `--no-state` skips persistence,
      `--fail-on-drift` exits 2 on drift / 0 when clean, `--output`
      JSON report shape, config-repo and live-fetch error surfacing,
      and end-to-end Typer dispatch in both drift and no-drift modes.

## Phase 8 tasks

- [x] `csfwctl/notifiers/__init__.py`: `Event` dataclass, `make_event`,
      `Notifier` protocol (runtime-checkable), `NOTIFIER_REGISTRY` dict,
      `register_notifier`, `setup_notifiers`, `emit`, `event_matches`.
      Built-in channel registration deferred inside `_register_builtins()`
      to break the circular import.
- [x] Five channels: `log` (JSONL append), `console` (Rich stderr,
      suppressed in CI), `teams` (MessageCard webhook), `gitlab` (MR
      comments via GitLab API), `syslog` (RFC 5424 UDP).
- [x] `notify_test_cmd.py`: `run_notify_test` — sends `notify.test`
      event directly (bypassing event routing) to one or all channels.
- [x] `cli.py`: `notify-test` stub replaced with working implementation
      wired to `run_notify_test`; added `--repo` local option.
- [x] `validate_cmd.py`: emits `validate.failed` on fatal lint findings.
- [x] `apply_cmd.py`: emits `apply.started`, `apply.succeeded`, and
      `apply.failed` in the appropriate positions.
- [x] `diff_cmd.py`: emits `diff.changes_detected` when the change set
      is non-empty.
- [x] `docs/notifications.md`: complete notifier reference replacing
      the Phase 0 placeholder.
- [x] Unit tests: 377 passing total (43 new in `test_notifiers.py`)
      covering Event/make_event, event_matches glob, Notifier protocol
      conformance, registry add/skip, setup_notifiers happy+error paths,
      emit dispatch/skip/swallow/continue, all five channels (happy
      path, missing-config errors, glob routing, UDP/HTTP mocking),
      notify-test CLI (no notifiers, unknown channel, log channel).

## Phase 7 tasks

- [x] `linter.py`: `Severity`, `LintFinding`, `LintContext`, `Lint`
      protocol, and a `LINT_REGISTRY` dict plus `register_lint()` so
      site-specific plug-ins can register at import time without
      touching core. `LintFinding` mirrors `LoadError`'s shape (path,
      line, field_path, message) so the validate renderer formats both
      kinds of records through one code path; `to_json()` is the shape
      Phase 8 notifiers will consume.
- [x] Built-in rules registered in declaration order:
      `precedence-cycle` (re-runs `resolve_precedence` and catches
      `PrecedenceError`), `orphan-rule-group` (rule groups no active
      policy lists), `policy-without-host-groups` (empty `host_groups`
      map), `deleted-without-tombstone` (`status: deleted` lacking a
      tombstone — the loader already rejects the inverse), and
      `broad-allow` (heuristic on `action: allow` rules: world-open
      addresses or no endpoint constraints; state-qualified rules
      exempt; configurable via `[lint.options.broad-allow]`).
- [x] `csfwctl.toml` `[lint]` section via new `LintSection` Pydantic
      model: `disabled: list[str]` and `options: dict[str, dict]`.
      Runtime overrides to `run_lints` union with file config.
- [x] `validate_cmd`: runs lints after a successful load, emits findings
      to stderr with Rich severity colours (path/rule id escaped so
      Rich does not strip them as markup, `crop=False`/`soft_wrap=True`
      so long paths survive). `error` findings always fatal; `--strict`
      promotes warnings/infos to fatal. Stdout summary gains a yellow
      `OK with N warning(s)` suffix when non-fatal findings fire.
- [x] CLI: `csfwctl validate --strict` wired through Typer.
- [x] Docs: `docs/cli_reference.md` documents the lint rule table and
      `[lint]` configuration; `docs/architecture.md` carries the
      Phase 7 design notes (rule architecture, finding shape, config
      shape, built-in rules, validate integration, test pattern);
      `docs/schema_reference.md` shows the new `[lint]` section.
- [x] Unit tests: 335 passing total (34 new):
      31 linter tests (`test_linter.py`) covering finding format/JSON,
      `has_errors`, realistic/minimal repo pass-through (no findings
      expected), each built-in rule's positive + negative + edge cases,
      `run_lints` registry order + runtime `disabled` + `csfwctl.toml`
      `disabled` + per-rule options, plug-in registration round-trip,
      registry sanity, plus three in-memory `ConfigRepo` tests for the
      states the loader rejects (deleted + tombstone, orphan-via-dead-
      policy reference).
      3 new `validate_cmd` tests for the warning-doesn't-fail-by-default
      flow, `--strict` promotion, and the unchanged clean-run output.

## Phase 6 tasks

- [x] `status.py`: `EnvState` / `StatusEntry` / `StatusReport` plus
      `build_status_report(state)` that groups every live record by
      `(kind, slug)` with one `EnvState` per env. Env labels derive
      from the display-name suffix for policies/rule groups and from
      the parsed signature for tenant-global locations. Unsuffixed
      records land in a `(no-env)` pseudo bucket so console-created
      objects stay visible. Description substring `Managed by csfwctl`
      is the sole managed-vs-unmanaged signal; malformed trailers parse
      to `signature=None` while keeping `managed=True`.
- [x] `status_cmd.py`: `run_status` mirroring the `validate_cmd` /
      `diff_cmd` pattern, with three output modes — flat table
      (one row per `(kind, slug, env)`), pivot table (`--all-envs`,
      one row per logical object with per-env columns), and JSON.
      State-provider injection point for tests.
- [x] `precedence_resolver.py`: `BUCKET_ORDER` / `BUCKET_RANK`,
      `ResolvedPolicy`, `PrecedenceComparison`. `resolve_precedence(repo)`
      runs the base bucket+alphabetical sort, applies overrides in
      declaration order, and raises `PrecedenceError` on cycles.
      `compare_to_live` env-filters live records, strips suffixes, and
      reports a clean match/mismatch verdict.
- [x] `precedence_cmd.py`: `run_precedence` loads the repo, resolves
      precedence, optionally fetches live and runs the comparison
      (lazy-builds a `FalconClient` only when `--env` is set). Renders
      per-platform tables plus a live-vs-resolved diff block, or a
      JSON document.
- [x] Wire `csfwctl status` and `csfwctl precedence` through `cli.py`
      (both were stubs). `precedence` gained `--repo` and `--format`
      options.
- [x] Docs: `docs/cli_reference.md` documents both commands with their
      output schemas and exit codes; `docs/architecture.md` carries
      the Phase 6 design notes (status grouping, location env
      handling, override topology, applier hook).
- [x] Unit tests: 301 passing total (45 new):
      15 status tests (`test_status.py`) covering env grouping,
      managed-vs-unmanaged signal, signature field parsing, unsuffixed
      and location records, garbled-input resilience, sort order,
      summary counts, `managed_envs` ordering, and the JSON shape.
      18 precedence resolver tests (`test_precedence_resolver.py`)
      covering bucket constants, base sort, per-platform splitting,
      `deleted` exclusion, override application (single, idempotent,
      cross-platform, multiple), cycle detection, live-state matching,
      mismatch detection, env filtering, live-only filtering, empty
      input, and the JSON shape.
      6 CLI command-body tests (`test_status_cmd.py`) for run_status
      direct invocation, JSON mode, table dispatch, `--all-envs` pivot,
      JSON output via Typer, and fetch-failure surfacing.
      6 CLI command-body tests (`test_precedence_cmd.py`) for the
      realistic-fixture resolver, env-comparison provider wiring,
      end-to-end table render, JSON dispatch, config-repo error
      surfacing, and the end-to-end `--env` flow.

## Phase 5 tasks

- [x] `safety.py`: `MetadataSignature` dataclass plus
      `render_signature` / `parse_signature` / `strip_signature` /
      `inject_signature` / `next_signature` so the trailer
      `Managed by csfwctl | version: N | git_sha: X | applied: TS | env: E`
      round-trips. Free-text in the description is preserved verbatim.
- [x] `safety.py`: `SafetyOptions` and the four gates —
      `check_bootstrap`, `check_drift`, `check_deletes`,
      `check_blast_radius` — each a pure function with its own
      exception type (`UnbootstrappedTenantError`, `DriftBlocked`,
      `SafetyError`, `BlastRadiusExceeded`).
- [x] `safety.current_git_sha`: env-var first (`CSFWCTL_GIT_SHA`),
      fallback to `git rev-parse HEAD`, finally `"unknown"`.
- [x] `applier.py`: `ApplyOptions`, `HostGroupPolicy`, `AppliedAction`,
      `ApplyReport`. Single public entrypoint `apply_change_set` that
      runs the four safety gates and then dispatches creates → updates
      → host-group reassignments → deletes in the fixed kind order
      (locations → rule groups → policies, deletes last in reverse).
- [x] Override-RG materialisation: rule-group create runs before the
      policy create that references it, and the freshly-minted id is
      threaded into the policy payload (no extra round-trip).
- [x] Host-group resolution with three modes (`warn` / `strict` /
      `create`); `--strict-groups` and `--create-groups` are mutually
      exclusive at the CLI.
- [x] Metadata trailer rewrite on every touched object: version
      monotonically increments off the previous signature parsed from
      live; bootstrap path issues metadata-only updates and refuses to
      modify rule content.
- [x] `--dry-run`: no writes, but actions still recorded and synthetic
      IDs threaded into downstream payloads so the full plan builds.
- [x] `apply_cmd.py`: CLI body following the `validate_cmd` /
      `diff_cmd` pattern with `--output` JSON dump; resolves
      credentials, fetches live state, computes diff, runs the
      applier, and renders a per-action summary.
- [x] Wire `csfwctl apply` through `cli.py` (was previously a stub).
- [x] Docs: `docs/cli_reference.md` documents the apply command, its
      flags, and exit codes; `docs/architecture.md` carries the
      Phase 5 design notes.
- [x] Unit tests: 256 passing total (53 new):
      31 safety tests (`test_safety.py`) covering signature render /
      parse / strip / inject / next-version, bootstrap detection,
      blast-radius limits (changes + deletes + bootstrap exempt),
      drift gate, delete gate, and the git-sha resolver
      (env / subprocess / OSError fallbacks).
      17 applier tests (`test_applier.py`) covering bootstrap gate,
      create/update/delete ordering, override-RG materialisation,
      metadata version bumping, drift refusal, blast-radius refusal,
      host-group modes (warn / strict / create), dry-run no-writes,
      bootstrap metadata-only writes, ApplyReport JSON serialization,
      and description free-text preservation.
      5 CLI command-body tests (`test_apply_cmd.py`) for dry-run flow,
      JSON output, config-repo error surfacing, mutually-exclusive
      host-group flags, and end-to-end Typer dispatch.

## Phase 4 tasks

- [x] `differ.py`: core engine. `LiveState` snapshot dataclass,
      `ChangeSet` aggregate with `creates` / `updates` / `deletes` /
      `no_changes` / `unmanaged` / `warnings` buckets, plus
      `ObjectChange`, `FieldChange`, `HostGroupChange` records. JSON
      and apply-ordered iteration on the change set.
- [x] Schema-domain comparison: translate live records via
      `exporter.*_from_api` (with `strip_suffix=True`), then compare
      `model_dump` dicts. `_diff_dicts` walks leaves and emits one
      `FieldChange` per difference (lists treated as scalars).
- [x] Per-env projection: `project_policy_for_env` filters
      `host_groups` to the env's group, prepends the synthesised
      override-RG slug to `rule_groups`, and empties inline `rules`
      so the desired shape matches what the applier will render.
- [x] Override-RG synthesis: `synthesise_override_rule_groups` emits
      `<policy-slug>-overrides-<env>` rule groups from every policy's
      inline rules. Mirrored on the live side by passing
      `fold_overrides=False` to `policy_from_api` (new parameter,
      defaults `True` for the importer).
- [x] Managed-vs-unmanaged classification from the
      `Managed by csfwctl` description trailer; live-only objects
      become `unmanaged` entries unless a matching tombstone queues a
      delete. Description excluded from comparison so the applier owns it.
- [x] `fetch_live_state(client)` convenience that walks every sub-client
      (policies, rule groups + their rules, locations) so the diff
      command body only owes credentials.
- [x] `diff_cmd.py`: command body following the `validate_cmd` /
      `import_cmd` pattern. Renders the rich text summary to stdout,
      writes JSON to `--output` when given, exits 1 only on repo-load
      or live-fetch failure. Accepts a `state_provider` callable so
      tests bypass the real Falcon client.
- [x] Wire `csfwctl diff --env` through `cli.py` (was previously a stub).
- [x] Docs: `docs/cli_reference.md` documents the `diff` command;
      `docs/architecture.md` carries the Phase 4 design notes (schema
      comparison, override-RG synthesis, host-group projection,
      managed-status rules).
- [x] Unit tests: 203 passing total (27 new):
      22 differ tests (`test_differ.py`) covering signature detection,
      override-RG synthesis, per-env policy projection, no-change /
      create / update / delete / unmanaged paths, env-suffix filtering,
      override round-trip, orphan-override warning, JSON serialization,
      unknown-env rejection, and a realistic-fixture integration test.
      5 CLI command-body tests (`test_diff_cmd.py`) for stub-provider
      flow, JSON output, repo-error surfacing, end-to-end Typer
      dispatch, and the no-changes path.

## Phase 3 tasks

- [x] `exporter.py`: name normalisation helpers (`strip_env_suffix`,
      `display_name_to_slug`, `clean_description`, override-group
      detection), API → Pydantic translators for rules / endpoints /
      rule groups / policies / locations, and inverse `*_to_api_shape`
      renderers used by tests + Phase 5 applier.
- [x] `exporter.import_policy` / `import_rule_group` / `import_location`
      / `import_all`: high-level entry points that drive the
      `FalconClient` sub-clients, validate via Pydantic, and write
      round-trippable YAML through a custom `dump_yaml` that strips
      defaults so emitted files match hand-authored shape.
- [x] Override-rule-group folding: when a policy references a rule
      group named `<policy-slug>-overrides-<env>`, fold its rules back
      into the policy YAML's inline `rules:` field instead of writing
      the override group as a separate file.
- [x] `falcon/rule_groups.py`: added `get_rules(ids)` so the importer
      can fetch rule contents (`get_rule_groups` only returns
      `rule_ids`).
- [x] `fixtures.py`: deterministic `Sanitizer` (UUIDs → counter UUIDs,
      IPv4/IPv6 → RFC 5737/3849 ranges, hostnames → `host-NNN.example.test`,
      emails → `user-NNN@example.test`, CIDRs preserve prefix length),
      `record_fixtures` driver that walks default read-only operations
      and writes per-op JSON, plus `filter_operations` for the
      `--operations` flag.
- [x] `import_cmd.py` + `record_fixtures_cmd.py`: command bodies
      (matching `validate_cmd.py` pattern) wired into `cli.py`. CLI
      now passes `--profile` through `ctx.obj` for sub-commands that
      need credentials.
- [x] API shape assumptions documented in `docs/architecture.md` —
      policy / rule-group / rule / location record layouts plus the
      override-folding contract and round-trip test design.
- [x] `docs/cli_reference.md` updated for `import` and `record-fixtures`.
- [x] Unit tests: 176 passing total (68 new):
      29 translation tests (`test_exporter_translation.py`),
      15 end-to-end round-trip tests (`test_exporter.py`) including the
      "import → load → validate is clean" contract against a fake
      `FalconClient` and the realistic fixture repo,
      15 sanitiser / record-fixtures tests (`test_fixtures.py`), and
      9 CLI command-body tests (`test_import_cmd.py`).

## Phase 2 tasks

- [x] `observability.py`: per-invocation request ID (contextvar) plus
      structured logger setup (text + JSON formatters).
- [x] `config.py`: `Credentials` model and loader. Env vars override
      profiles from `credentials.toml`. Clear error on missing creds.
- [x] `falcon/client.py`: `FalconClient` wrapper over FalconPy `OAuth2`.
      Retry with exponential backoff on 5xx; honor Retry-After on 429.
      Every API call logs at INFO with the current request ID.
- [x] Thin sub-clients: `policies.py`, `rule_groups.py`,
      `host_groups.py`, `locations.py` (FalconPy `network_locations`).
- [x] Location API spike findings in `docs/architecture.md`: FalconPy
      surface table, `any`-sentinel semantics, three items still
      pending tenant confirmation during initial bootstrap.
- [x] Wire global `--log-format` and `--quiet` flags through
      `observability.configure_logging` in the Typer callback.
- [x] Unit tests: 108 passing — observability (text + JSON formatters,
      idempotent setup, quiet level), config (env override, profile
      lookup, error paths), FalconClient retry (success / non-retry /
      retry-then-OK / exhaust / Retry-After / pythonic response /
      request-ID binding), one happy-path per sub-client via
      `responses`-mocked HTTP, and a meta-test enforcing "only
      `csfwctl/falcon/` may import `falconpy`".

## Phase 1 tasks (complete)

- [x] Shared schema types: `Platform`, `Status`, `PrecedenceBucket`,
      `Action`, `Direction`, `Protocol`, slug/display-name patterns,
      host-group env, connection state.
- [x] Pydantic v2 models: `Rule`, `RuleGroup`, `Policy`, `Location`,
      `Tombstones`, `PrecedenceOverrides`, `ToolConfig`.
- [x] Strict slug validation on object names. Cross-platform reference
      validation (Windows policy cannot reference a Mac rule group).
      No duplicate names within a kind. No duplicate inline rule names.
- [x] `ruamel.yaml` loader. Round-trip comment preservation. YAML
      parse errors carry file path and line number. Pydantic errors
      carry file path and dotted field path.
- [x] `ConfigRepo` aggregate: loads policies/, rule_groups/, locations/,
      tombstones.yaml, precedence.yaml, csfwctl.toml.
- [x] Cross-ref resolution: rule-group slugs in policies, location
      slugs in rules, tombstones don't match live objects, precedence
      overrides reference known policies.
- [x] Wire `csfwctl validate` end-to-end. Rich table summary on
      success, per-error stderr listing, exit 1 on any error.
- [x] Fixture config repos under `tests/fixtures/config_repos/minimal/`
      and `.../realistic/`.
- [x] Unit tests for every model and for the loader / cross-ref checks
      (80 tests, all passing).
- [x] `docs/schema_reference.md` reflects the models.
- [x] `docs/cli_reference.md` documents the `validate` command.

## Phase 0 tasks (complete)

- [x] Initialize git repo, MIT license, .gitignore for Python
- [x] Author pyproject.toml with project metadata and dependencies
- [x] Author Makefile with targets
- [x] Create directory skeleton matching project plan section 2
- [x] Author .github/workflows/ci.yml: ruff, mypy, pytest
- [x] Author csfwctl/cli.py with Typer app and stubbed subcommands
- [x] Author csfwctl/__main__.py so `python -m csfwctl` works
- [x] Author README.md
- [x] Add docs/ skeleton
- [x] Verify `make dev` then `make test` runs green
- [ ] Tag v0.0.1 (deferred — tag from maintainer machine after review)

## Open questions

(None at this time.)

## Security hardening applied post-v1

- [x] **Notifier env-var allowlists + HTTPS-only outbound.** A
      compromised `csfwctl.toml` could previously point the GitLab or
      Teams notifier at any environment variable (`CSFWCTL_CLIENT_SECRET`,
      `AWS_SECRET_ACCESS_KEY`, …) and exfiltrate it to an arbitrary URL.
      `csfwctl/notifiers/gitlab.py` and `.../teams.py` now reject env-var
      names that don't match the channel-specific allowlist regex, and
      reject `api_url` / resolved webhook URLs that aren't `https://`.
      See `docs/notifications.md` § Security boundary.
- [x] **Credentials file permission check.** `load_credentials` refuses
      to read a credentials TOML with any of the `0o077` (group/world)
      bits set; suggested fix message: `chmod 600 …`. POSIX only.
- [x] **HTTPS-only `base_url`.** `Credentials.base_url` must use
      `https://`; loopback `http://` (localhost / 127.0.0.1 / [::1]) is
      still allowed for local mocks.
- [x] **Fixture sanitiser catches MAC addresses.** New `MAC_RE` rule
      replaces IEEE 802 MACs with the IANA documentation OUI
      (`00:00:5E…`, RFC 7042). Added a pre-commit review checklist
      for recorded fixtures in `docs/operations.md`.
- [x] **`make lint-security`.** Grep guards in `Makefile` fail the build
      on direct `falconpy` imports outside `csfwctl/falcon/` and on
      forbidden dynamic-exec / unsafe-deserialise primitives
      (`eval(`, `exec(`, `pickle.loads(`, `yaml.unsafe_load(`,
      `shell=True`). Hooked into `make lint` so it runs in CI.

## Bug fixes applied post-v1

- [x] **Bug 3 — zero rule-group imports from real tenant**: Three root
      causes fixed together:
      - `query_rule_groups` default limit is 10; `RuleGroupsAPI.query` now
        passes `limit=5000` when the caller does not specify a limit, so
        `list_all()` fetches all groups rather than the first 10.
      - `_fetch_rules_for_groups` sent all rule IDs in a single HTTP call;
        with large rule sets this could exceed URL-length limits. Now batches
        in groups of 100 IDs per call.
      - The real API returns rule records indexed by a *numeric* `id`, but
        some tenants carry an additional `family_id` (32-char hex string)
        that appears in the rule group's `rule_ids` field.
        `_fetch_rules_for_groups` now indexes each fetched rule record under
        both its `id` and its `family_id` so lookups resolve either format.
      - `rule_from_api` was only handling the nested `local`/`remote` endpoint
        shape used by the test-fixture generator. The real API returns
        `local_address` / `local_port` / `remote_address` / `remote_port` as
        separate top-level fields. Both shapes are now handled, with the flat
        shape tried as a fallback when the nested key is absent.
      - `_flatten_addresses` now appends the CIDR prefix length when the API
        returns `{"address": "x.x.x.x", "netmask": N}` with `N > 0`.
      440 tests pass (6 new covering the batch logic, family_id indexing,
      flat endpoint fields, and netmask CIDR formatting).
- [x] **Bug 2 — non-slug object names silently dropped on import**: Policy,
      rule-group, and location names with spaces, underscores, or mixed-case
      (e.g. `cs default`, `platform_default`) failed `SLUG_RE` validation and
      were silently skipped. Fix:
      - Added `to_slug()` normaliser (`spaces/underscores → hyphens, lowercase`).
      - Added `display_name: CrowdStrikeName | None` field to `Policy`,
        `RuleGroup`, and `Location` models. Stores the verbatim CrowdStrike
        name when it doesn't match the derived slug.
      - Changed `Policy.name` type from `DisplayName` (TitleCase) to `Slug`.
        `display_name` carries the TitleCase original.
      - Importer sets `display_name` automatically when the imported name
        normalises to a different slug.
      - Applier, differ, and precedence resolver use `display_name or name`
        when constructing the CrowdStrike object name.
      - Updated all four fixture YAML files, all affected tests, and
        `docs/schema_reference.md`.
- [x] **Bug 1 — `--repo` ignored on import**: `cli.py` import handlers
      were ignoring the global `--repo` option. Added `_repo_from_ctx()`
      helper; all four import handlers now fall back to `--repo` when no
      explicit `--output-dir` is given.
- [x] **Bug 2 — non-slug object names silently dropped on import**: Policy,
      rule-group, and location names with spaces, underscores, or mixed-case
      (e.g. `cs default`, `platform_default`) failed `SLUG_RE` validation and
      were silently skipped. Fix:
      - Added `to_slug()` normaliser (`spaces/underscores → hyphens, lowercase`).
      - Added `display_name: CrowdStrikeName | None` field to `Policy`,
        `RuleGroup`, and `Location` models. Stores the verbatim CrowdStrike
        name when it doesn't match the derived slug.
      - Changed `Policy.name` type from `DisplayName` (TitleCase) to `Slug`.
        `display_name` carries the TitleCase original.
      - Importer sets `display_name` automatically when the imported name
        normalises to a different slug.
      - Applier, differ, and precedence resolver use `display_name or name`
        when constructing the CrowdStrike object name.
      - Updated all four fixture YAML files, all affected tests, and
        `docs/schema_reference.md`.

## Notes for next session

- **All planned phases and Sprint 11 are complete.** v1 scope is done
  plus the Sprint 11 post-v1 features; see the project plan's "Later
  sprints" section for remaining post-v1 items.
- **Phase 10 hooks for later work:**
  - `DriftState.last_alerted` is the dedupe substrate. Any future
    "acknowledge alert" command that wants to suppress pages without
    resolving drift should update this field atomically via
    `save_drift_state` (which uses `.tmp` + rename).
  - `_transition_name` in `drift_cmd.py` is the canonical four-label
    set (`stable` / `detected` / `ongoing` / `cleared`). Reuse it
    from dashboard renderers rather than re-deriving the truth table.
  - `DEFAULT_ALERT_WINDOW_MINUTES = 60` can be overridden per-repo via
    `csfwctl.toml` `[drift]` section in a future sprint if per-env
    windows become necessary.
- **Phase 7 hooks Phase 8+ should pick up:**
  - The linter's `register_lint()` + ordered `LINT_REGISTRY` is the
    template to mirror for `register_notifier()`. Same shape: protocol
    + ordered dict + idempotent insertion-order iteration.
  - `LintFinding.to_json()` is what a `validate.failed` event should
    embed under `details.findings`.
  - The `Severity` enum in `linter.py` and the `severity` field on
    `Event` should agree. Reuse the same enum if it makes sense, or at
    least keep the string values consistent (`error` / `warning` /
    `info`).
- **Phase 6 hooks that Phase 7+ should pick up:**
  - `precedence_resolver.resolve_precedence` already raises
    `PrecedenceError` on cycles. The linter can promote the same check
    to a non-fatal warning emitted at `validate` time so the operator
    catches it before getting near the apply.
  - `status.build_status_report` exposes managed-vs-unmanaged counts
    via `StatusReport.managed` / `.unmanaged`. The drift-check job
    (Phase 10) can compare those counts run-over-run; the JSON shape
    in `to_json()` is the contract.
  - The applier's step-4 precedence hook is live: `_apply_precedence`
    threads `resolve_precedence` output through `_LiveIndex.policies`
    and calls `PoliciesAPI.set_precedence` per platform, skipping the
    write when live already matches resolved. Unmanaged live IDs are
    preserved at the tail because CS's set-precedence rejects payloads
    that omit an existing policy for the platform. Dry-run records the
    action without calling the API.
- **Applier contract reminders for Phase 6+:**
  - The metadata trailer format is parsed by `safety.parse_signature`.
    Reuse it in the status command; do not re-derive the regex.
  - `ApplyReport.to_json()` is the shape the GitLab notifier will
    consume in Phase 8.
  - Bootstrap mode writes metadata-only payloads (`{"id", "description"}`).
    The status command should treat objects with a `version: 1` trailer
    where `applied` == bootstrap timestamp as "bootstrapped only".
- **Open questions surfaced during Phase 5:**
  - Real-tenant verification: does `firewall_rule_groups.update` accept
    a partial payload (just `id` + `description`) or does it require
    the full rule list? The bootstrap path assumes partial works; the
    first real-tenant run must confirm.
  - `client.policies.update` payload shape for host-group changes — the
    applier currently sends the full `groups` list; `perform_action`
    is also available. Pick whichever the tenant proves cleaner.
- **API shape assumptions** (recorded in `docs/architecture.md`) are
  the contract Phase 5 wrote against. If real-tenant interaction
  reveals discrepancies, all translation is localised to
  `csfwctl/exporter.py`'s `*_from_api` / `*_to_api_shape` helpers —
  the differ and applier do not parse API shapes directly.
- **Fake-client test pattern** lives in `tests/unit/test_applier.py`'s
  `FakeFalconClient` — Phase 6 status tests can reuse it. Each
  sub-client records `created` / `updated` / `deleted` lists so
  assertions can pin down exact API call sequences.
- **Location API spike** still has three confirmation items pending
  the first real-tenant interaction; see `docs/architecture.md`.
- `Credentials.redacted()` is what to put in logs / notifier payloads
  — never log a `Credentials` instance unredacted.
- The meta-test `test_only_falcon_subpackage_imports_falconpy` makes
  the no-direct-`falconpy` rule a CI failure. New imports of FalconPy
  types must re-export from `csfwctl.falcon`.
- Command-body pattern (one module per command, kept out of `cli.py`)
  is now used by `validate_cmd.py`, `import_cmd.py`,
  `record_fixtures_cmd.py`, `diff_cmd.py`, and `apply_cmd.py`. Apply
  the same shape for `status` and `precedence`.
- v0.0.1 tag intentionally left for a maintainer to apply locally; CI
  release workflow is not configured yet (lands in a later phase).
