# Architecture

Technical findings accumulated during implementation. This document
captures decisions and discoveries that affect how the code is
structured.

## Layering

- `csfwctl.cli` is the only entrypoint operators touch.
- `csfwctl.falcon.*` is the only module that talks to CrowdStrike. Every
  call funnels through `FalconClient.call`, which is where retry and
  per-call logging live (CLAUDE.md hard rule).
- `csfwctl.loader` and `csfwctl.schema.*` own the desired-state side.
- `csfwctl.differ` consumes both and produces a structured change set
  (Phase 4, pending).
- `csfwctl.applier` is the only module that performs writes, gated by
  `csfwctl.safety` (Phase 5, pending).

## Request IDs and logging

- One request ID per CLI invocation. Generated in the Typer callback
  (`cli.main`), bound on a `contextvars.ContextVar` in
  `csfwctl.observability`, and emitted on every log line.
- `FalconClient` re-binds the request ID at construction time so
  programmatic callers (tests, future library use) get a deterministic
  ID even without going through the CLI.
- `--log-format=json` switches to newline-delimited JSON records.
- One INFO log per API call (`api.call`) with `op`, `status`,
  `attempt`, `elapsed_ms`. One WARNING per retry (`api.retry`).

## Retry policy

`FalconClient.call` retries:

- Up to `DEFAULT_MAX_ATTEMPTS` (5) total tries.
- On HTTP 5xx and 429.
- 429 honors `Retry-After` / `X-Ratelimit-Retryafter` when present;
  otherwise exponential backoff `1s, 2s, 4s, 8s, …` capped at 30s.
- Final failure surfaces as `FalconAPIError`, carrying the operation
  name, status, and body for the notifier/runbook to consume.

## Location API spike — Phase 2 findings

Drove the `csfwctl/falcon/locations.py` wrapper. Captured here so the
team doesn't re-discover this during apply work.

**FalconPy surface.** What CrowdStrike's API and FalconPy call
"firewall locations" are exposed under `FirewallManagement` as
`network_locations`. The endpoints used by csfwctl:

| Operation                                | FalconPy method                  | HTTP                                                       |
|------------------------------------------|----------------------------------|------------------------------------------------------------|
| List IDs matching filter                 | `query_network_locations`        | `GET /fwmgr/queries/network-locations/v1`                  |
| Fetch details for a list of IDs          | `get_network_locations_details`  | `GET /fwmgr/entities/network-locations-details/v1`         |
| Create or update                         | `upsert_network_locations`       | `PUT /fwmgr/entities/network-locations/v1`                 |
| Delete                                   | `delete_network_locations`       | `DELETE /fwmgr/entities/network-locations/v1`              |
| Reorder                                  | `update_network_locations_precedence` | `POST /fwmgr/entities/network-locations-precedence/v1` |

We expose `query`, `get_details`, `list_all`, `upsert`, `delete`.
Reorder lands when multi-location scenarios become first-class (out of
scope for v1).

**The `any` location.** csfwctl reserves the slug `any` as a sentinel
meaning "no location constraint", and the loader excludes it from
cross-reference checks (`Rule.referenced_locations()`). On the
CrowdStrike side, the default location is auto-managed by the tenant
and does not appear in custom-location queries; rules whose location
list is empty (or that target the system default) are equivalent to
csfwctl's `any`.

**What still needs tenant confirmation.** Cannot be validated against a
sandbox tenant (CLAUDE.md — no test tenant). The first
`--initial-bootstrap` apply against real infrastructure must verify:

1. `query_network_locations` with no filter returns only
   *custom* locations (not the system default). Expected behavior; the
   importer drops anything matching the system default by ID.
2. A rule with `locations: [any]` round-trips to a CrowdStrike rule
   with an empty location-ID list — not to a rule that names the
   default location explicitly.
3. The system default location's ID is stable per tenant; if it ever
   surfaces in responses (e.g. through `get_details`), the importer
   must drop it consistently.

Once confirmed, fold the verified behavior into this section and remove
the "still needs confirmation" list. If any assumption is wrong, the
`LocationsAPI` wrapper is the only place that needs to change — the
loader/differ already treat `any` as a sentinel.

## Exporter / API shape assumptions (Phase 3)

The importer converts CrowdStrike API records into our Pydantic schema
and back. ``csfwctl/exporter.py`` carries both directions: the
``*_from_api`` functions consume the API shape, and the ``*_to_api_shape``
functions render a model into the shape we expect to see. Phase 5's
applier will reuse the renderers verbatim.

The API shapes below are inferred from CrowdStrike's Falcon Firewall
documentation and FalconPy method signatures. We have no test tenant
(see CLAUDE.md), so first-tenant interaction must verify each shape;
discrepancies are localised to the translation helpers.

**Firewall policy (FirewallPolicies.get_policies):**

```python
{
  "id": "<uuid>",
  "name": "ABC01-Endpoints-Windows-Test",
  "description": "...",
  "platform_name": "Windows",          # "Windows" | "Mac"
  "enabled": True,
  "groups": [{"id": "<uuid>", "name": "ABC01-Endpoints-Windows-Test"}],
  "settings": {
    "rule_group_ids": ["<uuid>", "<uuid>"],
    # default_inbound/default_outbound surfaces on the apply side; the
    # importer ignores them in v1.
  },
}
```

**Rule group (FirewallManagement.get_rule_groups):**

```python
{
  "id": "<uuid>",
  "name": "windows-baseline-Test",
  "description": "...",
  "platform": "0",                     # GET returns numeric ID: "0" Windows | "1" Mac
  "enabled": True,
  "rule_ids": ["<uuid>", "<uuid>"],
}
```

**Important:** The GET response uses numeric platform IDs (`"0"` / `"1"`), but the
CREATE and UPDATE endpoints require the name string (`"Windows"` / `"Mac"`).
`_PLATFORM_FROM_API` accepts both forms so the importer handles GET records
regardless. `rule_group_to_api_shape` emits the name string so it is correct
for CREATE/UPDATE payloads.

**Rule (FirewallManagement.get_rules):**

```python
{
  "id": "<uuid>",
  "name": "Allow corp DNS outbound",
  "enabled": True,
  "action": "ALLOW",                   # "ALLOW" | "DENY" | "MONITOR"
  "direction": "OUT",                  # "IN" | "OUT"
  "protocol": "17",                    # "0"/"*" any, "1" icmp, "6" tcp, "17" udp
  "address_family": "IP4",             # required by CREATE: "IP4" | "IP6"
  "fields": [{"name": "tcp_state", "value": "established"}],   # optional state
  "local": {"addresses": [...], "ports": [{"start": N, "end": M}]},
  "remote": {...},
  "locations": [...],                  # slug list (csfwctl convention)
}
```

**Important:** The CREATE endpoint rejects rules where `address_family` is absent or
empty. csfwctl does not store this field in the YAML schema — it is derived at
apply time by `_infer_address_family`: `"IP6"` when any endpoint address contains
`":"` (IPv6 CIDR), `"IP4"` otherwise. The importer silently drops this field on
import since it is fully recoverable from the address data.

**Network location (FirewallManagement.get_network_locations_details):**

```python
{
  "id": "<uuid>",
  "name": "corp-vpn",
  "enabled": True,
  "addresses": [{"address": "10.100.0.0/16"}],
  "dns_servers": [{"address": "10.1.1.53"}],
  "dns_resolution_targets": {"targets": [{"hostname": "corp.example.edu"}]},
  "default_gateways": [],
}
```

**Override rule-group folding.** The applier renders a policy's inline
``rules`` field as an anonymous rule group named
``<policy-slug>-overrides-<env>``. The importer detects that name shape
and folds the group's rules back into the policy YAML's ``rules:``
field; the override-group YAML itself is not written. Detection is in
``exporter.is_override_group_name`` and the folding logic is in
``policy_from_api``.

**Round-trip contract.** The unit tests in ``test_exporter.py`` start
with a hand-authored Pydantic model, render it into the API shapes
above (via the ``*_to_api_shape`` helpers), drive the importer against
a hand-rolled fake ``FalconClient``, and assert that the imported model
equals the original. This is the "import → load → diff should be empty"
guarantee from the project plan.

## Fixture sanitisation (Phase 3)

``csfwctl/fixtures.py`` ships a :class:`Sanitizer` that walks an API
response and replaces sensitive tokens with deterministic fakes:

| Token kind | Replacement                                                   |
|------------|---------------------------------------------------------------|
| UUID       | ``00000000-0000-0000-0000-XXXXXXXXXXXX`` counter              |
| IPv4       | RFC 5737 ranges ``192.0.2.0/24`` / ``198.51.100.0/24`` / ``203.0.113.0/24`` |
| IPv4 CIDR  | Same base ranges with the original prefix length preserved    |
| IPv6       | ``2001:db8::N`` (RFC 3849)                                    |
| Hostname   | ``host-NNN.example.test``                                     |
| Email      | ``user-NNN@example.test``                                     |

Mappings are stable for the lifetime of a :class:`Sanitizer` instance,
so cross-references between fixture files (e.g. a UUID appearing in
both ``policies-list.json`` and ``policies-query.json``) stay
consistent. ``record-fixtures`` uses one sanitiser per invocation.

The sanitiser is intentionally aggressive: when in doubt about whether
a token is sensitive it replaces it. Tests can opt slugs out via
``preserve_substrings``.

## Differ (Phase 4)

``csfwctl/differ.py`` compares a loaded :class:`ConfigRepo` against one
environment's live tenant state and emits a structured
:class:`ChangeSet`. The same change set is what the Phase 5 applier will
consume and what the drift-check job will surface to notifiers.

**Schema-domain comparison.** Live API records are translated into
Pydantic models via ``exporter.*_from_api`` (with env-suffix stripping
on names) before being matched by slug against the desired state. We
compare ``model_dump`` dicts rather than raw API payloads so that field
ordering, integer-vs-string protocol IDs, and other API-shape noise
don't bleed into the diff.

**Per-env projection.** A policy's ``host_groups`` field carries every
env in the YAML; before comparison the desired side is filtered to the
env's group only, matching what the live record exposes. Locations are
tenant-global and are diffed once per run.

**Override-RG synthesis.** Inline policy ``rules:`` are inverted into an
anonymous rule group named ``<policy-slug>-overrides-<env>`` on the
desired side, with the override slug prepended to ``rule_groups``. The
live side is translated with ``policy_from_api(fold_overrides=False)``
so the override-RG reference stays visible on both sides.

**Managed-vs-unmanaged classification.** The differ decides solely from
the live ``description``: presence of ``Managed by csfwctl`` →
``managed``, absence → ``unmanaged``. Unmanaged objects are reported
but never queued for change. Deletes require a matching entry in
``tombstones.yaml``; the entry kind (``policies`` / ``rule_groups`` /
``locations``) gates which live records can be removed.

**Field-level diffs.** :func:`_diff_dicts` walks two model dumps and
emits one :class:`FieldChange` per leaf difference, recording dotted
paths like ``platform`` or ``priority``. Lists are treated as opaque
scalars: a single FieldChange records the full before/after list when
they differ. This keeps the operator-facing summary terse while keeping
the JSON payload machine-parseable for the future applier and the
GitLab notifier.

**Description ignored in comparison.** The applier owns the description
trailer (``Managed by csfwctl | version: N | git_sha: X | …``). The
differ strips ``description`` from both sides before comparing so it
does not race the applier on that field.

**Translation failures are warnings, not aborts.** Individual live
records that fail to translate (corrupt or unexpected shape) are
skipped; surviving objects still get diffed. Operators see a
``warnings`` count on the summary table.

## Applier and safety rails (Phase 5)

``csfwctl/applier.py`` consumes a :class:`csfwctl.differ.ChangeSet` and
drives the FalconClient sub-clients to converge the tenant.
``csfwctl/safety.py`` owns the gating checks that fire before any
write. The split mirrors the differ/loader split: pure functions in
``safety``; side-effects in ``applier``.

**Operation order** is fixed and visible in :func:`apply_change_set`:

1. Locations (creates, then updates).
2. Rule groups (creates, then updates). Override rule groups
   (``<policy-slug>-overrides-<env>``) materialise here so subsequent
   policy payloads can reference their real IDs.
3. Policies (creates, then updates). The policy payload carries the
   resolved host-group membership in one round-trip.
4. Host-group reassignments — recorded explicitly on the apply report
   even though they ride on the policy update payload above.
5. Precedence ordering — Phase 6 stub.
6. Deletes — policies, then rule groups, then locations.

**Metadata trailer.** Every touched object's ``description`` is
rewritten to carry the canonical signature
``Managed by csfwctl | version: N | git_sha: X | applied: TS | env: E``.
The version is read off the live record (via
``safety.parse_signature``) and incremented; pre-existing free-text in
the description is preserved (``safety.inject_signature`` strips just
the trailer block and re-appends the new line). Bootstrap mode rewrites
only that field; it does not touch rule content, status, or
assignments.

**Rule-group update is diff-based (discovered in bootstrap testing).**
The firewall rule-group *update* endpoint
(``firewall_rule_groups.update`` → FalconPy ``update_rule_group``) does
**not** accept the same full-content shape as *create*. Its documented
body is ``{id, tracking, diff_type, rule_ids, rule_versions,
diff_operations}`` — there is no top-level ``description`` field, and a
``description`` key sent at the top level is silently ignored (HTTP 200,
zero writes). To change any field you submit a JSON Patch op in
``diff_operations``, and ``diff_type`` has exactly one accepted value,
``application/json-patch+json``. The endpoint also rejects payloads that
omit ``tracking`` or ``rule_ids`` with HTTP 400 (``"cannot be empty"`` /
``"array must be provided"``). Consequently **bootstrap** builds its
metadata-only rule-group update as a single
``replace /description`` patch (see
``applier._rule_group_metadata_payload``), copying ``rule_ids`` and
``tracking`` verbatim from the live record so rule content and the
optimistic-concurrency token are preserved. Locations and policies still
take the simple ``{id, description}`` update. NOTE: the *normal*
(non-bootstrap) rule-group update path in ``_build_rule_group_payload``
still emits the full-content shape with a top-level ``description``; that
path has not yet been exercised against a real tenant and likely needs
the same diff-based treatment — tracked as follow-up.

The *response* shape also differs from create-style endpoints: rule-group
create and update return ``resources`` as a list of bare **ID strings**,
not full objects. ``RuleGroupsAPI._first_resource`` normalises this —
wrapping a string as ``{"id": ...}`` and passing a dict through unchanged
— so callers can uniformly read ``result["id"]``.

**Safety rails.** Each gate is a small pure function in
``csfwctl/safety.py``:

- ``check_bootstrap`` — refuses a normal apply against a tenant where
  no live object carries the metadata signature. ``--initial-bootstrap``
  bypasses this check (and only this check) so the first run can install
  signatures.
- ``check_drift`` — refuses updates against managed objects unless
  ``--enforce`` is passed. Bootstrap mode skips the check because it
  never modifies rule content.
- ``check_deletes`` — refuses deletes unless ``--allow-delete`` is
  passed (in addition to the tombstone the differ already required).
  Bootstrap mode refuses deletes outright.
- ``check_blast_radius`` — caps creates + updates + deletes at
  ``--max-changes`` and deletes at ``--max-deletes``. The change cap
  is exempt under ``--initial-bootstrap`` (the explicit goal of that
  run is to write the metadata to every live object); the delete cap
  still applies.

**Host-group handling.** Three policies on missing host groups:
``warn`` (default, skips the assignment with a report warning),
``strict`` (raises ``ApplyError``, aborts the run), and ``create``
(creates the group as an empty static group before the policy write).
``--strict-groups`` and ``--create-groups`` are mutually exclusive at
the CLI.

**API-payload construction** reuses the exporter's ``*_to_api_shape``
helpers (which the differ already round-trips), then patches up three
things: the fake ``id`` is dropped on creates and replaced with the
live id on updates; the policy's ``groups`` list gets real host-group
IDs from ``host_groups.find_by_name``; and ``settings.rule_group_ids``
gets real rule-group IDs from the live index (or freshly-created ids
returned by the rule-group create that ran moments earlier). Dry-run
mode allocates synthetic IDs so downstream payload construction still
succeeds without making writes.

**Test pattern.** ``test_applier.py`` builds a hand-rolled
``FakeFalconClient`` whose sub-clients record every write call,
exercises the real differ to produce the change set, and then asserts
on the recorded API calls and the resulting ``ApplyReport``. This is
the same shape ``test_exporter.py`` uses for the round-trip tests
(Phase 3). No real ``falconpy`` import lives in the applier or the
safety module — the no-direct-FalconPy rule is preserved.

## Status and precedence (Phase 6)

``csfwctl/status.py`` and ``csfwctl/precedence_resolver.py`` are
read-only modules: both consume a snapshot the differ already produces
and translate it into operator-facing shapes. They share the env-suffix
helpers (``exporter.strip_env_suffix``) and the metadata-trailer parser
(``safety.parse_signature``) with the applier so a single source of
truth governs how names map to slugs and how trailers are decoded.

### Status engine

``build_status_report(state: LiveState)`` groups every live record by
``(kind, slug)`` with one :class:`status.EnvState` per environment.

- **Env labels.** Policies and rule groups derive their env from the
  display-name suffix (``-Test`` / ``-Pilot`` / ``-Production``). A
  record whose name lacks a suffix lands in the ``(no-env)`` pseudo
  bucket so console-created objects still appear in the report.
- **Locations are tenant-global.** They have no env suffix, so the env
  label comes from the most recently written signature (``signature.env``)
  or the literal ``any`` when no signature is present. Operators
  re-applying a location across environments will see the env tag
  change with each apply; this is consistent with how the applier
  writes them.
- **Managed vs. unmanaged.** The literal substring ``Managed by csfwctl``
  in the description is the sole signal — the same rule the differ
  uses. A description with the substring but a malformed trailer counts
  as ``managed=True`` with ``signature=None``; the pivot view shows
  that as ``M (unparseable)`` so it cannot be mistaken for a healthy
  managed entry.
- **Sorting.** Entries sort by kind in apply-order (location → rule
  group → policy), then by slug for determinism. JSON output preserves
  the same order.

### Status CLI

``status_cmd.run_status`` renders either a flat table (one row per
``(kind, slug, env)``), a pivot table (``--all-envs``, one row per
logical object with one column per env), or a JSON document
(``--format json``). The flat shape is easy to grep; the pivot shape
makes version drift across environments visible at a glance. JSON is
the form Phase 8 notifiers will consume.

### Precedence resolver

``resolve_precedence(repo)`` returns a per-platform list of
:class:`precedence_resolver.ResolvedPolicy` records:

1. **Base sort** — by bucket rank (``emergency`` → ``high`` → ``medium``
   → ``default`` → ``low``) then by display name alphabetic. The slug
   is the secondary tiebreaker so the sort is stable across runs.
2. **Override application** — each ``precedence.yaml`` override
   ``before/after`` pair is processed in declaration order. If ``before``
   is already ahead of ``after``, no-op. Otherwise ``before`` is moved
   to the slot immediately ahead of ``after``. Cycle detection raises
   :class:`PrecedenceError` so the operator notices an unsatisfiable
   pair instead of silently picking one.
3. **Status filter** — policies with ``status: deleted`` are excluded
   so the result reflects what the applier would actually push via
   :meth:`PoliciesAPI.set_precedence`.

``compare_to_live(resolved, live_records, *, env)`` strips env suffixes
off live names, filters down to slugs present in the resolved list, and
returns a :class:`PrecedenceComparison` whose ``matches`` field is true
only when the two slug sequences are identical. Live-only extras
(unmanaged hand-created policies) are filtered out so they don't
dominate the comparison.

### Phase 5 hook

The applier's step-4 precedence hook (see :func:`apply_change_set`) is
the natural follow-on: build the resolver output for the apply env,
call :meth:`PoliciesAPI.set_precedence` per platform with the ordered
IDs. The precedence command exists in advance of that wiring so
operators can preview what the applier will eventually do.

### Test pattern

Same shape as the differ tests: ``test_status.py`` and
``test_precedence_resolver.py`` build hand-rolled live records or
:class:`csfwctl.loader.ConfigRepo` instances directly; the CLI
command-body tests (``test_status_cmd.py``, ``test_precedence_cmd.py``)
inject a stub state provider so no real FalconPy traffic happens.
The realistic fixture's ``precedence.yaml`` exercises the override
path end-to-end through the CLI.

## Linter (Phase 7)

``csfwctl/linter.py`` adds the semantic checks that were intentionally
left out of the loader. The split mirrors the differ/loader split: the
loader runs the hard rules whose failure cannot be ignored (Pydantic
schema validation, platform mismatches, missing cross-references, a
tombstone that still has a YAML file); the linter runs softer rules
whose findings the operator may legitimately want to suppress on a
per-rule basis.

**Rule architecture.** Every built-in is a small class implementing the
:class:`csfwctl.linter.Lint` protocol — a stable ``rule_id``, a
``default_severity``, and a ``check(ctx) -> list[LintFinding]`` method.
Instances are kept in :data:`LINT_REGISTRY`, an ordered dict keyed by
``rule_id``. ``register_lint(my_lint)`` is the public seam for
site-specific rules to plug in at import time without touching the
core module.

**Findings.** :class:`LintFinding` carries the same fields as a
:class:`csfwctl.loader.LoadError` (path, line, dotted field path,
message) plus a ``rule_id`` and a :class:`Severity`. The shared shape
lets the ``validate`` renderer format loader errors and lint findings
through the same code path. ``LintFinding.to_json()`` is the form the
Phase 8 notifiers consume.

**Configuration.** The ``[lint]`` section of ``csfwctl.toml`` carries
two knobs:

- ``disabled``: list of ``rule_id`` strings to skip entirely.
- ``options``: dict keyed by ``rule_id``; the matching rule interprets
  its own options (see :class:`BroadAllowLint` for an example shape).

Runtime overrides may be passed to :func:`run_lints` directly; they
union with the file-based config so command-line flags can always
loosen but not tighten the rule set.

**Built-in rules.**

- ``precedence-cycle`` calls
  :func:`csfwctl.precedence_resolver.resolve_precedence` and catches
  :class:`PrecedenceError`, surfacing the cycle at validate time so the
  operator catches it before the differ does.
- ``orphan-rule-group`` walks every active policy's ``rule_groups`` and
  flags rule groups no policy lists. Deleted-status rule groups are
  skipped (covered by ``deleted-without-tombstone``).
- ``policy-without-host-groups`` flags policies whose ``host_groups``
  map is empty — they cannot apply to anything.
- ``deleted-without-tombstone`` flags any YAML object with
  ``status: deleted`` whose name does not appear in the matching
  tombstone list. The loader already rejects the inverse (a tombstone
  whose YAML file still exists), so the two checks cover the full
  consistency contract together.
- ``broad-allow`` is a heuristic on ``action: allow`` rules: it warns
  when ``0.0.0.0/0`` or ``::/0`` appears in a non-negated address list,
  or when the rule has neither address nor port constraints on either
  endpoint. Rules with a connection-state qualifier (``established`` /
  ``related``) are exempt — that's a meaningful constraint.

**Validate integration.** ``run_validate`` runs the loader first; on
success it calls :func:`run_lints` and prints every finding to stderr.
``error`` findings always fail the command. ``warning``/``info`` are
non-fatal by default; ``--strict`` promotes them to fatal so a CI job
can require a clean run.

**Test pattern.** ``tests/unit/test_linter.py`` exercises each rule
with both filesystem-based fixtures (the realistic and minimal config
repos plus an ``empty_repo`` builder) and hand-rolled in-memory
:class:`ConfigRepo` instances for states the loader rejects (e.g., a
deleted YAML object plus a matching tombstone — the loader rejects the
"matching" case, but the lint must still get the answer right when
called programmatically). ``test_validate_cmd.py`` covers the CLI
integration including ``--strict``.

## Drift-check job (Phase 9)

``csfwctl/drift_cmd.py`` is the scheduled-monitor sibling of
``diff_cmd``. The diff engine itself is shared: drift-check loads the
config repo, fetches live state, and calls
:func:`csfwctl.differ.compute_diff` with the named ``--env``. The two
things drift-check adds on top are persistent state and a
detected/cleared transition model on the notifier bus.

**State file.** Per-env, JSON, default path
``<repo>/.csfwctl/drift-state-<env>.json``. The shape is fixed:

```json
{
  "env":      "production",
  "has_drift": true,
  "last_run":  "2026-05-21T14:00:00+00:00",
  "summary":   { "creates": 1, "updates": 0, "deletes": 0, "unmanaged": 0 }
}
```

``save_drift_state`` writes via a ``<name>.tmp`` + rename so a crashed
job never leaves a half-written file. ``load_drift_state`` treats
missing or malformed files as "no prior run" and logs at WARNING — a
corrupted state must never block the monitor.

**Transition model.** Two consecutive verdicts (``prior.has_drift`` and
``drift_now``) yield one of four labels — ``stable`` / ``detected`` /
``ongoing`` / ``cleared`` — and at most one event:

- ``drift.detected`` (severity ``warn``) fires on ``detected``
  transitions and on ``ongoing`` transitions whose ``last_alerted``
  timestamp is outside the alert window (see Phase 10 section below).
- ``drift.cleared`` (severity ``info``) fires only on the
  ``cleared`` transition.
- ``stable`` runs (no prior drift, no current drift) emit nothing — a
  healthy monitor stays quiet.

The ``--no-state`` flag disables state read+write entirely;
``drift.cleared`` cannot fire in that mode, and ``drift.detected``
behaves like a stateless diff. Suitable for ad-hoc operator runs from a
laptop.

**Event payload.** ``drift.detected`` carries ``details = { env,
summary, change_set }`` where ``change_set`` is the full
:meth:`ChangeSet.to_json` payload — same shape MR comments and
dashboards already consume. ``drift.cleared`` carries
``previous_summary`` and ``previous_run`` so a receiver can show what
just resolved.

**Exit codes.** Default ``0`` regardless of verdict, so a cron line
``csfwctl drift-check --env production`` stays quiet on success. The
``--fail-on-drift`` flag swaps the drift case to exit ``2``, distinct
from the ``1`` reserved for infrastructure failures (repo load or
live-state fetch). CI pipelines that want a hard signal opt in.

**Test pattern.** ``tests/unit/test_drift_cmd.py`` reuses the
``state_provider`` test seam from ``diff_cmd`` and patches
``csfwctl.drift_cmd.emit`` to a list-recorder so each transition's
event payload can be asserted in isolation. The state file lives in
``tmp_path`` per-test so the four transitions (first run clean, first
run drifted, drift→clear, repeated drift) can be set up by
hand-writing the prior state and exercising one call.

## Alert deduplication (Phase 10)

**Problem.** The Phase 9 drift-check job emits ``drift.detected`` on every
run that finds drift, including the ``ongoing`` case. A one-hour cron job
would page the Teams channel 24 times per day for a single unresolved
incident — noisy enough that operators start ignoring it.

**Solution.** Add ``last_alerted: str | None`` to ``DriftState``. The field
records the ISO-8601 UTC timestamp of the last emitted ``drift.detected``
event. A helper ``_should_alert(prior, alert_window_minutes)`` returns
``False`` when the elapsed time since ``last_alerted`` is less than the
configured window, suppressing the repeat page.

```
drift.detected fires when:
  drift_now AND (
    last_alerted is None          ← first alert for this incident
    OR now - last_alerted ≥ window  ← window expired; re-page
  )
```

``drift.cleared`` resets ``last_alerted`` to ``None`` in the saved state
so the first recurrence after resolution always pages immediately regardless
of the previous ``last_alerted`` value.

**State file compatibility.** ``DriftState.from_json`` already uses
``data.get(...)`` for optional fields; ``last_alerted`` defaults to ``None``
for Phase 9 state files that lack the key. No migration needed.

**CLI surface.** ``--alert-window N`` (default 60 minutes) exposes the
window to operators. ``N=0`` disables windowing entirely (Phase 9
behaviour) for environments that need every run to page, or for testing.

**Test pattern.** Tests write a prior ``DriftState`` with a specific
``last_alerted`` timestamp (either ``datetime.now(UTC).isoformat()`` for
"inside window" or a day-old timestamp for "outside window") and assert
whether the captured events list is empty or contains one event. The
``DEFAULT_ALERT_WINDOW_MINUTES`` constant is exported so tests can assert
its documented value without hard-coding the integer.

## Credentials and profiles

- Env vars (`CSFWCTL_CLIENT_ID` / `CSFWCTL_CLIENT_SECRET`) take
  precedence so CI can inject scoped tokens per job (the GitLab
  config-repo pipeline binds the read-only or read/write client per
  stage).
- File fallback at `/etc/csfwctl/credentials.toml` with
  `[profile.<name>]` tables. `--profile` selects which.
- File path resolution order: `--credentials-file PATH` flag, then
  `$CSFWCTL_CREDENTIALS_PATH`, then `/etc/csfwctl/credentials.toml`.
  The flag is the explicit override for local development where
  exporting env vars is inconvenient.
- The CLI's `--profile {prod|dev}` from the project plan maps directly
  to a TOML profile name; ``readonly``/``readwrite`` is the convention
  for production CI.
- ``load_credentials`` logs the resolved source at INFO so operators
  can confirm which credentials file was read (or that env vars were
  used) without enabling debug output.
