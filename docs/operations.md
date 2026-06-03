# Operations

Runbooks for csfwctl: initial onboarding, rollback, drift response,
credential rotation.

---

## Table of contents

1. [Onboarding a new admin](#onboarding-a-new-admin)
2. [Writing and promoting a policy change](#writing-and-promoting-a-policy-change)
3. [Rolling back a policy change](#rolling-back-a-policy-change)
4. [Responding to drift alerts](#responding-to-drift-alerts)
5. [Initial tenant bootstrap](#initial-tenant-bootstrap)
6. [Credential rotation](#credential-rotation)
7. [Recording fixtures](#recording-fixtures)
8. [Troubleshooting](#troubleshooting)

---

## Onboarding a new admin

**Time required:** approximately 30 minutes.

### Prerequisites

- Python 3.11 or later on the admin workstation.
- Read access to the `csfwctl` code repository (GitHub).
- Read access to the `csfwctl-config` data repository (internal GitLab).
- CrowdStrike Falcon console access (read-only is sufficient for day-to-day work).
- GitLab account in the `firewall-admins` group (required to approve Pilot jobs).

### Install csfwctl

```bash
# Clone the code repo
git clone https://github.com/msiroskey/csfwctl.git
cd csfwctl

# Install into a local venv (no root needed for development use)
make dev

# Verify the install
csfwctl --help
```

For production installs that need the wrapper at `/usr/local/bin/csfwctl`:

```bash
sudo make install   # installs to /opt/csfwctl + /usr/local/bin/csfwctl
```

### Configure credentials

Credentials live in `/etc/csfwctl/credentials.toml` (production) or
`~/.config/csfwctl/credentials.toml` (personal dev). The file format is:

```toml
[prod]
client_id     = "YOUR_FALCON_CLIENT_ID"
client_secret = "YOUR_FALCON_CLIENT_SECRET"

[dev]
client_id     = "DEV_CLIENT_ID"
client_secret = "DEV_CLIENT_SECRET"
```

Alternatively, export environment variables for CI or ad-hoc use:

```bash
export CSFWCTL_CLIENT_ID="..."
export CSFWCTL_CLIENT_SECRET="..."
```

Credentials are resolved in this order (highest priority first):

1. `CSFWCTL_CLIENT_ID` / `CSFWCTL_CLIENT_SECRET` env vars.
2. `--credentials-file PATH` flag.
3. `$CSFWCTL_CREDENTIALS_PATH` env var pointing at a TOML file.
4. `/etc/csfwctl/credentials.toml`.

The credentials file **must be mode `0o600`** (owner read/write only). The
loader refuses files with any group- or world-readable bits set; restrict
access with `chmod 600 /etc/csfwctl/credentials.toml`. The `base_url`
must use `https://`; loopback HTTP is only accepted for local testing.

### Clone the config repo

```bash
git clone https://gitlab.example.edu/infosec/csfwctl-config.git
cd csfwctl-config
```

### Validate the current state

```bash
csfwctl validate --repo .
```

This performs a full schema and semantic lint without touching the tenant.
Exit 0 means the repo is clean.

### Review what is deployed

```bash
# Show all managed/unmanaged objects in the tenant
csfwctl status --all-envs --repo .

# See resolved policy precedence
csfwctl precedence --repo .

# Compare YAML to live state for Production
csfwctl diff --env production --repo .
```

---

## Writing and promoting a policy change

### 1. Create or edit a YAML file

All firewall objects live in the `csfwctl-config` repository under
`policies/`, `rule_groups/`, or `locations/`. Filenames are
`lowercase-kebab-case` slugs; object display names inside the file follow
`TitleCase-With-Hyphens`.

Example — add a rule to an existing rule group:

```bash
# Open the rule group in your editor
$EDITOR rule_groups/windows-baseline.yaml
```

Follow the schema documented in `docs/schema_reference.md`. Key points:

- `name` is the slug (e.g. `windows-baseline`); the environment suffix
  (`-Test`, `-Pilot`, `-Production`) is appended by csfwctl at apply time.
- `platform` must match every policy that references this rule group.
- Rule names must be unique within the rule group.

### 2. Validate locally

```bash
csfwctl validate --repo .          # schema + cross-ref
csfwctl validate --repo . --strict # promotes warnings to fatal
```

Fix any errors or warnings before opening a merge request.

### 3. Preview the change

```bash
csfwctl diff --env test --repo .
```

The diff shows exactly what csfwctl will create, update, or delete in the
Test environment. If the output is unexpected, review your YAML.

### 4. Open a merge request

Push your branch to the internal GitLab and open an MR against `main`.
The CI pipeline will automatically:

- Run `csfwctl validate`.
- Run `csfwctl diff --env test` and post the diff as an MR comment.

Review the MR comment diff to confirm the intended changes.

### 5. Merge and apply to Test

Merge the MR. The `apply-test` CI job runs automatically and applies the
change to the Test environment. Check the job log for the apply summary.

### 6. Apply to Pilot (manual gate, 1 approver)

In the GitLab CI pipeline for the merged commit, trigger the `apply-pilot`
job manually. One member of `firewall-admins` must approve the job in the
GitLab Pilot environment before it runs.

### 7. Apply to Production (manual gate, 2 approvers)

Trigger `apply-prod` manually. Two members of `firewall-admins` must approve.

Production applies the same commit SHA that was tested in Test and Pilot.
Nothing is recomputed between environments.

### Precedence changes

If you add a new policy or want to override the default bucket-based
ordering, update `precedence.yaml`:

```yaml
overrides:
  - before: emergency-incident-response-windows
    after: research-lab-7-windows
```

Run `csfwctl precedence --repo .` to verify the resolved order before
opening the MR.

### Deleting a managed object

Deletions require an explicit tombstone in `tombstones.yaml` and the
`--allow-delete` flag at apply time. Add the tombstone entry:

```yaml
policies:
  - name: legacy-vpn-policy
    deleted_in_sha: abc1234
    reason: Replaced by remote-access-windows
```

The CI pipeline will surface the planned deletion in the MR diff comment.
The `apply-*` jobs pass `--allow-delete` only when the environment variable
`CSFWCTL_ALLOW_DELETE=1` is set in the GitLab environment. Set it in the
GitLab CI variable configuration before triggering the apply job.

---

## Rolling back a policy change

The full audit trail lives in Git. Rolling back is a `git revert` followed
by a re-apply — no console interaction required.

**Target time:** under 15 minutes from decision to Production rollback for
a simple revert. Complex conflicts may take longer.

### Step-by-step

1. **Identify the SHA to revert.**

   ```bash
   git log --oneline -20
   # Find the commit that introduced the bad change
   ```

2. **Revert the commit and open an MR.**

   ```bash
   git revert <sha> --no-edit
   git push origin HEAD -u
   # Open an MR on the internal GitLab against main
   ```

   The CI pipeline validates the revert and posts a diff showing the
   reversal. The diff should be the mirror image of the original change.

3. **Merge and promote.**

   Merge the revert MR. The `apply-test` job runs automatically. Once
   Test is clean, trigger `apply-pilot` and then `apply-prod` through the
   normal manual approval flow.

4. **Verify.**

   ```bash
   csfwctl diff --env production --repo .
   ```

   The diff should be empty (no changes). If it is not, check whether the
   original change modified objects that have since been touched again by
   another MR, and resolve accordingly.

### Fast-path: Production-only emergency rollback

If the bad change has already reached Production and is causing an incident,
you can revert Production first while the MR review is in progress:

> **Note:** This creates intentional drift between Production and Test/Pilot
> until the revert MR is merged. Acknowledge the drift in the GitLab thread.

```bash
# On the admin workstation with production credentials
git revert <sha> --no-edit
# Apply the revert directly to Production (bypasses the normal gate)
csfwctl apply --env production --enforce --repo /path/to/config-repo
```

`--enforce` is required because the revert will appear as drift vs. the
current `main` state. Immediately open the revert MR to bring `main` back
in sync.

### What cannot be rolled back automatically

- **Name changes.** CrowdStrike object names never change once set.
  If the bad change renamed an object, the revert will recreate the old name
  but the new name will remain in the tenant as an unmanaged object.
  Use `csfwctl status` to identify it and delete it manually via the console,
  then add a tombstone so csfwctl knows it is gone.
- **Precedence reordering.** The precedence order is rewritten on every apply;
  a `git revert` + apply restores the previous order.

---

## Responding to drift alerts

The drift-check job runs hourly against Production. A `drift.detected` event
means the live tenant state no longer matches the YAML in `main`. This
usually indicates one of the following:

1. Someone made a manual change in the CrowdStrike console.
2. A CrowdStrike platform update modified a managed object's attributes.
3. A previous apply partially succeeded and left the tenant in a mid-state.

### Investigate

```bash
# Pull the latest diff (use --output to capture for later)
csfwctl diff --env production --repo /path/to/config-repo \
    --output /tmp/drift-$(date +%Y%m%d-%H%M%S).json

# Look at the human-readable output for the affected objects
```

The diff output labels each change with its kind (create / update / delete)
and the affected fields. A field named `description` that only shows a
signature version bump is noise (the applier rewrites descriptions); focus
on rule or host-group changes.

### Resolve: re-apply YAML state

If the drift is unwanted (a console edit that should be reverted):

```bash
csfwctl apply --env production --enforce --repo /path/to/config-repo
```

`--enforce` permits csfwctl to overwrite the drifted state. Without it,
apply refuses to modify objects whose live state differs from the prior
apply.

If this is an emergency and the blast-radius limits are exceeded:

```bash
csfwctl apply --env production --enforce \
    --max-changes 50 --max-deletes 5 \
    --repo /path/to/config-repo
```

### Resolve: accept the console change as authoritative

If the console change is intentional and should become the new desired state,
import the affected object and update the YAML:

```bash
csfwctl import policy "PolicyName-Production" --strip-env-suffix \
    --output /tmp/imported.yaml
# Diff the imported file against the current YAML and merge intentional changes
```

Commit the updated YAML via the normal MR workflow so the change is tracked
in Git.

### Alert deduplication

The drift-check job emits `drift.detected` on the first drifted run, then
suppresses repeated alerts for the same incident for 60 minutes (configurable
via `--alert-window`). If drift persists across the window, another alert
fires to remind the operator. Once drift resolves, `drift.cleared` is emitted
exactly once.

To force an immediate re-alert for an ongoing incident (e.g., after a shift
handoff), delete the state file and re-run the drift-check job:

```bash
rm /path/to/config-repo/.csfwctl/drift-state-production.json
csfwctl drift-check --env production --repo /path/to/config-repo
```

---

## Initial tenant bootstrap

Bootstrap runs once per tenant, before the first normal apply. It stamps
the csfwctl metadata signature on every existing CrowdStrike object that
matches a YAML file, without modifying any rule content.

### Prerequisites

- The `csfwctl-config` repo is populated (via `csfwctl import all` or
  by hand) and passes `csfwctl validate`.
- Read/write CrowdStrike credentials are available.

### Procedure

```bash
# Dry run first — review what will be touched
csfwctl apply --env test --initial-bootstrap --dry-run --repo .

# If the dry run looks correct, apply for real
csfwctl apply --env test --initial-bootstrap --repo .
```

Repeat for `--env pilot` and `--env production`.

After bootstrap, `csfwctl status --all-envs` should show all expected
objects as managed (`[M]`) with `version: 1`.

### First normal apply after bootstrap

After bootstrap the objects carry version:1 signatures. Any subsequent
`apply` that touches those objects — including the very first CI
`apply-test` run — **must pass `--enforce`**. Without it, the drift gate
blocks the apply because it sees managed objects whose live state differs
from the YAML (the intentional changes you are about to apply).

```bash
csfwctl apply --env test --enforce --repo .
```

`--enforce` tells csfwctl "this change is intentional; I reviewed the
diff." It is safe to use unconditionally in CI because the MR review
(including the diff comment posted by CI) is the gate that confirms
intent. The drift gate is a guard for *unexpected* console edits; it is
not meant to block planned CI applies.

> **CI configuration:** every `apply-test`, `apply-pilot`, and
> `apply-prod` GitLab job should always pass `--enforce`.

### What bootstrap does not do

- It does not create new objects. YAML entries with no matching live object
  are logged as warnings; create them with a subsequent normal apply.
- It does not modify rules, locations, or precedence.
- It does not remove unmanaged objects. Use `csfwctl status` to identify
  them; decide whether to import them into YAML or leave them unmanaged.

---

## Credential rotation

CrowdStrike API clients have a fixed expiry. Rotate before expiry by creating
the new client in the Falcon console and updating the credentials in the
appropriate store.

### GitLab CI rotation

1. In the Falcon console, create a new read-only API client for
   `drift-check` / `validate` / `diff` jobs, and a new read/write client
   for `apply-*` jobs.
2. In the GitLab project → Settings → CI/CD → Variables, update
   `CSFWCTL_CLIENT_ID` and `CSFWCTL_CLIENT_SECRET` for each GitLab
   environment (`test`, `pilot`, `production`).
3. Trigger a manual `validate` pipeline run to confirm the new credentials
   work before the old ones expire.
4. Revoke the old clients in the Falcon console.

### Admin workstation rotation

1. Create the new client in the Falcon console.
2. Update `/etc/csfwctl/credentials.toml` (or your personal credentials
   file) with the new `client_id` and `client_secret`.
3. Verify: `csfwctl status` (read-only, safe to run at any time).
4. Revoke the old client.

---

## Troubleshooting

### `csfwctl apply` refuses to run (unbootstrapped tenant)

```
Error: tenant is not bootstrapped. Re-run with --initial-bootstrap.
```

Run the [Initial tenant bootstrap](#initial-tenant-bootstrap) procedure.
This is a one-time operation.

### `csfwctl apply` refuses due to drift

```
apply: 1 managed object(s) have drifted: policy:foo. Rerun with --enforce to overwrite drifted state.
```

**In CI (`apply-test` / `apply-pilot` / `apply-prod`):** always pass
`--enforce`. CI applies are intentional YAML changes; `--enforce` is
required to apply them to managed objects. See
[First normal apply after bootstrap](#first-normal-apply-after-bootstrap).

**On a workstation:** review the unexpected change first, then decide.
See [Responding to drift alerts](#responding-to-drift-alerts).

### Blast-radius limit exceeded

```
Error: blast radius exceeded: 12 changes planned, limit is 10
```

Review the planned changes with `csfwctl diff --env ...`. If the changes are
intentional, increase the limit explicitly:

```bash
csfwctl apply --env test --max-changes 15 --repo .
```

### Notifier not firing

1. Check the channel config in `csfwctl.toml`:
   - Does the `events` list include the event type? Glob patterns like
     `drift.*` or `apply.*` are supported.
   - Is the required env var set (`url_env`, `TEAMS_WEBHOOK_URL`, etc.)?
2. Send a test notification:
   ```bash
   csfwctl notify-test --channel teams --repo .
   ```
3. Check the log notifier at `/var/log/csfwctl/events.jsonl` for events
   that did reach the bus but were not routed to your channel.

### State file is corrupted / blocking drift-check

The drift-check job treats a missing or malformed state file as "no prior
run" and logs a warning. If the file is in a bad state, delete it:

```bash
rm /path/to/config-repo/.csfwctl/drift-state-production.json
```

The next drift-check run will create a fresh state file.

### `mypy` or `ruff` failures in CI

Run locally before pushing:

```bash
make lint    # ruff + mypy
make test    # pytest
```

Fix any issues before opening the MR. The CI pipeline mirrors these exact
commands.

---

## Recording fixtures

`csfwctl record-fixtures` captures sanitised API responses from a live
tenant for the integration test suite. The built-in
[`Sanitizer`](../csfwctl/fixtures.py) replaces UUIDs, IPv4/IPv6
addresses, CIDRs, hostnames with TLDs, email addresses, and MAC
addresses with deterministic stand-ins drawn from IANA-reserved
documentation ranges (RFC 5737 / 3849 / 7042; `example.test`). Anything
the regexes do not match is passed through verbatim.

### Pre-commit review checklist

After running `csfwctl record-fixtures --output tests/fixtures/api_responses`,
review every changed file before committing:

- [ ] No real CrowdStrike UUIDs (must start with `00000000-`).
- [ ] No real IPv4/IPv6 addresses or CIDRs (must be in `192.0.2.0/24`,
      `198.51.100.0/24`, `203.0.113.0/24`, or `2001:db8::/32`).
- [ ] No real hostnames (must end in `.example.test`).
- [ ] **No single-label internal hostnames** (e.g. `dc01`, `fileserver`,
      `print-server`). These are not caught by the hostname regex and
      must be added to `Sanitizer.preserve_substrings` or scrubbed
      manually.
- [ ] No MAC addresses outside the `00:00:5E` OUI.
- [ ] No real usernames, account IDs, project names, or other
      tenant-identifying tokens.
- [ ] No CrowdStrike client IDs or secrets in any field.

If anything slips through, scrub it manually before `git add`. The
fixtures are committed to a **public** repository.
