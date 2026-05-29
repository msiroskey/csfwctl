# csfwctl-config CI setup

How to configure the `csfwctl-config` repository's GitLab CI pipeline to
install and run `csfwctl`. This covers the SSH deploy key needed for
authenticated access, the CI/CD variables, and an annotated example
`.gitlab-ci.yml`.

---

## Table of contents

1. [Overview](#overview)
2. [SSH deploy key setup](#ssh-deploy-key-setup)
3. [CI/CD variables reference](#cicd-variables-reference)
4. [Example .gitlab-ci.yml](#example-gitlab-ciyml)
5. [Pipeline behaviour](#pipeline-behaviour)
6. [Scheduling the drift-check job](#scheduling-the-drift-check-job)

---

## Overview

`csfwctl-config` does not vendor `csfwctl`. Instead, the CI pipeline installs
it at the start of every job via pip over SSH:

```bash
pip install "git+ssh://git@gitlab.example.com/group/csfwctl.git@main"
```

Swap `@main` for a tag (e.g. `@v1.2.0`) when you want jobs to pin to a
specific release rather than always tracking the latest commit on `main`.

Because the GitLab instance does not have HTTPS token authentication configured
for package installs, access is granted through an SSH deploy key scoped to the
`csfwctl` repository with read-only permissions.

---

## SSH deploy key setup

### 1 — Generate the key pair

Run this on an admin workstation. Do not set a passphrase (the private key
will be stored as a CI variable and must be usable non-interactively).

```bash
ssh-keygen -t ed25519 \
  -C "csfwctl-config CI deploy key" \
  -f csfwctl_deploy_key \
  -N ""
```

This produces two files:

| File | Contents |
|---|---|
| `csfwctl_deploy_key` | Private key — goes into GitLab CI variable |
| `csfwctl_deploy_key.pub` | Public key — goes into GitLab Deploy Keys |

### 2 — Add the public key to the `csfwctl` repository

In the `csfwctl` GitLab project:

1. Go to **Settings → Repository → Deploy Keys**.
2. Click **Add new deploy key**.
3. **Title:** `csfwctl-config CI`
4. **Key:** paste the full contents of `csfwctl_deploy_key.pub`.
5. Leave **Grant write permissions to this key** unchecked (read-only is sufficient).
6. Click **Add key**.

### 3 — Add the private key to `csfwctl-config`

GitLab's masked variable feature rejects values that contain whitespace.
SSH private keys contain newlines, so the key must be base64-encoded before
storing. The CI pipeline decodes it at runtime.

**Encode the private key** (run on the admin workstation):

```bash
# Linux
base64 -w 0 csfwctl_deploy_key

# macOS
base64 -i csfwctl_deploy_key
```

Copy the single-line output — that is the value to store.

In the `csfwctl-config` GitLab project:

1. Go to **Settings → CI/CD → Variables**.
2. Click **Add variable**.
3. Fill in:

   | Field | Value |
   |---|---|
   | Key | `CSFWCTL_DEPLOY_KEY` |
   | Value | The base64-encoded string from the step above |
   | Type | Variable |
   | Protect variable | Checked (only available on protected branches) |
   | Mask variable | Checked (hidden in job logs) |

4. Click **Add variable**.

### 4 — Delete the local key files

```bash
rm csfwctl_deploy_key csfwctl_deploy_key.pub
```

The private key now exists only inside GitLab. Do not commit it or store
it anywhere else.

---

## CI/CD variables reference

Set these in `csfwctl-config` → **Settings → CI/CD → Variables**.
Where a variable is environment-scoped, create one entry per GitLab
environment (`test`, `pilot`, `production`).

| Variable | Scope | Masked | Description |
|---|---|---|---|
| `CSFWCTL_DEPLOY_KEY` | All | Yes | SSH private key for `pip install` from `csfwctl` |
| `CSFWCTL_VERSION` | All | No | Branch, tag, or SHA to install (e.g. `main`, `v1.2.0`) |
| `CSFWCTL_CLIENT_ID` | Per env | Yes | CrowdStrike Falcon API client ID |
| `CSFWCTL_CLIENT_SECRET` | Per env | Yes | CrowdStrike Falcon API client secret |
| `CSFWCTL_ALLOW_DELETE` | Per env | No | Set to `1` to enable deletions in that environment |
| `HTTP_PROXY` | All | No | Corporate proxy URL (if required) |
| `HTTPS_PROXY` | All | No | Corporate proxy URL (if required) |
| `NO_PROXY` | All | No | Comma-separated list of hosts that bypass the proxy |

`CSFWCTL_CLIENT_ID` and `CSFWCTL_CLIENT_SECRET` should use separate
read-only API clients for `validate`, `diff`, and `drift-check` jobs, and
separate read/write clients for `apply-*` jobs. Use GitLab's environment
scope to keep them apart. See [Credential rotation](operations.md#credential-rotation).

---

## Example .gitlab-ci.yml

This is a reference starting point for `csfwctl-config`. Adjust environment
names, approval counts, and notifier config to match your deployment.

```yaml
stages:
  - validate
  - apply-test
  - apply-pilot
  - apply-production

variables:
  CSFWCTL_VERSION: "main"      # pin to a tag for stability: "v1.2.0"
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.cache/pip"

# ─── Shared template ─────────────────────────────────────────────────────────

# All jobs extend this template. It sets the Docker image and runner tag
# explicitly so that image/tags are never lost through an extends chain,
# installs openssh-client (absent from slim images), configures the SSH
# agent with the base64-encoded deploy key, and pip-installs csfwctl.
.csfwctl-job:
  image: python:3.11-slim
  tags:
    - docker
  variables:
    HTTP_PROXY: "$HTTP_PROXY"
    HTTPS_PROXY: "$HTTPS_PROXY"
    NO_PROXY: "$NO_PROXY"
    http_proxy: "$HTTP_PROXY"
    https_proxy: "$HTTPS_PROXY"
    no_proxy: "$NO_PROXY"
  cache:
    key: csfwctl-$CSFWCTL_VERSION
    paths:
      - .cache/pip/
  before_script:
    - apt-get update -qq && apt-get install -y openssh-client --no-install-recommends -qq
    - eval $(ssh-agent -s)
    - echo "$CSFWCTL_DEPLOY_KEY" | base64 -d > /tmp/csfwctl_deploy_key
    - chmod 600 /tmp/csfwctl_deploy_key
    - ssh-add /tmp/csfwctl_deploy_key
    - rm -f /tmp/csfwctl_deploy_key
    - mkdir -p ~/.ssh && chmod 700 ~/.ssh
    - ssh-keyscan -H gitlab.example.com >> ~/.ssh/known_hosts
    - chmod 644 ~/.ssh/known_hosts
    - pip install --upgrade pip --quiet
    - pip install "git+ssh://git@gitlab.example.com/group/csfwctl.git@${CSFWCTL_VERSION}" --quiet

# ─── Validate (runs on MRs and main) ─────────────────────────────────────────

validate:
  extends: .csfwctl-job
  stage: validate
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - csfwctl validate --repo .

# Posts a diff of planned Test changes as a comment on the MR.
diff-test:
  extends: .csfwctl-job
  stage: validate
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - csfwctl diff --env test --repo .

# ─── Apply — Test (automatic on merge) ───────────────────────────────────────

apply-test:
  extends: .csfwctl-job
  stage: apply-test
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment:
    name: test
  script:
    - csfwctl apply --env test --repo .

# ─── Apply — Pilot (manual gate, 1 approver) ─────────────────────────────────

apply-pilot:
  extends: .csfwctl-job
  stage: apply-pilot
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  environment:
    name: pilot
  script:
    - csfwctl apply --env pilot --repo .

# ─── Apply — Production (manual gate, 2 approvers) ───────────────────────────

apply-production:
  extends: .csfwctl-job
  stage: apply-production
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: manual
  environment:
    name: production
  script:
    - csfwctl apply --env production --repo .

# ─── Drift check (scheduled) ─────────────────────────────────────────────────

drift-check:
  extends: .csfwctl-job
  stage: validate
  rules:
    - if: $CI_PIPELINE_SOURCE == "schedule"
  script:
    - csfwctl drift-check --env production --repo .
```

Replace `gitlab.example.com` and `group/csfwctl` with your actual GitLab
hostname and project path.

---

## Pipeline behaviour

| Trigger | Jobs that run |
|---|---|
| Merge request opened / updated | `validate`, `diff-test` |
| Merge to `main` | `validate`, `apply-test`, then `apply-pilot` and `apply-production` on manual trigger |
| Scheduled pipeline | `validate`, `drift-check` |

**`apply-pilot`** and **`apply-production`** are `when: manual`. They appear
in the GitLab pipeline UI as blocked jobs. Use GitLab Environments with
required approvals to enforce the approval count — one approver for Pilot,
two for Production. Set this up in `csfwctl-config` →
**Settings → CI/CD → Environments**.

`CSFWCTL_ALLOW_DELETE=1` must be set in the relevant GitLab environment
before triggering an apply job that includes deletions. The CI pipeline will
surface planned deletions in the `diff-test` MR comment so they are visible
before approval. See [Deleting a managed object](operations.md#deleting-a-managed-object).

---

## Scheduling the drift-check job

1. In `csfwctl-config`, go to **CI/CD → Schedules → Create a new schedule**.
2. **Description:** `Drift check — production`
3. **Interval:** `0 * * * *` (every hour, on the hour)
4. **Target branch:** `main`
5. Leave **Variables** empty — the schedule uses the project-level CI variables.
6. Save.

The `drift-check` job runs `csfwctl drift-check --env production --repo .`.
Alerts fire through whichever notifier channels are configured in
`csfwctl.toml`. See [Responding to drift alerts](operations.md#responding-to-drift-alerts).
