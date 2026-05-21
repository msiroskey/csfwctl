# Notifications

Reference for the pluggable notifier system. Configure channels in
`csfwctl.toml`; each channel receives events routed by glob pattern.

---

## Event types

| Type | Severity | Emitted by |
|------|----------|------------|
| `validate.failed` | `error` | `csfwctl validate` on fatal findings |
| `diff.changes_detected` | `warn` | `csfwctl diff` when changes exist |
| `apply.started` | `info` | `csfwctl apply` before any writes |
| `apply.succeeded` | `info` | `csfwctl apply` on completion |
| `apply.failed` | `error` | `csfwctl apply` on safety or API error |
| `drift.detected` | `warn` | Drift-check job (Phase 10) |
| `drift.cleared` | `info` | Drift-check job (Phase 10) |
| `notify.test` | `info` | `csfwctl notify-test` only |

---

## Event payload

Every event carries:

```json
{
  "type":       "apply.succeeded",
  "severity":   "info",
  "timestamp":  "2026-05-21T14:30:00.000000+00:00",
  "env":        "production",
  "git_sha":    "abc1234",
  "summary":    "apply succeeded for env=production",
  "details":    { ... },
  "request_id": "req_aabbccddee"
}
```

The `details` dict is event-specific. For `apply.succeeded` it contains
the full `ApplyReport.to_json()` payload under the `"report"` key. For
`validate.failed` it contains a `"findings"` list of
`LintFinding.to_json()` objects.

---

## Routing

Each channel's `events` list accepts glob patterns matched with
`fnmatch`. The `*` wildcard matches within a single component:

```toml
events = ["apply.*"]         # apply.started, apply.succeeded, apply.failed
events = ["*"]               # every event type
events = ["drift.detected"]  # exact match
```

---

## Channels

### `log` — JSON Lines file

Appends one JSON object per event to a file. Creates parent directories
as needed. Suitable as an audit trail.

```toml
[notifications.log]
path   = "/var/log/csfwctl/events.jsonl"
events = ["*"]
```

### `console` — Rich console

Prints a severity-coloured one-liner to stderr. Automatically suppressed
when the `CI` environment variable is set.

```toml
[notifications.console]
events = ["apply.*", "validate.*"]
```

### `teams` — Microsoft Teams webhook

Posts a MessageCard to a Teams incoming webhook. The webhook URL is read
from an environment variable (never stored in the config repo).

```toml
[notifications.teams]
url_env = "TEAMS_WEBHOOK_URL"   # env var containing the webhook URL
events  = ["apply.failed", "drift.detected"]
```

### `gitlab` — GitLab MR comment

Posts a Markdown comment to a GitLab merge request. Designed for use in
GitLab CI where project ID and MR IID are available as built-in
variables.

```toml
[notifications.gitlab]
token_env      = "GITLAB_TOKEN"          # env var with API token
project_id_env = "CI_PROJECT_ID"         # or: project_id = "123"
mr_iid_env     = "CI_MERGE_REQUEST_IID"  # or: mr_iid = "42"
api_url        = "https://gitlab.com"    # optional; default gitlab.com
events         = ["diff.changes_detected", "validate.failed"]
```

### `syslog` — RFC 5424 UDP syslog

Sends RFC 5424-formatted datagrams over UDP to a remote syslog daemon.

```toml
[notifications.syslog]
host     = "syslog.example.edu"
port     = 514
facility = "local3"
events   = ["apply.*", "drift.*"]
```

Valid facility names: `kern`, `user`, `mail`, `daemon`, `auth`,
`syslog`, `lpr`, `news`, `uucp`, `cron`, `local0`–`local7`.

---

## Testing channels

```
csfwctl notify-test [--channel CHANNEL] [--repo PATH]
```

Sends a synthetic `notify.test` event directly to one or all configured
channels, bypassing event routing so the channel is exercised regardless
of its `events` filter. Exit 0 if at least one channel succeeded; exit 1
if all failed.

---

## Adding a custom channel

1. Create a class with `name: str`, `supports(event_type) -> bool`, and
   `send(event) -> None`.
2. Call `csfwctl.notifiers.register_notifier("my-channel", MyNotifier)`
   at import time from a site-local module.
3. Add `[notifications.my-channel]` to `csfwctl.toml`.
