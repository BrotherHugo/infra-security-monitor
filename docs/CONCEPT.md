# Infra Security Monitor (ISM)

## Project goal

A system daemon collects summaries from host security tools, compresses verbose output into what an operator actually needs to read, stores history in SQLite, and at configured time slots sends a plain-text report through enabled channels (file / telegram / email).

The operator interprets the report or relies on optional AI analysis (`google-ai`, Gemini). An automatic "all clear, stay silent" verdict is a future phase.

## Context

Typical deployment: Ubuntu with fail2ban, unattended-upgrades, auditd, rkhunter, chkrootkit, and lynis already installed and scheduled. Some scanners write daily logs (`/var/log/rkhunter.log`, `/var/log/chkrootkit.log`). ISM does not replace hardening — it monitors and reports.

## Core concepts

**Collector module.** A package with a shared interface: for each name in `modules.enabled`, runs commands and/or reads a log, stores a raw snapshot in SQLite (`raw_json` — JSON with named blobs), and parses that snapshot into a short report section plus module status. One module = one tool. Empty or missing `modules.enabled` means all known modules. A module error does not abort the cycle: an `ERROR` section appears in the report.

**Delivery channel.** Sends the finished report text. A channel is active only if its section exists in `reporting.channels`. File — timestamped file in `save_to_dir`. Telegram — Bot API `sendMessage`, long body split into ≤4096-byte parts. Email — SMTP `text/plain`, all `to_emails` in one message. At least one channel is required at startup — otherwise the config is invalid (a report must go somewhere).

**Analyzer.** Optional modules that append a section to the end of the report body after assembly and before channel delivery. Enabled via an `analyzers` config section (same pattern as `reporting.channels`). The first implementation is `google-ai`: when `analyzers.google_ai` is set, it sends full raw module snapshots from the current cycle (`raw_json`, named blobs) to Gemini — not compressed `section_text`. The model response becomes appendix `=== AI analysis (google-ai) ===`. Shared prompt settings live under `analyzers` (`prompt`, `custom_rules`, `timeout_seconds`); credentials and model under `analyzers.google_ai`. `timeout_seconds` limits a single HTTP call per analyzer, not the entire AI phase. Analyzer errors do not block delivery: the appendix gets `ERROR: …`, and the run status may become `degraded`.

**Report cycle.** At each moment from `reporting.time` (timezone = `timezone` or host local): for each enabled module, collect (capture raw → parse → persist) → prune by `keep_history_days` → assemble unified text from sections → optionally append analyzer appendix (AI on raw data) → send to all configured channels. Reports always go out, even when findings are few — the operator needs the quiet picture too.

## Configuration

Default path: `/etc/ism/config.yaml`. On start the daemon validates config (manual `Validate()`, no env/validator libraries) and exits with a clear error if invalid. Secrets in v1 live in the same YAML (simplicity); external secret storage may come later.

```yaml
reporting:
  time:
    - "12:30"
  channels:
    file:
      save_to_dir: /var/lib/ism/reports
    # telegram:          # optional: Bot API sendMessage; long report split into ≤4096-byte parts
    #   token: "..."       # bot token
    #   chat_id: "..."     # chat or group ID (string)
    #   message_thread_id: 123  # optional: forum topic; omit for regular chats
    # email:             # optional: SMTP text/plain, all to_emails in one message
    #   host: "smtp.example.com"
    #   port: "587"        # 587 + use_tls (STARTTLS) or 465 + use_ssl (implicit TLS)
    #   user: "..."
    #   password: "..."
    #   use_tls: true      # STARTTLS; do not combine with use_ssl
    #   use_ssl: false
    #   from_email: "ism@example.com"
    #   to_emails:
    #     - "admin@example.com"

keep_history_days: 30
# timezone: Europe/Berlin     # optional; missing/empty = host local time

modules:
  # enabled:                  # optional; missing/empty = all modules
  #   - fail2ban
  #   - auditd
  #   - rkhunter
  #   - chkrootkit
  #   - lynis
  #   - unattended-upgrades
  fail2ban:
    jails:
      - sshd
      - nginx-limit-req
  rkhunter:
    report_path: /var/log/rkhunter.log
    launch_params:
      - --check
      - --skip-keypress
      - --report-warnings-only
      - --logfile
      - /var/log/rkhunter.log
  chkrootkit:
    report_path: /var/log/chkrootkit.log
    launch_params:
      - -q

# analyzers:                  # optional; section presence = enabled (like channels)
#   # prompt: |                # optional; fully replaces DefaultPrompt
#   # custom_rules: |          # optional; appended under Custom rules:
#   #   Write the entire answer in Russian.
#   timeout_seconds: 120       # per analyzer HTTP call
#   google_ai:
#     api_key: "..."           # Google AI Studio key
#     model: gemini-2.5-flash  # optional; default gemini-2.5-flash
```

Default SQLite path: `/var/lib/ism/ism.db`. The daemon runs as root (no `sudo` in commands). systemd installation on Ubuntu — see [README.md](../README.md).

## What modules show the operator (compression)

Full tool output does not go to channels — compressed `section_text` does. SQLite keeps the raw snapshot (`raw_json`) for re-parsing and analyzer input. Per-module rules for what stays in the operator section:

- **fail2ban** — per jail from `modules.fail2ban.jails`: currently/total failed, currently/total banned, banned IP list. Attention when `currently_banned > 0` or IP list non-empty; otherwise short `ok`.
- **auditd** — key lines from `aureport --summary`; config/anomaly/file reports aggregated (counts by type/auid/path, short sample, no raw dumps); `aureport --anomaly` for anomalies. Attention on failed logins > 0, anomaly > 0, or file events.
- **rkhunter** — if `report_path` is set and readable: parse the log (typical setup runs `--report-warnings-only`). Otherwise run with `launch_params`. Report: summary (suspect files, possible rootkits, warnings found) + warning lines. Account for common false positives (file properties after apt without `--propupd`).
- **chkrootkit** — same path/launch pattern. Report: not `not infected` / `nothing found`, but infected / suspect files / sniffer / chkutmp anomalies. Mark known false positives (systemd-networkd sniffer, fail2ban test `.htaccess`, Java chkutmp).
- **lynis** — live `lynis audit system --quick`: Hardening index, Warnings list (not Suggestions), test counters. Suggestions excluded in v1.
- **unattended-upgrades** — log tail plus problem signals: WARNING/ERROR, kept back, missing recent `All upgrades installed`.

No diff against the previous run in v1.

## CLI (shape only; implementation later)

Binary name tentatively `ism`. Out of MVP code scope, but the intended contract:

- `ism now` — one collect+report+send cycle immediately
- `ism report list` — dates; within a date — modules
- `ism report show` — specific report/run
- `ism report export` — export
- `ism module list` — module reports by date
- `ism module export` — module export for a time range
- `ism status` — last run, modules.enabled, paths
- `ism validate-config` — validate config without running a cycle

For MVP debugging, daemon flag `--once` is the temporary equivalent of `ism now`.

## Completed phases

1. Skeleton: config, SQLite, scheduler, fail2ban, text report, file channel.
2. Remaining collectors + `raw_json` persistence.
3. Telegram and email channels.
4. Optional `google-ai` analyzer: appendix at end of report from full raw logs.

CLI (`ism now`, `ism report …`) is outside MVP code; use `ismd --once` for manual runs.

---

_Last updated: 2026-09-01_
