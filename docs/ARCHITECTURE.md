# Architecture

High-level map of the Infra Security Monitor (ISM) codebase. For product goals, configuration semantics, and per-module output rules, see [CONCEPT.md](CONCEPT.md). For installation and day-to-day operation, see [README.md](../README.md).

## Bird's Eye View

ISM is a root-owned daemon that runs on a schedule (or once via CLI flag), collects security tool output from the host, stores history in SQLite, assembles a single plain-text report, optionally appends an AI analysis section, and delivers the result to one or more configured channels.

The input state is a YAML config file plus the host environment (installed tools, log files, OS commands). The derived state is a `collection_run` row with per-module `raw_json` snapshots and a `TextReport` sent to operators. The client (operator or systemd) triggers cycles; the daemon never pulls work from a remote queue.

```
  config.yaml + host tools/logs
            |
            v
     collectors (OS adapters)
            |
            v
     SQLite (raw_json + section_text)
            |
            v
     formatter -> TextReport
            |
            v
     analyzers (optional appendix)
            |
            v
     channels (file / telegram / email)
```

## Dependency Direction

Layers follow Adapter → Service → Repository → Domain. Dependencies flow downward only:

```
cmd/ismd          entrypoint: flags, os.Exit, calls internal/app
      |
      v
internal/app      wiring: load config, build graph, RunOnce / RunScheduler
      |
      +-- internal/config
      +-- internal/scheduler
      +-- internal/service/report
      |       +-- collectors (ports)
      |       +-- store (repository port)
      |       +-- format
      |       +-- channels (ports)
      |       +-- analyzers (ports)
      +-- internal/collector/<name>   OS tool / log adapters
      +-- internal/execcmd            injectable os/exec runner
      +-- internal/channel/<name>     delivery adapters
      +-- internal/store/sqlite       repository
      +-- internal/domain             DTOs, module names, report types
```

**Architecture Invariant:** `cmd/ismd` does not assemble the dependency graph. It passes options to `internal/app`.

**Architecture Invariant:** no internal package imports `cmd/`.

**Architecture Invariant:** collectors and channels know nothing about SQLite. `ReportService` owns persistence.

**Architecture Invariant:** `internal/service/report` knows nothing about YAML. Config is loaded and validated in `internal/app` before the service is constructed.

## Code Map

This section answers "where is the thing that does X?" and "what does the package I'm looking at do?". Use symbol search to jump to named types and files.

### `cmd/ismd`

CLI entrypoint. Parses `--config`, `--db`, `--once`, sets up logging, calls `app.Run`. No business logic.

### `internal/app`

Composition root. Loads and validates config, opens SQLite, builds collectors/channels/analyzers via `BuildCollectors`, `BuildChannels`, `BuildAnalyzers`, constructs `report.Service` and `scheduler.Scheduler`, then runs either a single cycle (`--once`) or the time-slot loop.

**Architecture Invariant:** all concrete adapter wiring lives here (or in the `Build*` helpers in the same package). Other packages receive interfaces.

### `internal/config`

YAML load, defaults, and manual `Validate()`. No `env` tags, no validator library. Secrets live in the same file in v1.

### `internal/domain`

Shared DTOs: `ModuleName`, `ModuleResult`, `CollectionRun`, `TextReport`, `RunStatus`. No I/O, no config imports.

### `internal/service/report`

`ReportService.RunCycle` orchestrates one report slot: `BeginRun` → collect each enabled module → prune history → format → analyzer appendices → send to all channels → `FinishRun`.

Defines consumer-side ports: `Store`, `Sender` (channel), and uses `collector.Collector` and `analyze.Analyzer` from their packages.

**Architecture Invariant:** a non-nil `error` from `Collector.Collect` means the whole module failed. The service ignores `ModuleResult` fields on error (except `Collector.Name()`), persists an error row, writes an `ERROR` section, and continues to the next module.

**Architecture Invariant:** a failure in one channel does not cancel other channels. Failures are logged via `slog`.

**Architecture Invariant:** `FinishRun` runs after all send attempts. Run status: `ok` (no errors), `degraded` (≥1 collect/send/analyzer error but cycle completed), `failed` (cycle aborted before send phase finished, e.g. context cancelled).

### `internal/collector`

`Collector` interface and per-tool packages:

| Package | Source |
|---------|--------|
| `fail2ban` | `fail2ban-client` per configured jail |
| `auditd` | `aureport` subcommands |
| `rkhunter` | log file and/or `rkhunter` CLI |
| `chkrootkit` | log file and/or `chkrootkit` CLI |
| `lynis` | `lynis audit system --quick` |
| `unattendedupgrades` | unattended-upgrades log tail |

Each package: run command or read log → store raw output in `raw_json` → parse into `section_text` + module status. Parsing rules per module are documented in [CONCEPT.md](CONCEPT.md).

**Architecture Invariant:** collectors call OS binaries only through `execcmd.Runner` (injectable for tests). No `sudo` — the process runs as root.

### `internal/channel`

`Channel` interface. Implementations:

- **file** — atomic write of `ism-report-YYYYMMDD-HHMMSS.txt` to `save_to_dir`
- **telegram** — Bot API `sendMessage`; body split into ≤4096-byte chunks
- **email** — SMTP `text/plain`; `use_tls` (STARTTLS) and `use_ssl` (implicit TLS) are mutually exclusive

**Architecture Invariant:** channels receive a finished `TextReport`. They do not trigger collection or read SQLite.

### `internal/analyze`

`Analyzer` interface. Implementations append a text section to the report body after formatting and before send.

`analyze.Input` carries `TextReport`, the slice of `ModuleResult`, and `ModuleOrder` (for raw payloads in report order). There is no separate `ReportAppendix` type.

`internal/analyze/googleai` — Gemini `generateContent` client; reads full `raw_json` blobs, not compressed `section_text`. Analyzer errors become an `ERROR:` line in the appendix; delivery still proceeds.

### `internal/format`

Assembles the unified plain-text report from module sections and metadata (hostname, timestamp).

### `internal/store/sqlite`

Repository: `BeginRun`, `SaveModuleResult`, `FinishRun`, `Prune`, migrations. Default path `/var/lib/ism/ism.db` (overridable via `--db`).

**Architecture Invariant:** `raw_json` is the source of truth — a JSON object with named string blobs (raw tool output; keys vary by module). `section_text` is a projection for channels and operators. There is no separate `summary_json` cache.

Tables: `collection_runs` (`status`: `ok` | `degraded` | `failed`), `module_results` (`run_id`, `module`, `collected_at`, `status`, `raw_json`, `section_text`, `error`).

### `internal/scheduler`

Computes next fire time from `reporting.time` slots and configured timezone (or host local). Wakes `ReportService.RunCycle`.

### `internal/execcmd`

`Runner` interface and `Exec` production implementation wrapping `os/exec`.

### `configs/config.example.yaml`

Reference config checked into the repo.

### `deploy/systemd/`

systemd unit file for Ubuntu deployment.

## Cross-Cutting Concerns

### Report cycle

One slot, in order:

1. Scheduler (or `app` on `--once`) calls `ReportService.RunCycle`.
2. `BeginRun` opens the run record.
3. For each name in `modules.enabled` (config order; empty = all modules): `Collect` → persist result or error row.
4. `Prune` rows older than `keep_history_days`.
5. Formatter builds `TextReport`.
6. Each configured analyzer appends to `Body`.
7. Each configured channel `Send`s the same final text.
8. `FinishRun` with aggregated status.

Config validation requires at least one channel in `reporting.channels`. An empty channel set is a startup error — reports must go somewhere.

### Deployment

Process runs as **root**. No `sudo` inside collectors. Recommended paths: config `/etc/ism/config.yaml` (`chmod 600`), data `/var/lib/ism/` (SQLite and file reports). Manual test: `ismd --once`. See [README.md](../README.md) for package install and systemd setup.

### Privilege and security

Secrets (telegram token, SMTP password, API keys) are in YAML v1. Collectors only invoke configured commands and read configured log paths.

### Deferred scope

`[DEFERRED — Phase 2]` CLI subcommands (`ism report list`, `ism module export`, etc.) — contract described in [CONCEPT.md](CONCEPT.md); MVP uses `ismd --once` for manual runs.

`[DEFERRED — Phase 2]` automatic "all clear, stay silent" verdict — operator interprets reports; optional AI appendix is advisory.

---

_Last updated: 2026-09-01_
