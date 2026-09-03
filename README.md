# Infra Security Monitor (ISM)

`ismd` collects summaries from host security tools (fail2ban, auditd, rkhunter, chkrootkit, lynis, unattended-upgrades), stores history in SQLite, and sends a plain-text report to file, Telegram, and/or email. Optional Gemini analysis can be appended to the report.

Target OS: **Ubuntu 22.04 / 24.04**. The daemon **runs as root** (collectors do not use `sudo`). The tools themselves are not bundled — install them on the host first.

## Install

Download `ismd_*_linux_amd64.deb` or `ismd_*_linux_arm64.deb` from [GitHub Releases](https://github.com/BrotherHugo/infra-security-monitor/releases).

```bash
sudo dpkg -i ismd_*_linux_amd64.deb
# if dependencies are missing: sudo apt-get install -f
```

The package puts the binary in `/usr/bin/ismd` and the systemd unit in `/lib/systemd/system/`. On first install it copies a sample config to `/etc/ism/config.yaml` (only if that file does not exist), creates `/var/lib/ism/`, and **enables** the unit. It does **not** start the service — edit the config and run one cycle first (see below).

## Configuration

Edit `/etc/ism/config.yaml`. At least one delivery channel is required. `chmod 600` the file if it holds Telegram or SMTP secrets.

Minimal config that produces a file report (enable only modules you actually have on the host; list fail2ban jails that exist):

```yaml
keep_history_days: 30

modules:
  fail2ban:
    jails:
      - sshd
  rkhunter:
    launch_params:
      - --check
      - --skip-keypress
  chkrootkit:
    launch_params:
      - -q
  lynis:
    timeout_minutes: 20
  unattended_upgrades:
    log_path: /var/log/unattended-upgrades/unattended-upgrades.log
    tail_lines: 30
    stale_days: 3

reporting:
  time:
    - "03:30"
  channels:
    telegram:
      token: "1234567890:oyur-token"
      chat_id: "-1001234567890"
      message_thread_id: 2

analyzers:
  prompt: |
  custom_rules: |
    Write the entire answer in Spanish.
  google_ai:
    api_key: "your-api-key"
```

Omit `modules.enabled` to run all six modules. Add `telegram` / `email` under `reporting.channels`, or `analyzers.google_ai` for a Gemini appendix — full example: [`configs/config.example.yaml`](configs/config.example.yaml). API key: [Google AI Studio](https://aistudio.google.com/).

## First run

One report cycle, then exit (uses package default paths):

```bash
sudo ismd --once
```

Success: log line `report cycle finished`. With a file channel — a new file in `save_to_dir`. A missing tool does not abort the cycle; that module section shows `ERROR`.

Then start the daemon (already enabled by the package):

```bash
sudo systemctl start ismd.service
sudo journalctl -u ismd.service -f
```

After config changes: `sudo systemctl restart ismd.service`.

## Paths

| Item | Path |
|------|------|
| Config | `/etc/ism/config.yaml` |
| SQLite | `/var/lib/ism/ism.db` |
| File reports | `reporting.channels.file.save_to_dir` (example: `/var/lib/ism/reports`) |
| Binary | `/usr/bin/ismd` |

`--config` and `--db` override those paths (`ismd --help`). `ismd --version` prints the release version.

## Uninstall

```bash
sudo apt remove ismd      # binary and unit; /etc/ism often remains
sudo apt purge ismd       # also removes /etc/ism
```

SQLite and reports under `/var/lib/ism` are **not** removed on purge.

## Build from source

For local testing. Production install is the `.deb` above.

```bash
go test ./...
make build          # → bin/ismd
make deb            # → dist/*.deb (requires Goreleaser)
```

Go **1.26.5**. Releases: push to `main` runs [go-semantic-release](https://github.com/go-semantic-release/semantic-release) (tag, `CHANGELOG.md`), then CI writes `internal/version/version.go` from the computed version and commits both files to `main` with `[skip ci]`, then triggers Goreleaser to attach `.deb` packages. Do not edit `internal/version/version.go` or `CHANGELOG.md` by hand — use [Conventional Commits](https://www.conventionalcommits.org/) (`fix:`, `feat:`, breaking) in merge commits. Manual republish: Actions → **Release packages** → Run workflow → tag `v1.0.1` (etc.).

Concept and code map: [docs/CONCEPT.md](docs/CONCEPT.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). License: [MIT](LICENSE).

