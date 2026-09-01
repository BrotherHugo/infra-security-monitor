package app_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/app"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/store/sqlite"
)

func TestRun_once_createsFileAndSQLiteRun(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	dbPath := filepath.Join(dir, "ism.db")
	cfgPath := writeOnceConfig(t, dir, reportsDir)

	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	fixtureDir := filepath.Join("..", "collector", "fail2ban", "testdata")

	err := app.Run(ctx, app.Options{
		ConfigPath: cfgPath,
		DBPath:     dbPath,
		Once:       true,
		Runner:     fixtureRunner{dir: fixtureDir},
		Clock:      func() time.Time { return now },
		Hostname:   func() (string, error) { return "test-host", nil },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	reportPath := filepath.Join(reportsDir, "ism-report-20260813-123000.txt")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile(report) error = %v", err)
	}
	if !strings.Contains(string(data), "=== fail2ban ===") {
		t.Fatalf("report body missing fail2ban section: %q", string(data))
	}
	if !strings.Contains(string(data), "id: 1\n") {
		t.Fatalf("report body missing run id: %q", string(data))
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	defer store.Close()

	runs, err := store.ListRuns(ctx, 1)
	if err != nil {
		t.Fatalf("ListRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	if runs[0].Status != domain.RunStatusOK && runs[0].Status != domain.RunStatusDegraded {
		t.Fatalf("run status = %q", runs[0].Status)
	}
	if runs[0].Hostname != "test-host" {
		t.Fatalf("hostname = %q", runs[0].Hostname)
	}

	results, err := store.ListModuleResults(ctx, runs[0].ID)
	if err != nil {
		t.Fatalf("ListModuleResults() error = %v", err)
	}
	if len(results) != 1 || results[0].Name != "fail2ban" {
		t.Fatalf("module results = %+v", results)
	}
}

func TestRun_once_configHostnameOverride(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	dbPath := filepath.Join(dir, "ism.db")
	cfgPath := writeOnceConfigWithHostname(t, dir, reportsDir, "prod-web-1")

	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	fixtureDir := filepath.Join("..", "collector", "fail2ban", "testdata")

	err := app.Run(ctx, app.Options{
		ConfigPath: cfgPath,
		DBPath:     dbPath,
		Once:       true,
		Runner:     fixtureRunner{dir: fixtureDir},
		Clock:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	reportPath := filepath.Join(reportsDir, "ism-report-20260813-123000.txt")
	data, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile(report) error = %v", err)
	}
	if !strings.Contains(string(data), "host: prod-web-1\n") {
		t.Fatalf("report body hostname = %q", string(data))
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("sqlite.Open() error = %v", err)
	}
	defer store.Close()

	runs, err := store.ListRuns(ctx, 1)
	if err != nil {
		t.Fatalf("ListRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	if runs[0].Hostname != "prod-web-1" {
		t.Fatalf("hostname = %q", runs[0].Hostname)
	}
}

func writeOnceConfigWithHostname(t *testing.T, dir, reportsDir, hostname string) string {
	t.Helper()
	content := `
hostname: ` + hostname + `
reporting:
  time:
    - "12:30"
  channels:
    file:
      save_to_dir: ` + reportsDir + `
keep_history_days: 7
timezone: UTC
modules:
  enabled:
    - fail2ban
  fail2ban:
    jails:
      - sshd
      - nginx-limit-req
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeOnceConfig(t *testing.T, dir, reportsDir string) string {
	t.Helper()
	content := `
reporting:
  time:
    - "12:30"
  channels:
    file:
      save_to_dir: ` + reportsDir + `
keep_history_days: 7
timezone: UTC
modules:
  enabled:
    - fail2ban
  fail2ban:
    jails:
      - sshd
      - nginx-limit-req
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

type fixtureRunner struct {
	dir string
}

func (r fixtureRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	if name != "fail2ban-client" || len(args) != 2 || args[0] != "status" {
		return "", "", errUnexpectedCommand{name: name}
	}
	data, err := os.ReadFile(filepath.Join(r.dir, args[1]+".txt"))
	if err != nil {
		return "", "", err
	}
	return string(data), "", nil
}

type errUnexpectedCommand struct {
	name string
}

func (e errUnexpectedCommand) Error() string {
	return "unexpected command: " + e.name
}
