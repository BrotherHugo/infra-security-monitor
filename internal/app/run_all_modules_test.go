package app_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/app"
	"github.com/BrotherHugo/infra-security-monitor/internal/store/sqlite"
)

func TestRun_once_allModules(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	dbPath := filepath.Join(dir, "ism.db")
	cfgPath := writeAllModulesConfig(t, dir, reportsDir)

	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	runner := allModulesFixtureRunner{root: filepath.Join("..", "collector")}

	err := app.Run(ctx, app.Options{
		ConfigPath: cfgPath,
		DBPath:     dbPath,
		Once:       true,
		Runner:     runner,
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
	body := string(data)
	for _, section := range []string{
		"=== fail2ban ===",
		"=== auditd ===",
		"=== rkhunter ===",
		"=== chkrootkit ===",
		"=== lynis ===",
		"=== unattended-upgrades ===",
	} {
		if !strings.Contains(body, section) {
			t.Fatalf("report missing section %q: %q", section, body)
		}
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

	results, err := store.ListModuleResults(ctx, runs[0].ID)
	if err != nil {
		t.Fatalf("ListModuleResults() error = %v", err)
	}
	if len(results) != 6 {
		t.Fatalf("len(module results) = %d, want 6", len(results))
	}

	expectedRawKeys := map[string][]string{
		"fail2ban":            {"sshd", "nginx-limit-req"},
		"auditd":              {"summary", "config", "anomaly", "file"},
		"rkhunter":            {"last_run"},
		"chkrootkit":          {"last_run"},
		"lynis":               {"stdout"},
		"unattended-upgrades": {"tail"},
	}
	for _, result := range results {
		keys, ok := expectedRawKeys[string(result.Name)]
		if !ok {
			t.Fatalf("unexpected module %q", result.Name)
		}
		var blobs map[string]string
		if err := json.Unmarshal(result.Raw, &blobs); err != nil {
			t.Fatalf("module %q: json.Unmarshal(Raw) error = %v", result.Name, err)
		}
		for _, key := range keys {
			if strings.TrimSpace(blobs[key]) == "" {
				t.Fatalf("module %q: raw blob %q empty", result.Name, key)
			}
		}
		if result.Status == "" {
			t.Fatalf("module %q: empty status", result.Name)
		}
	}
}

func writeAllModulesConfig(t *testing.T, dir, reportsDir string) string {
	t.Helper()

	rkhunterLog := filepath.Join(dir, "rkhunter.log")
	chkrootkitLog := filepath.Join(dir, "chkrootkit.log")
	uuLog := filepath.Join(dir, "unattended-upgrades.log")

	writeTestFile(t, rkhunterLog, readCollectorFixture(t, "rkhunter", "testdata", "rkhunter-ok.txt"))
	writeTestFile(t, chkrootkitLog, readCollectorFixture(t, "chkrootkit", "testdata", "chkrootkit-ok.txt"))
	writeTestFile(t, uuLog, readCollectorFixture(t, "unattendedupgrades", "testdata", "unattended-ok.txt"))

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
    - auditd
    - rkhunter
    - chkrootkit
    - lynis
    - unattended-upgrades
  fail2ban:
    jails:
      - sshd
      - nginx-limit-req
  rkhunter:
    report_path: ` + rkhunterLog + `
  chkrootkit:
    report_path: ` + chkrootkitLog + `
  lynis:
    timeout_minutes: 20
  unattended_upgrades:
    log_path: ` + uuLog + `
    tail_lines: 10
    stale_days: 3
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func readCollectorFixture(t *testing.T, pkg, subdir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "collector", pkg, subdir, name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	return string(data)
}

type allModulesFixtureRunner struct {
	root string
}

func (r allModulesFixtureRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	switch name {
	case "fail2ban-client":
		if len(args) == 2 && args[0] == "status" {
			data, err := os.ReadFile(filepath.Join(r.root, "fail2ban", "testdata", "fail2ban-"+args[1]+".txt"))
			if err != nil {
				return "", "", err
			}
			return string(data), "", nil
		}
	case "aureport":
		key := strings.Join(args, " ")
		switch key {
		case "--summary -ts yesterday":
			return readFixture(r.root, "auditd", "auditd-summary-ok.txt"), "", nil
		case "-c -ts yesterday":
			return readFixture(r.root, "auditd", "auditd-config-change.txt"), "", nil
		case "--anomaly -ts yesterday":
			return readFixture(r.root, "auditd", "auditd-anomaly-empty.txt"), "", nil
		case "--file -ts yesterday":
			return readFixture(r.root, "auditd", "auditd-file-empty.txt"), "", nil
		}
	case "lynis":
		if len(args) >= 3 && args[0] == "audit" && args[1] == "system" && args[2] == "--quick" {
			return `
  Hardening Index : 78 [################____]

  Warnings (0):

  Suggestions (42):
`, "", nil
		}
	case "rkhunter":
		return readFixture(r.root, "rkhunter", "rkhunter-ok.txt"), "", nil
	case "chkrootkit":
		return readFixture(r.root, "chkrootkit", "chkrootkit-ok.txt"), "", nil
	}
	return "", "", errUnexpectedCommand{name: name}
}

func readFixture(root, pkg, name string) string {
	data, err := os.ReadFile(filepath.Join(root, pkg, "testdata", name))
	if err != nil {
		return ""
	}
	return string(data)
}
