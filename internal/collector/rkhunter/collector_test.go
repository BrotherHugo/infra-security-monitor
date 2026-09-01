package rkhunter_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/rkhunter"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestParse_targets_timestampedLogCheckWarnings(t *testing.T) {
	parsed, err := rkhunter.Parse(readFixture(t, "rkhunter-targets-timestamped.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.Targets) != 6 {
		t.Fatalf("len(Targets) = %d, want 6", len(parsed.Targets))
	}
	text := rkhunter.FormatSectionText(parsed)
	if !strings.Contains(text, "warnings (6):") {
		t.Fatalf("SectionText missing warnings: %q", text)
	}
	if !strings.Contains(text, "Checking if SSH root access is allowed") {
		t.Fatalf("SectionText missing check text: %q", text)
	}
	if strings.Contains(text, "[20:") {
		t.Fatalf("SectionText must not contain log timestamps: %q", text)
	}
}

func TestParse_fullRun(t *testing.T) {
	parsed, err := rkhunter.Parse(readFixture(t, "rkhunter-full-run.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.Targets) != 15 {
		t.Fatalf("len(Targets) = %d, want 15", len(parsed.Targets))
	}
	if parsed.SuspectFiles != 12 {
		t.Fatalf("SuspectFiles = %d, want 12", parsed.SuspectFiles)
	}
	if !parsed.NeedsAttention() {
		t.Fatal("NeedsAttention = false, want true")
	}
	text := rkhunter.FormatSectionText(parsed)
	if !strings.Contains(text, "warnings (15):") {
		t.Fatalf("SectionText missing warnings: %q", text)
	}
	if !strings.Contains(text, "Checking for hidden files and directories") {
		t.Fatalf("SectionText missing hidden files check: %q", text)
	}
}

func TestParse_warningBlocks(t *testing.T) {
	parsed, err := rkhunter.Parse(readFixture(t, "rkhunter-warning-blocks.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.Warnings) != 2 {
		t.Fatalf("len(Warnings) = %d, want 2", len(parsed.Warnings))
	}
	if !strings.Contains(parsed.Warnings[0], "/usr/sbin/sshd") {
		t.Fatalf("Warnings[0] = %q", parsed.Warnings[0])
	}
}

func TestParse_warningCron(t *testing.T) {
	parsed, err := rkhunter.Parse(readFixture(t, "rkhunter-warning-cron.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.WarningCount != 1 {
		t.Fatalf("WarningCount = %d, want 1", parsed.WarningCount)
	}
	if len(parsed.SummaryLines) == 0 {
		t.Fatal("SummaryLines empty")
	}
}

func TestParse_ok(t *testing.T) {
	parsed, err := rkhunter.Parse(readFixture(t, "rkhunter-ok.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.WarningCount != 0 {
		t.Fatalf("WarningCount = %d, want 0", parsed.WarningCount)
	}
}

func TestParse_cleanCronLog(t *testing.T) {
	parsed, err := rkhunter.Parse(readFixture(t, "rkhunter-clean-cron.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !parsed.CleanRun {
		t.Fatal("CleanRun = false, want true")
	}
	if parsed.WarningCount != 0 {
		t.Fatalf("WarningCount = %d, want 0", parsed.WarningCount)
	}
}

func TestCollector_Collect_fromExec_warnings(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	collector := rkhunter.New(
		fixtureRunner{content: readFixture(t, "rkhunter-warning-cron.txt")},
		"",
		[]string{"--check", "-q"},
	)
	collector.SetNow(func() time.Time { return now })

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	if !strings.Contains(result.SectionText, "warnings (1):") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	assertRawKeys(t, result.Raw, "last_run")
}

func TestCollector_Collect_fromExec_ok(t *testing.T) {
	collector := rkhunter.New(fixtureRunner{content: readFixture(t, "rkhunter-ok.txt")}, "", []string{"--check", "-q"})

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok", result.Status)
	}
	assertRawKeys(t, result.Raw, "last_run")
}

func TestCollector_Collect_execExitErrorWithWarnings(t *testing.T) {
	collector := rkhunter.New(
		fixtureRunner{content: readFixture(t, "rkhunter-warning-cron.txt"), err: errFixtureExit1{}},
		"",
		[]string{"--check", "--skip-keypress"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	if strings.Contains(result.SectionText, "no warnings in last run") {
		t.Fatalf("SectionText should not be clean run: %q", result.SectionText)
	}
}

func TestCollector_Collect_prefersLogAfterExec(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rkhunter.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "rkhunter-targets-timestamped.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	collector := rkhunter.New(
		fixtureRunner{content: readFixture(t, "rkhunter-exec-summary-only.txt")},
		logPath,
		[]string{"--check", "--skip-keypress", "--report-warnings-only"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	if !strings.Contains(result.SectionText, "warnings (6):") {
		t.Fatalf("SectionText = %q, want warnings from log not exec stdout", result.SectionText)
	}
}

func TestCollector_Collect_fallbackToLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "rkhunter.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "rkhunter-warning-cron.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	collector := rkhunter.New(
		fixtureRunner{err: errFixtureFailure{}},
		logPath,
		[]string{"--check", "-q"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
}

func assertRawKeys(t *testing.T, raw []byte, keys ...string) {
	t.Helper()
	var blobs map[string]string
	if err := json.Unmarshal(raw, &blobs); err != nil {
		t.Fatalf("json.Unmarshal(Raw) error = %v", err)
	}
	for _, key := range keys {
		if strings.TrimSpace(blobs[key]) == "" {
			t.Fatalf("Raw blob %q empty: %+v", key, blobs)
		}
	}
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	return string(readFixtureBytes(t, name))
}

func readFixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	return data
}

type fixtureRunner struct {
	content string
	err     error
}

func (r fixtureRunner) Run(_ context.Context, name string, _ ...string) (string, string, error) {
	if name != "rkhunter" {
		return "", "", errUnexpectedCommand{name: name}
	}
	if r.err != nil {
		return r.content, "boom", r.err
	}
	return r.content, "", nil
}

type errUnexpectedCommand struct {
	name string
}

func (e errUnexpectedCommand) Error() string {
	return "unexpected command: " + e.name
}

type errFixtureFailure struct{}

func (errFixtureFailure) Error() string {
	return "fixture exec failure"
}

type errFixtureExit1 struct{}

func (errFixtureExit1) Error() string {
	return "exit status 1"
}
