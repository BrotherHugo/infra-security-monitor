package unattendedupgrades_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/unattendedupgrades"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestParse_ok(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	parsed, err := unattendedupgrades.Parse(readFixture(t, "unattended-ok.txt"), 10, 3, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.Stale {
		t.Fatal("Stale = true, want false")
	}
	if parsed.LastSuccess == nil {
		t.Fatal("LastSuccess nil")
	}
}

func TestParse_warningAndStale(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	parsed, err := unattendedupgrades.Parse(readFixture(t, "unattended-warning.txt"), 10, 3, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !parsed.Stale {
		t.Fatal("Stale = false, want true")
	}
	if len(parsed.WarningLines) == 0 {
		t.Fatal("WarningLines empty")
	}
	if len(parsed.KeptBackLines) == 0 {
		t.Fatal("KeptBackLines empty")
	}
	if !unattendedupgrades.NeedsAttention(parsed) {
		t.Fatal("NeedsAttention = false, want true")
	}
}

func TestParse_fullRun(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	parsed, err := unattendedupgrades.Parse(readFixture(t, "unattended-full-run.txt"), 0, 3, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.LastSuccess == nil {
		t.Fatal("LastSuccess nil")
	}
	if !strings.Contains(parsed.LastSuccessRaw, "All upgrades installed") {
		t.Fatalf("LastSuccessRaw = %q", parsed.LastSuccessRaw)
	}
	if parsed.Stale {
		t.Fatal("Stale = true, want false (last success 2026-08-11)")
	}
	if len(parsed.WarningLines) == 0 {
		t.Fatal("WarningLines empty, want reboot-required warnings in log")
	}
	if !unattendedupgrades.NeedsAttention(parsed) {
		t.Fatal("NeedsAttention = false, want true")
	}
}

func TestParse_tailWindowOnlyWarnings(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	var lines []string
	lines = append(lines, "2026-06-01 06:00:00 WARNING old warning from june")
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf("2026-08-13 06:00:%02d INFO routine line %d", i, i))
	}
	content := strings.Join(lines, "\n") + "\n"

	parsed, err := unattendedupgrades.Parse(content, 5, 3, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(parsed.WarningLines) != 0 {
		t.Fatalf("WarningLines = %v, want empty (old warning outside tail)", parsed.WarningLines)
	}
	if len(parsed.TailLines) != 5 {
		t.Fatalf("len(TailLines) = %d, want 5", len(parsed.TailLines))
	}
}

func TestFormatSectionText_okNoTailDump(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	parsed, err := unattendedupgrades.Parse(readFixture(t, "unattended-ok.txt"), 10, 3, now)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	text := unattendedupgrades.FormatSectionText(parsed)
	if strings.Contains(text, "tail:") {
		t.Fatalf("FormatSectionText should not dump tail when ok: %q", text)
	}
}

func TestCollector_Collect_ok(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "unattended-upgrades.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "unattended-ok.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	collector := unattendedupgrades.New(logPath, 10, 3)
	collector.SetNow(func() time.Time { return now })

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok", result.Status)
	}
	assertRawKeys(t, result.Raw, "tail")
}

func TestCollector_Collect_attention(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "unattended-upgrades.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "unattended-warning.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.Local)
	collector := unattendedupgrades.New(logPath, 10, 3)
	collector.SetNow(func() time.Time { return now })

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	assertRawKeys(t, result.Raw, "tail")
}

func TestCollector_Collect_fullRun(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "unattended-upgrades.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "unattended-full-run.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	now := time.Date(2026, 8, 14, 12, 0, 0, 0, time.Local)
	collector := unattendedupgrades.New(logPath, 30, 3)
	collector.SetNow(func() time.Time { return now })

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention (stale: no success in tail window)", result.Status)
	}
	if !strings.Contains(result.SectionText, "stale: yes") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	if strings.Contains(result.SectionText, "warnings/errors in tail") {
		t.Fatalf("SectionText should not report warnings outside tail window: %q", result.SectionText)
	}
	assertRawKeys(t, result.Raw, "tail")
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
