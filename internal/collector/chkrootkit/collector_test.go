package chkrootkit_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/chkrootkit"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestParse_ok(t *testing.T) {
	parsed, err := chkrootkit.Parse(readFixture(t, "chkrootkit-ok.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.FindingCount != 0 {
		t.Fatalf("FindingCount = %d, want 0", parsed.FindingCount)
	}
}

func TestParse_findingsWithFP(t *testing.T) {
	parsed, err := chkrootkit.Parse(readFixture(t, "chkrootkit-findings.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.FindingCount < 2 {
		t.Fatalf("FindingCount = %d, want >= 2", parsed.FindingCount)
	}
	if parsed.FalsePositive == 0 {
		t.Fatal("FalsePositive = 0, want > 0")
	}
}

func TestParse_fullRun(t *testing.T) {
	parsed, err := chkrootkit.Parse(readFixture(t, "chkrootkit-full-run.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.FindingCount > 5 {
		t.Fatalf("FindingCount = %d, want <= 5 (no sniffer interface noise)", parsed.FindingCount)
	}
	if parsed.FalsePositive == 0 {
		t.Fatal("FalsePositive = 0, want > 0 (systemd-networkd sniffer)")
	}
	realFindings := parsed.FindingCount - parsed.FalsePositive
	if realFindings == 0 {
		t.Fatal("real findings = 0, want > 0 (chkutmp)")
	}
	if !strings.Contains(chkrootkit.FormatSectionText(parsed), "tty of the following process") {
		t.Fatal("SectionText missing chkutmp signal")
	}
}

func TestCollector_Collect_fromExec_ok(t *testing.T) {
	collector := chkrootkit.New(
		fixtureRunner{content: readFixture(t, "chkrootkit-ok.txt")},
		"",
		[]string{"-q"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok", result.Status)
	}
	assertRawKeys(t, result.Raw, "last_run")
}

func TestCollector_Collect_fromExec_fpOnlyOk(t *testing.T) {
	collector := chkrootkit.New(
		fixtureRunner{content: readFixture(t, "chkrootkit-findings.txt")},
		"",
		[]string{"-q"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok (only FP findings)", result.Status)
	}
}

func TestCollector_Collect_execExitErrorStillParses(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "chkrootkit.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "chkrootkit-ok.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	collector := chkrootkit.New(
		fixtureRunner{content: readFixture(t, "chkrootkit-findings.txt"), err: errFixtureExit1{}},
		logPath,
		[]string{"-q"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok (FP only from exec)", result.Status)
	}
}

func TestCollector_Collect_fallbackToLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "chkrootkit.log")
	if err := os.WriteFile(logPath, readFixtureBytes(t, "chkrootkit-findings.txt"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	collector := chkrootkit.New(
		fixtureRunner{err: errFixtureFailure{}},
		logPath,
		[]string{"-q"},
	)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok (only FP findings in log)", result.Status)
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
	if name != "chkrootkit" {
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
