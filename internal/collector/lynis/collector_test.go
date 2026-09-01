package lynis_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/lynis"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

const lynisStdoutOK = `
  Hardening Index : 78 [################____]

  Warnings (0):

  Suggestions (42):
`

func TestParse_ok(t *testing.T) {
	parsed, err := lynis.Parse(lynisStdoutOK)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.HardeningIndex != 78 {
		t.Fatalf("HardeningIndex = %d, want 78", parsed.HardeningIndex)
	}
	if parsed.WarningCount != 0 {
		t.Fatalf("WarningCount = %d, want 0", parsed.WarningCount)
	}
}

func TestParse_fullRun(t *testing.T) {
	parsed, err := lynis.Parse(readFixture(t, "lynis-full-run.txt"))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if parsed.HardeningIndex != 65 {
		t.Fatalf("HardeningIndex = %d, want 65", parsed.HardeningIndex)
	}
	if parsed.WarningCount != 2 {
		t.Fatalf("WarningCount = %d, want 2", parsed.WarningCount)
	}
	if len(parsed.Warnings) != 2 {
		t.Fatalf("len(Warnings) = %d, want 2", len(parsed.Warnings))
	}
	if !strings.Contains(parsed.Warnings[0], "vulnerable packages") {
		t.Fatalf("Warnings[0] = %q", parsed.Warnings[0])
	}
	if !strings.Contains(parsed.Warnings[1], "SMTP banner") {
		t.Fatalf("Warnings[1] = %q", parsed.Warnings[1])
	}
	text := lynis.FormatSectionText(parsed)
	if !strings.Contains(text, "hardening index: 65") {
		t.Fatalf("SectionText = %q", text)
	}
}

func TestParseReportDat(t *testing.T) {
	parsed, err := lynis.ParseReportDat(readFixture(t, "lynis-report.dat"))
	if err != nil {
		t.Fatalf("ParseReportDat() error = %v", err)
	}
	if parsed.HardeningIndex != 72 {
		t.Fatalf("HardeningIndex = %d, want 72", parsed.HardeningIndex)
	}
	if parsed.WarningCount != 1 {
		t.Fatalf("WarningCount = %d, want 1", parsed.WarningCount)
	}
}

func TestCollector_Collect_stdout(t *testing.T) {
	runner := fixtureRunner{content: readFixture(t, "lynis-full-run.txt")}
	collector := lynis.New(runner, 20, "")

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	assertRawKeys(t, result.Raw, "stdout")
}

func TestCollector_Collect_reportFallback(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "lynis-report.dat")
	if err := os.WriteFile(reportPath, []byte(readFixture(t, "lynis-report.dat")), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runner := fixtureRunner{content: "running tests...\n"}
	collector := lynis.New(runner, 20, reportPath)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	assertRawKeys(t, result.Raw, "stdout", "report_dat")
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
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", name, err)
	}
	return string(data)
}

type fixtureRunner struct {
	content string
}

func (r fixtureRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	if name != "lynis" || len(args) < 3 || args[0] != "audit" || args[1] != "system" || args[2] != "--quick" {
		return "", "", errUnexpectedCommand{name: name}
	}
	return r.content, "", nil
}

type errUnexpectedCommand struct {
	name string
}

func (e errUnexpectedCommand) Error() string {
	return "unexpected command: " + e.name
}
