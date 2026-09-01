package auditd_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/auditd"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestParseSummary_ok(t *testing.T) {
	summary, err := auditd.ParseSummary(readFixture(t, "auditd-summary-ok.txt"))
	if err != nil {
		t.Fatalf("ParseSummary() error = %v", err)
	}
	if summary.FailedLogins != 0 {
		t.Fatalf("FailedLogins = %d, want 0", summary.FailedLogins)
	}
	if summary.AnomalyEvents != 0 {
		t.Fatalf("AnomalyEvents = %d, want 0", summary.AnomalyEvents)
	}
	if len(summary.KeyLines) != 7 {
		t.Fatalf("len(KeyLines) = %d, want 7", len(summary.KeyLines))
	}
	for _, want := range []string{
		"Number of failed logins:",
		"changes to accounts, groups, or role",
		"Number of changes in configuration:",
		"Number of anomaly events:",
		"responses to anomaly events:",
		"Number of AVC",
		"Number of integrity events:",
	} {
		found := false
		for _, line := range summary.KeyLines {
			if strings.Contains(line, want) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("KeyLines missing %q: %v", want, summary.KeyLines)
		}
	}
}

func TestParseSummary_fullRun(t *testing.T) {
	summary, err := auditd.ParseSummary(readFixture(t, "auditd-summary-full-run.txt"))
	if err != nil {
		t.Fatalf("ParseSummary() error = %v", err)
	}
	if summary.FailedLogins != 30 {
		t.Fatalf("FailedLogins = %d, want 30", summary.FailedLogins)
	}
	if summary.AnomalyEvents != 56 {
		t.Fatalf("AnomalyEvents = %d, want 56", summary.AnomalyEvents)
	}
	if len(summary.KeyLines) != 7 {
		t.Fatalf("len(KeyLines) = %d, want 7", len(summary.KeyLines))
	}
}

func TestParseConfigChange_fullRun(t *testing.T) {
	report := auditd.ParseConfigChange(readFixture(t, "auditd-config-changes-full-run.txt"))
	if !report.HasEvents {
		t.Fatal("HasEvents = false, want true")
	}
	if report.Total < 200 {
		t.Fatalf("Total = %d, want >= 200", report.Total)
	}
	if report.ByType["CONFIG_CHANGE"] == 0 {
		t.Fatal("missing CONFIG_CHANGE events")
	}
	if report.ByType["NETFILTER_CFG"] == 0 {
		t.Fatal("missing NETFILTER_CFG events")
	}
}

func TestParseConfigChange_singleEvent(t *testing.T) {
	report := auditd.ParseConfigChange(readFixture(t, "auditd-config-change.txt"))
	if !report.HasEvents {
		t.Fatal("HasEvents = false, want true")
	}
	if report.Total != 1 {
		t.Fatalf("Total = %d, want 1", report.Total)
	}
	if report.ByType["fail2ban_config"] != 1 {
		t.Fatalf("ByType = %#v, want fail2ban_config=1", report.ByType)
	}
	if report.ByPath["/etc/fail2ban/jail.local"] != 1 {
		t.Fatalf("ByPath = %#v", report.ByPath)
	}
}

func TestParseAnomalyReport_fullRun(t *testing.T) {
	report := auditd.ParseAnomalyReport(readFixture(t, "auditd-anomaly-full-run.txt"))
	if !report.HasEvents {
		t.Fatal("HasEvents = false, want true")
	}
	if report.Total != 8 {
		t.Fatalf("Total = %d, want 8", report.Total)
	}
	if report.ByType["ANOM_PROMISCUOUS"] != 8 {
		t.Fatalf("ByType = %#v", report.ByType)
	}
}

func TestParseAnomalyReport_empty(t *testing.T) {
	report := auditd.ParseAnomalyReport(readFixture(t, "auditd-anomaly-empty.txt"))
	if report.HasEvents {
		t.Fatal("HasEvents = true, want false")
	}
}

func TestParseAnomalyReport_scoreFormat(t *testing.T) {
	report := auditd.ParseAnomalyReport(readFixture(t, "auditd-anomaly-score-format.txt"))
	if !report.HasEvents {
		t.Fatal("HasEvents = false, want true")
	}
	if report.ByType["login"] != 2 {
		t.Fatalf("ByType = %#v", report.ByType)
	}
	if report.ByType["exec"] != 1 {
		t.Fatalf("ByType = %#v", report.ByType)
	}
	if len(report.Sample) == 0 {
		t.Fatal("Sample empty, want event lines")
	}
}

func TestFormatSectionText_includesAnomalySample(t *testing.T) {
	summary := auditd.Summary{
		KeyLines:      []string{"Number of anomaly events: 28"},
		AnomalyEvents: 28,
	}
	text := auditd.FormatSectionText(
		summary,
		auditd.ConfigChangeReport{},
		auditd.ParseAnomalyReport(readFixture(t, "auditd-anomaly-full-run.txt")),
		auditd.FileReport{},
	)
	if !strings.Contains(text, "anomaly (28):") {
		t.Fatalf("SectionText missing anomaly count: %q", text)
	}
	if !strings.Contains(text, "  sample:") {
		t.Fatalf("SectionText missing anomaly sample header: %q", text)
	}
	if !strings.Contains(text, "ANOM_PROMISCUOUS /usr/bin/dockerd") {
		t.Fatalf("SectionText missing anomaly sample line: %q", text)
	}
}

func TestParseFileReport_fullRun(t *testing.T) {
	report := auditd.ParseFileReport(readFixture(t, "auditd-file-report-full-run.txt"))
	if !report.HasEvents {
		t.Fatal("HasEvents = false, want true")
	}
	if report.Total != 12 {
		t.Fatalf("Total = %d, want 12", report.Total)
	}
	if report.ByPath["/etc/nginx/nginx.conf"] != 3 {
		t.Fatalf("ByPath = %#v", report.ByPath)
	}
}

func TestParseFileReport_empty(t *testing.T) {
	report := auditd.ParseFileReport(readFixture(t, "auditd-file-empty.txt"))
	if report.HasEvents {
		t.Fatal("HasEvents = true, want false")
	}
}

func TestFormatSectionText_aggregatesConfigNoise(t *testing.T) {
	summary, err := auditd.ParseSummary(readFixture(t, "auditd-summary-full-run.txt"))
	if err != nil {
		t.Fatalf("ParseSummary() error = %v", err)
	}
	text := auditd.FormatSectionText(
		summary,
		auditd.ParseConfigChange(readFixture(t, "auditd-config-changes-full-run.txt")),
		auditd.ParseAnomalyReport(readFixture(t, "auditd-anomaly-empty.txt")),
		auditd.ParseFileReport(readFixture(t, "auditd-file-empty.txt")),
	)
	if strings.Contains(text, "NETFILTER_CFG -1 yes") {
		t.Fatalf("SectionText should not dump raw NETFILTER_CFG lines: %q", text)
	}
	if !strings.Contains(text, "config change (") || !strings.Contains(text, "by type:") {
		t.Fatalf("SectionText missing config aggregate: %q", text)
	}
	if !strings.Contains(text, "NETFILTER_CFG=") {
		t.Fatalf("SectionText missing NETFILTER_CFG count: %q", text)
	}
}

func TestCollector_Collect_ok(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	runner := fixtureRunner{dir: "testdata", variant: "ok"}
	collector := auditd.New(runner)
	collector.SetNow(func() time.Time { return now })

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusOK {
		t.Fatalf("Status = %q, want ok", result.Status)
	}
	if !strings.Contains(result.SectionText, "Number of integrity events:") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "config change (1):") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "anomaly: none") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "file events: none") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	assertRawKeys(t, result.Raw, "summary", "config", "anomaly", "file")
}

func TestCollector_Collect_noConfigChangesExit1(t *testing.T) {
	runner := fixtureRunner{dir: "testdata", variant: "ok", configExit1: true}
	collector := auditd.New(runner)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if !strings.Contains(result.SectionText, "config change: none") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
}

func TestCollector_Collect_fullRun(t *testing.T) {
	runner := fixtureRunner{dir: "testdata", variant: "full-run"}
	collector := auditd.New(runner)

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	if !strings.Contains(result.SectionText, "Number of failed logins:") {
		t.Fatalf("SectionText = %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "config change (") {
		t.Fatalf("SectionText missing config block: %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "file events (") {
		t.Fatalf("SectionText missing file events: %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "/etc/nginx/nginx.conf=3") {
		t.Fatalf("SectionText missing nginx.conf aggregate: %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "anomaly (56):") {
		t.Fatalf("SectionText missing anomaly section: %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "  sample:") || !strings.Contains(result.SectionText, "ANOM_PROMISCUOUS /usr/bin/dockerd") {
		t.Fatalf("SectionText missing anomaly sample: %q", result.SectionText)
	}
	if strings.Contains(result.SectionText, "auditctl -1 128") {
		t.Fatalf("SectionText should not dump all raw file lines: %q", result.SectionText)
	}
	assertRawKeys(t, result.Raw, "summary", "config", "anomaly", "file")
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
	dir         string
	variant     string
	configExit1 bool
}

func (r fixtureRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	if name != "aureport" {
		return "", "", errUnexpectedCommand{name: name}
	}
	key := strings.Join(args, " ")
	switch key {
	case "--summary -ts yesterday":
		if r.variant == "full-run" {
			return readFixtureFile(r.dir, "auditd-summary-full-run.txt"), "", nil
		}
		return readFixtureFile(r.dir, "auditd-summary-ok.txt"), "", nil
	case "-c -ts yesterday":
		if r.configExit1 {
			return "", "", errFixtureExit1{}
		}
		if r.variant == "full-run" {
			return readFixtureFile(r.dir, "auditd-config-changes-full-run.txt"), "", nil
		}
		return readFixtureFile(r.dir, "auditd-config-change.txt"), "", nil
	case "--anomaly -ts yesterday":
		if r.variant == "full-run" {
			return readFixtureFile(r.dir, "auditd-anomaly-full-run.txt"), "", nil
		}
		return readFixtureFile(r.dir, "auditd-anomaly-empty.txt"), "", nil
	case "--file -ts yesterday":
		if r.variant == "full-run" {
			return readFixtureFile(r.dir, "auditd-file-report-full-run.txt"), "", nil
		}
		return readFixtureFile(r.dir, "auditd-file-empty.txt"), "", nil
	default:
		return "", "", errUnexpectedCommand{name: name, args: args}
	}
}

func readFixtureFile(dir, name string) string {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		panic("readFixtureFile(" + name + "): " + err.Error())
	}
	return string(data)
}

type errUnexpectedCommand struct {
	name string
	args []string
}

func (e errUnexpectedCommand) Error() string {
	return "unexpected command: " + e.name
}

type errFixtureExit1 struct{}

func (errFixtureExit1) Error() string {
	return "exit status 1"
}
