package fail2ban_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/fail2ban"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestParseStatus_sshdNoBan(t *testing.T) {
	stdout := readFixture(t, "fail2ban-sshd.txt")
	stat, err := fail2ban.ParseStatus(stdout, "sshd")
	if err != nil {
		t.Fatalf("ParseStatus() error = %v", err)
	}
	if stat.CurrentlyBanned != 0 || stat.TotalBanned != 0 {
		t.Fatalf("banned counters = %+v, want zeros", stat)
	}
	if len(stat.BannedIPs) != 0 {
		t.Fatalf("BannedIPs = %v, want empty", stat.BannedIPs)
	}
}

func TestParseStatus_nginxWithIP(t *testing.T) {
	stdout := readFixture(t, "fail2ban-nginx-limit-req.txt")
	stat, err := fail2ban.ParseStatus(stdout, "nginx-limit-req")
	if err != nil {
		t.Fatalf("ParseStatus() error = %v", err)
	}
	if stat.CurrentlyBanned != 1 {
		t.Fatalf("CurrentlyBanned = %d, want 1", stat.CurrentlyBanned)
	}
	if len(stat.BannedIPs) != 1 || stat.BannedIPs[0] != "204.76.203.18" {
		t.Fatalf("BannedIPs = %v", stat.BannedIPs)
	}
}

func TestCollector_Collect(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	runner := fixtureRunner{dir: filepath.Join("testdata")}
	collector := fail2ban.New(runner, []string{"sshd", "nginx-limit-req"})
	collector.SetNow(func() time.Time { return now })

	result, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if result.Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", result.Status)
	}
	if !result.CollectedAt.Equal(now) {
		t.Fatalf("CollectedAt = %v, want %v", result.CollectedAt, now)
	}
	if !strings.Contains(result.SectionText, "jail sshd: failed=1/1 banned=0/0 ips=-") {
		t.Fatalf("SectionText missing sshd line: %q", result.SectionText)
	}
	if !strings.Contains(result.SectionText, "jail nginx-limit-req: failed=6/21946 banned=1/119 ips=204.76.203.18") {
		t.Fatalf("SectionText missing nginx line: %q", result.SectionText)
	}

	var blobs map[string]string
	if err := json.Unmarshal(result.Raw, &blobs); err != nil {
		t.Fatalf("json.Unmarshal(Raw) error = %v", err)
	}
	if blobs["sshd"] == "" || blobs["nginx-limit-req"] == "" {
		t.Fatalf("Raw blobs = %+v, want sshd and nginx-limit-req keys", blobs)
	}
}

func TestCollector_Collect_commandError(t *testing.T) {
	runner := fixtureRunner{
		dir: filepath.Join("testdata"),
		failJails: map[string]bool{
			"sshd": true,
		},
	}
	collector := fail2ban.New(runner, []string{"sshd"})

	_, err := collector.Collect(context.Background())
	if err == nil {
		t.Fatal("expected Collect() error")
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
	dir       string
	failJails map[string]bool
}

func (r fixtureRunner) Run(_ context.Context, name string, args ...string) (string, string, error) {
	if name != "fail2ban-client" || len(args) != 2 || args[0] != "status" {
		return "", "", errUnexpectedCommand{name: name, args: args}
	}
	jail := args[1]
	if r.failJails != nil && r.failJails[jail] {
		return "", "boom", errFixtureFailure{jail: jail}
	}
	data, err := os.ReadFile(filepath.Join(r.dir, "fail2ban-"+jail+".txt"))
	if err != nil {
		return "", "", err
	}
	return string(data), "", nil
}

type errUnexpectedCommand struct {
	name string
	args []string
}

func (e errUnexpectedCommand) Error() string {
	return "unexpected command: " + e.name
}

type errFixtureFailure struct {
	jail string
}

func (e errFixtureFailure) Error() string {
	return "fixture failure for jail " + e.jail
}
