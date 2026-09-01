package format_test

import (
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/format"
)

func TestBuild_reportLayout(t *testing.T) {
	loc := time.FixedZone("MSK", 3*3600)
	generatedAt := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)

	report := format.Build(format.RunMeta{
		RunID:       42,
		Hostname:    "host-a",
		GeneratedAt: generatedAt,
		Location:    loc,
		ModuleOrder: []string{"fail2ban", "auditd"},
	}, []domain.ModuleResult{
		{
			Name:        "fail2ban",
			Status:      domain.ModuleStatusAttention,
			SectionText: "jail sshd: failed=1/1 banned=0/0 ips=-",
		},
		{
			Name:   "auditd",
			Status: domain.ModuleStatusOK,
		},
	})

	if report.Hostname != "host-a" {
		t.Fatalf("Hostname = %q", report.Hostname)
	}
	if !strings.Contains(report.Body, "ISM report\n") {
		t.Fatalf("Body missing header: %q", report.Body)
	}
	if !strings.Contains(report.Body, "id: 42\n") {
		t.Fatalf("Body missing run id: %q", report.Body)
	}
	if !strings.Contains(report.Body, "time: 2026-08-13 15:30:00\n") {
		t.Fatalf("Body missing local time: %q", report.Body)
	}
	if !strings.Contains(report.Body, "modules: fail2ban, auditd\n") {
		t.Fatalf("Body missing modules line: %q", report.Body)
	}
	if !strings.Contains(report.Body, "=== fail2ban ===\njail sshd: failed=1/1 banned=0/0 ips=-\n") {
		t.Fatalf("Body missing fail2ban section: %q", report.Body)
	}
	if !strings.Contains(report.Body, "=== auditd ===\nstatus: ok\n") {
		t.Fatalf("Body missing auditd ok section: %q", report.Body)
	}
}

func TestBuild_errorSection(t *testing.T) {
	report := format.Build(format.RunMeta{
		Hostname:    "host-a",
		GeneratedAt: time.Now().UTC(),
		ModuleOrder: []string{"fail2ban"},
	}, []domain.ModuleResult{
		{
			Name:        "fail2ban",
			Status:      domain.ModuleStatusError,
			SectionText: "ERROR: command failed",
		},
	})

	if !strings.Contains(report.Body, "=== fail2ban ===\nERROR: command failed\n") {
		t.Fatalf("Body = %q", report.Body)
	}
}
