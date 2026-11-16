package format_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/auditd"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/chkrootkit"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/fail2ban"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/lynis"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/rkhunter"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/unattendedupgrades"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/format"
)

func TestBuild_reportLayout(t *testing.T) {
	loc := time.FixedZone("MSK", 3*3600)
	generatedAt := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)

	report, err := format.Build(format.RunMeta{
		RunID:       42,
		Hostname:    "host-a",
		GeneratedAt: generatedAt,
		Location:    loc,
		ModuleOrder: []string{"fail2ban", "auditd", "lynis", "chkrootkit"},
	}, []domain.ModuleResult{
		{
			Name:   "fail2ban",
			Status: domain.ModuleStatusAttention,
			Data: fail2ban.Snapshot{Jails: []fail2ban.JailStatus{{
				Name:            "sshd",
				CurrentlyFailed: 1,
				TotalFailed:     1,
			}}},
		},
		{
			Name:   "lynis",
			Status: domain.ModuleStatusAttention,
			Data: lynis.ParseResult{
				HardeningIndex: 70,
				WarningCount:   1,
				Warnings:       []string{"- weak umask"},
			},
		},
		{
			Name:   "rkhunter",
			Status: domain.ModuleStatusAttention,
			Data:   rkhunter.ParseResult{Targets: []string{"/tmp/x [ Warning ]"}},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if report.Hostname != "host-a" {
		t.Fatalf("Hostname = %q", report.Hostname)
	}

	want := strings.Join([]string{
		"Security Audit",
		"id: 42",
		"host: host-a",
		"time: 2026-08-13 15:30:00",
		"modules: fail2ban, auditd, lynis, chkrootkit",
		"",
		"=== fail2ban ===",
		"jail sshd: failed=1/1 banned=0/0 ips=-",
		"",
		"=== rkhunter ===",
		"warnings (1):",
		"  /tmp/x [ Warning ]",
		"note: file property warnings after package updates may be false positives; run rkhunter --propupd if needed",
		"",
		"=== lynis ===",
		"hardening index: 70",
		"warnings (1):",
		"  - weak umask",
		"",
	}, "\n")
	if report.Body != want {
		t.Fatalf("Body = %q, want %q", report.Body, want)
	}
}

func TestBuild_errorSection(t *testing.T) {
	tests := []struct {
		name   string
		result domain.ModuleResult
		want   string
	}{
		{
			name: "section text",
			result: domain.ModuleResult{
				Name:        "fail2ban",
				Status:      domain.ModuleStatusError,
				SectionText: "ERROR: command failed",
			},
			want: "command failed",
		},
		{
			name: "error field",
			result: domain.ModuleResult{
				Name:   "fail2ban",
				Status: domain.ModuleStatusError,
				Error:  "disk",
			},
			want: "disk",
		},
		{
			name: "unknown",
			result: domain.ModuleResult{
				Name:   "fail2ban",
				Status: domain.ModuleStatusError,
			},
			want: "unknown error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := format.Build(format.RunMeta{
				Hostname:    "host-a",
				GeneratedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
				Location:    time.UTC,
				ModuleOrder: []string{"fail2ban"},
			}, []domain.ModuleResult{tt.result})
			if err != nil {
				t.Fatalf("Build() error = %v", err)
			}
			if !strings.Contains(report.Body, "=== fail2ban ===\nERROR: "+tt.want+"\n") {
				t.Fatalf("Body = %q", report.Body)
			}
		})
	}
}

func TestBuild_customTemplateUsesNamedFields(t *testing.T) {
	renderer, err := format.Parse("{{with .Fail2ban}}{{range .Jails}}{{.Name}} banned={{.CurrentlyBanned}}\n{{end}}{{end}}{{with .Auditd}}auditd{{end}}")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	report, err := renderer.Build(format.RunMeta{
		Hostname:    "host-a",
		GeneratedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		Location:    time.UTC,
		ModuleOrder: []string{"fail2ban", "auditd"},
	}, []domain.ModuleResult{{
		Name:   "fail2ban",
		Status: domain.ModuleStatusAttention,
		Data: fail2ban.Snapshot{Jails: []fail2ban.JailStatus{{
			Name:            "sshd",
			CurrentlyBanned: 2,
		}}},
	}})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := "sshd banned=2\n"
	if report.Body != want {
		t.Fatalf("Body = %q, want %q", report.Body, want)
	}
}

func TestBuild_capsAndSortsBeforeTemplate(t *testing.T) {
	warnings := make([]string, 51)
	for i := range warnings {
		warnings[i] = "w"
	}
	byType := map[string]int{}
	for i := 0; i < 10; i++ {
		byType[string(rune('A'+i))] = i + 1
	}

	report, err := format.Build(format.RunMeta{
		Hostname:    "host-a",
		GeneratedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		Location:    time.UTC,
		ModuleOrder: []string{"lynis", "auditd"},
	}, []domain.ModuleResult{
		{
			Name:   "lynis",
			Status: domain.ModuleStatusAttention,
			Data:   lynis.ParseResult{WarningCount: 51, Warnings: warnings},
		},
		{
			Name:   "auditd",
			Status: domain.ModuleStatusAttention,
			Data: auditd.Snapshot{
				Summary: auditd.Summary{KeyLines: []string{"Number of failed logins: 1"}, FailedLogins: 1},
				Config: auditd.ConfigChangeReport{
					HasEvents: true,
					EventAggregate: auditd.EventAggregate{
						Total:  55,
						ByType: byType,
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !strings.Contains(report.Body, "... truncated") {
		t.Fatalf("Body missing truncation: %q", report.Body)
	}
	if strings.Contains(report.Body, "by type: A=") {
		t.Fatalf("lowest count leaked into top: %q", report.Body)
	}
	if !strings.Contains(report.Body, "by type: J=10, I=9, H=8, G=7, F=6, E=5, D=4, C=3") {
		t.Fatalf("Body missing sorted top: %q", report.Body)
	}
}

func TestBuild_analysisSection(t *testing.T) {
	report, err := format.Build(format.RunMeta{
		Hostname:    "host-a",
		GeneratedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		Location:    time.UTC,
		Analyses: []format.Analysis{
			{Name: "google-ai", Text: "all clear"},
			{Name: "other", Error: "down"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if !strings.Contains(report.Body, "=== AI analysis (google-ai) ===\nall clear\n") {
		t.Fatalf("Body = %q", report.Body)
	}
	if !strings.Contains(report.Body, "=== AI analysis (other) ===\nERROR: down\n") {
		t.Fatalf("Body = %q", report.Body)
	}
}

func TestBuild_minimalFingerprintTemplate(t *testing.T) {
	tmpl := strings.TrimSpace(`
{{.Host}}|{{.Time.Format "02.01 15:04"}}
{{- with .Fail2ban}}
f2b:{{range .Jails}} {{.Name}}={{.CurrentlyBanned}}/{{.TotalBanned}}{{end}}
{{- end}}
{{- with .Auditd}}
aud: fl={{.FailedLogins}} cfg={{.ConfigChanges}} nf={{.Config.HasNetfilterBurst}}
{{- end}}
{{- with .Rkhunter}}
rkh: {{.SuspectFiles}}/{{.FilesChecked}} paths={{len .SuspectPaths}} checks={{len .WarningChecks}} fp={{.HasPropertyWarnings}}
{{- end}}
{{- with .Chkrootkit}}
chk: {{.FindingTotal}} fp={{.FalsePositiveTotal}}{{range .Findings}} {{.FPCode}}{{end}}
{{- end}}
{{- with .Lynis}}
lyn: {{.HardeningIndex}}{{range .Warnings}} {{.ID}}{{end}}
{{- end}}
{{- with .Unattended}}
apt: {{if .LastSuccessTime}}{{.LastSuccessTime.Format "2006-01-02"}}{{else}}none{{end}} stale={{.Stale}}
{{- end}}
`) + "\n"

	renderer, err := format.Parse(tmpl)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	lastOK := time.Date(2026, 11, 11, 6, 5, 54, 0, time.UTC)
	report, err := renderer.Build(format.RunMeta{
		RunID:       110,
		Hostname:    "srv1",
		GeneratedAt: time.Date(2026, 11, 13, 3, 36, 11, 0, time.UTC),
		Location:    time.UTC,
	}, []domain.ModuleResult{
		{
			Name:   "fail2ban",
			Status: domain.ModuleStatusAttention,
			Data:   fail2ban.Snapshot{Jails: []fail2ban.JailStatus{{Name: "sshd", CurrentlyBanned: 11, TotalBanned: 379}}},
		},
		{
			Name:   "auditd",
			Status: domain.ModuleStatusAttention,
			Data: auditd.Snapshot{
				Summary: auditd.Summary{FailedLogins: 346, ConfigChanges: 192},
				Config: auditd.ConfigChangeReport{
					HasEvents:      true,
					EventAggregate: auditd.EventAggregate{Total: 192, ByType: map[string]int{"NETFILTER_CFG": 192}},
				},
			},
		},
		{
			Name:   "rkhunter",
			Status: domain.ModuleStatusAttention,
			Data: rkhunter.ParseResult{
				HasSummary:   true,
				FilesChecked: 178,
				SuspectFiles: 12,
				Targets:      []string{"/usr/bin/ssh", "Checking if SSH root access is allowed"},
			},
		},
		{
			Name:   "chkrootkit",
			Status: domain.ModuleStatusOK,
			Data: chkrootkit.ParseResult{
				FindingCount:  1,
				FalsePositive: 1,
				Findings:      []chkrootkit.Finding{{Line: "eth0: PACKET SNIFFER", PossibleFalsePositive: true, FPCode: "systemd_networkd"}},
			},
		},
		{
			Name:   "lynis",
			Status: domain.ModuleStatusAttention,
			Data: lynis.ParseResult{
				HardeningIndex: 68,
				WarningCount:   2,
				Warnings: []string{
					"- Can't find any security repository [PKGS-7388]",
					"! Found one or more vulnerable packages. [PKGS-7392]",
				},
			},
		},
		{
			Name:   "unattended-upgrades",
			Status: domain.ModuleStatusOK,
			Data:   unattendedupgrades.ParseResult{LastSuccess: &lastOK, Stale: false},
		},
	})
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := strings.Join([]string{
		"srv1|13.11 03:36",
		"f2b: sshd=11/379",
		"aud: fl=346 cfg=192 nf=true",
		"rkh: 12/178 paths=1 checks=1 fp=true",
		"chk: 1 fp=1 systemd_networkd",
		"lyn: 68 PKGS-7388 PKGS-7392",
		"apt: 2026-11-11 stale=false",
		"",
	}, "\n")
	if report.Body != want {
		t.Fatalf("Body = %q, want %q", report.Body, want)
	}
}

func TestLoad_fileAndErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "short.tmpl")
	if err := os.WriteFile(path, []byte("host {{.Host}}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	renderer, err := format.Load("short.tmpl", dir)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	report, err := renderer.Build(format.RunMeta{
		Hostname:    "host-a",
		GeneratedAt: time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC),
		Location:    time.UTC,
	}, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if report.Body != "host host-a\n" {
		t.Fatalf("Body = %q", report.Body)
	}

	if _, err := format.Load("", dir); err != nil {
		t.Fatalf("Load(empty) error = %v", err)
	}
	if _, err := format.Load("missing.tmpl", dir); err == nil {
		t.Fatal("Load(missing) error = nil")
	}

	bad := filepath.Join(dir, "bad.tmpl")
	if err := os.WriteFile(bad, []byte("{{.Host"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if _, err := format.Load(bad, dir); err == nil {
		t.Fatal("Load(bad syntax) error = nil")
	}
}
