package app_test

import (
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/app"
	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/execcmd"
)

func TestBuildCollectors_allModules(t *testing.T) {
	cfg := config.Config{
		Modules: config.Modules{
			Enabled: []string{
				config.ModuleFail2ban,
				config.ModuleAuditd,
				config.ModuleRkhunter,
				config.ModuleChkrootkit,
				config.ModuleLynis,
				config.ModuleUnattendedUpgrades,
			},
			Fail2ban: config.Fail2banSettings{Jails: []string{"sshd"}},
			Rkhunter: config.RkhunterSettings{
				ReportPath:   "/var/log/rkhunter.log",
				LaunchParams: []string{"--check"},
			},
			Chkrootkit: config.ChkrootkitSettings{
				ReportPath:   "/var/log/chkrootkit.log",
				LaunchParams: []string{"-q"},
			},
			Lynis: config.LynisSettings{
				TimeoutMinutes: 20,
				ReportPath:     "/var/log/lynis-report.dat",
			},
			UnattendedUpgrades: config.UnattendedUpgradesSettings{
				LogPath:   "/var/log/unattended-upgrades/unattended-upgrades.log",
				TailLines: 100,
				StaleDays: 3,
			},
		},
	}

	collectors, err := app.BuildCollectors(cfg, execcmd.Exec{})
	if err != nil {
		t.Fatalf("BuildCollectors() error = %v", err)
	}
	if len(collectors) != 6 {
		t.Fatalf("len(collectors) = %d, want 6", len(collectors))
	}
	want := []string{
		config.ModuleFail2ban,
		config.ModuleAuditd,
		config.ModuleRkhunter,
		config.ModuleChkrootkit,
		config.ModuleLynis,
		config.ModuleUnattendedUpgrades,
	}
	for i, name := range want {
		if collectors[i].Name() != name {
			t.Fatalf("collector[%d] name = %q, want %q", i, collectors[i].Name(), name)
		}
	}
}

func TestBuildCollectors_unknownModule(t *testing.T) {
	cfg := config.Config{
		Modules: config.Modules{
			Enabled: []string{"unknown-module"},
		},
	}

	_, err := app.BuildCollectors(cfg, execcmd.Exec{})
	if err == nil {
		t.Fatal("expected BuildCollectors() error")
	}
}
