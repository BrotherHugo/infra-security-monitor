package app

import (
	"fmt"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/auditd"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/chkrootkit"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/fail2ban"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/lynis"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/rkhunter"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/unattendedupgrades"
	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/execcmd"
)

// BuildCollectors builds collectors from modules.enabled.
func BuildCollectors(cfg config.Config, runner execcmd.Runner) ([]collector.Collector, error) {
	collectors := make([]collector.Collector, 0, len(cfg.Modules.Enabled))

	for _, name := range cfg.Modules.Enabled {
		switch name {
		case config.ModuleFail2ban:
			collectors = append(collectors, fail2ban.New(runner, cfg.Modules.Fail2ban.Jails))
		case config.ModuleAuditd:
			collectors = append(collectors, auditd.New(runner))
		case config.ModuleRkhunter:
			collectors = append(collectors, rkhunter.New(runner, cfg.Modules.Rkhunter.ReportPath, cfg.Modules.Rkhunter.LaunchParams))
		case config.ModuleChkrootkit:
			collectors = append(collectors, chkrootkit.New(runner, cfg.Modules.Chkrootkit.ReportPath, cfg.Modules.Chkrootkit.LaunchParams))
		case config.ModuleLynis:
			collectors = append(collectors, lynis.New(runner, cfg.Modules.Lynis.TimeoutMinutes, cfg.Modules.Lynis.ReportPath))
		case config.ModuleUnattendedUpgrades:
			collectors = append(collectors, unattendedupgrades.New(
				cfg.Modules.UnattendedUpgrades.LogPath,
				cfg.Modules.UnattendedUpgrades.TailLines,
				cfg.Modules.UnattendedUpgrades.StaleDays,
			))
		default:
			return nil, fmt.Errorf("unknown or not implemented module %q", name)
		}
	}

	return collectors, nil
}
