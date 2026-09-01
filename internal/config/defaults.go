package config

import "strings"

var (
	defaultFail2banJails = []string{"sshd", "nginx-limit-req"}

	defaultRkhunterReportPath = "/var/log/rkhunter.log"
	defaultRkhunterLaunchParams = []string{
		"--check",
		"--skip-keypress",
		"--report-warnings-only",
		"--logfile",
		"/var/log/rkhunter.log",
	}

	defaultChkrootkitReportPath   = "/var/log/chkrootkit.log"
	defaultChkrootkitLaunchParams = []string{"-q"}

	defaultLynisTimeoutMinutes = 20
	defaultLynisReportPath     = "/var/log/lynis-report.dat"

	defaultUnattendedUpgradesLogPath   = "/var/log/unattended-upgrades/unattended-upgrades.log"
	defaultUnattendedUpgradesTailLines = 30
	defaultUnattendedUpgradesStaleDays = 3

	defaultGoogleAIModel           = "gemini-2.5-flash"
	defaultAnalyzersTimeoutSeconds = 120

	// allModulesOrdered is the canonical module order when modules.enabled is empty.
	allModulesOrdered = []string{
		ModuleFail2ban,
		ModuleAuditd,
		ModuleRkhunter,
		ModuleChkrootkit,
		ModuleLynis,
		ModuleUnattendedUpgrades,
	}
)

func applyDefaults(cfg *Config) {
	cfg.Hostname = strings.TrimSpace(cfg.Hostname)
	if len(cfg.Modules.Enabled) == 0 {
		cfg.Modules.Enabled = append([]string(nil), allModulesOrdered...)
	}
	if len(cfg.Modules.Fail2ban.Jails) == 0 {
		cfg.Modules.Fail2ban.Jails = append([]string(nil), defaultFail2banJails...)
	}
	if cfg.Modules.Rkhunter.ReportPath == "" {
		cfg.Modules.Rkhunter.ReportPath = defaultRkhunterReportPath
	}
	if len(cfg.Modules.Rkhunter.LaunchParams) == 0 {
		cfg.Modules.Rkhunter.LaunchParams = append([]string(nil), defaultRkhunterLaunchParams...)
	}
	if cfg.Modules.Chkrootkit.ReportPath == "" {
		cfg.Modules.Chkrootkit.ReportPath = defaultChkrootkitReportPath
	}
	if len(cfg.Modules.Chkrootkit.LaunchParams) == 0 {
		cfg.Modules.Chkrootkit.LaunchParams = append([]string(nil), defaultChkrootkitLaunchParams...)
	}
	if cfg.Modules.Lynis.TimeoutMinutes <= 0 {
		cfg.Modules.Lynis.TimeoutMinutes = defaultLynisTimeoutMinutes
	}
	if cfg.Modules.Lynis.ReportPath == "" {
		cfg.Modules.Lynis.ReportPath = defaultLynisReportPath
	}
	if cfg.Modules.UnattendedUpgrades.LogPath == "" {
		cfg.Modules.UnattendedUpgrades.LogPath = defaultUnattendedUpgradesLogPath
	}
	if cfg.Modules.UnattendedUpgrades.TailLines <= 0 {
		cfg.Modules.UnattendedUpgrades.TailLines = defaultUnattendedUpgradesTailLines
	}
	if cfg.Modules.UnattendedUpgrades.StaleDays <= 0 {
		cfg.Modules.UnattendedUpgrades.StaleDays = defaultUnattendedUpgradesStaleDays
	}
	if cfg.Analyzers.GoogleAI != nil {
		if strings.TrimSpace(cfg.Analyzers.GoogleAI.Model) == "" {
			cfg.Analyzers.GoogleAI.Model = defaultGoogleAIModel
		}
		if cfg.Analyzers.TimeoutSeconds <= 0 {
			cfg.Analyzers.TimeoutSeconds = defaultAnalyzersTimeoutSeconds
		}
	}
}
