package config

import (
	"fmt"
	"strings"
	"time"
)

const (
	ModuleFail2ban           = "fail2ban"
	ModuleAuditd             = "auditd"
	ModuleRkhunter           = "rkhunter"
	ModuleChkrootkit         = "chkrootkit"
	ModuleLynis              = "lynis"
	ModuleUnattendedUpgrades = "unattended-upgrades"

	AnalyzerGoogleAI = "google-ai"
)

var knownModules = map[string]struct{}{
	ModuleFail2ban:           {},
	ModuleAuditd:             {},
	ModuleRkhunter:           {},
	ModuleChkrootkit:         {},
	ModuleLynis:              {},
	ModuleUnattendedUpgrades: {},
}

// Validate checks the config after Load and applyDefaults.
func (c Config) Validate() error {
	if err := c.validateReportingTime(); err != nil {
		return err
	}
	if err := c.validateModulesEnabled(); err != nil {
		return err
	}
	if err := c.validateChannels(); err != nil {
		return err
	}
	if err := c.validateAnalyzers(); err != nil {
		return err
	}
	if c.KeepHistoryDays <= 0 {
		return fmt.Errorf("keep_history_days must be > 0")
	}
	if c.hasModule(ModuleFail2ban) && len(c.Modules.Fail2ban.Jails) == 0 {
		return fmt.Errorf("modules.fail2ban.jails cannot be empty when fail2ban is enabled")
	}
	return nil
}

func (c Config) validateReportingTime() error {
	if len(c.Reporting.Time) == 0 {
		return fmt.Errorf("reporting.time: at least one slot required")
	}
	for _, slot := range c.Reporting.Time {
		if strings.TrimSpace(slot) == "" {
			return fmt.Errorf("reporting.time: empty slot")
		}
		if _, err := time.Parse("15:04", slot); err != nil {
			return fmt.Errorf("reporting.time: slot %q is not in HH:MM format", slot)
		}
	}
	return nil
}

func (c Config) validateModulesEnabled() error {
	for _, name := range c.Modules.Enabled {
		if _, ok := knownModules[name]; !ok {
			return fmt.Errorf("modules.enabled: unknown module %q", name)
		}
	}
	return nil
}

func (c Config) validateChannels() error {
	ch := c.Reporting.Channels
	count := 0
	if ch.File != nil {
		count++
		if strings.TrimSpace(ch.File.SaveToDir) == "" {
			return fmt.Errorf("reporting.channels.file.save_to_dir cannot be empty")
		}
	}
	if ch.Telegram != nil {
		count++
		if err := validateTelegramChannel(*ch.Telegram); err != nil {
			return err
		}
	}
	if ch.Email != nil {
		count++
		if err := validateEmailChannel(*ch.Email); err != nil {
			return err
		}
	}
	if count == 0 {
		return fmt.Errorf("reporting.channels: at least one channel required (file, telegram or email)")
	}
	return nil
}

func validateTelegramChannel(ch TelegramChannelConfig) error {
	if strings.TrimSpace(ch.Token) == "" {
		return fmt.Errorf("reporting.channels.telegram.token cannot be empty")
	}
	if strings.TrimSpace(ch.ChatID) == "" {
		return fmt.Errorf("reporting.channels.telegram.chat_id cannot be empty")
	}
	if ch.MessageThreadID != nil && *ch.MessageThreadID <= 0 {
		return fmt.Errorf("reporting.channels.telegram.message_thread_id must be > 0")
	}
	return nil
}

func validateEmailChannel(ch EmailChannelConfig) error {
	if ch.UseTLS && ch.UseSSL {
		return fmt.Errorf("reporting.channels.email: use_tls and use_ssl cannot both be true")
	}
	if strings.TrimSpace(ch.Host) == "" {
		return fmt.Errorf("reporting.channels.email.host cannot be empty")
	}
	if strings.TrimSpace(ch.Port) == "" {
		return fmt.Errorf("reporting.channels.email.port cannot be empty")
	}
	if strings.TrimSpace(ch.User) == "" {
		return fmt.Errorf("reporting.channels.email.user cannot be empty")
	}
	if strings.TrimSpace(ch.Password) == "" {
		return fmt.Errorf("reporting.channels.email.password cannot be empty")
	}
	if strings.TrimSpace(ch.FromEmail) == "" {
		return fmt.Errorf("reporting.channels.email.from_email cannot be empty")
	}
	if len(ch.ToEmails) == 0 {
		return fmt.Errorf("reporting.channels.email.to_emails cannot be empty")
	}
	for i, addr := range ch.ToEmails {
		if strings.TrimSpace(addr) == "" {
			return fmt.Errorf("reporting.channels.email.to_emails[%d] cannot be empty", i)
		}
	}
	return nil
}

func (c Config) validateAnalyzers() error {
	if c.Analyzers.GoogleAI == nil {
		return nil
	}
	s := c.Analyzers.GoogleAI
	if strings.TrimSpace(s.APIKey) == "" {
		return fmt.Errorf("analyzers.google_ai.api_key cannot be empty")
	}
	if strings.TrimSpace(s.Model) == "" {
		return fmt.Errorf("analyzers.google_ai.model cannot be empty")
	}
	if c.Analyzers.TimeoutSeconds < 1 {
		return fmt.Errorf("analyzers.timeout_seconds must be >= 1")
	}
	return nil
}

func (c Config) hasModule(name string) bool {
	for _, m := range c.Modules.Enabled {
		if m == name {
			return true
		}
	}
	return false
}
