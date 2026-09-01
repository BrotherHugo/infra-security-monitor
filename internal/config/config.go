package config

// Config is the root YAML config structure for ISM.
type Config struct {
	Reporting       Reporting `yaml:"reporting"`
	KeepHistoryDays int       `yaml:"keep_history_days"`
	Timezone        string    `yaml:"timezone"`
	Hostname        string    `yaml:"hostname,omitempty"`
	Modules         Modules   `yaml:"modules"`
	Analyzers       Analyzers `yaml:"analyzers"`
}

// Modules lists enabled collectors and their per-module settings.
// Empty Enabled after Load means all modules (see applyDefaults).
type Modules struct {
	Enabled            []string                    `yaml:"enabled"`
	Fail2ban           Fail2banSettings            `yaml:"fail2ban"`
	Rkhunter           RkhunterSettings            `yaml:"rkhunter"`
	Chkrootkit         ChkrootkitSettings          `yaml:"chkrootkit"`
	Lynis              LynisSettings               `yaml:"lynis"`
	UnattendedUpgrades UnattendedUpgradesSettings  `yaml:"unattended_upgrades"`
}

// Analyzers holds optional analyzer sections; nil means disabled.
type Analyzers struct {
	Prompt         string            `yaml:"prompt,omitempty"`
	CustomRules    string            `yaml:"custom_rules,omitempty"`
	TimeoutSeconds int               `yaml:"timeout_seconds,omitempty"`
	GoogleAI       *GoogleAISettings `yaml:"google_ai,omitempty"`
}

// Reporting is the report schedule and delivery channels.
type Reporting struct {
	Time     []string `yaml:"time"`
	Channels Channels `yaml:"channels"`
}

// Channels holds optional channel sections; nil means disabled.
type Channels struct {
	File     *FileChannelConfig     `yaml:"file,omitempty"`
	Telegram *TelegramChannelConfig `yaml:"telegram,omitempty"`
	Email    *EmailChannelConfig    `yaml:"email,omitempty"`
}

// FileChannelConfig writes the report to a directory on disk.
type FileChannelConfig struct {
	SaveToDir string `yaml:"save_to_dir"`
}

// TelegramChannelConfig delivers via Telegram Bot API.
type TelegramChannelConfig struct {
	Token           string `yaml:"token"`
	ChatID          string `yaml:"chat_id"`
	MessageThreadID *int   `yaml:"message_thread_id,omitempty"`
}

// EmailChannelConfig delivers via SMTP.
type EmailChannelConfig struct {
	Host      string   `yaml:"host"`
	Port      string   `yaml:"port"`
	User      string   `yaml:"user"`
	Password  string   `yaml:"password"`
	UseTLS    bool     `yaml:"use_tls"`
	UseSSL    bool     `yaml:"use_ssl"`
	FromEmail string   `yaml:"from_email"`
	ToEmails  []string `yaml:"to_emails"`
}

// GoogleAISettings configures the google-ai analyzer (Gemini).
type GoogleAISettings struct {
	APIKey string `yaml:"api_key"`
	Model  string `yaml:"model"`
}

// LynisSettings configures the live lynis scan.
type LynisSettings struct {
	TimeoutMinutes int    `yaml:"timeout_minutes"`
	ReportPath     string `yaml:"report_path"`
}

// UnattendedUpgradesSettings configures unattended-upgrades log reading.
type UnattendedUpgradesSettings struct {
	LogPath   string `yaml:"log_path"`
	TailLines int    `yaml:"tail_lines"`
	StaleDays int    `yaml:"stale_days"`
}

// Fail2banSettings lists jails for the fail2ban collector.
type Fail2banSettings struct {
	Jails []string `yaml:"jails"`
}

// RkhunterSettings is the log path and launch parameters for rkhunter.
type RkhunterSettings struct {
	ReportPath   string   `yaml:"report_path"`
	LaunchParams []string `yaml:"launch_params"`
}

// ChkrootkitSettings is the log path and launch parameters for chkrootkit.
type ChkrootkitSettings struct {
	ReportPath   string   `yaml:"report_path"`
	LaunchParams []string `yaml:"launch_params"`
}
