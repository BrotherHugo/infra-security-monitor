package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/config"
)

func TestLoad_exampleConfig(t *testing.T) {
	cfg, err := config.Load(filepath.Join("..", "..", "configs", "config.example.yaml"))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestLoad_defaultFail2banJails(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "08:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
  fail2ban: {}
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{"sshd", "nginx-limit-req"}
	if len(cfg.Modules.Fail2ban.Jails) != len(want) {
		t.Fatalf("jails = %v, want %v", cfg.Modules.Fail2ban.Jails, want)
	}
	for i, jail := range want {
		if cfg.Modules.Fail2ban.Jails[i] != jail {
			t.Fatalf("jails[%d] = %q, want %q", i, cfg.Modules.Fail2ban.Jails[i], jail)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestLoad_defaultRkhunterAndChkrootkit(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "08:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - auditd
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Modules.Rkhunter.ReportPath != "/var/log/rkhunter.log" {
		t.Fatalf("rkhunter report_path = %q", cfg.Modules.Rkhunter.ReportPath)
	}
	if len(cfg.Modules.Rkhunter.LaunchParams) == 0 {
		t.Fatal("expected default rkhunter launch_params")
	}
	if cfg.Modules.Chkrootkit.ReportPath != "/var/log/chkrootkit.log" {
		t.Fatalf("chkrootkit report_path = %q", cfg.Modules.Chkrootkit.ReportPath)
	}
	if len(cfg.Modules.Chkrootkit.LaunchParams) != 1 || cfg.Modules.Chkrootkit.LaunchParams[0] != "-q" {
		t.Fatalf("chkrootkit launch_params = %v", cfg.Modules.Chkrootkit.LaunchParams)
	}
}

func TestLoad_emptyEnabledMeansAllModules(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules: {}
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := []string{
		config.ModuleFail2ban,
		config.ModuleAuditd,
		config.ModuleRkhunter,
		config.ModuleChkrootkit,
		config.ModuleLynis,
		config.ModuleUnattendedUpgrades,
	}
	if len(cfg.Modules.Enabled) != len(want) {
		t.Fatalf("enabled = %v, want %v", cfg.Modules.Enabled, want)
	}
	for i, name := range want {
		if cfg.Modules.Enabled[i] != name {
			t.Fatalf("enabled[%d] = %q, want %q", i, cfg.Modules.Enabled[i], name)
		}
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidate_invalidTime(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "invalid format",
			content: `
reporting:
  time:
    - "25:99"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`,
			wantErr: "HH:MM",
		},
		{
			name: "empty slot list",
			content: `
reporting:
  time: []
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`,
			wantErr: "at least one slot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, tt.content)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatal("expected Validate() error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidate_unknownModule(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - unknown-mod
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate() error")
	}
	if !strings.Contains(err.Error(), "unknown module") {
		t.Fatalf("Validate() error = %q", err.Error())
	}
}

func TestValidate_emailTLSAndSSLMutuallyExclusive(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    email:
      host: smtp.example.com
      port: "587"
      user: u
      password: p
      use_tls: true
      use_ssl: true
      from_email: ism@example.com
      to_emails:
        - admin@example.com
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate() error")
	}
	if !strings.Contains(err.Error(), "use_tls") {
		t.Fatalf("Validate() error = %q", err.Error())
	}
}

func TestValidate_telegramMessageThreadID(t *testing.T) {
	t.Run("valid optional", func(t *testing.T) {
		path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    telegram:
      token: tok
      chat_id: "-100123"
      message_thread_id: 42
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Reporting.Channels.Telegram.MessageThreadID == nil || *cfg.Reporting.Channels.Telegram.MessageThreadID != 42 {
			t.Fatalf("message_thread_id = %v, want 42", cfg.Reporting.Channels.Telegram.MessageThreadID)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
	})

	t.Run("invalid zero", func(t *testing.T) {
		path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    telegram:
      token: tok
      chat_id: "-100123"
      message_thread_id: 0
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`)
		cfg, err := config.Load(path)
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		err = cfg.Validate()
		if err == nil {
			t.Fatal("expected Validate() error")
		}
		if !strings.Contains(err.Error(), "message_thread_id") {
			t.Fatalf("Validate() error = %q", err.Error())
		}
	})
}

func TestValidate_emptyChannels(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			name: "no channel sections",
			content: `
reporting:
  time:
    - "12:00"
  channels: {}
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`,
			wantErr: "at least one channel",
		},
		{
			name: "file without save_to_dir",
			content: `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: ""
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`,
			wantErr: "save_to_dir",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeTempConfig(t, tt.content)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			err = cfg.Validate()
			if err == nil {
				t.Fatal("expected Validate() error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidate_keepHistoryDays(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 0
modules:
  enabled:
    - fail2ban
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate() error")
	}
	if !strings.Contains(err.Error(), "keep_history_days") {
		t.Fatalf("Validate() error = %q", err.Error())
	}
}

func TestValidate_googleAIRequiresAPIKey(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
analyzers:
  google_ai:
    api_key: ""
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	err = cfg.Validate()
	if err == nil {
		t.Fatal("expected Validate() error")
	}
	if !strings.Contains(err.Error(), "api_key") {
		t.Fatalf("Validate() error = %q", err.Error())
	}
}

func TestValidate_googleAIAbsentOK(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestLoad_googleAIDefaults(t *testing.T) {
	path := writeTempConfig(t, `
reporting:
  time:
    - "12:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
analyzers:
  google_ai:
    api_key: secret
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Analyzers.GoogleAI.Model != "gemini-2.5-flash" {
		t.Fatalf("model = %q, want gemini-2.5-flash", cfg.Analyzers.GoogleAI.Model)
	}
	if cfg.Analyzers.TimeoutSeconds != 120 {
		t.Fatalf("timeout_seconds = %d, want 120", cfg.Analyzers.TimeoutSeconds)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestLoad_hostnameOverride(t *testing.T) {
	path := writeTempConfig(t, `
hostname: "  web-1  "
reporting:
  time:
    - "08:00"
  channels:
    file:
      save_to_dir: /tmp/ism-reports
keep_history_days: 7
modules:
  enabled:
    - fail2ban
`)

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Hostname != "web-1" {
		t.Fatalf("hostname = %q, want web-1", cfg.Hostname)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}
