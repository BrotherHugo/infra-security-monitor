package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/execcmd"
	"github.com/BrotherHugo/infra-security-monitor/internal/scheduler"
	"github.com/BrotherHugo/infra-security-monitor/internal/service/report"
	"github.com/BrotherHugo/infra-security-monitor/internal/store/sqlite"
)

// Options are daemon startup parameters passed from cmd/ismd.
type Options struct {
	ConfigPath string
	DBPath     string
	Once       bool

	// Test hooks; nil in production.
	Runner   execcmd.Runner
	Clock    func() time.Time
	Hostname func() (string, error)
}

// Run wires dependencies and starts the daemon (once or on schedule).
func Run(ctx context.Context, opts Options) error {
	setupLogging()

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return fmt.Errorf("config load: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validate: %w", err)
	}

	loc, err := loadLocation(cfg.Timezone)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(opts.DBPath), 0o750); err != nil {
		return fmt.Errorf("mkdir db dir: %w", err)
	}

	store, err := sqlite.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("sqlite open: %w", err)
	}
	defer store.Close()

	runner := opts.Runner
	if runner == nil {
		runner = execcmd.Exec{}
	}

	collectors, err := BuildCollectors(cfg, runner)
	if err != nil {
		return fmt.Errorf("collectors: %w", err)
	}

	channels, err := BuildChannels(cfg, loc)
	if err != nil {
		return fmt.Errorf("channels: %w", err)
	}

	analyzers, err := BuildAnalyzers(cfg)
	if err != nil {
		return fmt.Errorf("analyzers: %w", err)
	}

	clock := opts.Clock
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}

	reportService := report.New(
		store,
		collectors,
		channels,
		analyzers,
		resolveHostname(opts, cfg),
		clock,
		loc,
		cfg.KeepHistoryDays,
		cfg.Modules.Enabled,
	)

	slog.InfoContext(ctx, "ismd: starting",
		"config", opts.ConfigPath,
		"db", opts.DBPath,
		"once", opts.Once,
		"modules", len(collectors),
		"channels", len(channels),
		"analyzers", len(analyzers),
	)

	if opts.Once {
		return reportService.RunCycle(ctx)
	}

	sched := scheduler.New(cfg.Reporting.Time, loc, reportService)
	if opts.Clock != nil {
		sched.SetNow(opts.Clock)
	}
	return sched.Run(ctx)
}

func setupLogging() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))
}

// resolveHostname returns the func for ReportService: test hook, then config hostname, else os.Hostname.
func resolveHostname(opts Options, cfg config.Config) func() (string, error) {
	if opts.Hostname != nil {
		return opts.Hostname
	}
	if cfg.Hostname != "" {
		hostname := cfg.Hostname
		return func() (string, error) { return hostname, nil }
	}
	return nil
}
