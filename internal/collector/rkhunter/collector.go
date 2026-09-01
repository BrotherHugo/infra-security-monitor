package rkhunter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/execcmd"
)

const rkhunterCommand = "rkhunter"

// Collector runs rkhunter with launch_params; log file is only a fallback when exec fails.
type Collector struct {
	runner       execcmd.Runner
	reportPath   string
	launchParams []string
	now          func() time.Time
}

// New creates the rkhunter collector.
func New(runner execcmd.Runner, reportPath string, launchParams []string) *Collector {
	return &Collector{
		runner:       runner,
		reportPath:   reportPath,
		launchParams: append([]string(nil), launchParams...),
		now:          time.Now,
	}
}

// SetNow overrides the clock (tests only).
func (c *Collector) SetNow(now func() time.Time) {
	if now != nil {
		c.now = now
	}
}

// Name returns the module name.
func (c *Collector) Name() string {
	return config.ModuleRkhunter
}

// Collect runs launch_params each slot; prefers logfile (full output) for parsing.
func (c *Collector) Collect(ctx context.Context) (domain.ModuleResult, error) {
	content, source, err := c.loadOutput(ctx)
	if err != nil {
		return domain.ModuleResult{}, err
	}

	lastRun := ExtractLastRun(content)
	raw, err := domain.MarshalRaw(map[string]string{"last_run": lastRun})
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("rkhunter: marshal raw: %w", err)
	}

	parsed, err := Parse(lastRun)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("rkhunter: parse %s: %w", source, err)
	}

	moduleStatus := domain.ModuleStatusOK
	if parsed.NeedsAttention() {
		moduleStatus = domain.ModuleStatusAttention
	}

	return domain.ModuleResult{
		Name:        domain.ModuleName(config.ModuleRkhunter),
		Status:      moduleStatus,
		CollectedAt: c.now().UTC(),
		Raw:         raw,
		SectionText: FormatSectionText(parsed),
	}, nil
}

func (c *Collector) loadOutput(ctx context.Context) (string, string, error) {
	var execContent string
	if len(c.launchParams) > 0 {
		var err error
		execContent, err = c.exec(ctx)
		if err != nil {
			if logContent, logErr := c.readLog(); logErr == nil {
				return logContent, "log:" + c.reportPath, nil
			}
			return "", "", fmt.Errorf("rkhunter: exec: %w", err)
		}
	}

	// With --report-warnings-only stdout is mostly summary; [ Warning ] paths are in the logfile.
	if logContent, err := c.readLog(); err == nil {
		return logContent, "log:" + c.reportPath, nil
	}
	if execContent != "" {
		return execContent, "exec", nil
	}

	return "", "", fmt.Errorf("rkhunter: launch_params empty and log unavailable")
}

func (c *Collector) exec(ctx context.Context) (string, error) {
	stdout, stderr, err := c.runner.Run(ctx, rkhunterCommand, c.launchParams...)
	if strings.TrimSpace(stdout) != "" {
		// rkhunter exits 1 on warnings — stdout is still valid
		return combineOutput(stdout, stderr), nil
	}
	if err != nil {
		if msg := strings.TrimSpace(stderr); msg != "" {
			return "", fmt.Errorf("%w; stderr=%s", err, msg)
		}
		return "", err
	}
	if msg := strings.TrimSpace(stderr); msg != "" {
		return msg, nil
	}
	return "", fmt.Errorf("empty output")
}

func (c *Collector) readLog() (string, error) {
	if c.reportPath == "" {
		return "", fmt.Errorf("report_path is empty")
	}
	info, err := os.Stat(c.reportPath)
	if err != nil || info.Size() == 0 {
		return "", fmt.Errorf("file unavailable or empty")
	}
	data, err := os.ReadFile(c.reportPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", c.reportPath, err)
	}
	return string(data), nil
}

func combineOutput(stdout, stderr string) string {
	parts := make([]string, 0, 2)
	if strings.TrimSpace(stdout) != "" {
		parts = append(parts, stdout)
	}
	if strings.TrimSpace(stderr) != "" {
		parts = append(parts, stderr)
	}
	return strings.Join(parts, "\n")
}
