package chkrootkit

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

const chkrootkitCommand = "chkrootkit"

// Collector runs chkrootkit with launch_params; log file is only a fallback when exec fails.
type Collector struct {
	runner       execcmd.Runner
	reportPath   string
	launchParams []string
	now          func() time.Time
}

// New creates the chkrootkit collector.
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
	return config.ModuleChkrootkit
}

// Collect runs launch_params each slot; report_path only when exec fails.
func (c *Collector) Collect(ctx context.Context) (domain.ModuleResult, error) {
	content, source, err := c.loadOutput(ctx)
	if err != nil {
		return domain.ModuleResult{}, err
	}

	lastRun := ExtractLastRun(content)
	raw, err := domain.MarshalRaw(map[string]string{"last_run": lastRun})
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("chkrootkit: marshal raw: %w", err)
	}

	parsed, err := Parse(lastRun)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("chkrootkit: parse %s: %w", source, err)
	}

	moduleStatus := domain.ModuleStatusOK
	realFindings := parsed.FindingCount - parsed.FalsePositive
	if realFindings > 0 {
		moduleStatus = domain.ModuleStatusAttention
	}

	return domain.ModuleResult{
		Name:        domain.ModuleName(config.ModuleChkrootkit),
		Status:      moduleStatus,
		CollectedAt: c.now().UTC(),
		Raw:         raw,
		SectionText: FormatSectionText(parsed),
	}, nil
}

func (c *Collector) loadOutput(ctx context.Context) (string, string, error) {
	if len(c.launchParams) > 0 {
		content, err := c.exec(ctx)
		if err == nil {
			return content, "exec", nil
		}
		if logContent, logErr := c.readLog(); logErr == nil {
			return logContent, "log:" + c.reportPath, nil
		}
		return "", "", fmt.Errorf("chkrootkit: exec: %w", err)
	}

	logContent, err := c.readLog()
	if err != nil {
		return "", "", fmt.Errorf("chkrootkit: launch_params empty and log unavailable: %w", err)
	}
	return logContent, "log:" + c.reportPath, nil
}

func (c *Collector) exec(ctx context.Context) (string, error) {
	stdout, stderr, err := c.runner.Run(ctx, chkrootkitCommand, c.launchParams...)
	if strings.TrimSpace(stdout) != "" {
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
