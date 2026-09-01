package auditd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/execcmd"
)

const aureportCommand = "aureport"

// Collector gathers auditd summaries via aureport.
type Collector struct {
	runner execcmd.Runner
	now    func() time.Time
}

// New creates the auditd collector.
func New(runner execcmd.Runner) *Collector {
	return &Collector{
		runner: runner,
		now:    time.Now,
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
	return config.ModuleAuditd
}

// Collect runs aureport summary/config/anomaly/file for yesterday.
func (c *Collector) Collect(ctx context.Context) (domain.ModuleResult, error) {
	summaryStdout, stderr, err := c.runner.Run(ctx, aureportCommand, "--summary", "-ts", "yesterday")
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("auditd: summary: %w; stderr=%s", err, strings.TrimSpace(stderr))
	}

	configStdout, err := runAureport(ctx, c.runner, "-c", "-ts", "yesterday")
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("auditd: config change: %w", err)
	}

	anomalyStdout, err := runAureport(ctx, c.runner, "--anomaly", "-ts", "yesterday")
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("auditd: anomaly: %w", err)
	}

	fileStdout, err := runAureport(ctx, c.runner, "--file", "-ts", "yesterday")
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("auditd: file report: %w", err)
	}

	blobs := map[string]string{
		"summary": summaryStdout,
		"config":  configStdout,
		"anomaly": anomalyStdout,
		"file":    fileStdout,
	}
	raw, err := domain.MarshalRaw(blobs)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("auditd: marshal raw: %w", err)
	}

	summary, err := ParseSummary(blobs["summary"])
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("auditd: parse summary: %w", err)
	}
	configReport := ParseConfigChange(blobs["config"])
	anomalyReport := ParseAnomalyReport(blobs["anomaly"])
	fileReport := ParseFileReport(blobs["file"])

	moduleStatus := domain.ModuleStatusOK
	if summary.FailedLogins > 0 || summary.AnomalyEvents > 0 || fileReport.HasEvents {
		moduleStatus = domain.ModuleStatusAttention
	}

	return domain.ModuleResult{
		Name:        domain.ModuleName(config.ModuleAuditd),
		Status:      moduleStatus,
		CollectedAt: c.now().UTC(),
		Raw:         raw,
		SectionText: FormatSectionText(summary, configReport, anomalyReport, fileReport),
	}, nil
}

// runAureport runs aureport; exit 1 with empty stderr on empty/no-events output is normal.
func runAureport(ctx context.Context, runner execcmd.Runner, args ...string) (string, error) {
	stdout, stderr, err := runner.Run(ctx, aureportCommand, args...)
	if err == nil {
		return stdout, nil
	}
	trimmedStdout := strings.TrimSpace(stdout)
	trimmedStderr := strings.TrimSpace(stderr)
	if trimmedStderr == "" && (trimmedStdout == "" || isNoEventsOutput(trimmedStdout)) {
		return stdout, nil
	}
	return "", fmt.Errorf("exec %s %v: %w; stderr=%s", aureportCommand, args, err, trimmedStderr)
}
