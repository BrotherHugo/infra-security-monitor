package lynis

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

const lynisCommand = "lynis"

// Collector runs live lynis audit system --quick.
type Collector struct {
	runner         execcmd.Runner
	timeoutMinutes int
	reportPath     string
	now            func() time.Time
}

// New creates the lynis collector.
func New(runner execcmd.Runner, timeoutMinutes int, reportPath string) *Collector {
	return &Collector{
		runner:         runner,
		timeoutMinutes: timeoutMinutes,
		reportPath:     reportPath,
		now:            time.Now,
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
	return config.ModuleLynis
}

// Collect runs lynis audit system --quick with a timeout.
func (c *Collector) Collect(ctx context.Context) (domain.ModuleResult, error) {
	timeout := time.Duration(c.timeoutMinutes) * time.Minute
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout, stderr, err := c.runner.Run(runCtx, lynisCommand, "audit", "system", "--quick")
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("lynis: exec: %w; stderr=%s", err, strings.TrimSpace(stderr))
	}

	blobs := map[string]string{
		"stdout": stdout,
	}
	if strings.TrimSpace(stderr) != "" {
		blobs["stderr"] = stderr
	}
	if reportData, err := c.readReportFile(); err == nil && strings.TrimSpace(reportData) != "" {
		blobs["report_dat"] = reportData
	}

	raw, err := domain.MarshalRaw(blobs)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("lynis: marshal raw: %w", err)
	}

	parsed, err := parseFromBlobs(blobs)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("lynis: parse: %w", err)
	}

	moduleStatus := domain.ModuleStatusOK
	if parsed.WarningCount > 0 {
		moduleStatus = domain.ModuleStatusAttention
	}

	return domain.ModuleResult{
		Name:        domain.ModuleName(config.ModuleLynis),
		Status:      moduleStatus,
		CollectedAt: c.now().UTC(),
		Raw:         raw,
		SectionText: FormatSectionText(parsed),
	}, nil
}

func (c *Collector) readReportFile() (string, error) {
	if c.reportPath == "" {
		return "", fmt.Errorf("report_path is empty")
	}
	data, err := os.ReadFile(c.reportPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", c.reportPath, err)
	}
	return string(data), nil
}

func parseFromBlobs(blobs map[string]string) (ParseResult, error) {
	combined := combineOutput(blobs["stdout"], blobs["stderr"])

	var stdoutParsed ParseResult
	stdoutErr := tryParse(combined, &stdoutParsed)
	if stdoutErr == nil && stdoutParsed.isComplete() {
		return stdoutParsed, nil
	}

	reportDat := strings.TrimSpace(blobs["report_dat"])
	if reportDat != "" {
		reportParsed, reportErr := ParseReportDat(reportDat)
		if reportErr == nil {
			if stdoutErr == nil {
				merged := MergeParsed(stdoutParsed, reportParsed)
				if merged.isComplete() {
					return merged, nil
				}
			}
			if reportParsed.isComplete() {
				return reportParsed, nil
			}
		} else if stdoutErr != nil {
			return ParseResult{}, fmt.Errorf("stdout: %v; report: %v", stdoutErr, reportErr)
		}
	}

	if stdoutErr != nil {
		return ParseResult{}, stdoutErr
	}
	return ParseResult{}, fmt.Errorf("Hardening Index not found")
}

func tryParse(output string, dst *ParseResult) error {
	parsed, err := Parse(output)
	if err != nil {
		return err
	}
	*dst = parsed
	return nil
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
