package unattendedupgrades

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

// Collector reads the tail of the unattended-upgrades log.
type Collector struct {
	logPath   string
	tailLines int
	staleDays int
	now       func() time.Time
}

// New creates the unattended-upgrades collector.
func New(logPath string, tailLines, staleDays int) *Collector {
	return &Collector{
		logPath:   logPath,
		tailLines: tailLines,
		staleDays: staleDays,
		now:       time.Now,
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
	return config.ModuleUnattendedUpgrades
}

// Collect reads and analyzes the unattended-upgrades log.
func (c *Collector) Collect(ctx context.Context) (domain.ModuleResult, error) {
	if err := ctx.Err(); err != nil {
		return domain.ModuleResult{}, err
	}

	data, err := os.ReadFile(c.logPath)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("unattended-upgrades: read %s: %w", c.logPath, err)
	}

	lines := splitLines(string(data))
	tail := tailLinesFrom(lines, c.tailLines)
	tailText := strings.Join(tail, "\n")

	raw, err := domain.MarshalRaw(map[string]string{"tail": tailText})
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("unattended-upgrades: marshal raw: %w", err)
	}

	now := c.now()
	parsed, err := Parse(tailText, 0, c.staleDays, now)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("unattended-upgrades: parse: %w", err)
	}

	moduleStatus := domain.ModuleStatusOK
	if NeedsAttention(parsed) {
		moduleStatus = domain.ModuleStatusAttention
	}

	return domain.ModuleResult{
		Name:        domain.ModuleName(config.ModuleUnattendedUpgrades),
		Status:      moduleStatus,
		CollectedAt: now.UTC(),
		Raw:         raw,
		SectionText: FormatSectionText(parsed),
	}, nil
}
