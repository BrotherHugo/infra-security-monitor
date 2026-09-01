package fail2ban

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/execcmd"
)

const clientCommand = "fail2ban-client"

// Collector gathers jail status via fail2ban-client.
type Collector struct {
	runner execcmd.Runner
	jails  []string
	now    func() time.Time
}

// New creates the fail2ban collector.
func New(runner execcmd.Runner, jails []string) *Collector {
	return &Collector{
		runner: runner,
		jails:  append([]string(nil), jails...),
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
	return config.ModuleFail2ban
}

// Collect polls each jail and builds a summary.
func (c *Collector) Collect(ctx context.Context) (domain.ModuleResult, error) {
	if len(c.jails) == 0 {
		return domain.ModuleResult{}, fmt.Errorf("fail2ban: jail list is empty")
	}

	blobs := make(map[string]string, len(c.jails))
	var sections []string
	moduleStatus := domain.ModuleStatusOK

	for _, jail := range c.jails {
		stdout, stderr, err := c.runner.Run(ctx, clientCommand, "status", jail)
		if err != nil {
			return domain.ModuleResult{}, fmt.Errorf("fail2ban: jail %q: %w; stderr=%s", jail, err, strings.TrimSpace(stderr))
		}

		blobs[jail] = stdout

		stat, err := parseStatus(stdout, jail)
		if err != nil {
			return domain.ModuleResult{}, fmt.Errorf("fail2ban: jail %q: %w", jail, err)
		}
		sections = append(sections, formatJailSection(stat))

		if stat.CurrentlyBanned > 0 || len(stat.BannedIPs) > 0 {
			moduleStatus = domain.ModuleStatusAttention
		}
	}

	raw, err := domain.MarshalRaw(blobs)
	if err != nil {
		return domain.ModuleResult{}, fmt.Errorf("fail2ban: marshal raw: %w", err)
	}

	return domain.ModuleResult{
		Name:        domain.ModuleName(config.ModuleFail2ban),
		Status:      moduleStatus,
		CollectedAt: c.now().UTC(),
		Raw:         raw,
		SectionText: strings.Join(sections, "\n"),
	}, nil
}

func formatJailSection(stat JailStatus) string {
	ips := "-"
	if len(stat.BannedIPs) > 0 {
		ips = strings.Join(stat.BannedIPs, " ")
	}
	return fmt.Sprintf(
		"jail %s: failed=%d/%d banned=%d/%d ips=%s",
		stat.Name,
		stat.CurrentlyFailed,
		stat.TotalFailed,
		stat.CurrentlyBanned,
		stat.TotalBanned,
		ips,
	)
}
