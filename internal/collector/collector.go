package collector

import (
	"context"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

// Collector is the port for collecting data from an OS security tool.
type Collector interface {
	Name() string
	Collect(ctx context.Context) (domain.ModuleResult, error)
}
