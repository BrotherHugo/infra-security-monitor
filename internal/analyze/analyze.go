package analyze

import (
	"context"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

// Input is one cycle context for an analyzer: report, raw module results, section order.
type Input struct {
	Report      domain.TextReport
	Results     []domain.ModuleResult
	ModuleOrder []string
}

// Analyzer appends an analysis section to the report after format and before send.
type Analyzer interface {
	Name() string
	Append(ctx context.Context, in Input) (appendix string, err error)
}
