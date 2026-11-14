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

// Analyzer produces text for one report cycle. The template decides how to print it.
type Analyzer interface {
	Name() string
	Append(ctx context.Context, in Input) (appendix string, err error)
}
