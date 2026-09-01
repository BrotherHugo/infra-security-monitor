package channel

import (
	"context"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

// Channel is the port for delivering a finished text report.
type Channel interface {
	Name() string
	Send(ctx context.Context, report domain.TextReport) error
}
