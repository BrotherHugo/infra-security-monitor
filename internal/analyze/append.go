package analyze

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// AppendAll calls analyzers in order and appends to body.
// On a single analyzer error the cycle continues; errCount is the number of failures.
func AppendAll(ctx context.Context, body string, analyzers []Analyzer, in Input) (newBody string, errCount int) {
	newBody = body
	for _, a := range analyzers {
		header := fmt.Sprintf("\n=== AI analysis (%s) ===\n", a.Name())
		appendix, err := a.Append(ctx, in)
		if err != nil {
			errCount++
			slog.ErrorContext(ctx, "analyzer failed", "analyzer", a.Name(), "err", err)
			newBody += header + "ERROR: " + err.Error() + "\n"
			continue
		}
		newBody += header + strings.TrimSpace(appendix) + "\n"
	}
	return newBody, errCount
}
