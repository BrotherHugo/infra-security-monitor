package analyze

import (
	"context"
	"log/slog"
	"strings"
)

// Result is one analyzer outcome. The report template prints Name, Text, and Error.
type Result struct {
	Name  string
	Text  string
	Error string
}

// Run calls analyzers in order. A failure is a Result with Error set; the rest still run.
func Run(ctx context.Context, analyzers []Analyzer, in Input) (results []Result, errCount int) {
	results = make([]Result, 0, len(analyzers))
	for _, a := range analyzers {
		text, err := a.Append(ctx, in)
		if err != nil {
			errCount++
			slog.ErrorContext(ctx, "analyzer failed", "analyzer", a.Name(), "err", err)
			results = append(results, Result{Name: a.Name(), Error: err.Error()})
			continue
		}
		results = append(results, Result{Name: a.Name(), Text: strings.TrimSpace(text)})
	}
	return results, errCount
}
