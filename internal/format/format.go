package format

import (
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

// RunMeta is run metadata for the text report.
type RunMeta struct {
	RunID       int64
	Hostname    string
	GeneratedAt time.Time
	Location    *time.Location
	ModuleOrder []string
	Analyses    []Analysis
}

// Analysis is one analyzer result for the template. Error is set when the call failed.
type Analysis struct {
	Name  string
	Text  string
	Error string
}

// Build renders the built-in template.
func Build(meta RunMeta, results []domain.ModuleResult) (domain.TextReport, error) {
	return DefaultRenderer().Build(meta, results)
}

// Build renders the template for one cycle.
func (r *Renderer) Build(meta RunMeta, results []domain.ModuleResult) (domain.TextReport, error) {
	if r == nil {
		r = defaultRenderer
	}

	var body strings.Builder
	if err := r.tmpl.Execute(&body, newView(meta, results)); err != nil {
		return domain.TextReport{}, err
	}

	return domain.TextReport{
		GeneratedAt: meta.GeneratedAt,
		Hostname:    meta.Hostname,
		Body:        body.String(),
	}, nil
}
