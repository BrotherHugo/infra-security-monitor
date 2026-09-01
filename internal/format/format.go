package format

import (
	"fmt"
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
}

// Build assembles a single text report from module results.
func Build(meta RunMeta, results []domain.ModuleResult) domain.TextReport {
	loc := meta.Location
	if loc == nil {
		loc = time.Local
	}

	byName := make(map[string]domain.ModuleResult, len(results))
	for _, result := range results {
		byName[string(result.Name)] = result
	}

	var body strings.Builder
	fmt.Fprintf(&body, "ISM report\n")
	fmt.Fprintf(&body, "id: %d\n", meta.RunID)
	fmt.Fprintf(&body, "host: %s\n", meta.Hostname)
	fmt.Fprintf(&body, "time: %s\n", meta.GeneratedAt.In(loc).Format("2006-01-02 15:04:05"))
	fmt.Fprintf(&body, "modules: %s\n", strings.Join(meta.ModuleOrder, ", "))

	for _, name := range meta.ModuleOrder {
		result, ok := byName[name]
		fmt.Fprintf(&body, "\n=== %s ===\n", name)
		if !ok {
			fmt.Fprintf(&body, "status: ok\n")
			continue
		}
		writeModuleSection(&body, result)
	}

	return domain.TextReport{
		GeneratedAt: meta.GeneratedAt,
		Hostname:    meta.Hostname,
		Body:        body.String(),
	}
}

func writeModuleSection(body *strings.Builder, result domain.ModuleResult) {
	switch {
	case result.Status == domain.ModuleStatusError:
		if strings.TrimSpace(result.SectionText) != "" {
			fmt.Fprintf(body, "%s\n", strings.TrimSpace(result.SectionText))
			return
		}
		if strings.TrimSpace(result.Error) != "" {
			fmt.Fprintf(body, "ERROR: %s\n", strings.TrimSpace(result.Error))
			return
		}
		fmt.Fprintf(body, "ERROR: unknown error\n")
	case strings.TrimSpace(result.SectionText) == "":
		fmt.Fprintf(body, "status: ok\n")
	default:
		fmt.Fprintf(body, "%s\n", strings.TrimSpace(result.SectionText))
	}
}
