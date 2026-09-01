package lynis

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	hardeningIndexRE = regexp.MustCompile(`(?i)hardening\s+index\s*:\s*(\d+)`)
	warningsCountRE  = regexp.MustCompile(`(?i)warnings?\s*\(\s*(\d+)\s*\)`)
)

const maxWarningLines = 50

// ParseResult is the lynis stdout parse result.
type ParseResult struct {
	HardeningIndex int      `json:"hardening_index"`
	WarningCount   int      `json:"warning_count"`
	Warnings       []string `json:"warnings"`
	HasStdoutSummary bool   `json:"has_stdout_summary,omitempty"`
	FromReportFile   bool   `json:"from_report_file,omitempty"`
}

// Parse parses lynis audit system --quick stdout/stderr.
func Parse(output string) (ParseResult, error) {
	var result ParseResult
	inWarnings := false

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if m := hardeningIndexRE.FindStringSubmatch(trimmed); len(m) == 2 {
			idx, err := strconv.Atoi(m[1])
			if err != nil {
				return ParseResult{}, fmt.Errorf("hardening index: %w", err)
			}
			result.HardeningIndex = idx
			result.HasStdoutSummary = true
			continue
		}

		if m := warningsCountRE.FindStringSubmatch(trimmed); len(m) == 2 {
			count, err := strconv.Atoi(m[1])
			if err != nil {
				return ParseResult{}, fmt.Errorf("warnings count: %w", err)
			}
			result.WarningCount = count
			result.HasStdoutSummary = true
			inWarnings = count > 0
			continue
		}

		if strings.HasPrefix(strings.ToLower(trimmed), "suggestions (") {
			inWarnings = false
			continue
		}

		if inWarnings && isWarningBullet(trimmed) {
			result.Warnings = append(result.Warnings, trimmed)
		}
	}

	if !result.isComplete() {
		return ParseResult{}, fmt.Errorf("Hardening Index not found")
	}
	return result, nil
}

// ParseReportDat parses /var/log/lynis-report.dat (key=value).
func ParseReportDat(content string) (ParseResult, error) {
	var result ParseResult

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasPrefix(trimmed, "hardening_index=") {
			raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "hardening_index="))
			idx, err := strconv.Atoi(raw)
			if err != nil {
				return ParseResult{}, fmt.Errorf("hardening_index: %w", err)
			}
			result.HardeningIndex = idx
			result.FromReportFile = true
			continue
		}

		if strings.HasPrefix(trimmed, "warning[]=") {
			text := formatReportWarning(trimmed)
			result.Warnings = append(result.Warnings, text)
		}
	}

	result.WarningCount = len(result.Warnings)
	if result.HardeningIndex == 0 && result.WarningCount == 0 {
		return ParseResult{}, fmt.Errorf("report.dat: no hardening_index or warnings")
	}
	result.FromReportFile = true
	return result, nil
}

// MergeParsed merges stdout and report.dat results.
func MergeParsed(stdout, report ParseResult) ParseResult {
	merged := stdout
	if merged.HardeningIndex == 0 && report.HardeningIndex > 0 {
		merged.HardeningIndex = report.HardeningIndex
	}
	if len(merged.Warnings) == 0 && report.WarningCount > 0 {
		merged.Warnings = append([]string(nil), report.Warnings...)
		merged.WarningCount = report.WarningCount
	} else if merged.WarningCount == 0 && report.WarningCount > 0 {
		merged.WarningCount = report.WarningCount
	}
	if report.FromReportFile {
		merged.FromReportFile = true
	}
	if stdout.HasStdoutSummary {
		merged.HasStdoutSummary = true
	}
	return merged
}

func (p ParseResult) isComplete() bool {
	return p.HardeningIndex > 0 || p.HasStdoutSummary || p.WarningCount > 0 || len(p.Warnings) > 0
}

func isWarningBullet(line string) bool {
	if strings.HasPrefix(line, "!") {
		return true
	}
	if !strings.HasPrefix(line, "-") {
		return false
	}
	rest := strings.TrimSpace(strings.TrimPrefix(line, "-"))
	if rest == "" {
		return false
	}
	// Lynis prints separator "----------------------------" in the warnings section.
	return strings.Trim(rest, "-") != ""
}

func formatReportWarning(line string) string {
	value := strings.TrimPrefix(line, "warning[]=")
	parts := strings.Split(value, "|")
	if len(parts) >= 2 {
		testID := strings.TrimSpace(parts[0])
		text := strings.TrimSpace(parts[1])
		if testID != "" && text != "" {
			return fmt.Sprintf("- %s [%s]", text, testID)
		}
		if text != "" {
			return "- " + text
		}
	}
	return "- " + strings.TrimSpace(value)
}

// FormatSectionText builds the report section text.
func FormatSectionText(parsed ParseResult) string {
	var parts []string
	if parsed.HardeningIndex > 0 {
		parts = append(parts, fmt.Sprintf("hardening index: %d", parsed.HardeningIndex))
	}
	parts = append(parts, fmt.Sprintf("warnings (%d):", parsed.WarningCount))
	if len(parsed.Warnings) == 0 {
		parts = append(parts, "  none")
	} else {
		shown := parsed.Warnings
		if len(shown) > maxWarningLines {
			shown = shown[:maxWarningLines]
			parts = append(parts, fmt.Sprintf("  ... truncated, showing %d of %d", maxWarningLines, parsed.WarningCount))
		}
		for _, w := range shown {
			parts = append(parts, "  "+w)
		}
	}
	return strings.Join(parts, "\n")
}
