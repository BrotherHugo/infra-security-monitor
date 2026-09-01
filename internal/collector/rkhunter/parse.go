package rkhunter

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	markerCheckStarted = "=== rkhunter check started"
	warningPrefix      = "Warning:"
	maxWarningLines    = 50
	fpNote             = "note: file property warnings after package updates may be false positives; run rkhunter --propupd if needed"
)

var (
	warningBracketRE = regexp.MustCompile(`(?i)^(.+?)\s+\[\s*warning\s*\]\s*$`)
	suspectFilesRE   = regexp.MustCompile(`(?i)Suspect files:\s*(\d+)`)
	logTimestampRE   = regexp.MustCompile(`^\[\d{2}:\d{2}:\d{2}\]\s*`)
)

// ParseResult is the rkhunter log or stdout parse result.
type ParseResult struct {
	SummaryLines []string `json:"summary_lines"`
	Warnings     []string `json:"warnings"` // Warning: blocks (file property changes)
	Targets      []string `json:"targets"`  // lines with [ Warning ]: paths and checks
	WarningCount int      `json:"warning_count"`
	SuspectFiles int      `json:"suspect_files"`
	CleanRun     bool     `json:"clean_run,omitempty"`
}

// ExtractLastRun returns the last log chunk after the check started marker.
func ExtractLastRun(content string) string {
	content = strings.TrimSpace(content)
	if content == "" {
		return ""
	}
	idx := strings.LastIndex(content, markerCheckStarted)
	if idx < 0 {
		return content
	}
	return strings.TrimSpace(content[idx:])
}

// Parse parses rkhunter output.
func Parse(content string) (ParseResult, error) {
	chunk := ExtractLastRun(content)
	if strings.TrimSpace(chunk) == "" {
		return ParseResult{}, fmt.Errorf("empty rkhunter output")
	}

	var result ParseResult
	inSummary := false
	inWarningBlock := false
	var warningBlock []string

	flushWarningBlock := func() {
		if len(warningBlock) == 0 {
			inWarningBlock = false
			return
		}
		result.Warnings = append(result.Warnings, strings.Join(warningBlock, "\n"))
		warningBlock = nil
		inWarningBlock = false
	}

	for _, line := range strings.Split(chunk, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			flushWarningBlock()
			continue
		}
		if isCronMarker(trimmed) {
			flushWarningBlock()
			continue
		}

		if m := suspectFilesRE.FindStringSubmatch(trimmed); len(m) == 2 {
			if n, err := parseInt(m[1]); err == nil {
				result.SuspectFiles = n
			}
		}

		if text, ok := parseBracketWarning(trimmed); ok {
			flushWarningBlock()
			result.Targets = append(result.Targets, text)
			continue
		}

		if strings.HasPrefix(trimmed, "System checks summary") {
			flushWarningBlock()
			inSummary = true
			result.SummaryLines = append(result.SummaryLines, trimmed)
			continue
		}
		if inSummary {
			if strings.HasPrefix(trimmed, "===") || isWarningLine(trimmed) {
				inSummary = false
			} else {
				result.SummaryLines = append(result.SummaryLines, trimmed)
				continue
			}
		}
		if isSummaryStatLine(trimmed) {
			flushWarningBlock()
			result.SummaryLines = append(result.SummaryLines, trimmed)
			continue
		}

		if isWarningLine(trimmed) {
			flushWarningBlock()
			warningBlock = append(warningBlock, trimmed)
			inWarningBlock = true
			continue
		}
		if inWarningBlock && isWarningContinuation(trimmed, line) {
			warningBlock = append(warningBlock, trimmed)
			continue
		}

		flushWarningBlock()
	}
	flushWarningBlock()

	result.WarningCount = len(result.Warnings) + len(result.Targets)
	if len(result.SummaryLines) == 0 && result.WarningCount == 0 && result.SuspectFiles == 0 {
		result.CleanRun = true
	}
	return result, nil
}

// NeedsAttention is true when warnings, targets, or suspect files appear in the summary.
func (p ParseResult) NeedsAttention() bool {
	return p.WarningCount > 0 || p.SuspectFiles > 0
}

// FormatSectionText builds the report section text.
func FormatSectionText(parsed ParseResult) string {
	if parsed.CleanRun {
		return "status: ok (no warnings in last run)"
	}

	var parts []string
	if len(parsed.SummaryLines) > 0 {
		parts = append(parts, "system checks summary:")
		for _, line := range parsed.SummaryLines {
			parts = append(parts, "  "+line)
		}
	}
	warningItems := len(parsed.Targets) + len(parsed.Warnings)
	if warningItems > 0 {
		parts = append(parts, fmt.Sprintf("warnings (%d):", warningItems))
		shown := 0
		for _, target := range parsed.Targets {
			if shown >= maxWarningLines {
				break
			}
			parts = append(parts, "  "+target)
			shown++
		}
		for _, block := range parsed.Warnings {
			if shown >= maxWarningLines {
				break
			}
			for _, line := range strings.Split(block, "\n") {
				parts = append(parts, "  "+line)
			}
			shown++
		}
		if warningItems > maxWarningLines {
			parts = append(parts, fmt.Sprintf("  ... truncated, showing %d of %d", maxWarningLines, warningItems))
		}
		parts = append(parts, fpNote)
	} else {
		parts = append(parts, "warnings: 0")
	}
	return strings.Join(parts, "\n")
}

func parseBracketWarning(line string) (string, bool) {
	line = stripLogTimestamp(line)
	m := warningBracketRE.FindStringSubmatch(line)
	if len(m) != 2 {
		return "", false
	}
	text := strings.TrimSpace(m[1])
	if text == "" {
		return "", false
	}
	return text, true
}

func stripLogTimestamp(line string) string {
	return strings.TrimSpace(logTimestampRE.ReplaceAllString(strings.TrimSpace(line), ""))
}

func isCronMarker(line string) bool {
	return strings.HasPrefix(line, "=== rkhunter check ")
}

func isWarningLine(line string) bool {
	return strings.HasPrefix(line, warningPrefix) ||
		strings.HasPrefix(strings.ToLower(line), "warning:")
}

func isWarningContinuation(trimmed, raw string) bool {
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "file:") {
		return true
	}
	if strings.HasPrefix(lower, "current ") || strings.HasPrefix(lower, "stored ") {
		return true
	}
	return strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
}

func isSummaryStatLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasPrefix(lower, "number of ") ||
		strings.HasPrefix(lower, "suspect files:") ||
		strings.HasPrefix(lower, "possible rootkits:") ||
		strings.HasPrefix(lower, "rootkit checks:") ||
		strings.HasPrefix(lower, "files checked:")
}

func parseInt(raw string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(raw), "%d", &n)
	return n, err
}
