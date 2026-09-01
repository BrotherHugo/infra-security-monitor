package unattendedupgrades

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	markerAllInstalled  = "all upgrades installed"
	markerKeptBack      = "kept back"
	maxDisplayTailLines = 15
)

var logTimestampRE = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})`)

// ParseResult is the unattended-upgrades log analysis result.
type ParseResult struct {
	TailLines         []string   `json:"tail_lines"`
	WarningLines      []string   `json:"warning_lines"`
	KeptBackLines     []string   `json:"kept_back_lines"`
	LastSuccess       *time.Time `json:"last_success,omitempty"`
	LastSuccessRaw    string     `json:"last_success_raw,omitempty"`
	Stale             bool       `json:"stale"`
	StaleDays         int        `json:"stale_days"`
	TailWindowLines   int        `json:"tail_window_lines"`
}

// Parse parses the tail of the unattended-upgrades log.
func Parse(content string, tailLines int, staleDays int, now time.Time) (ParseResult, error) {
	lines := splitLines(content)
	if len(lines) == 0 {
		return ParseResult{}, fmt.Errorf("empty unattended-upgrades log")
	}

	if tailLines <= 0 {
		tailLines = len(lines)
	}
	tail := tailLinesFrom(lines, tailLines)

	result := ParseResult{
		TailLines:       tail,
		StaleDays:       staleDays,
		TailWindowLines: tailLines,
	}

	for i := len(lines) - 1; i >= 0; i-- {
		line := lines[i]
		lower := strings.ToLower(line)
		if strings.Contains(lower, markerAllInstalled) {
			if ts, ok := parseLogTimestamp(line); ok {
				result.LastSuccess = &ts
				result.LastSuccessRaw = line
				break
			}
		}
	}

	for _, line := range tail {
		lower := strings.ToLower(line)
		if isWarningOrErrorLine(lower) {
			result.WarningLines = append(result.WarningLines, line)
		}
		if strings.Contains(lower, markerKeptBack) {
			result.KeptBackLines = append(result.KeptBackLines, line)
		}
	}

	if result.LastSuccess != nil && staleDays > 0 {
		deadline := now.AddDate(0, 0, -staleDays)
		if result.LastSuccess.Before(deadline) {
			result.Stale = true
		}
	} else if staleDays > 0 {
		result.Stale = true
	}

	return result, nil
}

// NeedsAttention returns true when the log shows problems.
func NeedsAttention(parsed ParseResult) bool {
	return len(parsed.WarningLines) > 0 || len(parsed.KeptBackLines) > 0 || parsed.Stale
}

// FormatSectionText builds the report section text.
func FormatSectionText(parsed ParseResult) string {
	var parts []string
	if parsed.LastSuccessRaw != "" {
		parts = append(parts, "last success: "+parsed.LastSuccessRaw)
	} else {
		parts = append(parts, "last success: not found")
	}
	if parsed.Stale {
		parts = append(parts, fmt.Sprintf("stale: yes (> %d days)", parsed.StaleDays))
	} else {
		parts = append(parts, "stale: no")
	}
	if len(parsed.WarningLines) > 0 {
		parts = append(parts, fmt.Sprintf("warnings/errors in tail (%d):", len(parsed.WarningLines)))
		for _, line := range parsed.WarningLines {
			parts = append(parts, "  "+line)
		}
	}
	if len(parsed.KeptBackLines) > 0 {
		parts = append(parts, fmt.Sprintf("kept back in tail (%d):", len(parsed.KeptBackLines)))
		for _, line := range parsed.KeptBackLines {
			parts = append(parts, "  "+line)
		}
	}

	if NeedsAttention(parsed) {
		parts = append(parts, formatTailSection(parsed.TailLines))
	}
	return strings.Join(parts, "\n")
}

func formatTailSection(tail []string) string {
	if len(tail) == 0 {
		return "tail: empty"
	}
	display := tail
	label := "tail:"
	if len(display) > maxDisplayTailLines {
		display = display[len(display)-maxDisplayTailLines:]
		label = fmt.Sprintf("tail (last %d of %d lines in window):", len(display), len(tail))
	}
	var parts []string
	parts = append(parts, label)
	for _, line := range display {
		parts = append(parts, "  "+line)
	}
	return strings.Join(parts, "\n")
}

func tailLinesFrom(lines []string, tailLines int) []string {
	if tailLines <= 0 || len(lines) <= tailLines {
		return append([]string(nil), lines...)
	}
	start := len(lines) - tailLines
	return append([]string(nil), lines[start:]...)
}

func isWarningOrErrorLine(lower string) bool {
	return strings.Contains(lower, "warning") || strings.Contains(lower, "error")
}

func splitLines(content string) []string {
	raw := strings.Split(content, "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func parseLogTimestamp(line string) (time.Time, bool) {
	m := logTimestampRE.FindStringSubmatch(strings.TrimSpace(line))
	if len(m) != 3 {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation("2006-01-02 15:04:05", m[1]+" "+m[2], time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}
