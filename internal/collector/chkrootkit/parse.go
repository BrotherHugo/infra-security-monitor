package chkrootkit

import (
	"fmt"
	"strings"
)

const maxFindingLines = 50

// Finding is one suspicious chkrootkit line.
type Finding struct {
	Line                  string `json:"line"`
	PossibleFalsePositive bool   `json:"possible_false_positive,omitempty"`
	Reason                string `json:"reason,omitempty"`
}

// ParseResult is the chkrootkit log parse result.
type ParseResult struct {
	Findings      []Finding `json:"findings"`
	FindingCount  int       `json:"finding_count"`
	FalsePositive int       `json:"false_positive_count"`
}

// ExtractLastRun returns the last log chunk after the check started marker.
func ExtractLastRun(content string) string {
	content = strings.TrimSpace(content)
	if content == "" {
		return ""
	}
	marker := "=== chkrootkit check started"
	idx := strings.LastIndex(content, marker)
	if idx < 0 {
		return content
	}
	return strings.TrimSpace(content[idx:])
}

// Parse parses chkrootkit output.
func Parse(content string) (ParseResult, error) {
	chunk := ExtractLastRun(content)
	if strings.TrimSpace(chunk) == "" {
		return ParseResult{}, fmt.Errorf("empty chkrootkit output")
	}

	var result ParseResult
	for _, line := range strings.Split(chunk, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if isHealthyNoise(trimmed) {
			continue
		}
		if !isSuspiciousLine(trimmed) {
			continue
		}
		finding := Finding{Line: trimmed}
		if reason := detectFalsePositive(trimmed); reason != "" {
			finding.PossibleFalsePositive = true
			finding.Reason = reason
			result.FalsePositive++
		}
		result.Findings = append(result.Findings, finding)
	}

	result.FindingCount = len(result.Findings)
	return result, nil
}

// FormatSectionText builds the report section text.
func FormatSectionText(parsed ParseResult) string {
	if parsed.FindingCount == 0 {
		return "findings: 0"
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("findings (%d):", parsed.FindingCount))
	shown := parsed.Findings
	if len(shown) > maxFindingLines {
		shown = shown[:maxFindingLines]
		parts = append(parts, fmt.Sprintf("  ... truncated, showing %d of %d", maxFindingLines, parsed.FindingCount))
	}
	for _, f := range shown {
		line := "  " + f.Line
		if f.PossibleFalsePositive {
			line += " [possible_false_positive: " + f.Reason + "]"
		}
		parts = append(parts, line)
	}
	return strings.Join(parts, "\n")
}

func isHealthyNoise(line string) bool {
	lower := strings.ToLower(line)
	if strings.HasPrefix(lower, "=== chkrootkit check") {
		return true
	}

	healthySubstrings := []string{
		"not infected",
		"nothing found",
		"no suspect files",
		"not promisc and no packet sniffer sockets",
		"chkutmp: nothing deleted",
		"chkproc: nothing detected",
		"chkwtmp: nothing deleted",
		"chklastlog: nothing deleted",
		"not tested",
		"output from ifpromisc:",
	}
	for _, pattern := range healthySubstrings {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	if strings.Contains(lower, "checking `") && strings.HasSuffix(lower, "not found") {
		return true
	}
	return false
}

func isSuspiciousLine(line string) bool {
	if isHealthyNoise(line) {
		return false
	}

	lower := strings.ToLower(line)
	if strings.Contains(lower, "infected") {
		return true
	}
	if strings.Contains(lower, "packet sniffer(") {
		return true
	}
	if strings.Contains(lower, "tty of the following process") {
		return true
	}
	if strings.HasPrefix(line, "!") {
		return true
	}
	return false
}

func detectFalsePositive(line string) string {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "fail2ban/tests") {
		return "fail2ban test path"
	}
	if strings.Contains(lower, "packet sniffer") && strings.Contains(lower, "systemd-networkd") {
		return "systemd-networkd sniffer"
	}
	if strings.HasPrefix(strings.TrimSpace(line), "!") && len(line) > 120 {
		return "long chkutmp cmdline"
	}
	return ""
}
