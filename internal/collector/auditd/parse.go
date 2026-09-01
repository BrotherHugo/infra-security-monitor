package auditd

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const (
	markerFailedLogins  = "Number of failed logins:"
	markerAnomalyEvents = "Number of anomaly events:"
	markerNoEvents      = "<no events"

	maxTopEntries  = 8
	maxSampleLines = 5

	netfilterNote = "note: NETFILTER_CFG bursts are often fail2ban/iptables reloads"
)

var (
	eventLineRE      = regexp.MustCompile(`^(?:\d+\.\s+)?(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})\s+(.+)$`)
	looseEventWhenRE = regexp.MustCompile(`\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}`)
)

// Summary Report line markers for section_text (order matches aureport).
var summaryLineMarkers = []string{
	markerFailedLogins,
	"changes to accounts, groups, or role",
	"Number of changes in configuration:",
	markerAnomalyEvents,
	"responses to anomaly events:",
	"Number of AVC",
	"Number of integrity events:",
}

// Summary holds key lines from aureport --summary.
type Summary struct {
	KeyLines       []string `json:"key_lines"`
	FailedLogins   int      `json:"failed_logins"`
	AnomalyEvents  int      `json:"anomaly_events"`
}

// EventAggregate aggregates aureport event lines.
type EventAggregate struct {
	Total             int            `json:"total"`
	ByType            map[string]int `json:"by_type,omitempty"`
	ByAUID            map[string]int `json:"by_auid,omitempty"`
	ByPath            map[string]int `json:"by_path,omitempty"`
	FirstTime         string         `json:"first_time,omitempty"`
	LastTime          string         `json:"last_time,omitempty"`
	Sample            []string       `json:"sample,omitempty"`
	InterestingSample []string       `json:"interesting_sample,omitempty"`
}

// ConfigChangeReport is an aggregated config change report.
type ConfigChangeReport struct {
	HasEvents bool `json:"has_events"`
	EventAggregate
}

// AnomalyReport is an aggregated anomaly report.
type AnomalyReport struct {
	HasEvents bool `json:"has_events"`
	EventAggregate
}

// FileReport aggregates events from aureport --file.
type FileReport struct {
	HasEvents bool `json:"has_events"`
	EventAggregate
}

// ParseSummary parses aureport --summary stdout.
func ParseSummary(stdout string) (Summary, error) {
	var summary Summary
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, markerFailedLogins) {
			value, err := parseTrailingInt(line, markerFailedLogins)
			if err != nil {
				return Summary{}, fmt.Errorf("failed logins: %w", err)
			}
			summary.FailedLogins = value
			summary.KeyLines = append(summary.KeyLines, line)
			continue
		}
		if strings.Contains(line, markerAnomalyEvents) {
			value, err := parseTrailingInt(line, markerAnomalyEvents)
			if err != nil {
				return Summary{}, fmt.Errorf("anomaly events: %w", err)
			}
			summary.AnomalyEvents = value
			summary.KeyLines = append(summary.KeyLines, line)
			continue
		}
		if isSummaryKeyLine(line) {
			summary.KeyLines = append(summary.KeyLines, line)
		}
	}
	if len(summary.KeyLines) == 0 {
		return Summary{}, fmt.Errorf("summary key lines not found")
	}
	return summary, nil
}

// ParseConfigChange parses aureport -c stdout.
func ParseConfigChange(stdout string) ConfigChangeReport {
	return ConfigChangeReport{
		HasEvents:      !isNoEventsOutput(stdout),
		EventAggregate: aggregateEventLines(stdout, aggregateOptions{interestingTypeSkip: "NETFILTER_CFG"}),
	}
}

// ParseAnomalyReport parses aureport -a stdout.
func ParseAnomalyReport(stdout string) AnomalyReport {
	if isNoEventsOutput(stdout) {
		return AnomalyReport{HasEvents: false}
	}
	agg := aggregateEventLines(stdout, aggregateOptions{anomaly: true})
	if len(agg.Sample) == 0 {
		agg.Sample = extractFallbackSample(stdout)
	}
	return AnomalyReport{
		HasEvents:      agg.Total > 0 || len(agg.Sample) > 0,
		EventAggregate: agg,
	}
}

// ParseFileReport parses aureport --file stdout.
func ParseFileReport(stdout string) FileReport {
	if isNoEventsOutput(stdout) {
		return FileReport{HasEvents: false}
	}
	agg := aggregateEventLines(stdout, aggregateOptions{fileReport: true})
	if agg.Total == 0 {
		return FileReport{HasEvents: false}
	}
	return FileReport{
		HasEvents:      true,
		EventAggregate: agg,
	}
}

// FormatSectionText builds compressed section text for the operator.
func FormatSectionText(summary Summary, config ConfigChangeReport, anomaly AnomalyReport, file FileReport) string {
	var parts []string
	parts = append(parts, "Summary Report:")
	for _, line := range summary.KeyLines {
		parts = append(parts, "  "+line)
	}
	parts = append(parts, formatConfigSection(config)...)
	parts = append(parts, formatAnomalySection(summary, anomaly)...)
	parts = append(parts, formatFileSection(file)...)
	return strings.Join(parts, "\n")
}

type aggregateOptions struct {
	fileReport          bool
	anomaly             bool
	interestingTypeSkip string
}

func aggregateEventLines(stdout string, opts aggregateOptions) EventAggregate {
	var agg EventAggregate
	agg.ByType = make(map[string]int)
	agg.ByAUID = make(map[string]int)
	agg.ByPath = make(map[string]int)

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "=") {
			continue
		}
		if isReportHeaderLine(trimmed) {
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), markerNoEvents) {
			continue
		}

		matches := eventLineRE.FindStringSubmatch(trimmed)
		if len(matches) != 3 {
			continue
		}
		when := matches[1]
		body := matches[2]
		agg.Total++
		updateTimeWindow(&agg, when)
		appendSample(&agg, trimmed)

		eventType, auid, path := classifyEventBody(body, opts)
		if eventType != "" {
			agg.ByType[eventType]++
			if opts.interestingTypeSkip != "" && eventType != opts.interestingTypeSkip {
				appendInterestingSample(&agg, trimmed)
			}
		}
		if auid != "" {
			agg.ByAUID[auid]++
		}
		if path != "" {
			agg.ByPath[path]++
		}
	}
	return agg
}

func classifyEventBody(body string, opts aggregateOptions) (eventType, auid, path string) {
	fields := strings.Fields(body)
	if len(fields) == 0 {
		return "", "", ""
	}
	if strings.HasPrefix(fields[0], "/") {
		path = fields[0]
		if !opts.fileReport {
			if len(fields) >= 3 {
				eventType = fields[2]
			} else if len(fields) >= 2 {
				eventType = fields[1]
			}
		}
		return eventType, "", path
	}
	if opts.fileReport {
		for i, field := range fields {
			if strings.HasPrefix(field, "/") {
				path = field
				if i > 0 {
					eventType = fields[0]
				}
				break
			}
		}
		if path == "" && len(fields) > 0 {
			eventType = fields[0]
		}
		return eventType, "", path
	}
	eventType = fields[0]
	if len(fields) >= 2 && looksLikeAUID(fields[1]) {
		auid = fields[1]
	}
	if opts.anomaly {
		if extracted := extractTypeLabel(body); extracted != "" {
			eventType = extracted
		} else if len(fields) >= 2 && looksLikeScore(fields[0]) {
			eventType = fields[1]
		}
	}
	return eventType, auid, path
}

func formatConfigSection(config ConfigChangeReport) []string {
	if !config.HasEvents || config.Total == 0 {
		return []string{"config change: none"}
	}
	lines := []string{fmt.Sprintf("config change (%d):", config.Total)}
	lines = append(lines, formatCountLine("  by type", config.ByType)...)
	lines = append(lines, formatCountLine("  by auid", config.ByAUID)...)
	if config.FirstTime != "" && config.LastTime != "" {
		lines = append(lines, fmt.Sprintf("  window: %s .. %s", config.FirstTime, config.LastTime))
	}
	if hasKey(config.ByType, "NETFILTER_CFG") {
		lines = append(lines, "  "+netfilterNote)
	}
	lines = append(lines, formatInterestingSample("  sample", config.InterestingSample, config.Sample)...)
	return lines
}

func formatAnomalySection(summary Summary, anomaly AnomalyReport) []string {
	if summary.AnomalyEvents == 0 && (!anomaly.HasEvents || anomaly.Total == 0) {
		return []string{"anomaly: none"}
	}
	count := firstPositive(summary.AnomalyEvents, anomaly.Total)
	lines := []string{fmt.Sprintf("anomaly (%d):", count)}
	lines = append(lines, formatCountLine("  by type", anomaly.ByType)...)
	if anomaly.FirstTime != "" && anomaly.LastTime != "" {
		lines = append(lines, fmt.Sprintf("  window: %s .. %s", anomaly.FirstTime, anomaly.LastTime))
	}
	if count > 0 {
		lines = append(lines, formatRequiredSampleBlock("  sample", anomaly.Sample)...)
	}
	return lines
}

func formatFileSection(file FileReport) []string {
	if !file.HasEvents || file.Total == 0 {
		return []string{"file events: none"}
	}
	lines := []string{fmt.Sprintf("file events (%d):", file.Total)}
	lines = append(lines, formatCountLine("  by path", file.ByPath)...)
	lines = append(lines, formatSampleBlock("  sample", file.Sample)...)
	return lines
}

func formatCountLine(prefix string, counts map[string]int) []string {
	if len(counts) == 0 {
		return nil
	}
	parts := topCountEntries(counts, maxTopEntries)
	return []string{prefix + ": " + strings.Join(parts, ", ")}
}

func formatInterestingSample(prefix string, interesting, fallback []string) []string {
	if len(interesting) > 0 {
		return formatSampleBlock(prefix, interesting)
	}
	return formatSampleBlock(prefix, fallback)
}

func formatSampleBlock(prefix string, sample []string) []string {
	if len(sample) == 0 {
		return nil
	}
	return formatRequiredSampleBlock(prefix, sample)
}

func formatRequiredSampleBlock(prefix string, sample []string) []string {
	lines := []string{prefix + ":"}
	for _, line := range sample {
		lines = append(lines, "    "+line)
	}
	return lines
}

func topCountEntries(counts map[string]int, limit int) []string {
	type kv struct {
		key   string
		count int
	}
	items := make([]kv, 0, len(counts))
	for key, count := range counts {
		items = append(items, kv{key: key, count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].count == items[j].count {
			return items[i].key < items[j].key
		}
		return items[i].count > items[j].count
	})
	if len(items) > limit {
		items = items[:limit]
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		parts = append(parts, fmt.Sprintf("%s=%d", item.key, item.count))
	}
	return parts
}

func updateTimeWindow(agg *EventAggregate, when string) {
	if agg.FirstTime == "" || when < agg.FirstTime {
		agg.FirstTime = when
	}
	if agg.LastTime == "" || when > agg.LastTime {
		agg.LastTime = when
	}
}

func appendSample(agg *EventAggregate, line string) {
	if len(agg.Sample) >= maxSampleLines {
		return
	}
	agg.Sample = append(agg.Sample, line)
}

func appendInterestingSample(agg *EventAggregate, line string) {
	if len(agg.InterestingSample) >= maxSampleLines {
		return
	}
	agg.InterestingSample = append(agg.InterestingSample, line)
}

func isReportHeaderLine(line string) bool {
	lower := strings.ToLower(line)
	return strings.HasSuffix(lower, " report") ||
		strings.Contains(lower, "config change report") ||
		strings.Contains(lower, "anomaly report") ||
		strings.Contains(lower, "file report")
}

func looksLikeAUID(value string) bool {
	if value == "yes" || value == "no" {
		return false
	}
	_, err := strconv.Atoi(value)
	return err == nil
}

func looksLikeScore(value string) bool {
	n, err := strconv.Atoi(value)
	return err == nil && n >= 0
}

func extractTypeLabel(body string) string {
	for _, key := range []string{"type=", "type:"} {
		if extracted := extractKeyValue(body, key); extracted != "" {
			return extracted
		}
	}
	return ""
}

func extractFallbackSample(stdout string) []string {
	var sample []string
	for _, line := range strings.Split(stdout, "\n") {
		trimmed := strings.TrimRight(line, "\r")
		trimmed = strings.TrimSpace(trimmed)
		if trimmed == "" || isReportHeaderLine(trimmed) || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "=") {
			continue
		}
		if strings.Contains(strings.ToLower(trimmed), markerNoEvents) {
			continue
		}
		if eventLineRE.MatchString(trimmed) {
			continue
		}
		if !looseEventWhenRE.MatchString(trimmed) {
			continue
		}
		sample = append(sample, trimmed)
		if len(sample) >= maxSampleLines {
			break
		}
	}
	return sample
}

func extractKeyValue(body, key string) string {
	idx := strings.Index(body, key)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(body[idx+len(key):])
	if rest == "" {
		return ""
	}
	if end := strings.IndexAny(rest, " \t"); end >= 0 {
		return rest[:end]
	}
	return rest
}

func hasKey(counts map[string]int, key string) bool {
	_, ok := counts[key]
	return ok
}

func firstPositive(values ...int) int {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func isSummaryKeyLine(line string) bool {
	for _, marker := range summaryLineMarkers {
		if strings.Contains(line, marker) {
			return true
		}
	}
	return false
}

func parseTrailingInt(line, label string) (int, error) {
	idx := strings.Index(line, label)
	if idx < 0 {
		return 0, fmt.Errorf("label %q not found", label)
	}
	raw := strings.TrimSpace(line[idx+len(label):])
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("parse int %q: %w", raw, err)
	}
	return value, nil
}

func isNoEventsOutput(stdout string) bool {
	lower := strings.ToLower(strings.TrimSpace(stdout))
	if lower == "" {
		return true
	}
	return strings.Contains(lower, markerNoEvents) ||
		strings.Contains(lower, "no events found") ||
		strings.Contains(lower, "no data")
}
