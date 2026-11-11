package format

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/collector/auditd"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/chkrootkit"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/fail2ban"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/lynis"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/rkhunter"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector/unattendedupgrades"
	"github.com/BrotherHugo/infra-security-monitor/internal/config"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

const (
	maxListLines = 50
	maxTailLines = 15
	maxTopCounts = 8
)

// View is the root object passed to a report template.
// A module pointer is nil when that module did not run.
type View struct {
	ID          int64
	Host        string
	Time        time.Time
	ModuleNames []string
	Fail2ban    *Fail2ban
	Auditd      *Auditd
	Rkhunter    *Rkhunter
	Chkrootkit  *Chkrootkit
	Lynis       *Lynis
	Unattended  *Unattended
}

// Fail2ban is one jail list, already parsed.
type Fail2ban struct {
	Error string
	Jails []Jail
}

// Jail is one fail2ban jail.
type Jail struct {
	Name            string
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
	BannedIPs       []string
}

// Auditd is aureport analytics with counts sorted and capped.
type Auditd struct {
	Error         string
	Summary       []string
	FailedLogins  int
	AnomalyEvents int
	Config        AuditEvents
	Anomaly       AuditEvents
	File          AuditEvents
}

// AuditEvents is one aureport block. Empty Total means none.
type AuditEvents struct {
	Title  string
	Total  int
	ByType []Count
	ByAUID []Count
	ByPath []Count
	Window string
	Note   string
	Sample []string
}

// Count is one sorted tally entry.
type Count struct {
	Name string
	N    int
}

// TypeLine is "name=n, name=n" in count order.
func (e AuditEvents) TypeLine() string { return joinCounts(e.ByType) }

// AUIDLine is "name=n, name=n" in count order.
func (e AuditEvents) AUIDLine() string { return joinCounts(e.ByAUID) }

// PathLine is "name=n, name=n" in count order.
func (e AuditEvents) PathLine() string { return joinCounts(e.ByPath) }

// Rkhunter is the last run, with warnings already capped.
type Rkhunter struct {
	Error             string
	Summary           []string
	SuspectFiles      int
	Warnings          []string
	WarningTotal      int
	WarningsTruncated bool
	Note              string
}

// Chkrootkit is capped findings. Reason is set for a possible false positive.
type Chkrootkit struct {
	Error             string
	FindingTotal      int
	Findings          []Finding
	FindingsTruncated bool
}

// Finding is one chkrootkit line.
type Finding struct {
	Line   string
	Reason string
}

// Lynis is the hardening summary. Warnings is capped; WarningTotal is the full count.
type Lynis struct {
	Error             string
	HardeningIndex    int
	WarningTotal      int
	Warnings          []string
	WarningsTruncated bool
}

// Unattended is the log tail. Tail is the last lines only.
type Unattended struct {
	Error         string
	LastSuccess   string
	Stale         bool
	StaleDays     int
	Warnings      []string
	KeptBack      []string
	Tail          []string
	TailTotal     int
	TailTruncated bool
}

func newView(meta RunMeta, results []domain.ModuleResult) View {
	loc := meta.Location
	if loc == nil {
		loc = time.Local
	}

	view := View{
		ID:          meta.RunID,
		Host:        meta.Hostname,
		Time:        meta.GeneratedAt.In(loc),
		ModuleNames: append([]string(nil), meta.ModuleOrder...),
	}
	for _, result := range results {
		view.add(result)
	}
	return view
}

func (v *View) add(result domain.ModuleResult) {
	switch string(result.Name) {
	case config.ModuleFail2ban:
		v.Fail2ban = fail2banView(result)
	case config.ModuleAuditd:
		v.Auditd = auditdView(result)
	case config.ModuleRkhunter:
		v.Rkhunter = rkhunterView(result)
	case config.ModuleChkrootkit:
		v.Chkrootkit = chkrootkitView(result)
	case config.ModuleLynis:
		v.Lynis = lynisView(result)
	case config.ModuleUnattendedUpgrades:
		v.Unattended = unattendedView(result)
	}
}

func fail2banView(result domain.ModuleResult) *Fail2ban {
	out := &Fail2ban{}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	snap, ok := result.Data.(fail2ban.Snapshot)
	if !ok {
		return out
	}
	out.Jails = make([]Jail, len(snap.Jails))
	for i, jail := range snap.Jails {
		out.Jails[i] = Jail{
			Name:            jail.Name,
			CurrentlyFailed: jail.CurrentlyFailed,
			TotalFailed:     jail.TotalFailed,
			CurrentlyBanned: jail.CurrentlyBanned,
			TotalBanned:     jail.TotalBanned,
			BannedIPs:       append([]string(nil), jail.BannedIPs...),
		}
	}
	return out
}

func auditdView(result domain.ModuleResult) *Auditd {
	out := &Auditd{
		Config:  AuditEvents{Title: "config change"},
		Anomaly: AuditEvents{Title: "anomaly"},
		File:    AuditEvents{Title: "file events"},
	}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	snap, ok := result.Data.(auditd.Snapshot)
	if !ok {
		return out
	}
	out.Summary = append([]string(nil), snap.Summary.KeyLines...)
	out.FailedLogins = snap.Summary.FailedLogins
	out.AnomalyEvents = snap.Summary.AnomalyEvents

	note := ""
	if _, ok := snap.Config.ByType["NETFILTER_CFG"]; ok {
		note = auditd.NetfilterNote
	}
	configTotal := 0
	if snap.Config.HasEvents {
		configTotal = snap.Config.Total
	}
	out.Config = auditEvents("config change", configTotal, snap.Config.EventAggregate, preferSample(snap.Config.InterestingSample, snap.Config.Sample), note)

	anomalyTotal := snap.Anomaly.Total
	if snap.Summary.AnomalyEvents > anomalyTotal {
		anomalyTotal = snap.Summary.AnomalyEvents
	}
	if !snap.Anomaly.HasEvents && snap.Summary.AnomalyEvents == 0 {
		anomalyTotal = 0
	}
	out.Anomaly = auditEvents("anomaly", anomalyTotal, snap.Anomaly.EventAggregate, snap.Anomaly.Sample, "")

	fileTotal := 0
	if snap.File.HasEvents {
		fileTotal = snap.File.Total
	}
	out.File = auditEvents("file events", fileTotal, snap.File.EventAggregate, snap.File.Sample, "")
	return out
}

func rkhunterView(result domain.ModuleResult) *Rkhunter {
	out := &Rkhunter{}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	parsed, ok := result.Data.(rkhunter.ParseResult)
	if !ok {
		return out
	}
	out.Summary = append([]string(nil), parsed.SummaryLines...)
	out.SuspectFiles = parsed.SuspectFiles
	out.WarningTotal = len(parsed.Targets) + len(parsed.Warnings)
	out.Warnings, out.WarningsTruncated = rkhunterLines(parsed.Targets, parsed.Warnings, maxListLines)
	if out.WarningTotal > 0 {
		out.Note = rkhunter.FalsePositiveNote
	}
	return out
}

func chkrootkitView(result domain.ModuleResult) *Chkrootkit {
	out := &Chkrootkit{}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	parsed, ok := result.Data.(chkrootkit.ParseResult)
	if !ok {
		return out
	}
	out.FindingTotal = parsed.FindingCount
	if out.FindingTotal < len(parsed.Findings) {
		out.FindingTotal = len(parsed.Findings)
	}
	shown := parsed.Findings
	if len(shown) > maxListLines {
		shown = shown[:maxListLines]
		out.FindingsTruncated = true
	}
	out.Findings = make([]Finding, len(shown))
	for i, finding := range shown {
		out.Findings[i] = Finding{Line: finding.Line, Reason: finding.Reason}
	}
	return out
}

func lynisView(result domain.ModuleResult) *Lynis {
	out := &Lynis{}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	parsed, ok := result.Data.(lynis.ParseResult)
	if !ok {
		return out
	}
	out.HardeningIndex = parsed.HardeningIndex
	out.WarningTotal = parsed.WarningCount
	if out.WarningTotal < len(parsed.Warnings) {
		out.WarningTotal = len(parsed.Warnings)
	}
	out.Warnings, out.WarningsTruncated = capStrings(parsed.Warnings, maxListLines)
	return out
}

func unattendedView(result domain.ModuleResult) *Unattended {
	out := &Unattended{LastSuccess: "not found"}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	parsed, ok := result.Data.(unattendedupgrades.ParseResult)
	if !ok {
		return out
	}
	if strings.TrimSpace(parsed.LastSuccessRaw) != "" {
		out.LastSuccess = parsed.LastSuccessRaw
	}
	out.Stale = parsed.Stale
	out.StaleDays = parsed.StaleDays
	out.Warnings, _ = capStrings(parsed.WarningLines, maxListLines)
	out.KeptBack, _ = capStrings(parsed.KeptBackLines, maxListLines)
	out.Tail, out.TailTotal, out.TailTruncated = lastLines(parsed.TailLines, maxTailLines)
	return out
}

func auditEvents(title string, total int, agg auditd.EventAggregate, sample []string, note string) AuditEvents {
	out := AuditEvents{Title: title}
	if total == 0 {
		return out
	}
	out.Total = total
	out.ByType = topCounts(agg.ByType, maxTopCounts)
	out.ByAUID = topCounts(agg.ByAUID, maxTopCounts)
	out.ByPath = topCounts(agg.ByPath, maxTopCounts)
	if agg.FirstTime != "" && agg.LastTime != "" {
		out.Window = agg.FirstTime + " .. " + agg.LastTime
	}
	out.Note = note
	out.Sample = append([]string(nil), sample...)
	return out
}

func preferSample(interesting, fallback []string) []string {
	if len(interesting) > 0 {
		return interesting
	}
	return fallback
}

func rkhunterLines(targets, blocks []string, limit int) ([]string, bool) {
	total := len(targets) + len(blocks)
	var lines []string
	items := 0
	for _, target := range targets {
		if items >= limit {
			break
		}
		lines = append(lines, target)
		items++
	}
	for _, block := range blocks {
		if items >= limit {
			break
		}
		lines = append(lines, strings.Split(block, "\n")...)
		items++
	}
	return lines, total > limit
}

func topCounts(counts map[string]int, limit int) []Count {
	if len(counts) == 0 {
		return nil
	}
	items := make([]Count, 0, len(counts))
	for name, n := range counts {
		items = append(items, Count{Name: name, N: n})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].N == items[j].N {
			return items[i].Name < items[j].Name
		}
		return items[i].N > items[j].N
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items
}

func joinCounts(counts []Count) string {
	if len(counts) == 0 {
		return ""
	}
	parts := make([]string, len(counts))
	for i, count := range counts {
		parts[i] = fmt.Sprintf("%s=%d", count.Name, count.N)
	}
	return strings.Join(parts, ", ")
}

func capStrings(in []string, n int) ([]string, bool) {
	if len(in) <= n {
		return append([]string(nil), in...), false
	}
	return append([]string(nil), in[:n]...), true
}

func lastLines(in []string, n int) (shown []string, total int, truncated bool) {
	total = len(in)
	if total > n {
		return append([]string(nil), in[total-n:]...), total, true
	}
	return append([]string(nil), in...), total, false
}

func moduleError(result domain.ModuleResult) string {
	if text := strings.TrimSpace(result.Error); text != "" {
		return text
	}
	text := strings.TrimSpace(result.SectionText)
	text = strings.TrimPrefix(text, "ERROR:")
	text = strings.TrimSpace(text)
	if text != "" {
		return text
	}
	return "unknown error"
}
