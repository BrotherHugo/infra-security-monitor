package format

import (
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
	Analyses    []Analysis
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

// Auditd holds structured aureport counters and event aggregates with no preset labels.
type Auditd struct {
	Error            string
	FailedLogins     int
	AccountChanges   int
	ConfigChanges    int
	AnomalyEvents    int
	AnomalyResponses int
	AVCs             int
	IntegrityEvents  int
	Config           AuditEvents
	Anomaly          AuditEvents
	File             AuditEvents
}

// AuditEvents is one aureport block. Zero Total means no events.
type AuditEvents struct {
	Total             int
	ByType            []Count
	ByAUID            []Count
	ByPath            []Count
	FirstTime         string
	LastTime          string
	HasNetfilterBurst bool
	Sample            []string
}

// Count is one sorted tally entry.
type Count struct {
	Name string
	N    int
}

// Rkhunter holds structured rkhunter counters and capped warning lists.
type Rkhunter struct {
	Error               string
	HasSummary          bool
	FilesChecked        int
	SuspectFiles        int
	RootkitsChecked     int
	PossibleRootkits    int
	SuspectPaths        []string
	WarningChecks       []string
	Warnings            []string
	WarningTotal        int
	WarningsTruncated   bool
	HasPropertyWarnings bool
}

// Chkrootkit holds capped findings and structured false-positive markers.
type Chkrootkit struct {
	Error              string
	FindingTotal       int
	FalsePositiveTotal int
	Findings           []Finding
	FindingsTruncated  bool
}

// Finding is one chkrootkit line with structured false-positive metadata.
type Finding struct {
	Line          string
	FalsePositive bool
	FPCode        string
}

// Lynis holds the hardening index and structured warnings with test IDs separated.
type Lynis struct {
	Error             string
	HardeningIndex    int
	WarningTotal      int
	Warnings          []LynisWarning
	WarningsTruncated bool
}

// LynisWarning is one Lynis warning with ID (e.g. "PKGS-7392") separated from Text.
type LynisWarning struct {
	ID   string
	Text string
}

// Unattended holds structured unattended-upgrades timestamps, flags, and capped lines.
type Unattended struct {
	Error           string
	LastSuccessTime *time.Time
	Stale           bool
	StaleDays       int
	Warnings        []string
	KeptBack        []string
	Tail            []string
	TailTotal       int
	TailTruncated   bool
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
		Analyses:    append([]Analysis(nil), meta.Analyses...),
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
	out := &Auditd{}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	snap, ok := result.Data.(auditd.Snapshot)
	if !ok {
		return out
	}
	out.FailedLogins = snap.Summary.FailedLogins
	out.AccountChanges = snap.Summary.AccountChanges
	out.ConfigChanges = snap.Summary.ConfigChanges
	out.AnomalyEvents = snap.Summary.AnomalyEvents
	out.AnomalyResponses = snap.Summary.AnomalyResponses
	out.AVCs = snap.Summary.AVCs
	out.IntegrityEvents = snap.Summary.IntegrityEvents

	_, netfilterBurst := snap.Config.ByType["NETFILTER_CFG"]
	configTotal := 0
	if snap.Config.HasEvents {
		configTotal = snap.Config.Total
	}
	out.Config = auditEvents(configTotal, snap.Config.EventAggregate, preferSample(snap.Config.InterestingSample, snap.Config.Sample), netfilterBurst)

	anomalyTotal := snap.Anomaly.Total
	if snap.Summary.AnomalyEvents > anomalyTotal {
		anomalyTotal = snap.Summary.AnomalyEvents
	}
	if !snap.Anomaly.HasEvents && snap.Summary.AnomalyEvents == 0 {
		anomalyTotal = 0
	}
	out.Anomaly = auditEvents(anomalyTotal, snap.Anomaly.EventAggregate, snap.Anomaly.Sample, false)

	fileTotal := 0
	if snap.File.HasEvents {
		fileTotal = snap.File.Total
	}
	out.File = auditEvents(fileTotal, snap.File.EventAggregate, snap.File.Sample, false)
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
	out.HasSummary = parsed.HasSummary || len(parsed.SummaryLines) > 0
	out.FilesChecked = parsed.FilesChecked
	out.SuspectFiles = parsed.SuspectFiles
	out.RootkitsChecked = parsed.RootkitsChecked
	out.PossibleRootkits = parsed.PossibleRootkits
	out.WarningTotal = len(parsed.Targets) + len(parsed.Warnings)
	out.SuspectPaths, out.WarningChecks = splitRkhunterTargets(parsed.Targets, parsed.Warnings, maxListLines)
	out.Warnings, out.WarningsTruncated = rkhunterLines(parsed.Targets, parsed.Warnings, maxListLines)
	out.HasPropertyWarnings = len(parsed.Warnings) > 0 || len(out.SuspectPaths) > 0 || parsed.SuspectFiles > 0
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
	out.FalsePositiveTotal = parsed.FalsePositive
	shown := parsed.Findings
	if len(shown) > maxListLines {
		shown = shown[:maxListLines]
		out.FindingsTruncated = true
	}
	out.Findings = make([]Finding, len(shown))
	for i, finding := range shown {
		out.Findings[i] = Finding{
			Line:          finding.Line,
			FalsePositive: finding.PossibleFalsePositive,
			FPCode:        finding.FPCode,
		}
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
	capped, truncated := capStrings(parsed.Warnings, maxListLines)
	out.WarningsTruncated = truncated
	out.Warnings = make([]LynisWarning, len(capped))
	for i, raw := range capped {
		item := lynis.SplitWarning(raw)
		out.Warnings[i] = LynisWarning{ID: item.ID, Text: item.Text}
	}
	return out
}

func unattendedView(result domain.ModuleResult) *Unattended {
	out := &Unattended{}
	if result.Status == domain.ModuleStatusError {
		out.Error = moduleError(result)
		return out
	}
	parsed, ok := result.Data.(unattendedupgrades.ParseResult)
	if !ok {
		return out
	}
	if parsed.LastSuccess != nil {
		ts := *parsed.LastSuccess
		out.LastSuccessTime = &ts
	}
	out.Stale = parsed.Stale
	out.StaleDays = parsed.StaleDays
	out.Warnings, _ = capStrings(parsed.WarningLines, maxListLines)
	out.KeptBack, _ = capStrings(parsed.KeptBackLines, maxListLines)
	out.Tail, out.TailTotal, out.TailTruncated = lastLines(parsed.TailLines, maxTailLines)
	return out
}

func auditEvents(total int, agg auditd.EventAggregate, sample []string, netfilterBurst bool) AuditEvents {
	var out AuditEvents
	if total == 0 {
		return out
	}
	out.Total = total
	out.ByType = topCounts(agg.ByType, maxTopCounts)
	out.ByAUID = topCounts(agg.ByAUID, maxTopCounts)
	out.ByPath = topCounts(agg.ByPath, maxTopCounts)
	out.FirstTime = agg.FirstTime
	out.LastTime = agg.LastTime
	out.HasNetfilterBurst = netfilterBurst
	out.Sample = append([]string(nil), sample...)
	return out
}

func preferSample(interesting, fallback []string) []string {
	if len(interesting) > 0 {
		return interesting
	}
	return fallback
}

func splitRkhunterTargets(targets, blocks []string, limit int) (paths, checks []string) {
	for _, target := range targets {
		if strings.HasPrefix(target, "/") {
			if len(paths) < limit {
				paths = append(paths, target)
			}
		} else if len(checks) < limit {
			checks = append(checks, target)
		}
	}
	for _, block := range blocks {
		if len(checks) >= limit {
			break
		}
		checks = append(checks, strings.Split(block, "\n")...)
	}
	return paths, checks
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
