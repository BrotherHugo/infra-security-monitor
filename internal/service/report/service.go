package report

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/format"
)

// Store is the persistence port for ReportService.
type Store interface {
	BeginRun(ctx context.Context, hostname string, startedAt time.Time) (runID int64, err error)
	SaveModuleResult(ctx context.Context, runID int64, result domain.ModuleResult) error
	FinishRun(ctx context.Context, runID int64, finishedAt time.Time, status domain.RunStatus) error
	Prune(ctx context.Context, olderThan time.Time) error
}

// Service orchestrates collect -> persist -> prune -> format -> send.
type Service struct {
	store           Store
	collectors      []collector.Collector
	channels        []Sender
	analyzers       []analyze.Analyzer
	hostname        func() (string, error)
	clock           func() time.Time
	location        *time.Location
	keepHistoryDays int
	moduleOrder     []string
}

// Sender is the minimal delivery channel port for the service.
type Sender interface {
	Name() string
	Send(ctx context.Context, report domain.TextReport) error
}

// New creates a ReportService.
func New(
	store Store,
	collectors []collector.Collector,
	channels []Sender,
	analyzers []analyze.Analyzer,
	hostname func() (string, error),
	clock func() time.Time,
	location *time.Location,
	keepHistoryDays int,
	moduleOrder []string,
) *Service {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if hostname == nil {
		hostname = defaultHostname
	}
	loc := location
	if loc == nil {
		loc = time.Local
	}

	return &Service{
		store:           store,
		collectors:      collectors,
		channels:        channels,
		analyzers:       append([]analyze.Analyzer(nil), analyzers...),
		hostname:        hostname,
		clock:           clock,
		location:        loc,
		keepHistoryDays: keepHistoryDays,
		moduleOrder:     append([]string(nil), moduleOrder...),
	}
}

// RunCycle runs one report cycle.
func (s *Service) RunCycle(ctx context.Context) error {
	hostname, err := s.hostname()
	if err != nil {
		return fmt.Errorf("hostname: %w", err)
	}

	startedAt := s.clock()
	runID, err := s.store.BeginRun(ctx, hostname, startedAt)
	if err != nil {
		return fmt.Errorf("begin run: %w", err)
	}

	finished := false
	defer func() {
		if finished {
			return
		}
		if err := s.store.FinishRun(ctx, runID, s.clock(), domain.RunStatusFailed); err != nil {
			slog.ErrorContext(ctx, "finish run after abort", "run_id", runID, "err", err)
		}
	}()

	moduleResults, moduleErrors := s.collectModules(ctx, runID)

	if s.keepHistoryDays > 0 {
		cutoff := s.clock().AddDate(0, 0, -s.keepHistoryDays)
		if err := s.store.Prune(ctx, cutoff); err != nil {
			return fmt.Errorf("prune: %w", err)
		}
	}

	generatedAt := s.clock()
	report := format.Build(format.RunMeta{
		RunID:       runID,
		Hostname:    hostname,
		GeneratedAt: generatedAt,
		Location:    s.location,
		ModuleOrder: s.moduleOrder,
	}, moduleResults)

	analyzerInput := analyze.Input{
		Report:      report,
		Results:     moduleResults,
		ModuleOrder: s.moduleOrder,
	}
	var analyzerErrors int
	report.Body, analyzerErrors = analyze.AppendAll(ctx, report.Body, s.analyzers, analyzerInput)

	channelErrors := s.sendReport(ctx, report)

	runStatus := domain.RunStatusOK
	if moduleErrors > 0 || channelErrors > 0 || analyzerErrors > 0 {
		runStatus = domain.RunStatusDegraded
	}
	if err := s.store.FinishRun(ctx, runID, s.clock(), runStatus); err != nil {
		return fmt.Errorf("finish run: %w", err)
	}
	finished = true

	slog.InfoContext(ctx, "report cycle finished",
		"run_id", runID,
		"modules", len(s.collectors),
		"channels", len(s.channels),
		"status", runStatus,
	)
	return nil
}

func (s *Service) collectModules(ctx context.Context, runID int64) ([]domain.ModuleResult, int) {
	results := make([]domain.ModuleResult, 0, len(s.collectors))
	moduleErrors := 0

	for _, c := range s.collectors {
		result, err := c.Collect(ctx)
		if err != nil {
			moduleErrors++
			result = domain.ModuleResult{
				Name:        domain.ModuleName(c.Name()),
				Status:      domain.ModuleStatusError,
				CollectedAt: s.clock(),
				Raw:         domain.EmptyRaw(),
				SectionText: fmt.Sprintf("ERROR: %s", err.Error()),
				Error:       err.Error(),
			}
		}

		if saveErr := s.store.SaveModuleResult(ctx, runID, result); saveErr != nil {
			slog.ErrorContext(ctx, "save module result", "module", c.Name(), "err", saveErr)
			moduleErrors++
			result = domain.ModuleResult{
				Name:        domain.ModuleName(c.Name()),
				Status:      domain.ModuleStatusError,
				CollectedAt: s.clock(),
				Raw:         domain.EmptyRaw(),
				SectionText: fmt.Sprintf("ERROR: %s", saveErr.Error()),
				Error:       saveErr.Error(),
			}
		}

		results = append(results, result)
	}

	return results, moduleErrors
}

func (s *Service) sendReport(ctx context.Context, report domain.TextReport) int {
	channelErrors := 0
	for _, ch := range s.channels {
		if err := ch.Send(ctx, report); err != nil {
			channelErrors++
			slog.ErrorContext(ctx, "channel send failed", "channel", ch.Name(), "err", err)
		}
	}
	return channelErrors
}

func defaultHostname() (string, error) {
	hostname, err := osHostname()
	if err != nil {
		return "", err
	}
	return hostname, nil
}
