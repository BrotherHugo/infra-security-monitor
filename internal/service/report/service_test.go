package report_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/collector"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/service/report"
)

func TestService_RunCycle_success(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{}
	coll := &fakeCollector{
		name: "fail2ban",
		result: domain.ModuleResult{
			Name:        "fail2ban",
			Status:      domain.ModuleStatusOK,
			CollectedAt: now,
			SectionText: "jail sshd: failed=0/0 banned=0/0 ips=-",
		},
	}
	channel := &fakeChannel{name: "file"}

	svc := report.New(
		store,
		[]collector.Collector{coll},
		[]report.Sender{channel},
		nil,
		func() (string, error) { return "host-a", nil },
		func() time.Time { return now },
		time.UTC,
		30,
		[]string{"fail2ban"},
	)

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if store.finishStatus != domain.RunStatusOK {
		t.Fatalf("finish status = %q, want ok", store.finishStatus)
	}
	if len(channel.sent) != 1 {
		t.Fatalf("sent reports = %d, want 1", len(channel.sent))
	}
	if !strings.Contains(channel.sent[0].Body, "=== fail2ban ===") {
		t.Fatalf("report body = %q", channel.sent[0].Body)
	}
	if !strings.Contains(channel.sent[0].Body, "id: 1\n") {
		t.Fatalf("report body missing run id: %q", channel.sent[0].Body)
	}
}

func TestService_RunCycle_collectErrorDegraded(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{}
	coll := &fakeCollector{
		name: "fail2ban",
		err:  errCollect("boom"),
	}
	channel := &fakeChannel{name: "file"}

	svc := report.New(
		store,
		[]collector.Collector{coll},
		[]report.Sender{channel},
		nil,
		func() (string, error) { return "host-a", nil },
		func() time.Time { return now },
		time.UTC,
		30,
		[]string{"fail2ban"},
	)

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if store.finishStatus != domain.RunStatusDegraded {
		t.Fatalf("finish status = %q, want degraded", store.finishStatus)
	}
	if len(store.saved) != 1 || store.saved[0].Status != domain.ModuleStatusError {
		t.Fatalf("saved result = %+v", store.saved)
	}
	if !strings.Contains(channel.sent[0].Body, "ERROR: boom") {
		t.Fatalf("report body = %q", channel.sent[0].Body)
	}
}

func TestService_RunCycle_sendErrorDegraded(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{}
	coll := &fakeCollector{
		name: "fail2ban",
		result: domain.ModuleResult{
			Name:        "fail2ban",
			Status:      domain.ModuleStatusOK,
			CollectedAt: now,
			SectionText: "status: ok",
		},
	}
	channel := &fakeChannel{name: "file", err: errSend("disk full")}

	svc := report.New(
		store,
		[]collector.Collector{coll},
		[]report.Sender{channel},
		nil,
		func() (string, error) { return "host-a", nil },
		func() time.Time { return now },
		time.UTC,
		30,
		[]string{"fail2ban"},
	)

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if store.finishStatus != domain.RunStatusDegraded {
		t.Fatalf("finish status = %q, want degraded", store.finishStatus)
	}
}

func TestService_RunCycle_analyzerAppendix(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{}
	coll := &fakeCollector{
		name: "fail2ban",
		result: domain.ModuleResult{
			Name:        "fail2ban",
			Status:      domain.ModuleStatusOK,
			CollectedAt: now,
			SectionText: "status: ok",
		},
	}
	channel := &fakeChannel{name: "file"}
	analyzer := &fakeAnalyzer{name: "google-ai", appendix: "Summary: all clear"}

	svc := report.New(
		store,
		[]collector.Collector{coll},
		[]report.Sender{channel},
		[]analyze.Analyzer{analyzer},
		func() (string, error) { return "host-a", nil },
		func() time.Time { return now },
		time.UTC,
		30,
		[]string{"fail2ban"},
	)

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if store.finishStatus != domain.RunStatusOK {
		t.Fatalf("finish status = %q, want ok", store.finishStatus)
	}
	body := channel.sent[0].Body
	if !strings.Contains(body, "=== AI analysis (google-ai) ===") {
		t.Fatalf("report body missing analyzer header: %q", body)
	}
	if !strings.Contains(body, "Summary: all clear") {
		t.Fatalf("report body missing analyzer text: %q", body)
	}
}

func TestService_RunCycle_analyzerErrorDegraded(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{}
	coll := &fakeCollector{
		name: "fail2ban",
		result: domain.ModuleResult{
			Name:        "fail2ban",
			Status:      domain.ModuleStatusOK,
			CollectedAt: now,
			SectionText: "status: ok",
		},
	}
	channel := &fakeChannel{name: "file"}
	analyzer := &fakeAnalyzer{name: "google-ai", err: errors.New("api down")}

	svc := report.New(
		store,
		[]collector.Collector{coll},
		[]report.Sender{channel},
		[]analyze.Analyzer{analyzer},
		func() (string, error) { return "host-a", nil },
		func() time.Time { return now },
		time.UTC,
		30,
		[]string{"fail2ban"},
	)

	if err := svc.RunCycle(ctx); err != nil {
		t.Fatalf("RunCycle() error = %v", err)
	}
	if store.finishStatus != domain.RunStatusDegraded {
		t.Fatalf("finish status = %q, want degraded", store.finishStatus)
	}
	body := channel.sent[0].Body
	if !strings.Contains(body, "=== AI analysis (google-ai) ===\nERROR: api down") {
		t.Fatalf("report body = %q", body)
	}
}

func TestService_RunCycle_abortMarksFailed(t *testing.T) {
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	store := &fakeStore{pruneErr: errPrune("stop")}
	coll := &fakeCollector{name: "fail2ban", result: domain.ModuleResult{Name: "fail2ban", Status: domain.ModuleStatusOK}}

	svc := report.New(
		store,
		[]collector.Collector{coll},
		nil,
		nil,
		func() (string, error) { return "host-a", nil },
		func() time.Time { return now },
		time.UTC,
		30,
		[]string{"fail2ban"},
	)

	if err := svc.RunCycle(context.Background()); err == nil {
		t.Fatal("expected RunCycle() error")
	}
	if store.finishStatus != domain.RunStatusFailed {
		t.Fatalf("finish status = %q, want failed", store.finishStatus)
	}
}

type fakeStore struct {
	runID        int64
	saved        []domain.ModuleResult
	finishStatus domain.RunStatus
	pruneErr     error
}

func (s *fakeStore) BeginRun(_ context.Context, _ string, _ time.Time) (int64, error) {
	s.runID++
	return s.runID, nil
}

func (s *fakeStore) SaveModuleResult(_ context.Context, _ int64, result domain.ModuleResult) error {
	s.saved = append(s.saved, result)
	return nil
}

func (s *fakeStore) FinishRun(_ context.Context, _ int64, _ time.Time, status domain.RunStatus) error {
	s.finishStatus = status
	return nil
}

func (s *fakeStore) Prune(context.Context, time.Time) error {
	return s.pruneErr
}

type fakeCollector struct {
	name   string
	result domain.ModuleResult
	err    error
}

func (c *fakeCollector) Name() string { return c.name }

func (c *fakeCollector) Collect(context.Context) (domain.ModuleResult, error) {
	if c.err != nil {
		return domain.ModuleResult{}, c.err
	}
	return c.result, nil
}

type fakeChannel struct {
	name string
	sent []domain.TextReport
	err  error
}

func (c *fakeChannel) Name() string { return c.name }

func (c *fakeChannel) Send(_ context.Context, report domain.TextReport) error {
	if c.err != nil {
		return c.err
	}
	c.sent = append(c.sent, report)
	return nil
}

type errCollect string

func (e errCollect) Error() string { return string(e) }

type errSend string

func (e errSend) Error() string { return string(e) }

type errPrune string

func (e errPrune) Error() string { return string(e) }

type fakeAnalyzer struct {
	name     string
	appendix string
	err      error
}

func (a *fakeAnalyzer) Name() string { return a.name }

func (a *fakeAnalyzer) Append(context.Context, analyze.Input) (string, error) {
	if a.err != nil {
		return "", a.err
	}
	return a.appendix, nil
}

var _ analyze.Analyzer = (*fakeAnalyzer)(nil)
