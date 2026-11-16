package analyze_test

import (
	"context"
	"errors"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestRun_noAnalyzers(t *testing.T) {
	got, errCount := analyze.Run(context.Background(), nil, analyze.Input{})
	if len(got) != 0 {
		t.Fatalf("results = %+v, want none", got)
	}
	if errCount != 0 {
		t.Fatalf("errCount = %d, want 0", errCount)
	}
}

func TestRun_success(t *testing.T) {
	a := &stubAnalyzer{name: "google-ai", appendix: "Summary: ok"}
	got, errCount := analyze.Run(context.Background(), []analyze.Analyzer{a}, analyze.Input{})
	if errCount != 0 {
		t.Fatalf("errCount = %d, want 0", errCount)
	}
	if len(got) != 1 || got[0].Name != "google-ai" || got[0].Text != "Summary: ok" || got[0].Error != "" {
		t.Fatalf("results = %+v", got)
	}
}

func TestRun_error(t *testing.T) {
	a := &stubAnalyzer{name: "google-ai", err: errors.New("boom")}
	got, errCount := analyze.Run(context.Background(), []analyze.Analyzer{a}, analyze.Input{})
	if errCount != 1 {
		t.Fatalf("errCount = %d, want 1", errCount)
	}
	if len(got) != 1 || got[0].Error != "boom" || got[0].Text != "" {
		t.Fatalf("results = %+v", got)
	}
}

func TestRun_orderAndTrim(t *testing.T) {
	first := &stubAnalyzer{name: "first", appendix: "  one  \n"}
	second := &stubAnalyzer{name: "second", appendix: "two"}
	got, errCount := analyze.Run(context.Background(), []analyze.Analyzer{first, second}, analyze.Input{})
	if errCount != 0 || len(got) != 2 {
		t.Fatalf("results = %+v errCount = %d", got, errCount)
	}
	if got[0].Name != "first" || got[0].Text != "one" || got[1].Name != "second" || got[1].Text != "two" {
		t.Fatalf("results = %+v", got)
	}
}

func TestRun_partialFailureContinues(t *testing.T) {
	ok := &stubAnalyzer{name: "ok", appendix: "fine"}
	bad := &stubAnalyzer{name: "bad", err: errors.New("fail")}
	got, errCount := analyze.Run(context.Background(), []analyze.Analyzer{bad, ok}, analyze.Input{})
	if errCount != 1 || len(got) != 2 {
		t.Fatalf("results = %+v errCount = %d", got, errCount)
	}
	if got[0].Error != "fail" || got[1].Text != "fine" {
		t.Fatalf("results = %+v", got)
	}
}

type stubAnalyzer struct {
	name     string
	appendix string
	err      error
}

func (s *stubAnalyzer) Name() string { return s.name }

func (s *stubAnalyzer) Append(context.Context, analyze.Input) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return s.appendix, nil
}

var _ analyze.Analyzer = (*stubAnalyzer)(nil)

func TestInput_carriesReportAndResults(t *testing.T) {
	var captured analyze.Input
	a := &captureAnalyzer{capture: &captured, appendix: "x"}
	report := domain.TextReport{Hostname: "host-a", Body: "body"}
	results := []domain.ModuleResult{{Name: "fail2ban", Status: domain.ModuleStatusOK}}
	order := []string{"fail2ban"}

	_, _ = analyze.Run(context.Background(), []analyze.Analyzer{a}, analyze.Input{
		Report:      report,
		Results:     results,
		ModuleOrder: order,
	})

	if captured.Report != report {
		t.Fatalf("Report = %+v, want %+v", captured.Report, report)
	}
	if len(captured.Results) != 1 || captured.Results[0].Name != "fail2ban" {
		t.Fatalf("Results = %+v", captured.Results)
	}
	if len(captured.ModuleOrder) != 1 || captured.ModuleOrder[0] != "fail2ban" {
		t.Fatalf("ModuleOrder = %+v", captured.ModuleOrder)
	}
}

type captureAnalyzer struct {
	capture  *analyze.Input
	appendix string
}

func (c *captureAnalyzer) Name() string { return "capture" }

func (c *captureAnalyzer) Append(_ context.Context, in analyze.Input) (string, error) {
	*c.capture = in
	return c.appendix, nil
}
