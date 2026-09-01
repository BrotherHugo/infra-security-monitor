package analyze_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestAppendAll_noAnalyzers(t *testing.T) {
	body := "ISM report\nhost: a"
	got, errCount := analyze.AppendAll(context.Background(), body, nil, analyze.Input{})
	if got != body {
		t.Fatalf("body = %q, want unchanged", got)
	}
	if errCount != 0 {
		t.Fatalf("errCount = %d, want 0", errCount)
	}
}

func TestAppendAll_success(t *testing.T) {
	a := &stubAnalyzer{name: "google-ai", appendix: "Summary: ok"}
	body := "base report"
	got, errCount := analyze.AppendAll(
		context.Background(),
		body,
		[]analyze.Analyzer{a},
		analyze.Input{},
	)
	if errCount != 0 {
		t.Fatalf("errCount = %d, want 0", errCount)
	}
	wantSuffix := "\n=== AI analysis (google-ai) ===\nSummary: ok\n"
	if !strings.HasSuffix(got, wantSuffix) {
		t.Fatalf("body = %q, want suffix %q", got, wantSuffix)
	}
	if !strings.HasPrefix(got, body) {
		t.Fatalf("body should keep prefix %q", body)
	}
}

func TestAppendAll_errorAppendix(t *testing.T) {
	a := &stubAnalyzer{name: "google-ai", err: errors.New("boom")}
	got, errCount := analyze.AppendAll(
		context.Background(),
		"base",
		[]analyze.Analyzer{a},
		analyze.Input{},
	)
	if errCount != 1 {
		t.Fatalf("errCount = %d, want 1", errCount)
	}
	want := "base\n=== AI analysis (google-ai) ===\nERROR: boom\n"
	if got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestAppendAll_multipleAnalyzersOrder(t *testing.T) {
	first := &stubAnalyzer{name: "first", appendix: "one"}
	second := &stubAnalyzer{name: "second", appendix: "two"}
	got, errCount := analyze.AppendAll(
		context.Background(),
		"base",
		[]analyze.Analyzer{first, second},
		analyze.Input{},
	)
	if errCount != 0 {
		t.Fatalf("errCount = %d, want 0", errCount)
	}
	firstIdx := strings.Index(got, "=== AI analysis (first) ===")
	secondIdx := strings.Index(got, "=== AI analysis (second) ===")
	if firstIdx < 0 || secondIdx < 0 {
		t.Fatalf("missing headers in %q", got)
	}
	if firstIdx >= secondIdx {
		t.Fatalf("wrong order: first@%d second@%d in %q", firstIdx, secondIdx, got)
	}
}

func TestAppendAll_trimsAppendixWhitespace(t *testing.T) {
	a := &stubAnalyzer{name: "google-ai", appendix: "  text with spaces  \n\n"}
	got, _ := analyze.AppendAll(context.Background(), "base", []analyze.Analyzer{a}, analyze.Input{})
	if !strings.Contains(got, "=== AI analysis (google-ai) ===\ntext with spaces\n") {
		t.Fatalf("body = %q", got)
	}
}

func TestAppendAll_partialFailureContinues(t *testing.T) {
	ok := &stubAnalyzer{name: "ok", appendix: "fine"}
	bad := &stubAnalyzer{name: "bad", err: errors.New("fail")}
	got, errCount := analyze.AppendAll(
		context.Background(),
		"base",
		[]analyze.Analyzer{bad, ok},
		analyze.Input{},
	)
	if errCount != 1 {
		t.Fatalf("errCount = %d, want 1", errCount)
	}
	if !strings.Contains(got, "ERROR: fail") {
		t.Fatalf("missing error appendix in %q", got)
	}
	if !strings.Contains(got, "=== AI analysis (ok) ===\nfine") {
		t.Fatalf("missing success appendix in %q", got)
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

	_, _ = analyze.AppendAll(context.Background(), "base", []analyze.Analyzer{a}, analyze.Input{
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
