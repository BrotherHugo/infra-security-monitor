package app_test

import (
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/app"
	"github.com/BrotherHugo/infra-security-monitor/internal/config"
)

func TestBuildAnalyzers_googleAI(t *testing.T) {
	cfg := config.Config{
		Analyzers: config.Analyzers{
			TimeoutSeconds: 120,
			GoogleAI: &config.GoogleAISettings{
				APIKey: "test-key",
				Model:  "gemini-2.5-flash",
			},
		},
	}

	analyzers, err := app.BuildAnalyzers(cfg)
	if err != nil {
		t.Fatalf("BuildAnalyzers() error = %v", err)
	}
	if len(analyzers) != 1 {
		t.Fatalf("len(analyzers) = %d, want 1", len(analyzers))
	}
	if analyzers[0].Name() != config.AnalyzerGoogleAI {
		t.Fatalf("analyzer name = %q, want %q", analyzers[0].Name(), config.AnalyzerGoogleAI)
	}
}

func TestBuildAnalyzers_empty(t *testing.T) {
	analyzers, err := app.BuildAnalyzers(config.Config{})
	if err != nil {
		t.Fatalf("BuildAnalyzers() error = %v", err)
	}
	if len(analyzers) != 0 {
		t.Fatalf("len(analyzers) = %d, want 0", len(analyzers))
	}
}
