package app

import (
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/analyze/googleai"
	"github.com/BrotherHugo/infra-security-monitor/internal/config"
)

// BuildAnalyzers builds analyzers from the analyzers config section.
func BuildAnalyzers(cfg config.Config) ([]analyze.Analyzer, error) {
	analyzers := make([]analyze.Analyzer, 0, 1)

	if cfg.Analyzers.GoogleAI != nil {
		s := cfg.Analyzers.GoogleAI
		timeout := time.Duration(cfg.Analyzers.TimeoutSeconds) * time.Second
		systemPrompt := analyze.BuildSystemPrompt(cfg.Analyzers.Prompt, cfg.Analyzers.CustomRules)
		analyzers = append(analyzers, googleai.New(s.APIKey, s.Model, systemPrompt, timeout))
	}

	return analyzers, nil
}
