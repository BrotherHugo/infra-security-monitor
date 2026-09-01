package googleai

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
)

const (
	analyzerName = "google-ai"
	apiBaseURL   = "https://generativelanguage.googleapis.com"
	defaultModel = "gemini-2.5-flash"
)

// HTTPDoer performs HTTP requests (for test doubles).
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Analyzer calls Gemini generateContent and returns the appendix text.
type Analyzer struct {
	apiKey       string
	model        string
	systemPrompt string
	timeout      time.Duration
	client       HTTPDoer
	baseURL      string
}

// New creates a google-ai analyzer. systemPrompt is the ready system instruction (see analyze.BuildSystemPrompt).
func New(apiKey, model, systemPrompt string, timeout time.Duration) *Analyzer {
	if strings.TrimSpace(model) == "" {
		model = defaultModel
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Analyzer{
		apiKey:       apiKey,
		model:        model,
		systemPrompt: systemPrompt,
		timeout:      timeout,
		client:       http.DefaultClient,
		baseURL:      apiBaseURL,
	}
}

// Name returns the analyzer identifier.
func (a *Analyzer) Name() string {
	return analyzerName
}

// SetHTTPClient overrides the HTTP client (tests only).
func (a *Analyzer) SetHTTPClient(client HTTPDoer) {
	if client != nil {
		a.client = client
	}
}

// SetBaseURL overrides the API base URL (tests only).
func (a *Analyzer) SetBaseURL(baseURL string) {
	if strings.TrimSpace(baseURL) != "" {
		a.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// Append builds the raw payload and calls Gemini.
func (a *Analyzer) Append(ctx context.Context, in analyze.Input) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	callCtx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	userPayload := buildUserPayload(in)
	return a.generateContent(callCtx, a.systemPrompt, userPayload)
}
