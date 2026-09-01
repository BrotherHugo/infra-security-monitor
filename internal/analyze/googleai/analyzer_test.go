package googleai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/analyze/googleai"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestAnalyzer_Append_success(t *testing.T) {
	var captured generateContentRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if got := r.Header.Get("x-goog-api-key"); got != "TEST_KEY" {
			t.Errorf("api key header = %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"Summary: all clear"}]}}]}`))
	}))
	defer server.Close()

	a := googleai.New("TEST_KEY", "gemini-2.5-flash", analyze.DefaultPrompt, time.Minute)
	a.SetBaseURL(server.URL)
	a.SetHTTPClient(server.Client())

	in := sampleInput()
	got, err := a.Append(context.Background(), in)
	if err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if got != "Summary: all clear" {
		t.Fatalf("appendix = %q", got)
	}
	if a.Name() != "google-ai" {
		t.Fatalf("Name() = %q", a.Name())
	}
	if captured.GenerationConfig.Temperature != 0.2 {
		t.Fatalf("temperature = %v", captured.GenerationConfig.Temperature)
	}
	if len(captured.SystemInstruction.Parts) != 1 || captured.SystemInstruction.Parts[0].Text != analyze.DefaultPrompt {
		t.Fatalf("systemInstruction = %+v", captured.SystemInstruction)
	}
	userText := captured.Contents[0].Parts[0].Text
	if !strings.Contains(userText, `"jail_log": "raw fail2ban data"`) {
		t.Fatalf("user payload missing raw blob: %q", userText)
	}
	if strings.Contains(userText, "short summary for humans") {
		t.Fatalf("user payload must not contain section_text: %q", userText)
	}
	if !strings.Contains(userText, "hostname: web-1") {
		t.Fatalf("user payload missing hostname: %q", userText)
	}
}

func TestAnalyzer_Append_customPrompt(t *testing.T) {
	var captured generateContentRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
	}))
	defer server.Close()

	custom := "Custom analyst prompt"
	a := googleai.New("KEY", "gemini-2.5-flash", custom, time.Minute)
	a.SetBaseURL(server.URL)
	a.SetHTTPClient(server.Client())

	if _, err := a.Append(context.Background(), sampleInput()); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if captured.SystemInstruction.Parts[0].Text != custom {
		t.Fatalf("systemInstruction = %q", captured.SystemInstruction.Parts[0].Text)
	}
}

func TestAnalyzer_Append_defaultPromptWhenEmpty(t *testing.T) {
	var captured generateContentRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`))
	}))
	defer server.Close()

	a := googleai.New("KEY", "", analyze.DefaultPrompt, time.Minute)
	a.SetBaseURL(server.URL)
	a.SetHTTPClient(server.Client())

	if _, err := a.Append(context.Background(), sampleInput()); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	if captured.SystemInstruction.Parts[0].Text != analyze.DefaultPrompt {
		t.Fatalf("systemInstruction = %q", captured.SystemInstruction.Parts[0].Text)
	}
}

func TestAnalyzer_Append_httpErrorUsesMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"API key not valid. Please pass a valid API key."}}`))
	}))
	defer server.Close()

	a := googleai.New("BAD", "gemini-2.5-flash", analyze.DefaultPrompt, time.Minute)
	a.SetBaseURL(server.URL)
	a.SetHTTPClient(server.Client())

	_, err := a.Append(context.Background(), sampleInput())
	if err == nil {
		t.Fatal("expected Append() error")
	}
	if !strings.Contains(err.Error(), "API key not valid") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestAnalyzer_Append_emptyCandidates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"candidates":[]}`))
	}))
	defer server.Close()

	a := googleai.New("KEY", "gemini-2.5-flash", analyze.DefaultPrompt, time.Minute)
	a.SetBaseURL(server.URL)
	a.SetHTTPClient(server.Client())

	_, err := a.Append(context.Background(), sampleInput())
	if err == nil {
		t.Fatal("expected Append() error")
	}
	if !strings.Contains(err.Error(), "empty candidates") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestAnalyzer_Append_blockedPrompt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"promptFeedback":{"blockReason":"SAFETY"},"candidates":[]}`))
	}))
	defer server.Close()

	a := googleai.New("KEY", "gemini-2.5-flash", analyze.DefaultPrompt, time.Minute)
	a.SetBaseURL(server.URL)
	a.SetHTTPClient(server.Client())

	_, err := a.Append(context.Background(), sampleInput())
	if err == nil {
		t.Fatal("expected Append() error")
	}
	if !strings.Contains(err.Error(), "prompt blocked") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestAnalyzer_Append_contextCanceled(t *testing.T) {
	a := googleai.New("KEY", "gemini-2.5-flash", analyze.DefaultPrompt, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.Append(ctx, sampleInput())
	if err == nil {
		t.Fatal("expected Append() error")
	}
}

type generateContentRequest struct {
	SystemInstruction struct {
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"systemInstruction"`
	Contents []struct {
		Role  string `json:"role"`
		Parts []struct {
			Text string `json:"text"`
		} `json:"parts"`
	} `json:"contents"`
	GenerationConfig struct {
		Temperature float64 `json:"temperature"`
	} `json:"generationConfig"`
}

func sampleInput() analyze.Input {
	raw, _ := json.Marshal(map[string]string{
		"jail_log": "raw fail2ban data",
	})
	return analyze.Input{
		Report: domain.TextReport{
			Hostname:    "web-1",
			GeneratedAt: time.Date(2026, 8, 14, 12, 30, 0, 0, time.UTC),
		},
		ModuleOrder: []string{"fail2ban", "auditd"},
		Results: []domain.ModuleResult{
			{
				Name:        "fail2ban",
				Status:      domain.ModuleStatusOK,
				Raw:         raw,
				SectionText: "short summary for humans",
			},
			{
				Name:        "auditd",
				Status:      domain.ModuleStatusError,
				Error:       "auditctl failed",
				SectionText: "ERROR: auditctl failed",
			},
		},
	}
}
