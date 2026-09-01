package telegram_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/BrotherHugo/infra-security-monitor/internal/channel/telegram"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestChannel_Send_postsSendMessage(t *testing.T) {
	var requests []sendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/botTEST_TOKEN/sendMessage" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
			return
		}
		var req sendMessageRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("Unmarshal() error = %v", err)
			return
		}
		requests = append(requests, req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ch := telegram.New("TEST_TOKEN", "-100123", 0)
	ch.SetBaseURL(server.URL)
	ch.SetHTTPClient(server.Client())

	report := domain.TextReport{
		Body: "ISM report\nhost: test\n",
	}
	if err := ch.Send(context.Background(), report); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	if requests[0].ChatID != "-100123" {
		t.Fatalf("chat_id = %q", requests[0].ChatID)
	}
	if requests[0].Text != report.Body {
		t.Fatalf("text = %q", requests[0].Text)
	}
	if requests[0].MessageThreadID != 0 {
		t.Fatalf("message_thread_id = %d, want 0", requests[0].MessageThreadID)
	}
}

func TestChannel_Send_includesMessageThreadID(t *testing.T) {
	var requests []sendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll() error = %v", err)
			return
		}
		var req sendMessageRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Errorf("Unmarshal() error = %v", err)
			return
		}
		requests = append(requests, req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ch := telegram.New("TEST_TOKEN", "-100123", 42)
	ch.SetBaseURL(server.URL)
	ch.SetHTTPClient(server.Client())

	if err := ch.Send(context.Background(), domain.TextReport{Body: "hi"}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	if requests[0].MessageThreadID != 42 {
		t.Fatalf("message_thread_id = %d, want 42", requests[0].MessageThreadID)
	}
}

func TestChannel_Send_chunksLongBody(t *testing.T) {
	var mu sync.Mutex
	var texts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req sendMessageRequest
		_ = json.Unmarshal(body, &req)
		mu.Lock()
		texts = append(texts, req.Text)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ch := telegram.New("TOKEN", "1", 0)
	ch.SetBaseURL(server.URL)
	ch.SetHTTPClient(server.Client())

	longBody := strings.Repeat("x", 5000)
	if err := ch.Send(context.Background(), domain.TextReport{Body: longBody}); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(texts) < 2 {
		t.Fatalf("messages = %d, want >= 2", len(texts))
	}
	if len([]rune(texts[0])) > 4096 {
		t.Fatalf("first message too long: %d", len([]rune(texts[0])))
	}
	if !strings.Contains(texts[1], "--- ISM report (part 2/") {
		t.Fatalf("second message missing header: %q", texts[1][:min(60, len(texts[1]))])
	}
}

func TestChannel_Send_apiError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"description":"chat not found"}`))
	}))
	defer server.Close()

	ch := telegram.New("TOKEN", "1", 0)
	ch.SetBaseURL(server.URL)
	ch.SetHTTPClient(server.Client())

	err := ch.Send(context.Background(), domain.TextReport{Body: "hi"})
	if err == nil {
		t.Fatal("expected Send() error")
	}
	if !strings.Contains(err.Error(), "chat not found") {
		t.Fatalf("error = %q", err.Error())
	}
}

func TestChannel_Send_contextCanceled(t *testing.T) {
	ch := telegram.New("TOKEN", "1", 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := ch.Send(ctx, domain.TextReport{Body: "hi"})
	if err == context.Canceled {
		return
	}
	if err == nil {
		t.Fatal("expected Send() error")
	}
}

func TestChannel_Send_partialFailureReturnsError(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"description":"rate limit"}`))
	}))
	defer server.Close()

	ch := telegram.New("TOKEN", "1", 0)
	ch.SetBaseURL(server.URL)
	ch.SetHTTPClient(server.Client())

	err := ch.Send(context.Background(), domain.TextReport{Body: strings.Repeat("y", 5000)})
	if err == nil {
		t.Fatal("expected Send() error")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Fatalf("error = %q", err.Error())
	}
}

type sendMessageRequest struct {
	ChatID          string `json:"chat_id"`
	Text            string `json:"text"`
	MessageThreadID int    `json:"message_thread_id,omitempty"`
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
