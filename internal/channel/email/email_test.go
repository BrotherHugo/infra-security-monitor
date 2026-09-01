package email_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/channel/email"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestChannel_Send_buildsMIMEAndDelivers(t *testing.T) {
	var got []byte
	ch, err := email.New(email.HostConfig{
		Host:      "smtp.example.com",
		Port:      "587",
		User:      "ism",
		Password:  "secret",
		UseTLS:    true,
		UseSSL:    false,
		FromEmail: "ism@example.com",
		ToEmails:  []string{"admin@example.com", "ops@example.com"},
	}, time.FixedZone("MSK", 3*3600))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ch.SetDeliverer(func(_ context.Context, msg []byte) error {
		got = append([]byte(nil), msg...)
		return nil
	})

	generatedAt := time.Date(2026, 8, 14, 9, 30, 0, 0, time.UTC)
	report := domain.TextReport{
		GeneratedAt: generatedAt,
		Hostname:    "host-a",
		Body:        "ISM report\nhost: host-a\n",
	}
	if err := ch.Send(context.Background(), report); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	text := string(got)
	if !strings.Contains(text, "From: ism@example.com") {
		t.Fatalf("missing From header: %q", text)
	}
	if !strings.Contains(text, "To: admin@example.com") {
		t.Fatalf("missing first To header: %q", text)
	}
	if !strings.Contains(text, "To: ops@example.com") {
		t.Fatalf("missing second To header: %q", text)
	}
	wantSubject := "Subject: ISM report: host-a 2026-08-14 12:30:00"
	if !strings.Contains(text, wantSubject) {
		t.Fatalf("subject = missing %q in %q", wantSubject, text)
	}
	if !strings.Contains(text, "Content-Type: text/plain; charset=utf-8") {
		t.Fatalf("missing content type: %q", text)
	}
	if !strings.Contains(text, "ISM report") || !strings.Contains(text, "host: host-a") {
		t.Fatalf("missing body: %q", text)
	}
}

func TestChannel_Send_contextCanceled(t *testing.T) {
	ch, err := email.New(email.HostConfig{
		Host:      "smtp.example.com",
		Port:      "587",
		User:      "ism",
		Password:  "secret",
		UseTLS:    true,
		FromEmail: "ism@example.com",
		ToEmails:  []string{"admin@example.com"},
	}, time.Local)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = ch.Send(ctx, domain.TextReport{Body: "hi"})
	if err == context.Canceled {
		return
	}
	if err == nil {
		t.Fatal("expected Send() error")
	}
}
