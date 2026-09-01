package googleai

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/BrotherHugo/infra-security-monitor/internal/analyze"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestBuildUserPayload_missingModuleStatusOk(t *testing.T) {
	payload := buildUserPayload(analyze.Input{
		Report: domain.TextReport{
			Hostname:    "host",
			GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		ModuleOrder: []string{"fail2ban", "missing"},
		Results: []domain.ModuleResult{
			{
				Name:   "fail2ban",
				Status: domain.ModuleStatusOK,
				Raw:    mustRaw(t, map[string]string{"log": "x"}),
			},
		},
	})

	if !strings.Contains(payload, "=== missing ===\nstatus: ok\n") {
		t.Fatalf("payload = %q", payload)
	}
}

func TestBuildUserPayload_includesErrorStatus(t *testing.T) {
	payload := buildUserPayload(analyze.Input{
		Report: domain.TextReport{
			Hostname:    "host",
			GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		ModuleOrder: []string{"auditd"},
		Results: []domain.ModuleResult{
			{
				Name:   "auditd",
				Status: domain.ModuleStatusError,
				Error:  "auditctl failed",
			},
		},
	})

	if !strings.Contains(payload, "status: error\nerror: auditctl failed\n") {
		t.Fatalf("payload = %q", payload)
	}
}

func TestBuildUserPayload_truncatesHeaviestModuleFirst(t *testing.T) {
	heavy := strings.Repeat("H", 700_000)
	light := strings.Repeat("L", 250_000)

	payload := buildUserPayload(analyze.Input{
		Report: domain.TextReport{
			Hostname:    "host",
			GeneratedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		},
		ModuleOrder: []string{"lynis", "fail2ban"},
		Results: []domain.ModuleResult{
			{
				Name:   "lynis",
				Status: domain.ModuleStatusOK,
				Raw:    mustRaw(t, map[string]string{"report": heavy}),
			},
			{
				Name:   "fail2ban",
				Status: domain.ModuleStatusOK,
				Raw:    mustRaw(t, map[string]string{"log": light}),
			},
		},
	})

	if utf8.RuneCountInString(payload) > 900_000 {
		t.Fatalf("payload too long: %d runes", utf8.RuneCountInString(payload))
	}
	if !strings.HasPrefix(payload, "WARNING: payload truncated") {
		t.Fatalf("missing truncation warning: %q", payload[:80])
	}
	if !strings.Contains(payload, "[... truncated ...]") {
		t.Fatal("expected truncated blob marker")
	}
	if strings.Contains(payload, heavy) {
		t.Fatal("lynis blob should be truncated")
	}
	if !strings.Contains(payload, light) {
		t.Fatal("fail2ban blob should remain intact")
	}
}

func mustRaw(t *testing.T, blobs map[string]string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(blobs)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}
