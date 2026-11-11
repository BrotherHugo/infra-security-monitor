package telegram

import (
	"strings"
	"testing"
)

func TestSplitMessages_singleChunk(t *testing.T) {
	body := "short report"
	parts := splitMessages(body)
	if len(parts) != 1 {
		t.Fatalf("parts = %d, want 1", len(parts))
	}
	if parts[0] != body {
		t.Fatalf("part = %q, want %q", parts[0], body)
	}
}

func TestSplitMessages_multiChunk(t *testing.T) {
	body := makeRuneString(5000)
	parts := splitMessages(body)

	if len(parts) < 2 {
		t.Fatalf("parts = %d, want >= 2", len(parts))
	}
	for i, part := range parts {
		if len([]rune(part)) > 4096 {
			t.Fatalf("part %d len = %d, want <= 4096", i+1, len([]rune(part)))
		}
	}
	if strings.Join(parts, "") != body {
		t.Fatal("rejoined body mismatch")
	}
}

func makeRuneString(n int) string {
	runes := make([]rune, n)
	for i := range runes {
		runes[i] = 'a'
	}
	return string(runes)
}
