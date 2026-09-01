package telegram

import (
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

func TestSplitMessages_multiChunkWithHeaders(t *testing.T) {
	body := makeRuneString(5000)
	parts := splitMessages(body)

	if len(parts) < 2 {
		t.Fatalf("parts = %d, want >= 2", len(parts))
	}
	if len([]rune(parts[0])) > 4096 {
		t.Fatalf("first part len = %d, want <= 4096", len([]rune(parts[0])))
	}
	for i, part := range parts[1:] {
		if len([]rune(part)) > 4096 {
			t.Fatalf("part %d len = %d, want <= 4096", i+2, len([]rune(part)))
		}
		if !contains(part, "--- ISM report (part ") {
			t.Fatalf("part %d missing continuation header: %q", i+2, part[:min(80, len(part))])
		}
	}
	rejoined := parts[0]
	for i, part := range parts[1:] {
		headerEnd := indexContinuationBody(part)
		if headerEnd < 0 {
			t.Fatalf("part %d: continuation header not found", i+2)
		}
		rejoined += part[headerEnd:]
	}
	if rejoined != body {
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

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func indexContinuationBody(part string) int {
	const marker = "---\n"
	idx := indexOf(part, marker)
	if idx < 0 {
		return -1
	}
	return idx + len(marker)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
