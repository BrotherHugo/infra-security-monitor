package file_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/channel/file"
	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
)

func TestChannel_Send_writesReportAtomically(t *testing.T) {
	dir := t.TempDir()
	loc := time.FixedZone("MSK", 3*3600)
	generatedAt := time.Date(2026, 8, 13, 12, 30, 0, 0, time.UTC)
	ch := file.New(dir, loc)

	report := domain.TextReport{
		GeneratedAt: generatedAt,
		Hostname:    "host-a",
		Body:        "ISM report\nhost: host-a\n",
	}
	if err := ch.Send(context.Background(), report); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	path := ch.LastWrittenPath(report)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != report.Body {
		t.Fatalf("file content = %q, want %q", string(data), report.Body)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat(dir) error = %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("save_to_dir is not a directory")
	}

	tmpMatches, err := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(tmpMatches) != 0 {
		t.Fatalf("temp files left behind: %v", tmpMatches)
	}
}
