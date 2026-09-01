package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/store/sqlite"
)

func TestStore_migrateSummaryJSONToRawJSON(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "legacy.db")

	db, err := sqlite.OpenLegacySummarySchema(path)
	if err != nil {
		t.Fatalf("OpenLegacySummarySchema() error = %v", err)
	}
	defer db.Close()

	startedAt := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	runID, err := db.BeginRun(ctx, "legacy-host", startedAt)
	if err != nil {
		t.Fatalf("BeginRun() error = %v", err)
	}
	if err := db.SaveLegacyModuleResult(ctx, runID, domain.ModuleResult{
		Name:        domain.ModuleName("fail2ban"),
		Status:      domain.ModuleStatusOK,
		CollectedAt: startedAt,
		SectionText: "legacy section",
	}); err != nil {
		t.Fatalf("SaveModuleResult() error = %v", err)
	}

	store, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()

	results, err := store.ListModuleResults(ctx, runID)
	if err != nil {
		t.Fatalf("ListModuleResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if string(results[0].Raw) != "{}" {
		t.Fatalf("Raw after migrate = %q, want {}", results[0].Raw)
	}
	if results[0].SectionText != "legacy section" {
		t.Fatalf("SectionText = %q", results[0].SectionText)
	}
}
