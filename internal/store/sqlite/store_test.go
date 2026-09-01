package sqlite_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"
	"github.com/BrotherHugo/infra-security-monitor/internal/store/sqlite"
)

func TestStore_saveAndReadRun(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	startedAt := time.Date(2026, 8, 13, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Minute)

	runID, err := store.BeginRun(ctx, "host-a", startedAt)
	if err != nil {
		t.Fatalf("BeginRun() error = %v", err)
	}

	summary, err := json.Marshal(map[string]string{"sshd": "Status for the jail: sshd"})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	err = store.SaveModuleResult(ctx, runID, domain.ModuleResult{
		Name:        domain.ModuleName("fail2ban"),
		Status:      domain.ModuleStatusAttention,
		CollectedAt: startedAt.Add(time.Minute),
		Raw:         summary,
		SectionText: "jail sshd: banned=1",
	})
	if err != nil {
		t.Fatalf("SaveModuleResult() error = %v", err)
	}

	if err := store.FinishRun(ctx, runID, finishedAt, domain.RunStatusDegraded); err != nil {
		t.Fatalf("FinishRun() error = %v", err)
	}

	run, err := store.GetRun(ctx, runID)
	if err != nil {
		t.Fatalf("GetRun() error = %v", err)
	}
	if run.Hostname != "host-a" {
		t.Fatalf("Hostname = %q, want host-a", run.Hostname)
	}
	if run.Status != domain.RunStatusDegraded {
		t.Fatalf("Status = %q, want degraded", run.Status)
	}
	if run.FinishedAt == nil || !run.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", run.FinishedAt, finishedAt)
	}

	results, err := store.ListModuleResults(ctx, runID)
	if err != nil {
		t.Fatalf("ListModuleResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].SectionText != "jail sshd: banned=1" {
		t.Fatalf("SectionText = %q", results[0].SectionText)
	}
	if string(results[0].Raw) != string(summary) {
		t.Fatalf("Raw = %q, want %q", results[0].Raw, summary)
	}

	runs, err := store.ListRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListRuns() error = %v", err)
	}
	if len(runs) != 1 || runs[0].ID != runID {
		t.Fatalf("ListRuns() = %+v, want one run id=%d", runs, runID)
	}
}

func TestStore_pruneRemovesOldRuns(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	oldStarted := time.Date(2026, 7, 1, 8, 0, 0, 0, time.UTC)
	newStarted := time.Date(2026, 8, 13, 8, 0, 0, 0, time.UTC)

	oldRunID, err := store.BeginRun(ctx, "host-old", oldStarted)
	if err != nil {
		t.Fatalf("BeginRun(old) error = %v", err)
	}
	if err := store.FinishRun(ctx, oldRunID, oldStarted.Add(time.Minute), domain.RunStatusOK); err != nil {
		t.Fatalf("FinishRun(old) error = %v", err)
	}
	if err := store.SaveModuleResult(ctx, oldRunID, domain.ModuleResult{
		Name:        domain.ModuleName("fail2ban"),
		Status:      domain.ModuleStatusOK,
		CollectedAt: oldStarted,
		SectionText: "old",
	}); err != nil {
		t.Fatalf("SaveModuleResult(old) error = %v", err)
	}

	newRunID, err := store.BeginRun(ctx, "host-new", newStarted)
	if err != nil {
		t.Fatalf("BeginRun(new) error = %v", err)
	}
	if err := store.FinishRun(ctx, newRunID, newStarted.Add(time.Minute), domain.RunStatusOK); err != nil {
		t.Fatalf("FinishRun(new) error = %v", err)
	}

	cutoff := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	if err := store.Prune(ctx, cutoff); err != nil {
		t.Fatalf("Prune() error = %v", err)
	}

	runs, err := store.ListRuns(ctx, 10)
	if err != nil {
		t.Fatalf("ListRuns() error = %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("len(runs) after prune = %d, want 1", len(runs))
	}
	if runs[0].ID != newRunID {
		t.Fatalf("remaining run id = %d, want %d", runs[0].ID, newRunID)
	}

	oldResults, err := store.ListModuleResults(ctx, oldRunID)
	if err != nil {
		t.Fatalf("ListModuleResults(old) error = %v", err)
	}
	if len(oldResults) != 0 {
		t.Fatalf("old module results still present: %+v", oldResults)
	}
}

func TestStore_saveModuleResultUpsert(t *testing.T) {
	ctx := context.Background()
	store := openTestStore(t)
	defer store.Close()

	startedAt := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	runID, err := store.BeginRun(ctx, "host-a", startedAt)
	if err != nil {
		t.Fatalf("BeginRun() error = %v", err)
	}

	first := domain.ModuleResult{
		Name:        domain.ModuleName("auditd"),
		Status:      domain.ModuleStatusOK,
		CollectedAt: startedAt,
		SectionText: "first",
	}
	second := domain.ModuleResult{
		Name:        domain.ModuleName("auditd"),
		Status:      domain.ModuleStatusAttention,
		CollectedAt: startedAt.Add(time.Minute),
		SectionText: "second",
	}

	if err := store.SaveModuleResult(ctx, runID, first); err != nil {
		t.Fatalf("SaveModuleResult(first) error = %v", err)
	}
	if err := store.SaveModuleResult(ctx, runID, second); err != nil {
		t.Fatalf("SaveModuleResult(second) error = %v", err)
	}

	results, err := store.ListModuleResults(ctx, runID)
	if err != nil {
		t.Fatalf("ListModuleResults() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if results[0].SectionText != "second" {
		t.Fatalf("SectionText = %q, want second", results[0].SectionText)
	}
	if results[0].Status != domain.ModuleStatusAttention {
		t.Fatalf("Status = %q, want attention", results[0].Status)
	}
}

func openTestStore(t *testing.T) *sqlite.Store {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ism.db")
	store, err := sqlite.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return store
}
