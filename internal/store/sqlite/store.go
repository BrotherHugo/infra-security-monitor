package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"

	_ "modernc.org/sqlite"
)

// Store is the SQLite store for runs and module results.
type Store struct {
	db *sql.DB
}

// Open opens the database file and applies migrations.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enabling foreign_keys: %w", err)
	}

	store := &Store{db: db}
	if err := store.Migrate(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Migrate creates tables if they do not exist yet.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schemaSQL); err != nil {
		return fmt.Errorf("sqlite migration: %w", err)
	}
	if err := s.migrateModuleResultsRawJSON(ctx); err != nil {
		return err
	}
	return nil
}

// BeginRun inserts a run row; finished_at stays NULL until FinishRun.
func (s *Store) BeginRun(ctx context.Context, hostname string, startedAt time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
INSERT INTO collection_runs (started_at, hostname, status)
VALUES (?, ?, ?)`,
		formatTimeUTC(startedAt),
		hostname,
		string(domain.RunStatusOK),
	)
	if err != nil {
		return 0, fmt.Errorf("BeginRun: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("BeginRun last insert id: %w", err)
	}
	return id, nil
}

// SaveModuleResult inserts or updates a module result for a run.
func (s *Store) SaveModuleResult(ctx context.Context, runID int64, result domain.ModuleResult) error {
	raw := result.Raw
	if len(raw) == 0 {
		raw = []byte("{}")
	}

	_, err := s.db.ExecContext(ctx, `
INSERT INTO module_results (
  run_id, module, collected_at, status, raw_json, section_text, error
) VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(run_id, module) DO UPDATE SET
  collected_at = excluded.collected_at,
  status = excluded.status,
  raw_json = excluded.raw_json,
  section_text = excluded.section_text,
  error = excluded.error`,
		runID,
		string(result.Name),
		formatTimeUTC(result.CollectedAt),
		string(result.Status),
		string(raw),
		result.SectionText,
		result.Error,
	)
	if err != nil {
		return fmt.Errorf("SaveModuleResult: %w", err)
	}
	return nil
}

// FinishRun closes a run and sets the final status.
func (s *Store) FinishRun(ctx context.Context, runID int64, finishedAt time.Time, status domain.RunStatus) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE collection_runs
SET finished_at = ?, status = ?
WHERE id = ?`,
		formatTimeUTC(finishedAt),
		string(status),
		runID,
	)
	if err != nil {
		return fmt.Errorf("FinishRun: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("FinishRun rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("FinishRun: run %d not found", runID)
	}
	return nil
}

// Prune deletes runs older than olderThan together with module_results (CASCADE).
func (s *Store) Prune(ctx context.Context, olderThan time.Time) error {
	_, err := s.db.ExecContext(ctx, `
DELETE FROM collection_runs
WHERE started_at < ?`,
		formatTimeUTC(olderThan),
	)
	if err != nil {
		return fmt.Errorf("Prune: %w", err)
	}
	return nil
}

// ListRuns returns recent runs for future CLI use.
func (s *Store) ListRuns(ctx context.Context, limit int) ([]domain.CollectionRun, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, started_at, finished_at, hostname, status
FROM collection_runs
ORDER BY started_at DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	defer rows.Close()

	var runs []domain.CollectionRun
	for rows.Next() {
		run, err := scanCollectionRun(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListRuns rows: %w", err)
	}
	return runs, nil
}

// GetRun returns a run by id.
func (s *Store) GetRun(ctx context.Context, runID int64) (domain.CollectionRun, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, started_at, finished_at, hostname, status
FROM collection_runs
WHERE id = ?`, runID)

	run, err := scanCollectionRun(row)
	if err != nil {
		return domain.CollectionRun{}, err
	}
	return run, nil
}

// ListModuleResults returns module results for a run.
func (s *Store) ListModuleResults(ctx context.Context, runID int64) ([]domain.ModuleResult, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT module, collected_at, status, raw_json, section_text, error
FROM module_results
WHERE run_id = ?
ORDER BY module`, runID)
	if err != nil {
		return nil, fmt.Errorf("ListModuleResults: %w", err)
	}
	defer rows.Close()

	var results []domain.ModuleResult
	for rows.Next() {
		result, err := scanModuleResult(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ListModuleResults rows: %w", err)
	}
	return results, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanCollectionRun(row rowScanner) (domain.CollectionRun, error) {
	var (
		run           domain.CollectionRun
		startedAt     string
		finishedAtRaw sql.NullString
		status        string
	)
	if err := row.Scan(&run.ID, &startedAt, &finishedAtRaw, &run.Hostname, &status); err != nil {
		if err == sql.ErrNoRows {
			return domain.CollectionRun{}, fmt.Errorf("run not found")
		}
		return domain.CollectionRun{}, fmt.Errorf("scan collection run: %w", err)
	}

	started, err := parseTimeUTC(startedAt)
	if err != nil {
		return domain.CollectionRun{}, err
	}
	run.StartedAt = started
	run.Status = domain.RunStatus(status)

	if finishedAtRaw.Valid && strings.TrimSpace(finishedAtRaw.String) != "" {
		finished, err := parseTimeUTC(finishedAtRaw.String)
		if err != nil {
			return domain.CollectionRun{}, err
		}
		run.FinishedAt = &finished
	}
	return run, nil
}

func scanModuleResult(row rowScanner) (domain.ModuleResult, error) {
	var (
		result    domain.ModuleResult
		module    string
		collected string
		status    string
		raw       string
	)
	if err := row.Scan(&module, &collected, &status, &raw, &result.SectionText, &result.Error); err != nil {
		return domain.ModuleResult{}, fmt.Errorf("scan module result: %w", err)
	}

	collectedAt, err := parseTimeUTC(collected)
	if err != nil {
		return domain.ModuleResult{}, err
	}

	result.Name = domain.ModuleName(module)
	result.Status = domain.ModuleStatus(status)
	result.CollectedAt = collectedAt
	result.Raw = []byte(raw)
	return result, nil
}
