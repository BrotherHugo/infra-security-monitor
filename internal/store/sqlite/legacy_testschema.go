package sqlite

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/BrotherHugo/infra-security-monitor/internal/domain"

	_ "modernc.org/sqlite"
)

const legacySummarySchemaSQL = `
CREATE TABLE IF NOT EXISTS collection_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  hostname TEXT NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS module_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES collection_runs(id) ON DELETE CASCADE,
  module TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  status TEXT NOT NULL,
  summary_json TEXT NOT NULL DEFAULT '{}',
  section_text TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  UNIQUE(run_id, module)
);
`

// OpenLegacySummarySchema opens a DB with the legacy summary_json schema (migration tests only).
func OpenLegacySummarySchema(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON"); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("enabling foreign_keys: %w", err)
	}
	if _, err := db.Exec(legacySummarySchemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("legacy schema: %w", err)
	}

	return &Store{db: db}, nil
}

// SaveLegacyModuleResult saves a result into the legacy summary_json schema (migration tests only).
func (s *Store) SaveLegacyModuleResult(ctx context.Context, runID int64, result domain.ModuleResult) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO module_results (
  run_id, module, collected_at, status, summary_json, section_text, error
) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		runID,
		string(result.Name),
		formatTimeUTC(result.CollectedAt),
		string(result.Status),
		"{}",
		result.SectionText,
		result.Error,
	)
	if err != nil {
		return fmt.Errorf("saveLegacyModuleResult: %w", err)
	}
	return nil
}
