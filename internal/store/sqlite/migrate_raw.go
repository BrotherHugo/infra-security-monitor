package sqlite

import (
	"context"
	"fmt"
)

func (s *Store) migrateModuleResultsRawJSON(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `PRAGMA table_info(module_results)`)
	if err != nil {
		return fmt.Errorf("pragma table_info module_results: %w", err)
	}
	defer rows.Close()

	hasSummary := false
	hasRaw := false
	for rows.Next() {
		var (
			cid       int
			name      string
			ctype     string
			notNull   int
			dfltValue any
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dfltValue, &pk); err != nil {
			return fmt.Errorf("scan table_info: %w", err)
		}
		switch name {
		case "summary_json":
			hasSummary = true
		case "raw_json":
			hasRaw = true
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("table_info rows: %w", err)
	}

	if hasRaw || !hasSummary {
		return nil
	}

	if _, err := s.db.ExecContext(ctx, migrateSummaryToRawSQL); err != nil {
		return fmt.Errorf("migrate summary_json to raw_json: %w", err)
	}
	return nil
}
