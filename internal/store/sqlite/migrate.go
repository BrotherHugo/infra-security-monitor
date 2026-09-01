package sqlite

const schemaSQL = `
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
  raw_json TEXT NOT NULL DEFAULT '{}',
  section_text TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  UNIQUE(run_id, module)
);
`

const migrateSummaryToRawSQL = `
ALTER TABLE module_results RENAME TO module_results_old;

CREATE TABLE module_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER NOT NULL REFERENCES collection_runs(id) ON DELETE CASCADE,
  module TEXT NOT NULL,
  collected_at TEXT NOT NULL,
  status TEXT NOT NULL,
  raw_json TEXT NOT NULL DEFAULT '{}',
  section_text TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  UNIQUE(run_id, module)
);

INSERT INTO module_results (
  run_id, module, collected_at, status, raw_json, section_text, error
)
SELECT run_id, module, collected_at, status, '{}', section_text, error
FROM module_results_old;

DROP TABLE module_results_old;
`
