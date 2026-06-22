-- Insider Guard schema (SQLite / better-sqlite3, WAL mode)

-- a dataset = one ingest/seed RUN (corpus + its computed incidents)
CREATE TABLE IF NOT EXISTS datasets (
  id            TEXT PRIMARY KEY,            -- "ds_" + nanoid
  name          TEXT NOT NULL,
  source        TEXT NOT NULL,               -- 'seed' | 'upload'
  has_ground_truth INTEGER NOT NULL DEFAULT 0,
  event_count   INTEGER NOT NULL DEFAULT 0,
  user_count    INTEGER NOT NULL DEFAULT 0,
  day_count     INTEGER NOT NULL DEFAULT 0,
  resource_count INTEGER NOT NULL DEFAULT 0,
  host_count    INTEGER NOT NULL DEFAULT 0,
  incident_count INTEGER NOT NULL DEFAULT 0,
  active        INTEGER NOT NULL DEFAULT 0,   -- exactly one row =1 (UI default)
  window_from   TEXT, window_to TEXT,         -- ISO span
  created_at    TEXT NOT NULL                 -- ISO
);

-- raw normalized access events (canonical format). Indexed for per-user-day grouping.
CREATE TABLE IF NOT EXISTS events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id  TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  user        TEXT NOT NULL,
  role        TEXT,
  resource    TEXT,
  db          TEXT,
  host        TEXT,
  ip          TEXT,
  geo         TEXT,
  action      TEXT NOT NULL,
  rows        INTEGER NOT NULL DEFAULT 0,
  ts          TEXT NOT NULL,
  ts_day      TEXT NOT NULL,
  ts_hour     INTEGER NOT NULL,
  channel     TEXT,
  edge_from   TEXT,
  edge_to     TEXT,
  label_malicious INTEGER,
  label_typology  TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ds_user_day ON events(dataset_id, user, ts_day);
CREATE INDEX IF NOT EXISTS idx_events_ds_user     ON events(dataset_id, user);
CREATE INDEX IF NOT EXISTS idx_events_ds          ON events(dataset_id);

-- one incident = one flagged (user, user-day) window with score>0 or any trigger
CREATE TABLE IF NOT EXISTS incidents (
  id          TEXT PRIMARY KEY,
  dataset_id  TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  user        TEXT NOT NULL,
  role        TEXT,
  typology    TEXT,
  title       TEXT NOT NULL,
  channel     TEXT,
  window_date TEXT NOT NULL,
  score       INTEGER NOT NULL,
  priority_lvl   TEXT NOT NULL,
  priority_color TEXT NOT NULL,
  priority_note  TEXT,
  rows_touched INTEGER NOT NULL DEFAULT 0,
  event_count  INTEGER NOT NULL DEFAULT 0,
  mitigation_factor REAL,
  mitigation_note   TEXT,
  cycle_json   TEXT,
  baseline_json TEXT NOT NULL,
  observed_json TEXT NOT NULL,
  graph_json   TEXT NOT NULL,
  playbook_json TEXT,
  label_malicious INTEGER,
  label_typology  TEXT,
  markers_json TEXT,
  related_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_inc_ds_score ON incidents(dataset_id, score DESC);

-- SHAP factors per incident (1 row per trigger)
CREATE TABLE IF NOT EXISTS incident_factors (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  code        TEXT NOT NULL,
  label       TEXT NOT NULL,
  weight      INTEGER NOT NULL,
  contribution INTEGER NOT NULL,
  detail      TEXT,
  severity    TEXT,
  rank        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_factors_inc ON incident_factors(incident_id, rank);

-- graph edges per incident (subgraph for the user-day)
CREATE TABLE IF NOT EXISTS incident_edges (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  from_id     TEXT NOT NULL,
  to_id       TEXT NOT NULL,
  node_kind_from TEXT, node_kind_to TEXT,
  action      TEXT, rows INTEGER, ts TEXT, channel TEXT,
  crit        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_edges_inc ON incident_edges(incident_id);

-- clean (scored) user-days — kept for honest TN/FN in metrics on labeled sets
CREATE TABLE IF NOT EXISTS clean_user_days (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  dataset_id  TEXT NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
  user        TEXT NOT NULL,
  window_date TEXT NOT NULL,
  score       INTEGER NOT NULL DEFAULT 0,
  label_malicious INTEGER,
  event_count INTEGER NOT NULL DEFAULT 0,
  rows_touched INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_clean_ds ON clean_user_days(dataset_id);

-- run metadata / engine config snapshot
CREATE TABLE IF NOT EXISTS run_meta (
  dataset_id  TEXT PRIMARY KEY REFERENCES datasets(id) ON DELETE CASCADE,
  engine_version TEXT,
  config_json TEXT,
  duration_ms INTEGER,
  created_at  TEXT
);
