'use strict';
// db.js — better-sqlite3 singleton (WAL), boot-applies schema if tables absent.

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// On serverless (Vercel/Lambda) the project filesystem is read-only except /tmp,
// and WAL on a Lambda /tmp can stall on the shared-memory (-shm) mmap. Since each
// cold instance re-seeds the deterministic corpus anyway, we use a pure IN-MEMORY
// SQLite database there (no filesystem, no WAL). Locally keep the on-disk data/
// dir (WAL). Explicit DB_PATH env always wins.
const IS_SERVERLESS = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NOW_REGION);
const DEFAULT_DB_PATH = IS_SERVERLESS
  ? ':memory:'
  : path.join(__dirname, '..', 'data', 'insider.db');

const DB_PATH = process.env.DB_PATH || DEFAULT_DB_PATH;
const IN_MEMORY = DB_PATH === ':memory:';

// ensure parent dir exists (only for on-disk DBs)
if (!IN_MEMORY) {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

const db = new Database(DB_PATH);
// WAL only helps a persistent on-disk DB; for in-memory it is a no-op / unsafe,
// so keep the default (MEMORY) journal there.
if (!IN_MEMORY) db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// boot-apply schema (idempotent — CREATE TABLE IF NOT EXISTS)
function applySchema() {
  const schemaPath = path.join(__dirname, 'schema.sql');
  const ddl = fs.readFileSync(schemaPath, 'utf8');
  db.exec(ddl);
}

// run schema if the primary table is absent
const hasDatasets = db
  .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='datasets'")
  .get();
if (!hasDatasets) applySchema();

// prepared-statement cache
const _stmtCache = new Map();
function prep(sql) {
  if (!_stmtCache.has(sql)) _stmtCache.set(sql, db.prepare(sql));
  return _stmtCache.get(sql);
}

module.exports = { db, prep, applySchema, DB_PATH };
