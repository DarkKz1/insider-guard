'use strict';
// db.js — better-sqlite3 singleton (WAL), boot-applies schema if tables absent.

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

const DB_PATH =
  process.env.DB_PATH || path.join(__dirname, '..', 'data', 'insider.db');

// ensure parent dir exists
const dir = path.dirname(DB_PATH);
if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
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
