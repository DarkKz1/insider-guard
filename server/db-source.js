'use strict';
// db-source.js — REAL SQL database source for live monitoring.
//
// Uses node:sqlite (built into Node 22+/25, ZERO npm deps) → a genuine on-disk
// SQL database, fully offline, no external service. This is the "подключение к
// БД" layer: access events live in an `access_log` table; the watcher reads new
// rows incrementally (real-time) and feeds them to the same detection engine.
//
// Prod swap: the SAME 12-field contract maps 1:1 to a Postgres `access_log`
// table — only the driver changes (node:sqlite → pg). The query shape (read new
// rows since a cursor) is identical, so streaming/CDC is a driver swap.

const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DB_FILE = process.env.DB_SQLITE_PATH || path.join(__dirname, '..', 'data', 'insider.db');

let _db = null;
function db() {
  if (_db) return _db;
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  _db = new DatabaseSync(DB_FILE);
  _db.exec(`
    CREATE TABLE IF NOT EXISTS access_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT NOT NULL,
      "user" TEXT NOT NULL,
      role TEXT, resource TEXT, db TEXT, host TEXT, ip TEXT, geo TEXT,
      action TEXT NOT NULL, "rows" INTEGER DEFAULT 0,
      channel TEXT, edge_from TEXT, edge_to TEXT,
      label_malicious INTEGER, label_typology TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_access_ts ON access_log(ts);
  `);
  return _db;
}

// SQL row -> canonical engine event (reconstruct derived ts_day/ts_hour + from/to)
function rowToEvent(r) {
  const ts = r.ts;
  return {
    user: r.user, role: r.role, resource: r.resource, db: r.db, host: r.host,
    ip: r.ip, geo: r.geo, action: r.action, rows: r.rows || 0, ts,
    ts_day: ts.slice(0, 10), ts_hour: parseInt(ts.slice(11, 13), 10) || 0,
    channel: r.channel, from: r.edge_from, to: r.edge_to,
    label_malicious: r.label_malicious == null ? null : r.label_malicious,
    label_typology: r.label_typology,
  };
}

function insertEvents(events) {
  const d = db();
  const stmt = d.prepare(`INSERT INTO access_log
    (ts,"user",role,resource,db,host,ip,geo,action,"rows",channel,edge_from,edge_to,label_malicious,label_typology)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
  d.exec('BEGIN');
  try {
    for (const e of events) {
      stmt.run(
        e.ts, String(e.user), e.role ?? null, e.resource ?? null, e.db ?? null,
        e.host ?? null, e.ip ?? null, e.geo ?? null, e.action, e.rows ?? 0,
        e.channel ?? null, (e.from ?? null), (e.to ?? null),
        (e.label_malicious == null ? null : e.label_malicious), e.label_typology ?? null,
      );
    }
    d.exec('COMMIT');
  } catch (err) {
    d.exec('ROLLBACK');
    throw err;
  }
  return events.length;
}

function count() { return db().prepare('SELECT COUNT(*) c FROM access_log').get().c; }
function maxId() { return db().prepare('SELECT COALESCE(MAX(id),0) m FROM access_log').get().m; }
function readAll() {
  return db().prepare('SELECT * FROM access_log ORDER BY ts ASC, id ASC').all().map(rowToEvent);
}
function readSinceId(id) {
  return db().prepare('SELECT * FROM access_log WHERE id > ? ORDER BY id ASC').all(id).map(rowToEvent);
}
function clear() { db().exec('DELETE FROM access_log'); }
function maxDay() {
  const r = db().prepare('SELECT MAX(substr(ts,1,10)) d FROM access_log').get();
  return (r && r.d) || '2026-06-30';
}
function sampleUsers(n = 30) {
  return db()
    .prepare('SELECT DISTINCT "user" u FROM access_log WHERE (label_malicious IS NULL OR label_malicious=0) ORDER BY "user" LIMIT ?')
    .all(n)
    .map((r) => r.u);
}

module.exports = { db, DB_FILE, insertEvents, count, maxId, maxDay, readAll, readSinceId, clear, sampleUsers, rowToEvent };
