'use strict';
// pg-source.js — REAL PostgreSQL source. Same interface as db-source (SQLite),
// so the watcher is driver-agnostic. Two modes:
//   • PG_URL set   → connect to a real Postgres SERVER via the `pg` driver (prod:
//                    a bank / gov Postgres — only the connection string changes).
//   • PG_URL unset → embedded PostgreSQL via pglite (the real Postgres engine
//                    compiled to WASM — `SELECT version()` → "PostgreSQL 18.x"),
//                    in-process, OFFLINE, no daemon. Proves the SAME 12-field
//                    access_log contract works on the Postgres dialect.

const path = require('path');

const PG_URL = process.env.PG_URL || '';
const PG_DATADIR = process.env.PG_DATADIR || path.join(__dirname, '..', 'data', 'pgdata');

let _mode = null; // 'server' | 'pglite'
let _pool = null;
let _lite = null;
let _ready = null;

async function init() {
  if (_ready) return _ready;
  _ready = (async () => {
    if (PG_URL) {
      const { Pool } = require('pg');
      _pool = new Pool({ connectionString: PG_URL, max: 4 });
      _mode = 'server';
    } else {
      const { PGlite } = await import('@electric-sql/pglite');
      _lite = await PGlite.create(PG_DATADIR);
      _mode = 'pglite';
    }
    await q(`CREATE TABLE IF NOT EXISTS access_log (
        id BIGSERIAL PRIMARY KEY,
        ts TEXT NOT NULL,
        "user" TEXT NOT NULL,
        role TEXT, resource TEXT, db TEXT, host TEXT, ip TEXT, geo TEXT,
        action TEXT NOT NULL, "rows" INTEGER DEFAULT 0,
        channel TEXT, edge_from TEXT, edge_to TEXT,
        label_malicious INTEGER, label_typology TEXT)`);
    await q('CREATE INDEX IF NOT EXISTS idx_access_ts ON access_log(ts)');
  })();
  return _ready;
}

async function q(sql, params = []) {
  if (_mode === 'server') return (await _pool.query(sql, params)).rows;
  return (await _lite.query(sql, params)).rows;
}

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

async function insertEvents(events) {
  if (!events.length) return 0;
  const cols = '(ts,"user",role,resource,db,host,ip,geo,action,"rows",channel,edge_from,edge_to,label_malicious,label_typology)';
  const CHUNK = 200;
  for (let i = 0; i < events.length; i += CHUNK) {
    const chunk = events.slice(i, i + CHUNK);
    const vals = [];
    const ph = [];
    chunk.forEach((e, j) => {
      const b = j * 15;
      ph.push(`($${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5},$${b + 6},$${b + 7},$${b + 8},$${b + 9},$${b + 10},$${b + 11},$${b + 12},$${b + 13},$${b + 14},$${b + 15})`);
      vals.push(
        e.ts, String(e.user), e.role ?? null, e.resource ?? null, e.db ?? null, e.host ?? null,
        e.ip ?? null, e.geo ?? null, e.action, e.rows ?? 0, e.channel ?? null,
        (e.from ?? null), (e.to ?? null), (e.label_malicious == null ? null : e.label_malicious), e.label_typology ?? null,
      );
    });
    await q(`INSERT INTO access_log ${cols} VALUES ${ph.join(',')}`, vals);
  }
  return events.length;
}

async function count() { return Number((await q('SELECT COUNT(*)::int c FROM access_log'))[0].c); }
async function maxId() { return Number((await q('SELECT COALESCE(MAX(id),0) m FROM access_log'))[0].m); }
async function maxDay() { const r = await q('SELECT MAX(substr(ts,1,10)) d FROM access_log'); return (r[0] && r[0].d) || '2026-06-30'; }
async function readAll() { return (await q('SELECT * FROM access_log ORDER BY ts ASC, id ASC')).map(rowToEvent); }
async function readSinceId(id) { return (await q('SELECT * FROM access_log WHERE id > $1 ORDER BY id ASC', [id])).map(rowToEvent); }
async function clear() { await q('DELETE FROM access_log'); }
async function sampleUsers(n = 30) {
  return (await q('SELECT DISTINCT "user" u FROM access_log WHERE (label_malicious IS NULL OR label_malicious=0) ORDER BY "user" LIMIT $1', [n])).map((r) => r.u);
}

module.exports = { init, insertEvents, count, maxId, maxDay, readAll, readSinceId, clear, sampleUsers, rowToEvent };
Object.defineProperty(module.exports, 'backend', {
  get() {
    return _mode === 'server'
      ? 'Postgres · pg driver · server'
      : 'PostgreSQL · pglite (embedded, on-device)';
  },
});
Object.defineProperty(module.exports, 'DB_FILE', {
  get() { return _mode === 'server' ? 'postgres://server/access_log' : PG_DATADIR; },
});
