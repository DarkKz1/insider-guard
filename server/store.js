'use strict';
// store.js — pure-JS data store (NO native modules) with persistence. Holds
// datasets and their computed incidents / clean-user-days / run-meta as plain JS
// objects, keyed by datasetId.
//
// Persistence backends (priority order):
//   1. Supabase Postgres  — when SUPABASE_URL + SUPABASE_KEY are set. The ENTIRE
//      store snapshot is kept as ONE row in public.ig_snapshot (id='main',
//      data=jsonb). This survives serverless cold-starts / redeploys (Vercel
//      freezes/discards the per-instance memory between invocations). We use the
//      Supabase PostgREST API directly via global `fetch` (NOT the
//      @supabase/supabase-js SDK): the SDK's createClient() builds a Realtime
//      client that needs a native WebSocket, which throws on Node < 22 (Vercel
//      pins Node 20) and silently disabled persistence. PostgREST over fetch
//      needs no WebSocket and no extra deps. Loading is
//      ASYNC — callers MUST `await ensureLoaded()` before reading the store (an
//      Express middleware does this per request). Mutations `await saveSnapshot`
//      so the row is written BEFORE the HTTP response returns (a Vercel instance
//      may be frozen the instant after res, so a fire-and-forget save can lose).
//   2. On-disk JSON snapshot (DB_PATH, default ./data/store.json) — local/dev
//      fallback when Supabase env is NOT set. Atomic write (temp + rename).
//
// Graceful degradation: ANY Supabase error -> one warn + continue purely
// in-memory (never crash). Correctness is in RAM; persistence is best-effort.
//
// Engine output (rich incident objects) is stored as-is. The only non-JSON
// field on a record is `incidentsById` (a Map); it is DROPPED on save and
// REBUILT from `incidents` on load, so the snapshot is plain JSON.

const fs = require('fs');
const path = require('path');

// datasetId -> {
//   meta: { id,name,source,has_ground_truth,event_count,user_count,day_count,
//           resource_count,host_count,incident_count,active,window_from,window_to,created_at },
//   incidents: [ <enriched engine incident, with _id/_seq/related/markers> ],
//   incidentsById: Map(_id -> incident),   // derived, not persisted
//   cleanUserDays: [ {user,day,score,label} ],
//   runMeta: { engine_version, config, duration_ms, created_at },
// }
const _datasets = new Map();

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'data', 'store.json');

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const SNAPSHOT_ID = 'main';
const TABLE = 'ig_snapshot';

let _loaded = false; // have we attempted to load the snapshot yet?
let _loadPromise = null; // Promise-once for the async load
let _persistDisabled = false; // turned on after a write failure (warn once)
let _warnedLoad = false; // warn-once on a load failure

// --- supabase persistence via PostgREST (native fetch, NO sdk) -----------
// We talk to Supabase's auto-generated REST API directly with global `fetch`
// instead of @supabase/supabase-js. The SDK's createClient() instantiates a
// Realtime client that REQUIRES a native WebSocket; on Node < 22 (Vercel pins
// Node 20) that throws ("Node.js 20 detected without native WebSocket support"),
// which silently disabled persistence. PostgREST over fetch needs no WebSocket,
// no extra deps, and is exactly what the SDK does for table reads/writes.

const supabaseEnabled = () => !!(SUPABASE_URL && SUPABASE_KEY);

const _restBase = () => `${SUPABASE_URL.replace(/\/+$/, '')}/rest/v1/${TABLE}`;
const _restHeaders = () => ({
  apikey: SUPABASE_KEY,
  Authorization: `Bearer ${SUPABASE_KEY}`,
});

// SELECT data WHERE id='main' (single row). Returns the parsed `data` jsonb or
// null when the row is absent. Throws on a non-2xx response so the caller's
// catch can warn-once and fall back.
async function _restSelectSnapshot() {
  const url = `${_restBase()}?id=eq.${encodeURIComponent(SNAPSHOT_ID)}&select=data`;
  const resp = await fetch(url, { headers: { ..._restHeaders(), Accept: 'application/json' } });
  if (!resp.ok) throw new Error(`PostgREST select ${resp.status} ${resp.statusText}: ${await resp.text()}`);
  const rows = await resp.json();
  const row = Array.isArray(rows) ? rows[0] : null;
  return row && row.data ? row.data : null;
}

// UPSERT {id:'main', data, updated_at}. PostgREST does an upsert when the body
// targets the PK and Prefer:resolution=merge-duplicates is set. Throws on
// non-2xx so the caller can warn-once and continue in-memory.
async function _restUpsertSnapshot(snapshot) {
  const resp = await fetch(_restBase(), {
    method: 'POST',
    headers: {
      ..._restHeaders(),
      'Content-Type': 'application/json',
      Prefer: 'resolution=merge-duplicates,return=minimal',
    },
    body: JSON.stringify({ id: SNAPSHOT_ID, data: snapshot, updated_at: new Date().toISOString() }),
  });
  if (!resp.ok) throw new Error(`PostgREST upsert ${resp.status} ${resp.statusText}: ${await resp.text()}`);
  return true;
}

// --- (de)serialize -------------------------------------------------------

function _rebuildIndex(rec) {
  // incidentsById is derived from incidents (_id). Rebuild it after load so
  // queries.js (rec.incidentsById.get(id)) works without a round-trip.
  rec.incidentsById = new Map((rec.incidents || []).map((inc) => [inc._id, inc]));
  return rec;
}

function _snapshotObject() {
  // plain-JSON snapshot of the whole store (drop the derived Map).
  const datasets = [..._datasets.values()].map((rec) => ({
    meta: rec.meta,
    incidents: rec.incidents,
    cleanUserDays: rec.cleanUserDays,
    runMeta: rec.runMeta,
  }));
  return { version: 1, savedAt: new Date().toISOString(), datasets };
}

function _hydrateFrom(parsed) {
  const records = Array.isArray(parsed) ? parsed : (parsed && parsed.datasets) || [];
  _datasets.clear();
  for (const rec of records) {
    if (!rec || !rec.meta || !rec.meta.id) continue;
    _datasets.set(rec.meta.id, _rebuildIndex(rec));
  }
}

// --- async load (Supabase first, disk fallback) --------------------------

async function _loadSupabase() {
  if (!supabaseEnabled()) return false;
  const data = await _restSelectSnapshot();
  if (data) {
    _hydrateFrom(data);
    // eslint-disable-next-line no-console
    console.log(`[store] loaded ${_datasets.size} dataset(s) from Supabase (${TABLE}/${SNAPSHOT_ID})`);
  } else {
    // eslint-disable-next-line no-console
    console.log(`[store] no Supabase snapshot yet — starting empty (bootstrap will seed)`);
  }
  return true;
}

function _loadFromDiskSync() {
  try {
    if (!fs.existsSync(DB_PATH)) return; // no snapshot yet -> stay empty, will seed
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    if (!raw.trim()) return;
    _hydrateFrom(JSON.parse(raw));
    // eslint-disable-next-line no-console
    console.log(`[store] loaded ${_datasets.size} dataset(s) from ${DB_PATH}`);
  } catch (e) {
    // Corrupt / partial snapshot: do not crash. Start empty so seed can repair.
    // eslint-disable-next-line no-console
    console.warn(`[store] could not load snapshot ${DB_PATH}: ${e.message} — starting empty`);
    _datasets.clear();
  }
}

/**
 * ensureLoaded — lazy, idempotent, Promise-once async load. MUST be awaited
 * before any store read on serverless (Supabase load is async). Express
 * middleware awaits this per request. On any failure: warn once, stay empty.
 */
function ensureLoaded() {
  if (_loaded) return Promise.resolve();
  if (_loadPromise) return _loadPromise;
  _loadPromise = (async () => {
    try {
      if (supabaseEnabled()) {
        const ok = await _loadSupabase();
        if (!ok) _loadFromDiskSync();
      } else {
        _loadFromDiskSync();
      }
    } catch (e) {
      if (!_warnedLoad) {
        // eslint-disable-next-line no-console
        console.warn(`[store] load failed (${e.message}) — starting empty, continuing in-memory`);
        _warnedLoad = true;
      }
      _datasets.clear();
    } finally {
      _loaded = true;
    }
  })();
  return _loadPromise;
}

// Sync best-effort load for any legacy sync read path (local/dev only). On
// Supabase the load is async-only; sync reads rely on the middleware having
// awaited ensureLoaded() first.
function _ensureLoadedSync() {
  if (_loaded) return;
  if (supabaseEnabled()) return; // async-only; do NOT block — middleware handles it
  _loaded = true;
  _loadFromDiskSync();
}

// --- async save (Supabase upsert, disk fallback) -------------------------

async function _saveSupabase(snapshot) {
  if (!supabaseEnabled()) return false;
  await _restUpsertSnapshot(snapshot);
  return true;
}

function _saveToDiskSync(snapshot) {
  if (_persistDisabled) return;
  let json;
  try {
    json = JSON.stringify(snapshot);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`[store] serialize failed: ${e.message} — running in-memory only`);
    _persistDisabled = true;
    return;
  }
  try {
    const dir = path.dirname(DB_PATH);
    fs.mkdirSync(dir, { recursive: true });
    // atomic: write temp in the SAME dir, then rename over the target.
    const tmp = path.join(dir, `.store.${process.pid}.${Date.now()}.tmp`);
    fs.writeFileSync(tmp, json);
    fs.renameSync(tmp, DB_PATH);
  } catch (e) {
    if (!_persistDisabled) {
      // eslint-disable-next-line no-console
      console.warn(
        `[store] persist to ${DB_PATH} failed (${e.code || e.message}) — continuing in-memory only (no volume?).`,
      );
    }
    _persistDisabled = true;
  }
}

/**
 * saveSnapshot — persist the WHOLE store. Returns a Promise that MUST be
 * awaited by mutating routes BEFORE sending the HTTP response (serverless can
 * freeze the instance right after res). Any error -> warn once, resolve anyway
 * (best-effort persistence; never throw into the request path).
 */
async function saveSnapshot() {
  let snapshot;
  try {
    snapshot = _snapshotObject();
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`[store] snapshot serialize failed: ${e.message} — in-memory only`);
    return;
  }
  if (supabaseEnabled()) {
    try {
      await _saveSupabase(snapshot);
      return;
    } catch (e) {
      if (!_persistDisabled) {
        // eslint-disable-next-line no-console
        console.warn(`[store] Supabase save failed (${e.message}) — continuing in-memory only`);
      }
      _persistDisabled = true;
      return; // do NOT fall back to disk on a serverless host
    }
  }
  _saveToDiskSync(snapshot);
}

// --- store API -----------------------------------------------------------
// Reads are SYNC (RAM). Writes update RAM synchronously and RETURN the
// saveSnapshot() Promise so callers (persist.js / routes) can `await` the
// durable write before responding.

function putDataset(rec) {
  _ensureLoadedSync();
  _datasets.set(rec.meta.id, rec);
  return saveSnapshot();
}

function clearActive() {
  _ensureLoadedSync();
  for (const rec of _datasets.values()) rec.meta.active = 0;
  return saveSnapshot();
}

// RAM-only deactivate (no save). Used by persistDataset before putDataset so a
// single consistent snapshot is written (avoids two concurrent upserts).
function deactivateAllInMemory() {
  _ensureLoadedSync();
  for (const rec of _datasets.values()) rec.meta.active = 0;
}

function getActiveDataset() {
  _ensureLoadedSync();
  const recs = [..._datasets.values()].filter((r) => r.meta.active === 1);
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs[0] ? recs[0].meta : undefined;
}

function getDatasetById(id) {
  _ensureLoadedSync();
  const rec = _datasets.get(id);
  return rec ? rec.meta : undefined;
}

function latestDataset() {
  _ensureLoadedSync();
  const recs = [..._datasets.values()];
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs[0] ? recs[0].meta : undefined;
}

function resolveDataset(id) {
  if (id) return getDatasetById(id);
  return getActiveDataset() || latestDataset();
}

function allDatasetsMeta() {
  _ensureLoadedSync();
  const recs = [..._datasets.values()];
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs.map((r) => r.meta);
}

function getRecord(id) {
  _ensureLoadedSync();
  return _datasets.get(id);
}

function hasSeed() {
  _ensureLoadedSync();
  for (const r of _datasets.values()) if (r.meta.source === 'seed') return true;
  return false;
}

function setActive(id) {
  _ensureLoadedSync();
  if (!_datasets.has(id)) return false;
  for (const rec of _datasets.values()) rec.meta.active = 0;
  _datasets.get(id).meta.active = 1;
  // fire the durable save; route awaits saveSnapshot() separately for safety.
  saveSnapshot();
  return true;
}

function isUp() {
  return true; // in-memory store is always available
}

function size() {
  _ensureLoadedSync();
  return _datasets.size;
}

function backend() {
  return supabaseEnabled() ? 'supabase' : 'disk';
}

module.exports = {
  ensureLoaded,
  saveSnapshot,
  putDataset,
  clearActive,
  deactivateAllInMemory,
  getActiveDataset,
  getDatasetById,
  latestDataset,
  resolveDataset,
  allDatasetsMeta,
  getRecord,
  hasSeed,
  setActive,
  isUp,
  size,
  backend,
  supabaseEnabled,
  DB_PATH, // exposed for diagnostics
};
