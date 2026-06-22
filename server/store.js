'use strict';
// store.js — pure-JS data store (NO native modules) with OPTIONAL on-disk
// persistence. Holds datasets and their computed incidents / clean-user-days /
// run-meta as plain JS objects, keyed by datasetId.
//
// Persistence (added for long-lived hosts like Railway with a mounted volume):
//   - DB_PATH env (default ./data/store.json) points at a JSON snapshot file.
//   - On first use the store auto-loads that file if it exists (datasets +
//     active flags survive process restarts). If it does NOT exist, the store
//     stays empty and bootstrap.js seeds it (which triggers a save).
//   - Every mutation (putDataset / clearActive / setActive) saves atomically
//     (write temp + rename) so a crash mid-write never corrupts the snapshot.
//   - Graceful degradation: on a read-only / ephemeral filesystem (Vercel,
//     where /tmp or /data is not writable) a failed write is WARNED once and
//     the store keeps working purely in-memory. The process never crashes on a
//     persistence error — persistence is best-effort, correctness is in RAM.
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

let _loaded = false; // have we attempted to load the snapshot yet?
let _persistDisabled = false; // turned on after a write failure (warn once)

// --- persistence: load ---------------------------------------------------

function _rebuildIndex(rec) {
  // incidentsById is derived from incidents (_id). Rebuild it after load so
  // queries.js (rec.incidentsById.get(id)) works without a SQLite round-trip.
  rec.incidentsById = new Map((rec.incidents || []).map((inc) => [inc._id, inc]));
  return rec;
}

function _loadFromDisk() {
  if (_loaded) return;
  _loaded = true;
  try {
    if (!fs.existsSync(DB_PATH)) return; // no snapshot yet -> stay empty, will seed
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    if (!raw.trim()) return;
    const parsed = JSON.parse(raw);
    const records = Array.isArray(parsed) ? parsed : parsed.datasets || [];
    for (const rec of records) {
      if (!rec || !rec.meta || !rec.meta.id) continue;
      _datasets.set(rec.meta.id, _rebuildIndex(rec));
    }
    // eslint-disable-next-line no-console
    console.log(`[store] loaded ${_datasets.size} dataset(s) from ${DB_PATH}`);
  } catch (e) {
    // Corrupt / partial snapshot: do not crash. Start empty so seed can repair.
    // eslint-disable-next-line no-console
    console.warn(`[store] could not load snapshot ${DB_PATH}: ${e.message} — starting empty`);
    _datasets.clear();
  }
}

// --- persistence: save (atomic, best-effort) -----------------------------

function _serialize() {
  // strip the derived Map (incidentsById) — it is rebuilt on load.
  const datasets = [..._datasets.values()].map((rec) => ({
    meta: rec.meta,
    incidents: rec.incidents,
    cleanUserDays: rec.cleanUserDays,
    runMeta: rec.runMeta,
  }));
  return JSON.stringify({ version: 1, savedAt: new Date().toISOString(), datasets });
}

function _saveToDisk() {
  if (_persistDisabled) return; // already known read-only — skip, stay in-memory
  let json;
  try {
    json = _serialize();
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn(`[store] serialize failed: ${e.message} — running in-memory only`);
    _persistDisabled = true;
    return;
  }
  try {
    const dir = path.dirname(DB_PATH);
    fs.mkdirSync(dir, { recursive: true });
    // atomic: write to a temp file in the SAME dir, then rename over the target.
    // rename is atomic on POSIX so a crash mid-write cannot truncate the snapshot.
    const tmp = path.join(dir, `.store.${process.pid}.${Date.now()}.tmp`);
    fs.writeFileSync(tmp, json);
    fs.renameSync(tmp, DB_PATH);
  } catch (e) {
    // Read-only / ephemeral FS (e.g. Vercel /data, /var/task). Warn ONCE and
    // continue purely in-memory — never crash on a persistence failure.
    if (!_persistDisabled) {
      // eslint-disable-next-line no-console
      console.warn(
        `[store] persist to ${DB_PATH} failed (${e.code || e.message}) — continuing in-memory only (no volume?).`,
      );
    }
    _persistDisabled = true;
  }
}

// --- store API (signatures unchanged from the in-memory-only version) ----

function putDataset(rec) {
  _loadFromDisk();
  _datasets.set(rec.meta.id, rec);
  _saveToDisk();
}

function clearActive() {
  _loadFromDisk();
  for (const rec of _datasets.values()) rec.meta.active = 0;
  _saveToDisk();
}

function getActiveDataset() {
  _loadFromDisk();
  const recs = [..._datasets.values()].filter((r) => r.meta.active === 1);
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs[0] ? recs[0].meta : undefined;
}

function getDatasetById(id) {
  _loadFromDisk();
  const rec = _datasets.get(id);
  return rec ? rec.meta : undefined;
}

function latestDataset() {
  _loadFromDisk();
  const recs = [..._datasets.values()];
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs[0] ? recs[0].meta : undefined;
}

function resolveDataset(id) {
  if (id) return getDatasetById(id);
  return getActiveDataset() || latestDataset();
}

function allDatasetsMeta() {
  _loadFromDisk();
  const recs = [..._datasets.values()];
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs.map((r) => r.meta);
}

function getRecord(id) {
  _loadFromDisk();
  return _datasets.get(id);
}

function hasSeed() {
  _loadFromDisk();
  for (const r of _datasets.values()) if (r.meta.source === 'seed') return true;
  return false;
}

function setActive(id) {
  _loadFromDisk();
  if (!_datasets.has(id)) return false;
  for (const rec of _datasets.values()) rec.meta.active = 0;
  _datasets.get(id).meta.active = 1;
  _saveToDisk();
  return true;
}

function isUp() {
  return true; // in-memory store is always available
}

function size() {
  _loadFromDisk();
  return _datasets.size;
}

module.exports = {
  putDataset,
  clearActive,
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
  DB_PATH, // exposed for diagnostics
};
