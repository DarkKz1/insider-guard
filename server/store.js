'use strict';
// store.js — pure-JS in-memory data store (NO native modules). Replaces the
// SQLite layer for serverless reliability. Holds datasets and their computed
// incidents / clean-user-days / run-meta as plain JS objects. Process-local:
// on a warm serverless instance it persists across requests; a cold start (or
// `npm start`) begins empty and is re-seeded by bootstrap.js.
//
// Engine output (rich incident objects) is stored as-is, so no flatten/reparse
// round-trip is needed — queries read straight from the in-memory objects.

// datasetId -> {
//   meta: { id,name,source,has_ground_truth,event_count,user_count,day_count,
//           resource_count,host_count,incident_count,active,window_from,window_to,created_at },
//   incidents: [ <enriched engine incident, with _id/_seq/related/markers> ],
//   incidentsById: Map(_id -> incident),
//   cleanUserDays: [ {user,day,score,label} ],
//   runMeta: { engine_version, config, duration_ms, created_at },
// }
const _datasets = new Map();

function putDataset(rec) {
  _datasets.set(rec.meta.id, rec);
}

function clearActive() {
  for (const rec of _datasets.values()) rec.meta.active = 0;
}

function getActiveDataset() {
  const recs = [..._datasets.values()].filter((r) => r.meta.active === 1);
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs[0] ? recs[0].meta : undefined;
}

function getDatasetById(id) {
  const rec = _datasets.get(id);
  return rec ? rec.meta : undefined;
}

function latestDataset() {
  const recs = [..._datasets.values()];
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs[0] ? recs[0].meta : undefined;
}

function resolveDataset(id) {
  if (id) return getDatasetById(id);
  return getActiveDataset() || latestDataset();
}

function allDatasetsMeta() {
  const recs = [..._datasets.values()];
  recs.sort((a, b) => (a.meta.created_at < b.meta.created_at ? 1 : -1));
  return recs.map((r) => r.meta);
}

function getRecord(id) {
  return _datasets.get(id);
}

function hasSeed() {
  for (const r of _datasets.values()) if (r.meta.source === 'seed') return true;
  return false;
}

function setActive(id) {
  if (!_datasets.has(id)) return false;
  clearActive();
  _datasets.get(id).meta.active = 1;
  return true;
}

function isUp() {
  return true; // in-memory store is always available
}

function size() {
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
};
