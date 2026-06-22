'use strict';
// persist.js — run the engine and store a dataset (computed incidents) into the
// in-memory store. Shared by bootstrap/seed and the /api/ingest route. Pure JS,
// no native DB — incidents are kept as the engine's rich objects (plus _id/_seq
// and data-driven cross-links), so queries.js reads them directly.

const { nanoid } = require('nanoid');
const store = require('./store');
const { detect, ENGINE_VERSION } = require('./engine');

/**
 * persistDataset — full pipeline.
 * @param {Object} args { name, source, events, hasGroundTruth, activate }
 * @returns summary object (datasetId, counts, summary, durationMs, incidentCount)
 */
function persistDataset({ name, source, events, hasGroundTruth, activate = true }) {
  const result = detect(events, {});
  const { incidents, cleanUserDays, meta } = result;

  const datasetId = 'ds_' + nanoid(10);
  const nowIso = new Date().toISOString();

  // 2nd pass: data-driven cross-links. A host/ip appearing in >=2 incidents,
  // OR a covert channel re-used, bridges incidents (CROSS_TAGS idea).
  const markerToIncidents = new Map(); // marker -> [incidentIdx]
  incidents.forEach((inc, i) => {
    const m = inc._markers || {};
    const markers = [
      ...(m.compromise ? m.hosts.map((h) => 'host:' + h) : []),
      ...(m.compromise ? m.ips.map((ip) => 'ip:' + ip) : []),
      ...(m.covertChannels || []).map((c) => 'chan:' + c),
    ];
    for (const k of markers) {
      if (!markerToIncidents.has(k)) markerToIncidents.set(k, []);
      markerToIncidents.get(k).push(i);
    }
  });

  // assign stable, GLOBALLY-UNIQUE incident ids. Display sequence is dataset-
  // scoped (INC-0001..), the id is suffixed with the dataset's short id.
  const dsSuffix = datasetId.replace(/^ds_/, '');
  incidents.forEach((inc, i) => {
    inc._seq = `INC-${String(i + 1).padStart(4, '0')}`;
    inc._id = `${inc._seq}-${dsSuffix}`;
  });

  const relatedByIdx = incidents.map(() => new Map());
  for (const [, idxs] of markerToIncidents.entries()) {
    if (idxs.length < 2) continue;
    for (const a of idxs)
      for (const b of idxs)
        if (a !== b) relatedByIdx[a].set(incidents[b]._id, incidents[b].title);
  }

  // attach related-links + label flags onto each incident for direct serving
  incidents.forEach((inc, i) => {
    inc._related = [...relatedByIdx[i].entries()].map(([rid, title]) => ({ id: rid, title }));
  });

  // priority summary
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) {
    if (inc.priority.color === 'crit') summary.critical++;
    else if (inc.priority.color === 'bad') summary.high++;
    else if (inc.priority.color === 'warn') summary.medium++;
    else summary.low++;
  }

  const datasetMeta = {
    id: datasetId,
    name,
    source,
    has_ground_truth: hasGroundTruth ? 1 : 0,
    event_count: meta.eventCount,
    user_count: meta.userCount,
    day_count: meta.dayCount,
    resource_count: meta.resourceCount,
    host_count: meta.hostCount,
    incident_count: incidents.length,
    active: activate ? 1 : 0,
    window_from: meta.window.from,
    window_to: meta.window.to,
    created_at: nowIso,
  };

  if (activate) store.clearActive();

  store.putDataset({
    meta: datasetMeta,
    incidents,
    incidentsById: new Map(incidents.map((inc) => [inc._id, inc])),
    cleanUserDays: cleanUserDays.map((c) => ({
      user: c.user,
      day: c.day,
      score: 0,
      label: c.label || null,
    })),
    runMeta: {
      engine_version: ENGINE_VERSION,
      config: meta.config,
      duration_ms: meta.durationMs,
      created_at: nowIso,
    },
  });

  return {
    datasetId,
    name,
    eventCount: meta.eventCount,
    userCount: meta.userCount,
    dayCount: meta.dayCount,
    resourceCount: meta.resourceCount,
    hostCount: meta.hostCount,
    incidentCount: incidents.length,
    hasGroundTruth,
    durationMs: meta.durationMs,
    summary,
    window: meta.window,
  };
}

module.exports = { persistDataset };
