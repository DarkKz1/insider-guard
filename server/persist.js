'use strict';
// persist.js — write a dataset (events + computed incidents) into SQLite.
// Shared by seed.js and the /api/ingest route. Runs the engine, persists
// incidents/factors/edges/clean-days/run_meta in a single transaction.

const { nanoid } = require('nanoid');
const { db, prep } = require('./db');
const { detect, ENGINE_VERSION } = require('./engine');

const insDataset = () =>
  prep(`INSERT INTO datasets
    (id,name,source,has_ground_truth,event_count,user_count,day_count,resource_count,host_count,incident_count,active,window_from,window_to,created_at)
    VALUES (@id,@name,@source,@has_ground_truth,@event_count,@user_count,@day_count,@resource_count,@host_count,@incident_count,@active,@window_from,@window_to,@created_at)`);

const insEvent = () =>
  prep(`INSERT INTO events
    (dataset_id,user,role,resource,db,host,ip,geo,action,rows,ts,ts_day,ts_hour,channel,edge_from,edge_to,label_malicious,label_typology)
    VALUES (@dataset_id,@user,@role,@resource,@db,@host,@ip,@geo,@action,@rows,@ts,@ts_day,@ts_hour,@channel,@edge_from,@edge_to,@label_malicious,@label_typology)`);

const insIncident = () =>
  prep(`INSERT INTO incidents
    (id,dataset_id,user,role,typology,title,channel,window_date,score,priority_lvl,priority_color,priority_note,
     rows_touched,event_count,mitigation_factor,mitigation_note,cycle_json,baseline_json,observed_json,graph_json,
     playbook_json,label_malicious,label_typology,markers_json,related_json)
    VALUES (@id,@dataset_id,@user,@role,@typology,@title,@channel,@window_date,@score,@priority_lvl,@priority_color,@priority_note,
     @rows_touched,@event_count,@mitigation_factor,@mitigation_note,@cycle_json,@baseline_json,@observed_json,@graph_json,
     @playbook_json,@label_malicious,@label_typology,@markers_json,@related_json)`);

const insFactor = () =>
  prep(`INSERT INTO incident_factors
    (incident_id,code,label,weight,contribution,detail,severity,rank)
    VALUES (@incident_id,@code,@label,@weight,@contribution,@detail,@severity,@rank)`);

const insEdge = () =>
  prep(`INSERT INTO incident_edges
    (incident_id,from_id,to_id,node_kind_from,node_kind_to,action,rows,ts,channel,crit)
    VALUES (@incident_id,@from_id,@to_id,@node_kind_from,@node_kind_to,@action,@rows,@ts,@channel,@crit)`);

const insClean = () =>
  prep(`INSERT INTO clean_user_days
    (dataset_id,user,window_date,score,label_malicious,event_count,rows_touched)
    VALUES (@dataset_id,@user,@window_date,@score,@label_malicious,@event_count,@rows_touched)`);

const insRunMeta = () =>
  prep(`INSERT INTO run_meta (dataset_id,engine_version,config_json,duration_ms,created_at)
    VALUES (@dataset_id,@engine_version,@config_json,@duration_ms,@created_at)`);

const updIncidentCount = () =>
  prep(`UPDATE datasets SET incident_count=@n WHERE id=@id`);
const updRelated = () => prep(`UPDATE incidents SET related_json=@related WHERE id=@id`);

const clearActive = () => prep(`UPDATE datasets SET active=0`);

// node kind helper from graph nodes
function kindOf(graph, id) {
  const n = (graph.nodes || []).find((x) => x.id === id);
  return n ? n.kind : null;
}

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
  // assign stable, GLOBALLY-UNIQUE incident ids first. The display sequence is
  // dataset-scoped (INC-0001..), but the PK must be unique across datasets, so we
  // suffix with the dataset's short id (e.g. INC-0001-DsZRQ35ZoX).
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

  const tx = db.transaction(() => {
    if (activate) clearActive().run();

    // figure out covert-channel flag bump globally: a covert channel used in >=2
    // incidents would warrant a higher weight — but engine already scored per-day.
    // We keep the score as engine computed (auditable); cross-links are metadata.

    insDataset().run({
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
    });

    const eStmt = insEvent();
    for (const e of events) {
      eStmt.run({
        dataset_id: datasetId,
        user: e.user,
        role: e.role ?? null,
        resource: e.resource ?? null,
        db: e.db ?? null,
        host: e.host ?? null,
        ip: e.ip ?? null,
        geo: e.geo ?? null,
        action: e.action,
        rows: e.rows ?? 0,
        ts: e.ts,
        ts_day: e.ts_day || e.ts.slice(0, 10),
        ts_hour: e.ts_hour != null ? e.ts_hour : parseInt(e.ts.slice(11, 13), 10) || 0,
        channel: e.channel ?? null,
        edge_from: e.from ?? null,
        edge_to: e.to ?? null,
        label_malicious: e.label_malicious ?? null,
        label_typology: e.label_typology ?? null,
      });
    }

    const iStmt = insIncident();
    const fStmt = insFactor();
    const gStmt = insEdge();
    incidents.forEach((inc, i) => {
      const id = inc._id;
      iStmt.run({
        id,
        dataset_id: datasetId,
        user: inc.user,
        role: inc.role ?? null,
        typology: inc.typology,
        title: inc.title,
        channel: inc.channel ?? null,
        window_date: inc.windowDate,
        score: Number.isFinite(inc.score) ? inc.score : 0,
        priority_lvl: inc.priority.lvl,
        priority_color: inc.priority.color,
        priority_note: inc.priority.note,
        rows_touched: inc.rowsTouched,
        event_count: inc.eventCount,
        mitigation_factor: inc.mitigation ? inc.mitigation.factor : null,
        mitigation_note: inc.mitigation ? inc.mitigation.note : null,
        cycle_json: inc.graph.cycle ? JSON.stringify(inc.graph.cycle) : null,
        baseline_json: JSON.stringify(inc.baseline),
        observed_json: JSON.stringify(inc.observed),
        graph_json: JSON.stringify({ nodes: inc.graph.nodes, hub: inc.graph.hub, cycle: inc.graph.cycle }),
        playbook_json: JSON.stringify(inc.playbook || []),
        label_malicious: inc.label ? (inc.label.malicious ? 1 : 0) : null,
        label_typology: inc.label ? inc.label.typology : null,
        markers_json: JSON.stringify(inc._markers || {}),
        related_json: JSON.stringify(
          [...relatedByIdx[i].entries()].map(([rid, title]) => ({ id: rid, title }))
        ),
      });

      inc.shap.forEach((s, rank) => {
        fStmt.run({
          incident_id: id,
          code: s.code,
          label: s.label,
          weight: s.weight,
          contribution: s.contribution,
          detail: s.detail ?? null,
          severity: s.severity ?? null,
          rank,
        });
      });

      for (const e of inc.graph.edges) {
        gStmt.run({
          incident_id: id,
          from_id: e.from,
          to_id: e.to,
          node_kind_from: kindOf(inc.graph, e.from),
          node_kind_to: kindOf(inc.graph, e.to),
          action: e.action ?? null,
          rows: e.rows ?? 0,
          ts: e.ts ?? null,
          channel: e.channel ?? null,
          crit: e.crit ? 1 : 0,
        });
      }
    });

    // clean user-days (only persist labeled ones to keep table small but honest
    // for metrics; if no ground-truth, we still store a sample for distribution)
    const cStmt = insClean();
    for (const c of cleanUserDays) {
      // persist every clean day so corpus stats/score-distribution are honest
      cStmt.run({
        dataset_id: datasetId,
        user: c.user,
        window_date: c.day,
        score: 0,
        label_malicious: c.label ? (c.label.malicious ? 1 : 0) : null,
        event_count: 0,
        rows_touched: 0,
      });
    }

    insRunMeta().run({
      dataset_id: datasetId,
      engine_version: ENGINE_VERSION,
      config_json: JSON.stringify(meta.config),
      duration_ms: meta.durationMs,
      created_at: nowIso,
    });

    updIncidentCount().run({ n: incidents.length, id: datasetId });
  });

  tx();

  // summary by priority
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const inc of incidents) {
    if (inc.priority.color === 'crit') summary.critical++;
    else if (inc.priority.color === 'bad') summary.high++;
    else if (inc.priority.color === 'warn') summary.medium++;
    else summary.low++;
  }

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
