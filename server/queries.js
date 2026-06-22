'use strict';
// queries.js — read helpers (datasets, incidents, metrics) from SQLite.

const { db, prep } = require('./db');

function getActiveDataset() {
  return prep('SELECT * FROM datasets WHERE active=1 ORDER BY created_at DESC LIMIT 1').get();
}
function getDatasetById(id) {
  return prep('SELECT * FROM datasets WHERE id=?').get(id);
}
function resolveDataset(id) {
  if (id) return getDatasetById(id);
  return getActiveDataset() || prep('SELECT * FROM datasets ORDER BY created_at DESC LIMIT 1').get();
}

function listDatasets() {
  const rows = prep('SELECT * FROM datasets ORDER BY created_at DESC').all();
  return rows.map((d) => ({
    id: d.id,
    name: d.name,
    source: d.source,
    eventCount: d.event_count,
    userCount: d.user_count,
    incidentCount: d.incident_count,
    hasGroundTruth: !!d.has_ground_truth,
    createdAt: d.created_at,
    active: !!d.active,
  }));
}

function datasetSummary(d) {
  const rows = prep('SELECT priority_color c, COUNT(*) n FROM incidents WHERE dataset_id=? GROUP BY priority_color').all(d.id);
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const r of rows) {
    if (r.c === 'crit') summary.critical = r.n;
    else if (r.c === 'bad') summary.high = r.n;
    else if (r.c === 'warn') summary.medium = r.n;
    else summary.low = r.n;
  }
  return summary;
}

function datasetDetail(d) {
  const summary = datasetSummary(d);
  // heroStat: threats flagged illicit. If ground-truth -> labeled malicious; else score-based (>=55)
  let threats;
  if (d.has_ground_truth) {
    threats = prep('SELECT COUNT(*) n FROM incidents WHERE dataset_id=? AND label_malicious=1').get(d.id).n;
  } else {
    threats = prep('SELECT COUNT(*) n FROM incidents WHERE dataset_id=? AND score>=55').get(d.id).n;
  }
  return {
    id: d.id,
    name: d.name,
    source: d.source,
    createdAt: d.created_at,
    active: !!d.active,
    eventCount: d.event_count,
    userCount: d.user_count,
    dayCount: d.day_count,
    resourceCount: d.resource_count,
    hostCount: d.host_count,
    incidentCount: d.incident_count,
    hasGroundTruth: !!d.has_ground_truth,
    summary,
    heroStat: { threats, critical: summary.critical },
    window: { from: d.window_from, to: d.window_to },
    baselineNote:
      'baseline вычислен из истории каждого пользователя (avg rows/day, типичные часы, известные ресурсы/хосты)',
  };
}

const PRIMARY_TRIGGER_LABEL = {
  VOLUME_ANOMALY: 'Объём',
  VOLUME_SOFT: 'Объём (мягко)',
  LATERAL_MOVEMENT: 'Боковое движение',
  BROAD_ACCESS: 'Широкий доступ',
  SENSITIVE_ACCESS: 'Вне профиля',
  BULK_EXFIL: 'Выгрузка',
  OFF_HOURS_VELOCITY: 'Вне часов',
  PRIV_ESCALATION: 'Эскалация',
  COMPROMISE_INDICATORS: 'Компрометация',
  STAGING_EXFIL: 'Стейджинг',
  COVERT_CHANNEL: 'Скрытый канал',
};

function listIncidents(d, opts = {}) {
  const where = ['dataset_id=@ds'];
  const params = { ds: d.id };
  if (opts.minScore != null) { where.push('score>=@minScore'); params.minScore = opts.minScore; }
  if (opts.priority) { where.push('priority_color=@prio'); params.prio = opts.priority; }
  if (opts.typology) { where.push('typology=@typ'); params.typ = opts.typology; }
  const limit = opts.limit != null ? Math.max(1, Math.min(5000, opts.limit)) : 1000;
  const offset = opts.offset != null ? Math.max(0, opts.offset) : 0;

  const total = prep(`SELECT COUNT(*) n FROM incidents WHERE ${where.join(' AND ')}`).get(params).n;
  const rows = db
    .prepare(`SELECT * FROM incidents WHERE ${where.join(' AND ')} ORDER BY score DESC LIMIT ${limit} OFFSET ${offset}`)
    .all(params);

  const incidents = rows.map((r) => {
    const top = prep('SELECT code,label FROM incident_factors WHERE incident_id=? ORDER BY rank LIMIT 1').get(r.id);
    const out = {
      id: r.id,
      user: r.user,
      role: r.role,
      typology: r.typology,
      title: r.title,
      channel: r.channel,
      score: r.score,
      priority: { lvl: r.priority_lvl, color: r.priority_color, note: r.priority_note },
      primaryTrigger: top
        ? { code: top.code, label: PRIMARY_TRIGGER_LABEL[top.code] || top.label }
        : null,
      windowDate: r.window_date,
      rowsTouched: r.rows_touched,
      eventCount: r.event_count,
    };
    if (d.has_ground_truth && r.label_malicious != null) {
      out.label = { malicious: r.label_malicious === 1, typology: r.label_typology };
    }
    return out;
  });

  return { datasetId: d.id, total, incidents };
}

function incidentDetail(d, id) {
  const r = prep('SELECT * FROM incidents WHERE dataset_id=? AND id=?').get(d.id, id);
  if (!r) return null;
  const factors = prep('SELECT code,label,weight,contribution,detail,severity,rank FROM incident_factors WHERE incident_id=? ORDER BY rank').all(id);
  const edgeRows = prep('SELECT from_id,to_id,node_kind_from,node_kind_to,action,rows,ts,channel,crit FROM incident_edges WHERE incident_id=? ORDER BY ts').all(id);
  const graphMeta = JSON.parse(r.graph_json);
  const baseline = JSON.parse(r.baseline_json);
  const observed = JSON.parse(r.observed_json);
  const related = r.related_json ? JSON.parse(r.related_json) : [];
  const playbook = r.playbook_json ? JSON.parse(r.playbook_json) : [];

  const triggers = factors.map((f) => ({
    code: f.code,
    label: f.label,
    weight: f.weight,
    detail: f.detail,
    severity: f.severity,
  }));
  const shap = factors.map((f) => ({
    code: f.code,
    label: f.label,
    severity: f.severity,
    contribution: f.contribution,
  }));
  const edges = edgeRows.map((e) => ({
    from: e.from_id,
    to: e.to_id,
    action: e.action,
    rows: e.rows,
    ts: e.ts,
    channel: e.channel,
    crit: !!e.crit,
  }));

  const out = {
    id: r.id,
    datasetId: r.dataset_id,
    user: r.user,
    role: r.role,
    typology: r.typology,
    title: r.title,
    channel: r.channel,
    windowDate: r.window_date,
    score: r.score,
    priority: { lvl: r.priority_lvl, color: r.priority_color, note: r.priority_note },
    baseline: {
      avg_rows_per_day: baseline.avg_rows_per_day,
      work_hours: baseline.work_hours,
      known_resources: baseline.known_resources,
      known_hosts: baseline.known_hosts,
      home_geo: baseline.home_geo,
      dayCountObserved: baseline.dayCountObserved,
      established: baseline.established,
      volume_cv: baseline.volume_cv,
      source: 'computed-from-history',
    },
    observed,
    triggers,
    shap,
    mitigation:
      r.mitigation_factor != null ? { factor: r.mitigation_factor, note: r.mitigation_note } : null,
    graph: {
      nodes: graphMeta.nodes,
      edges,
      hub: graphMeta.hub,
      cycle: graphMeta.cycle || null,
    },
    related,
    playbook,
  };
  if (d.has_ground_truth && r.label_malicious != null) {
    out.label = { malicious: r.label_malicious === 1, typology: r.label_typology };
  }
  return out;
}

// METRICS — confusion / precision / recall / f1 / accuracy / AUPRC + naive-DLP,
// recomputed from stored incident scores+labels at a what-if threshold. No engine rerun.
function metrics(d, threshold = 55) {
  const out = {
    datasetId: d.id,
    hasGroundTruth: !!d.has_ground_truth,
    threshold,
    corpus: {
      total: 0,
      illicit: 0,
      benign: 0,
      eventCount: d.event_count,
      userCount: d.user_count,
      dayCount: d.day_count,
    },
  };

  // all scored user-days = incidents (score>0) + clean labeled days (score 0)
  const incs = prep('SELECT score, label_malicious, event_count FROM incidents WHERE dataset_id=?').all(d.id);
  const cleans = prep('SELECT label_malicious FROM clean_user_days WHERE dataset_id=?').all(d.id);

  if (!d.has_ground_truth) {
    // no labels — only score distribution + corpus stats
    const dist = { p1: 0, p2: 0, p3: 0, p4: 0 };
    for (const i of incs) {
      if (i.score >= 80) dist.p1++;
      else if (i.score >= 55) dist.p2++;
      else if (i.score >= 30) dist.p3++;
      else dist.p4++;
    }
    out.corpus.total = incs.length + cleans.length;
    out.confusion = null;
    out.quality = null;
    out.naive = null;
    out.scoreDistribution = dist;
    out.incidentCount = incs.length;
    out.note =
      'Загруженный лог без ground-truth — показаны только объёмные статистики и распределение score (метрики качества требуют меток).';
    return out;
  }

  // labeled corpus: combine
  const labeled = [
    ...incs.filter((i) => i.label_malicious != null).map((i) => ({ score: i.score, bad: i.label_malicious === 1 })),
    ...cleans.filter((c) => c.label_malicious != null).map((c) => ({ score: 0, bad: c.label_malicious === 1 })),
  ];
  const total = labeled.length;
  const illicit = labeled.filter((x) => x.bad).length;
  const benign = total - illicit;

  let TP = 0, FP = 0, FN = 0, TN = 0;
  for (const x of labeled) {
    const flagged = x.score >= threshold;
    if (flagged && x.bad) TP++;
    else if (flagged && !x.bad) FP++;
    else if (!flagged && x.bad) FN++;
    else TN++;
  }
  const precision = TP + FP ? TP / (TP + FP) : 1;
  const recall = TP + FN ? TP / (TP + FN) : 1;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = total ? (TP + TN) / total : 0;
  const alertsShown = TP + FP;

  // recall@top-N (N = #illicit): among top-N by score, how many illicit
  const ranked = labeled.slice().sort((a, b) => b.score - a.score);
  const topN = ranked.slice(0, illicit);
  const hitsTopN = topN.filter((x) => x.bad).length;
  const recallTopN = illicit ? Math.round((hitsTopN / illicit) * 100) : 100;

  // AUPRC by score ranking
  let auprc = 0;
  if (illicit) {
    let tp = 0, fp = 0, prevRecall = 0;
    for (const x of ranked) {
      if (x.bad) tp++;
      else fp++;
      const rec = tp / illicit;
      const prec = tp + fp ? tp / (tp + fp) : 1;
      auprc += prec * (rec - prevRecall);
      prevRecall = rec;
    }
  } else auprc = 1;

  // naive perimeter-DLP baseline on the SAME corpus: a crude rule with NO
  // personal baseline — flag any user-day whose raw read volume >= NAIVE_VOLUME
  // OR event count >= NAIVE_EVENTS. This is the kind of rule that drowns a SOC
  // in false positives (it cannot tell a legit large-volume ETL/audit from an
  // insider) and misses quiet insiders (lateral/priv-esc whose raw numbers are
  // small). Computed over the labeled user-days we have stats for (the planted
  // benign hard-negatives surface here as naive FPs — which is the point).
  const NAIVE_VOLUME = 30000;
  const NAIVE_EVENTS = 5;
  const incRich = prep('SELECT rows_touched, event_count, label_malicious FROM incidents WHERE dataset_id=? AND label_malicious IS NOT NULL').all(d.id);
  let naiveTP = 0, naiveFP = 0, naiveFN = 0;
  // incidents (have activity)
  for (const i of incRich) {
    const flagged = i.rows_touched >= NAIVE_VOLUME || i.event_count >= NAIVE_EVENTS;
    const bad = i.label_malicious === 1;
    if (flagged && bad) naiveTP++;
    else if (flagged && !bad) naiveFP++;
    else if (!flagged && bad) naiveFN++;
  }
  // labeled clean days never trip naive (rows 0, events 0); malicious clean days (none here) would be FN
  for (const c of cleans.filter((c) => c.label_malicious != null)) {
    if (c.label_malicious === 1) naiveFN++;
  }
  const naiveAlerts = naiveTP + naiveFP;
  const reduction = naiveFP > 0 ? Math.max(0, Math.round((1 - FP / naiveFP) * 100)) : 0;

  out.corpus.total = total;
  out.corpus.illicit = illicit;
  out.corpus.benign = benign;
  out.confusion = { TP, FP, FN, TN };
  out.quality = {
    precision: round3(precision),
    recall: round3(recall),
    f1: round3(f1),
    accuracy: round3(accuracy),
    auprc: round3(auprc),
    recallTopN,
    alertsShown,
  };
  out.naive = { naiveTP, naiveFP, naiveFN, naiveAlerts, reduction };
  out.note = null;
  return out;
}

function round3(n) {
  return Math.round(n * 1000) / 1000;
}

module.exports = {
  getActiveDataset,
  getDatasetById,
  resolveDataset,
  listDatasets,
  datasetDetail,
  datasetSummary,
  listIncidents,
  incidentDetail,
  metrics,
};
