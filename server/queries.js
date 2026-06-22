'use strict';
// queries.js — read helpers (datasets, incidents, metrics) from the in-memory
// store. Same exported signatures + output shapes as the prior SQLite version,
// so the route layer and frontend contract are unchanged.

const store = require('./store');

function getActiveDataset() {
  return store.getActiveDataset();
}
function getDatasetById(id) {
  return store.getDatasetById(id);
}
function resolveDataset(id) {
  return store.resolveDataset(id);
}

function listDatasets() {
  return store.allDatasetsMeta().map((d) => ({
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
  const rec = store.getRecord(d.id);
  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  if (!rec) return summary;
  for (const inc of rec.incidents) {
    if (inc.priority.color === 'crit') summary.critical++;
    else if (inc.priority.color === 'bad') summary.high++;
    else if (inc.priority.color === 'warn') summary.medium++;
    else summary.low++;
  }
  return summary;
}

function datasetDetail(d) {
  const summary = datasetSummary(d);
  const rec = store.getRecord(d.id);
  const incs = rec ? rec.incidents : [];
  // heroStat: threats flagged illicit. If ground-truth -> labeled malicious; else score-based (>=55)
  let threats;
  if (d.has_ground_truth) {
    threats = incs.filter((i) => i.label && i.label.malicious).length;
  } else {
    threats = incs.filter((i) => i.score >= 55).length;
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
  const rec = store.getRecord(d.id);
  let incs = rec ? rec.incidents.slice() : [];

  if (opts.minScore != null) incs = incs.filter((i) => i.score >= opts.minScore);
  if (opts.priority) incs = incs.filter((i) => i.priority.color === opts.priority);
  if (opts.typology) incs = incs.filter((i) => i.typology === opts.typology);

  // sort by score desc (engine already sorted, but re-sort after filters)
  incs.sort((a, b) => b.score - a.score);

  const total = incs.length;
  const limit = opts.limit != null ? Math.max(1, Math.min(5000, opts.limit)) : 1000;
  const offset = opts.offset != null ? Math.max(0, opts.offset) : 0;
  const page = incs.slice(offset, offset + limit);

  const incidents = page.map((inc) => {
    const top = (inc.shap && inc.shap[0]) || null;
    const out = {
      id: inc._id,
      user: inc.user,
      role: inc.role ?? null,
      typology: inc.typology,
      title: inc.title,
      channel: inc.channel ?? null,
      score: Number.isFinite(inc.score) ? inc.score : 0,
      priority: { lvl: inc.priority.lvl, color: inc.priority.color, note: inc.priority.note },
      primaryTrigger: top
        ? { code: top.code, label: PRIMARY_TRIGGER_LABEL[top.code] || top.label }
        : null,
      windowDate: inc.windowDate,
      rowsTouched: inc.rowsTouched,
      eventCount: inc.eventCount,
    };
    if (d.has_ground_truth && inc.label != null) {
      out.label = { malicious: !!inc.label.malicious, typology: inc.label.typology };
    }
    return out;
  });

  return { datasetId: d.id, total, incidents };
}

function incidentDetail(d, id) {
  const rec = store.getRecord(d.id);
  if (!rec) return null;
  const inc = rec.incidentsById.get(id);
  if (!inc) return null;

  const triggers = (inc.triggers || []).map((f) => ({
    code: f.code,
    label: f.label,
    weight: f.weight,
    detail: f.detail ?? null,
    severity: f.severity ?? null,
  }));
  const shap = (inc.shap || []).map((f) => ({
    code: f.code,
    label: f.label,
    severity: f.severity ?? null,
    contribution: f.contribution,
  }));
  const edges = (inc.graph.edges || []).map((e) => ({
    from: e.from,
    to: e.to,
    action: e.action ?? null,
    rows: e.rows ?? 0,
    ts: e.ts ?? null,
    channel: e.channel ?? null,
    crit: !!e.crit,
  }));

  const baseline = inc.baseline || {};
  const out = {
    id: inc._id,
    datasetId: d.id,
    user: inc.user,
    role: inc.role ?? null,
    typology: inc.typology,
    title: inc.title,
    channel: inc.channel ?? null,
    windowDate: inc.windowDate,
    score: inc.score,
    priority: { lvl: inc.priority.lvl, color: inc.priority.color, note: inc.priority.note },
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
    observed: inc.observed,
    triggers,
    shap,
    mitigation: inc.mitigation
      ? { factor: inc.mitigation.factor, note: inc.mitigation.note }
      : null,
    graph: {
      nodes: inc.graph.nodes,
      edges,
      hub: inc.graph.hub,
      cycle: inc.graph.cycle || null,
    },
    related: inc._related || [],
    playbook: inc.playbook || [],
  };
  if (d.has_ground_truth && inc.label != null) {
    out.label = { malicious: !!inc.label.malicious, typology: inc.label.typology };
  }
  return out;
}

// METRICS — confusion / precision / recall / f1 / accuracy / AUPRC + naive-DLP,
// recomputed from stored incident scores+labels at a what-if threshold.
function metrics(d, threshold = 55) {
  const rec = store.getRecord(d.id);
  const incsAll = rec ? rec.incidents : [];
  const cleansAll = rec ? rec.cleanUserDays : [];

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

  const incs = incsAll.map((i) => ({
    score: i.score,
    label_malicious: i.label ? (i.label.malicious ? 1 : 0) : null,
    event_count: i.eventCount,
    rows_touched: i.rowsTouched,
  }));
  const cleans = cleansAll.map((c) => ({
    label_malicious: c.label ? (c.label.malicious ? 1 : 0) : null,
  }));

  if (!d.has_ground_truth) {
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

  const ranked = labeled.slice().sort((a, b) => b.score - a.score);
  const topN = ranked.slice(0, illicit);
  const hitsTopN = topN.filter((x) => x.bad).length;
  const recallTopN = illicit ? Math.round((hitsTopN / illicit) * 100) : 100;

  let auprc = 0;
  if (illicit) {
    let tp = 0, fp = 0, prevRecall = 0;
    for (const x of ranked) {
      if (x.bad) tp++;
      else fp++;
      const rec2 = tp / illicit;
      const prec = tp + fp ? tp / (tp + fp) : 1;
      auprc += prec * (rec2 - prevRecall);
      prevRecall = rec2;
    }
  } else auprc = 1;

  // naive perimeter-DLP baseline on the SAME corpus.
  const NAIVE_VOLUME = 30000;
  const NAIVE_EVENTS = 5;
  const incRich = incs.filter((i) => i.label_malicious != null);
  let naiveTP = 0, naiveFP = 0, naiveFN = 0;
  for (const i of incRich) {
    const flagged = i.rows_touched >= NAIVE_VOLUME || i.event_count >= NAIVE_EVENTS;
    const bad = i.label_malicious === 1;
    if (flagged && bad) naiveTP++;
    else if (flagged && !bad) naiveFP++;
    else if (!flagged && bad) naiveFN++;
  }
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
