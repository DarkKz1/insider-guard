'use strict';
// contract-test.js — proves each endpoint returns the documented shape.
// Usage: npm start (in one shell) then `node server/contract-test.js`
// or set BASE=http://localhost:3000 (default).

const BASE = process.env.BASE || 'http://localhost:3000';

function assert(cond, msg) {
  if (!cond) throw new Error('FAIL: ' + msg);
  console.log('  ok:', msg);
}

async function j(method, path, body, isForm) {
  const opts = { method, headers: {} };
  if (body && !isForm) {
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  } else if (isForm) {
    opts.body = body;
  }
  const r = await fetch(BASE + path, opts);
  const txt = await r.text();
  let data;
  try {
    data = JSON.parse(txt);
  } catch {
    data = txt;
  }
  return { status: r.status, data };
}

async function main() {
  console.log('contract test against', BASE);

  // health
  let r = await j('GET', '/api/health');
  assert(r.status === 200 && r.data.ok === true && r.data.db === 'up', 'GET /api/health ok');

  // dataset
  r = await j('GET', '/api/dataset');
  assert(r.status === 200 && r.data.id && r.data.eventCount > 0, 'GET /api/dataset has id+eventCount');
  assert(r.data.heroStat && typeof r.data.heroStat.threats === 'number', 'dataset.heroStat.threats');
  assert(r.data.summary && 'critical' in r.data.summary, 'dataset.summary');
  const dsId = r.data.id;

  // datasets list
  r = await j('GET', '/api/datasets');
  assert(r.status === 200 && Array.isArray(r.data.datasets) && r.data.datasets.length >= 1, 'GET /api/datasets list');

  // incidents
  r = await j('GET', '/api/incidents');
  assert(r.status === 200 && Array.isArray(r.data.incidents) && r.data.incidents.length > 0, 'GET /api/incidents list');
  const first = r.data.incidents[0];
  assert(first.id && typeof first.score === 'number' && first.priority && first.primaryTrigger, 'incident row shape');
  const incId = first.id;

  // incident detail
  r = await j('GET', '/api/incidents/' + incId);
  assert(r.status === 200 && r.data.id === incId, 'GET /api/incidents/:id');
  assert(r.data.baseline && r.data.baseline.source === 'computed-from-history', 'detail.baseline computed-from-history');
  assert(Array.isArray(r.data.shap) && r.data.shap.length >= 1, 'detail.shap present');
  const shapSum = r.data.shap.reduce((s, x) => s + x.contribution, 0);
  assert(shapSum === r.data.score, `SHAP sum (${shapSum}) === score (${r.data.score})`);
  assert(r.data.graph && Array.isArray(r.data.graph.nodes) && Array.isArray(r.data.graph.edges), 'detail.graph nodes+edges');
  assert(Array.isArray(r.data.playbook), 'detail.playbook');

  // metrics
  r = await j('GET', '/api/metrics?threshold=55');
  assert(r.status === 200 && r.data.confusion && r.data.quality, 'GET /api/metrics confusion+quality');
  assert(r.data.naive && typeof r.data.naive.reduction === 'number', 'metrics.naive.reduction');
  console.log('  metrics@55:', JSON.stringify({ confusion: r.data.confusion, precision: r.data.quality.precision, recall: r.data.quality.recall, auprc: r.data.quality.auprc, naive: r.data.naive }));

  // report (mock)
  r = await j('POST', '/api/report/' + incId, {});
  assert(r.status === 200 && r.data.mode === 'mock' && typeof r.data.text === 'string' && r.data.text.length > 50, 'POST /api/report/:id mock');

  // ingest (JSON body, small synthetic with a clear anomaly)
  const events = [];
  // 12 normal days for u1 (~100 rows/day) then a spike day
  for (let d = 1; d <= 12; d++) {
    const day = `2026-05-${String(d).padStart(2, '0')}`;
    events.push({ user: 'u1', role: 'analyst', resource: 'DB-A', db: 'a', host: 'WS1', ip: '10.0.0.1', geo: 'Астана', action: 'SELECT', rows: 100, ts: `${day}T10:00:00`, channel: 'db', label: 0 });
    events.push({ user: 'u1', role: 'analyst', resource: 'DB-A', db: 'a', host: 'WS1', ip: '10.0.0.1', geo: 'Астана', action: 'SELECT', rows: 120, ts: `${day}T11:00:00`, channel: 'db', label: 0 });
  }
  // anomaly day for u1: 50,000 rows at 02:00
  events.push({ user: 'u1', role: 'analyst', resource: 'DB-A', db: 'a', host: 'WS1', ip: '10.0.0.1', geo: 'Астана', action: 'SELECT', rows: 50000, ts: '2026-05-20T02:00:00', channel: 'db', label: 1 });
  r = await j('POST', '/api/ingest', { name: 'contract-test-upload', events });
  assert(r.status === 201 && r.data.datasetId && r.data.incidentCount >= 1, 'POST /api/ingest creates incidents');
  console.log('  ingest result:', JSON.stringify(r.data));
  const upId = r.data.datasetId;

  // verify the uploaded anomaly surfaced
  r = await j('GET', '/api/incidents?datasetId=' + upId);
  assert(r.status === 200 && r.data.incidents.some((i) => i.user === 'u1'), 'uploaded anomaly surfaced for u1');

  // reactivate seed
  r = await j('POST', '/api/dataset/' + dsId + '/activate', {});
  assert(r.status === 200 && r.data.ok === true, 'POST /api/dataset/:id/activate');

  console.log('\nALL CONTRACT TESTS PASSED');
}

main().catch((e) => {
  console.error(e.message || e);
  process.exit(1);
});
