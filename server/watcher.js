'use strict';
// watcher.js — REAL-TIME monitor. Polls the live DB source for new access
// events, re-runs the detection engine, and updates ONE live incident dataset
// in place. Driver-agnostic: SQLite (node:sqlite) by default, or PostgreSQL
// (pglite embedded / pg server) when DB_DRIVER=pg / PG_URL is set. Everything is
// local: DB + engine + (offline mock report) — no network, no GPU. This is the
// "в реальном времени" + "offline" layer made real (not faked).

const source = require('./source');
const { persistDataset } = require('./persist');
const { generateNormal } = require('./seed/generator');

const LIVE_ID = 'ds_dblive01'; // fixed id → updated in place each poll
const DEFAULT_INTERVAL = Number(process.env.WATCH_INTERVAL_MS) || 3000;

const state = {
  watching: false,
  intervalMs: DEFAULT_INTERVAL,
  lastId: 0,
  timer: null,
  datasetId: LIVE_ID,
  startedAt: null,
  lastPoll: null,
  polls: 0,
  newEventsTotal: 0,
  eventCount: 0,
  incidentCount: 0,
  lastNewIncidents: 0,
};

// run detection on everything currently in the DB → overwrite the live dataset
async function rebuild() {
  const events = await source.readAll();
  state.eventCount = events.length;
  if (!events.length) return null;
  const hasGT = events.some((e) => e.label_malicious != null);
  const summary = await persistDataset({
    name: 'Live · поток из БД',
    source: 'db-live',
    events,
    hasGroundTruth: hasGT,
    activate: true,
    datasetId: LIVE_ID,
  });
  state.incidentCount = summary.incidentCount;
  state.lastId = await source.maxId();
  return summary;
}

// seed a real background population so personal baselines exist to deviate from
async function ensureSeeded() {
  if ((await source.count()) > 0) return;
  const { events } = generateNormal(42);
  await source.insertEvents(events);
}

async function start(opts = {}) {
  if (opts.intervalMs) state.intervalMs = Math.max(1000, Number(opts.intervalMs));
  await source.init();
  await ensureSeeded();
  await rebuild();
  state.startedAt = new Date().toISOString();
  state.watching = true;
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(() => { poll().catch(() => {}); }, state.intervalMs);
  if (state.timer.unref) state.timer.unref();
  return status();
}

async function poll() {
  try {
    const fresh = await source.readSinceId(state.lastId);
    state.lastPoll = new Date().toISOString();
    state.polls++;
    if (!fresh.length) { state.lastNewIncidents = 0; return; }
    state.newEventsTotal += fresh.length;
    const before = state.incidentCount;
    await rebuild();
    state.lastNewIncidents = Math.max(0, state.incidentCount - before);
  } catch (e) {
    // never let the interval crash the process
    // eslint-disable-next-line no-console
    console.warn('[watcher] poll error', e.message);
  }
}

function stop() {
  if (state.timer) clearInterval(state.timer);
  state.timer = null;
  state.watching = false;
  return status();
}

// attack-event factory: 5 distinct insider typologies. Each deviates from a real
// background user's baseline, so the engine flags it on the next poll.
function attackEvents(actor, day, kind) {
  const at = (h, m = 0) => `${day}T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00`;
  const E = [];
  const P = (o) => E.push({
    user: actor, role: o.role || 'support', resource: o.resource || null, db: o.db || 'db',
    host: o.host || null, ip: o.ip || '10.0.0.66', geo: o.geo || 'Астана', action: o.action,
    rows: o.rows || 0, ts: o.ts, channel: o.channel || null, from: o.from || null, to: o.to || null,
    label_malicious: 1, label_typology: o.typ || kind,
  });
  if (kind === 'mass_exfil') {
    P({ action: 'LOGIN', host: 'H-DB-1', ts: at(2, 9), from: '-', to: 'H-DB-1' });
    P({ action: 'SELECT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 1500, ts: at(2, 12) });
    P({ action: 'EXPORT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 84000, ts: at(2, 18) });
  } else if (kind === 'lateral') {
    P({ action: 'LOGIN', host: 'H-WS-1', ts: at(1, 3), from: '-', to: 'H-WS-1' });
    P({ action: 'LOGIN', host: 'H-JUMP-1', ts: at(1, 6), from: 'H-WS-1', to: 'H-JUMP-1' });
    P({ action: 'LOGIN', host: 'H-APP-7', ts: at(1, 9), from: 'H-JUMP-1', to: 'H-APP-7' });
    P({ action: 'LOGIN', host: 'H-DB-1', ts: at(1, 12), from: 'H-APP-7', to: 'H-DB-1' });
    P({ action: 'SELECT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 2200, ts: at(1, 15) });
  } else if (kind === 'compromise') {
    // impossible travel: same user, Астана → Москва in 7 min, then exfil
    P({ action: 'LOGIN', host: 'H-WS-1', ts: at(11, 2), geo: 'Астана', ip: '2.72.1.10', from: '-', to: 'H-WS-1' });
    P({ action: 'LOGIN', host: 'H-WS-1', ts: at(11, 9), geo: 'Москва', ip: '95.31.4.5', from: '-', to: 'H-WS-1' });
    P({ action: 'EXPORT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 30000, ts: at(11, 16), geo: 'Москва', ip: '95.31.4.5' });
  } else if (kind === 'broad') {
    ['DB-CARDS', 'DB-LOANS', 'DB-KYC', 'DB-SALARY', 'DB-PERSONS', 'DB-TX', 'DB-SCORING', 'DB-AML', 'DB-VIP', 'DB-AUDIT', 'DB-REF', 'DB-HR']
      .forEach((r, i) => P({ action: 'SELECT', resource: r, host: 'H-DB-1', rows: 400 + i * 30, ts: at(3, i) }));
  } else { // offhours spike
    P({ action: 'LOGIN', host: 'H-WS-1', ts: at(3, 30), from: '-', to: 'H-WS-1' });
    for (let i = 0; i < 8; i++) P({ action: 'SELECT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 1200, ts: at(3, 32 + i) });
  }
  return E;
}

async function attackDay() {
  const base = new Date((await source.maxDay()) + 'T00:00:00');
  base.setDate(base.getDate() + 1);
  return base.toISOString().slice(0, 10);
}

// INJECT one fresh insider-attack burst → next poll picks it up → incident live.
async function inject() {
  const users = await source.sampleUsers(40);
  const actor = users.length ? users[(state.newEventsTotal + state.polls) % users.length] : 'U-LIVE-1';
  const day = await attackDay();
  const ev = attackEvents(actor, day, 'mass_exfil');
  await source.insertEvents(ev);
  return { actor, day, kind: 'mass_exfil', events: ev.length };
}

// SCENARIO: fire 5 DISTINCT attacks staggered over time → the live queue fills
// with threats one after another = a breathing SOC under attack (the wow moment).
let _scenarioRunning = false;
async function injectScenario() {
  if (_scenarioRunning) return { alreadyRunning: true };
  _scenarioRunning = true;
  const users = await source.sampleUsers(40);
  const day = await attackDay();
  const kinds = ['mass_exfil', 'lateral', 'compromise', 'broad', 'offhours'];
  let i = 0;
  const fire = async () => {
    try {
      const actor = users[(i * 7) % Math.max(1, users.length)] || ('U-LIVE-' + i);
      await source.insertEvents(attackEvents(actor, day, kinds[i]));
    } catch (e) { /* keep the storm going */ }
    i++;
    if (i < kinds.length) { const t = setTimeout(() => { fire().catch(() => {}); }, 3500); if (t.unref) t.unref(); }
    else _scenarioRunning = false;
  };
  await fire();
  return { scenario: kinds, count: kinds.length, started: true };
}

// liveSupported — can REAL-TIME monitoring actually run on THIS host? Two hard
// requirements that serverless cannot meet:
//   • a long-lived process — the poll timer (setInterval) must keep firing.
//     Serverless (Vercel/Lambda) FREEZES the function after each response, so a
//     background timer never ticks → no stream.
//   • a usable on-disk DB — the default SQLite driver needs node:sqlite (Node
//     >=22.5); a serverless FS is read-only anyway. The pg/pglite driver works
//     anywhere a long-lived host exists.
// Returns { ok, reason } so /live.html can degrade gracefully (a clear banner)
// instead of surfacing a raw 500.
function liveSupported() {
  if (process.env.VERCEL || process.env.VERCEL_ENV || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NOW_REGION) {
    return { ok: false, reason: 'serverless' };
  }
  if (process.env.DB_DRIVER === 'pg' || process.env.PG_URL) return { ok: true, reason: null };
  try {
    require('node:sqlite');
    return { ok: true, reason: null };
  } catch (e) {
    return { ok: false, reason: 'node-sqlite-unavailable' };
  }
}

function status() {
  const sup = liveSupported();
  return {
    watching: state.watching,
    intervalMs: state.intervalMs,
    datasetId: state.datasetId,
    dbFile: source.DB_FILE,
    backend: source.backend,
    eventCount: state.eventCount,
    incidentCount: state.incidentCount,
    polls: state.polls,
    newEventsTotal: state.newEventsTotal,
    lastNewIncidents: state.lastNewIncidents,
    startedAt: state.startedAt,
    lastPoll: state.lastPoll,
    offline: true,
    supported: sup.ok,
    unsupportedReason: sup.reason,
  };
}

module.exports = { start, stop, poll, inject, injectScenario, status, liveSupported, rebuild, ensureSeeded, LIVE_ID };
