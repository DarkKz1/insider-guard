'use strict';
// watcher.js — REAL-TIME monitor. Polls the SQL database for new access events,
// re-runs the detection engine on the full history (baselines need it), and
// updates ONE live incident dataset in place. Everything is local: SQLite +
// engine + (offline mock report) — no network, no GPU. This is the "в реальном
// времени" + "offline" layer made real (not faked).

const dbSource = require('./db-source');
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
  const events = dbSource.readAll();
  state.eventCount = events.length;
  if (!events.length) return null;
  const hasGT = events.some((e) => e.label_malicious != null);
  const summary = await persistDataset({
    name: 'Live · поток из БД (SQLite)',
    source: 'db-live',
    events,
    hasGroundTruth: hasGT,
    activate: true,
    datasetId: LIVE_ID,
  });
  state.incidentCount = summary.incidentCount;
  state.lastId = dbSource.maxId();
  return summary;
}

// seed a real background population so personal baselines exist to deviate from
async function ensureSeeded() {
  if (dbSource.count() > 0) return;
  const { events } = generateNormal(42);
  dbSource.insertEvents(events);
}

async function start(opts = {}) {
  if (opts.intervalMs) state.intervalMs = Math.max(1000, Number(opts.intervalMs));
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
    const fresh = dbSource.readSinceId(state.lastId);
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

// INJECT a fresh insider-attack burst into the DB against a real background user
// (so it deviates from THEIR baseline). Next poll picks it up → incident appears
// live. This is the on-stage "watch it get caught in real-time" trigger.
function inject() {
  const users = dbSource.sampleUsers(30);
  const actor = users.length ? users[(state.newEventsTotal + state.polls) % users.length] : 'U-LIVE-1';
  const base = new Date(dbSource.maxDay() + 'T00:00:00');
  base.setDate(base.getDate() + 1);
  const day = base.toISOString().slice(0, 10);
  const at = (h, m = 0) => `${day}T${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:00`;

  const ev = [];
  const push = (o) => ev.push({
    user: actor, role: o.role || 'support', resource: o.resource || null, db: o.db || 'db',
    host: o.host || null, ip: o.ip || '10.0.0.66', geo: o.geo || 'Астана', action: o.action,
    rows: o.rows || 0, ts: o.ts, channel: o.channel || null, from: o.from || null, to: o.to || null,
    label_malicious: 1, label_typology: o.typ || null,
  });

  // night-time lateral chain → host with the sensitive DB
  push({ action: 'LOGIN', host: 'H-WS-1', ts: at(2, 3), from: '-', to: 'H-WS-1', typ: 'lateral' });
  push({ action: 'LOGIN', host: 'H-JUMP-1', ts: at(2, 6), from: 'H-WS-1', to: 'H-JUMP-1', typ: 'lateral' });
  push({ action: 'LOGIN', host: 'H-DB-1', ts: at(2, 9), from: 'H-JUMP-1', to: 'H-DB-1', typ: 'lateral' });
  // mass exfil of PII at 02:00 — far above personal norm
  push({ action: 'SELECT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 1500, ts: at(2, 12), typ: 'mass_exfil' });
  push({ action: 'EXPORT', resource: 'DB-PERSONS', host: 'H-DB-1', rows: 84000, ts: at(2, 18), typ: 'mass_exfil' });

  dbSource.insertEvents(ev);
  return { actor, day, events: ev.length };
}

function status() {
  return {
    watching: state.watching,
    intervalMs: state.intervalMs,
    datasetId: state.datasetId,
    dbFile: dbSource.DB_FILE,
    backend: 'SQLite · node:sqlite · on-device',
    eventCount: state.eventCount,
    incidentCount: state.incidentCount,
    polls: state.polls,
    newEventsTotal: state.newEventsTotal,
    lastNewIncidents: state.lastNewIncidents,
    startedAt: state.startedAt,
    lastPoll: state.lastPoll,
    offline: true,
  };
}

module.exports = { start, stop, poll, inject, status, rebuild, ensureSeeded, LIVE_ID };
