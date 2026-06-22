'use strict';
// bootstrap.js — ensure the demo seed corpus exists in the (per-instance) DB.
// On serverless cold-start the /tmp DB is empty, so we generate the deterministic
// seed dataset once per warm instance. Idempotent: if an active seed dataset is
// already present, it is a no-op. Safe to call on every request (cheap check).

const { db } = require('./db');

let _seeded = false;

function hasSeedDataset() {
  try {
    const row = db
      .prepare("SELECT id FROM datasets WHERE source='seed' ORDER BY created_at DESC LIMIT 1")
      .get();
    return !!row;
  } catch (e) {
    // table may not exist yet on a brand-new DB — schema is applied in db.js on
    // require, but guard anyway.
    return false;
  }
}

function ensureSeed() {
  if (_seeded) return;
  if (hasSeedDataset()) {
    _seeded = true;
    return;
  }
  // generate deterministically (SEED=42 inside seed pipeline) — ~200ms.
  const { generateNormal } = require('./seed/generator');
  const { injectAttacks } = require('./seed/attacks');
  const { persistDataset } = require('./persist');

  const SEED = 42;
  const { users, events, days } = generateNormal(SEED);
  const { attackEvents } = injectAttacks(users, days);
  const allEvents = events.concat(attackEvents);
  allEvents.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));

  persistDataset({
    name: 'Корпус-демо (синтетика)',
    source: 'seed',
    events: allEvents,
    hasGroundTruth: true,
    activate: true,
  });

  _seeded = true;
  // eslint-disable-next-line no-console
  console.log('[bootstrap] seed corpus generated (', allEvents.length, 'events )');
}

module.exports = { ensureSeed };
