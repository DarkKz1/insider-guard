'use strict';
// bootstrap.js — ensure the demo seed corpus exists in the (per-instance) DB.
// On serverless cold-start the /tmp DB is empty, so we generate the deterministic
// seed dataset once per warm instance. Idempotent: if an active seed dataset is
// already present, it is a no-op. Safe to call on every request (cheap check).

const store = require('./store');

let _seeded = false;

function hasSeedDataset() {
  try {
    return store.hasSeed();
  } catch (e) {
    return false;
  }
}

// ASYNC: the snapshot load (Supabase) is async and persistDataset awaits the
// durable save. Callers MUST `await ensureLoaded()` before this (so a snapshot
// restored from Supabase is seen and we DON'T re-seed over it). The seed
// middleware in server.js awaits ensureLoaded() then ensureSeed().
async function ensureSeed() {
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

  await persistDataset({
    name: 'Корпус-демо (синтетика)',
    source: 'seed',
    events: allEvents,
    hasGroundTruth: true,
    activate: true,
  });

  _seeded = true;
  // eslint-disable-next-line no-console
  console.log('[bootstrap] seed corpus generated (', allEvents.length, 'events ) — persisted');
}

module.exports = { ensureSeed };
