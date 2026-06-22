'use strict';
// seed.js — generate the realistic corpus (40 users × ~30d normal activity +
// 8 malicious + 2 benign-hard-negative labeled incidents), run the engine,
// persist dataset+events+incidents. Deterministic (seeded PRNG). Idempotent:
// `npm run seed` re-creates a fresh seed dataset unless --keep and one exists.

const { db } = require('./db');
const { generateNormal } = require('./seed/generator');
const { injectAttacks } = require('./seed/attacks');
const { persistDataset } = require('./persist');

const SEED = 42;
const KEEP_IF_EXISTS = process.argv.includes('--keep');

function existingSeed() {
  return db.prepare("SELECT id FROM datasets WHERE source='seed' ORDER BY created_at DESC LIMIT 1").get();
}

function run() {
  const prior = existingSeed();
  if (prior && KEEP_IF_EXISTS) {
    console.log('[seed] seed dataset already exists (', prior.id, ') and --keep set — skipping.');
    return prior.id;
  }
  // wipe prior seed datasets (cascades events/incidents) for a clean reproducible run
  const priors = db.prepare("SELECT id FROM datasets WHERE source='seed'").all();
  if (priors.length) {
    const delTx = db.transaction(() => {
      for (const p of priors) {
        db.prepare('DELETE FROM events WHERE dataset_id=?').run(p.id);
        db.prepare('DELETE FROM incidents WHERE dataset_id=?').run(p.id);
        db.prepare('DELETE FROM incident_factors WHERE incident_id IN (SELECT id FROM incidents WHERE dataset_id=?)').run(p.id);
        db.prepare('DELETE FROM incident_edges WHERE incident_id IN (SELECT id FROM incidents WHERE dataset_id=?)').run(p.id);
        db.prepare('DELETE FROM clean_user_days WHERE dataset_id=?').run(p.id);
        db.prepare('DELETE FROM run_meta WHERE dataset_id=?').run(p.id);
        db.prepare('DELETE FROM datasets WHERE id=?').run(p.id);
      }
    });
    delTx();
    console.log('[seed] removed', priors.length, 'prior seed dataset(s).');
  }

  console.log('[seed] generating normal activity (seed=' + SEED + ')...');
  const { users, events, days } = generateNormal(SEED);
  console.log(`[seed]   ${users.length} users, ${events.length} normal events over ${days.length} days.`);

  console.log('[seed] injecting 8 malicious + 2 benign-hard-negative incidents...');
  const { attackEvents, groundTruth } = injectAttacks(users, days);
  console.log(`[seed]   ${attackEvents.length} attack events, ${groundTruth.length} ground-truth labels.`);

  const allEvents = events.concat(attackEvents);
  // sort by ts for determinism
  allEvents.sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));

  console.log(`[seed] running engine on ${allEvents.length} events...`);
  const summary = persistDataset({
    name: 'Корпус-демо (синтетика)',
    source: 'seed',
    events: allEvents,
    hasGroundTruth: true,
    activate: true,
  });

  console.log('[seed] DONE.');
  console.log('[seed]   datasetId   :', summary.datasetId);
  console.log('[seed]   events      :', summary.eventCount);
  console.log('[seed]   users       :', summary.userCount);
  console.log('[seed]   days        :', summary.dayCount);
  console.log('[seed]   resources   :', summary.resourceCount);
  console.log('[seed]   hosts       :', summary.hostCount);
  console.log('[seed]   incidents   :', summary.incidentCount);
  console.log('[seed]   summary     :', JSON.stringify(summary.summary));
  console.log('[seed]   engine ms   :', summary.durationMs);
  console.log('[seed]   window      :', summary.window.from, '..', summary.window.to);

  // quick ground-truth recall sanity check (how many planted malicious surfaced as P1/P2)
  const gt = groundTruth.filter((g) => g.malicious);
  let surfaced = 0;
  for (const g of gt) {
    const inc = db
      .prepare("SELECT score FROM incidents WHERE dataset_id=? AND user=? AND window_date=? ORDER BY score DESC LIMIT 1")
      .get(summary.datasetId, g.user, g.day);
    if (inc && inc.score >= 55) surfaced++;
  }
  console.log(`[seed]   ground-truth recall@P2(55): ${surfaced}/${gt.length} malicious surfaced as P1/P2`);

  return summary.datasetId;
}

if (require.main === module) {
  try {
    run();
    process.exit(0);
  } catch (e) {
    console.error('[seed] FAILED:', e);
    process.exit(1);
  }
}

module.exports = { run };
