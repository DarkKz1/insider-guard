'use strict';
// seed.js — generate the realistic corpus (40 users × ~30d normal activity +
// 8 malicious + 2 benign-hard-negative labeled incidents), run the engine,
// persist dataset+incidents into the in-memory store. Deterministic (seeded
// PRNG). With the in-memory store the corpus lives per-process, so this is
// primarily a sanity/dev entry point; the running server seeds itself on the
// first request via server/bootstrap.js.

const store = require('./store');
const { generateNormal } = require('./seed/generator');
const { injectAttacks } = require('./seed/attacks');
const { persistDataset } = require('./persist');

const SEED = 42;

function run() {
  console.log('[seed] generating normal activity (seed=' + SEED + ')...');
  const { users, events, days } = generateNormal(SEED);
  console.log(`[seed]   ${users.length} users, ${events.length} normal events over ${days.length} days.`);

  console.log('[seed] injecting 8 malicious + 2 benign-hard-negative incidents...');
  const { attackEvents, groundTruth } = injectAttacks(users, days);
  console.log(`[seed]   ${attackEvents.length} attack events, ${groundTruth.length} ground-truth labels.`);

  const allEvents = events.concat(attackEvents);
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

  // quick ground-truth recall sanity check
  const rec = store.getRecord(summary.datasetId);
  const gt = groundTruth.filter((g) => g.malicious);
  let surfaced = 0;
  for (const g of gt) {
    const inc = rec.incidents.find((i) => i.user === g.user && i.windowDate === g.day);
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
