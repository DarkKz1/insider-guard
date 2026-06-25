'use strict';
// watch.routes.js — control surface for the real-time DB monitor.
//   GET  /api/watch/status  — current watcher state (connected, polls, counts)
//   POST /api/watch/start   — connect to the SQL DB + start polling (real-time)
//   POST /api/watch/stop    — stop polling
//   POST /api/watch/inject  — insert a live insider-attack burst into the DB
//   POST /api/watch/reset   — wipe the DB table and re-seed the background corpus
const express = require('express');
const watcher = require('../watcher');
const source = require('../source');

const router = express.Router();

// Live needs a long-lived host (background poll timer + writable on-disk DB). On
// serverless (Vercel) it can't run — answer with a clean, self-describing JSON
// instead of a raw 500 so /live.html degrades to a banner. status() stays
// ungated: the client polls it to LEARN that Live is unavailable.
function ensureLive(res) {
  const s = watcher.status();
  if (s.supported) return true;
  res.json({
    ok: false,
    supported: false,
    reason: s.unsupportedReason,
    note: 'Live-мониторинг доступен только на долгоживущем хосте (on-prem / Railway / localhost). На serverless (Vercel) фоновый опрос не выполняется, а ФС только на чтение.',
  });
  return false;
}

router.get('/watch/status', (req, res) => res.json(watcher.status()));

router.post('/watch/start', async (req, res) => {
  if (!ensureLive(res)) return;
  try {
    const s = await watcher.start({ intervalMs: req.body && req.body.intervalMs });
    res.json({ ok: true, ...s });
  } catch (e) {
    res.status(500).json({ error: 'watch start failed', detail: e.message });
  }
});

router.post('/watch/stop', (req, res) => res.json({ ok: true, ...watcher.stop() }));

router.post('/watch/inject', async (req, res) => {
  if (!ensureLive(res)) return;
  try {
    const injected = await watcher.inject();
    res.json({ ok: true, injected, note: 'появится в очереди при следующем опросе БД' });
  } catch (e) {
    res.status(500).json({ error: 'inject failed', detail: e.message });
  }
});

router.post('/watch/scenario', async (req, res) => {
  if (!ensureLive(res)) return;
  try {
    const r = await watcher.injectScenario();
    res.json({ ok: true, ...r, note: '5 атак влетят в очередь по очереди в реальном времени' });
  } catch (e) {
    res.status(500).json({ error: 'scenario failed', detail: e.message });
  }
});

router.post('/watch/reset', async (req, res) => {
  if (!ensureLive(res)) return;
  try {
    await source.init();
    await source.clear();
    const s = await watcher.start({ intervalMs: req.body && req.body.intervalMs });
    res.json({ ok: true, reset: true, ...s });
  } catch (e) {
    res.status(500).json({ error: 'reset failed', detail: e.message });
  }
});

module.exports = router;
