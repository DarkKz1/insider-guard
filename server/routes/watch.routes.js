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

router.get('/watch/status', (req, res) => res.json(watcher.status()));

router.post('/watch/start', async (req, res) => {
  try {
    const s = await watcher.start({ intervalMs: req.body && req.body.intervalMs });
    res.json({ ok: true, ...s });
  } catch (e) {
    res.status(500).json({ error: 'watch start failed', detail: e.message });
  }
});

router.post('/watch/stop', (req, res) => res.json({ ok: true, ...watcher.stop() }));

router.post('/watch/inject', async (req, res) => {
  try {
    const injected = await watcher.inject();
    res.json({ ok: true, injected, note: 'появится в очереди при следующем опросе БД' });
  } catch (e) {
    res.status(500).json({ error: 'inject failed', detail: e.message });
  }
});

router.post('/watch/scenario', async (req, res) => {
  try {
    const r = await watcher.injectScenario();
    res.json({ ok: true, ...r, note: '5 атак влетят в очередь по очереди в реальном времени' });
  } catch (e) {
    res.status(500).json({ error: 'scenario failed', detail: e.message });
  }
});

router.post('/watch/reset', async (req, res) => {
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
