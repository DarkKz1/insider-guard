'use strict';
// server.js — Express app: static public/, JSON body, mounts routes, error
// handler, GET /api/health. Single source of truth for the HTTP surface.

const path = require('path');
const express = require('express');
const pkg = require('../package.json');
const store = require('./store');
const { ensureSeed } = require('./bootstrap');

const ingestRoutes = require('./routes/ingest.routes');
const incidentsRoutes = require('./routes/incidents.routes');
const reportRoutes = require('./routes/report.routes');
const metricsRoutes = require('./routes/metrics.routes');
const datasetRoutes = require('./routes/dataset.routes');

const app = express();
const PORT = process.env.PORT || 3000;

// --- body parsing ---
app.use(express.json({ limit: '64mb' }));
app.use(express.urlencoded({ extended: true }));

// --- CORS (open for local dev front; single-origin in prod) ---
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- persistence load guard: GUARANTEE the snapshot is loaded (async, e.g.
// Supabase) BEFORE any store read in this request. On serverless the per-
// instance memory is empty on a cold start; this hydrates it from the durable
// snapshot first. ensureLoaded() is Promise-once (loads at most once per
// instance) and never throws (warns + stays empty on failure).
app.use('/api', async (req, res, next) => {
  try {
    await store.ensureLoaded();
  } catch (e) {
    // ensureLoaded already swallows errors, but be defensive — never block.
  }
  next();
});

// --- cold-start seed guard: ensure the demo corpus exists before any API call.
// Runs AFTER ensureLoaded so a snapshot restored from Supabase is seen and we
// do NOT re-seed over it. ensureSeed is async (it awaits the durable save).
app.use('/api', async (req, res, next) => {
  try {
    await ensureSeed();
    next();
  } catch (e) {
    console.error('[bootstrap] seed failed', e);
    next(e);
  }
});

// --- health (Railway/Render liveness probe) ---
app.get('/api/health', (req, res) => {
  let dbUp = 'up';
  try {
    if (!store.isUp()) dbUp = 'down';
  } catch (e) {
    dbUp = 'down';
  }
  let backend = 'disk';
  try {
    backend = store.backend();
  } catch (e) {
    /* noop */
  }
  res.json({
    ok: dbUp === 'up',
    db: dbUp,
    store: backend === 'supabase' ? 'supabase-backed' : 'in-memory+disk',
    backend, // 'supabase' | 'disk'
    persistent: backend === 'supabase',
    datasets: (() => {
      try {
        return store.size();
      } catch (e) {
        return null;
      }
    })(),
    version: pkg.version,
  });
});

// --- API routes ---
app.use('/api', ingestRoutes);
app.use('/api', incidentsRoutes);
app.use('/api', reportRoutes);
app.use('/api', metricsRoutes);
app.use('/api', datasetRoutes);

// --- static front (served from public/) ---
const publicDir = path.join(__dirname, '..', 'public');
app.use(express.static(publicDir));

// SPA-ish fallback: serve index.html for non-API, non-file GETs
app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/')) return next();
  res.sendFile(path.join(publicDir, 'index.html'), (err) => {
    if (err) next();
  });
});

// --- error handler ---
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[error]', err);
  res.status(err.status || 500).json({ error: 'internal', detail: err.message });
});

if (require.main === module) {
  // bind 0.0.0.0 so Railway/containers can route external traffic to PORT.
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[server] Insider Guard up on http://localhost:${PORT}`);
    console.log(`[server] health: http://localhost:${PORT}/api/health`);
    try {
      console.log(`[server] store snapshot: ${store.DB_PATH}`);
    } catch (e) {
      /* noop */
    }
  });
}

module.exports = app;
