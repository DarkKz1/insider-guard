'use strict';
// server.js — Express app: static public/, JSON body, mounts routes, error
// handler, GET /api/health. Single source of truth for the HTTP surface.

const path = require('path');
const express = require('express');
const pkg = require('../package.json');
const { db } = require('./db');
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

// --- cold-start seed guard: ensure the demo corpus exists before any API call.
// On serverless the /tmp DB starts empty on a cold instance; this generates the
// deterministic seed once per warm instance. Cheap no-op once seeded.
app.use('/api', (req, res, next) => {
  try {
    ensureSeed();
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
    db.prepare('SELECT 1').get();
  } catch (e) {
    dbUp = 'down';
  }
  res.json({ ok: dbUp === 'up', db: dbUp, version: pkg.version });
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
  app.listen(PORT, () => {
    console.log(`[server] Insider Guard up on http://localhost:${PORT}`);
    console.log(`[server] health: http://localhost:${PORT}/api/health`);
  });
}

module.exports = app;
