'use strict';
// server.js — Express app: static public/, JSON body, mounts routes, error
// handler, GET /api/health. Single source of truth for the HTTP surface.

const path = require('path');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const pkg = require('../package.json');
const store = require('./store');
const { ensureSeed } = require('./bootstrap');

const ingestRoutes = require('./routes/ingest.routes');
const incidentsRoutes = require('./routes/incidents.routes');
const reportRoutes = require('./routes/report.routes');
const metricsRoutes = require('./routes/metrics.routes');
const datasetRoutes = require('./routes/dataset.routes');
const watchRoutes = require('./routes/watch.routes');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust the first proxy hop (Vercel/Railway/Render terminate TLS in front of
// us). Needed so express-rate-limit keys on the real client IP via
// X-Forwarded-For instead of the proxy's address. '1' (not `true`) avoids the
// permissive-trust setup that would let a client spoof its rate-limit key.
app.set('trust proxy', 1);

// --- security headers (helmet): HSTS, X-Frame-Options, X-Content-Type-Options,
// Referrer-Policy, etc. CSP is disabled because the static demo (public/index.html)
// loads vendored React/Babel/Tailwind + inline scripts on the same origin; a strict
// CSP would break the prototype's in-browser transpile. API responses still gain
// the rest of the hardening headers. ---
app.use(helmet({ contentSecurityPolicy: false }));

// --- body parsing ---
// Cap the JSON body to bound memory per request (DoS surface). 32 MB is ample
// for the largest reasonable { events:[...] } ingest payload while rejecting an
// abusive multi-hundred-MB body before it is buffered. urlencoded is small (only
// a couple of form fields are ever sent) and limited explicitly.
app.use(express.json({ limit: '32mb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb', parameterLimit: 100 }));

// --- CORS (open for local dev front; single-origin in prod) ---
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// --- rate limiting (OWASP A04 Insecure Design — anti-DoS) ------------------
// A security tool must not itself be a trivial DoS / brute-force target. Cap
// every client (per-IP) to RATE_LIMIT_MAX requests per RATE_LIMIT_WINDOW_MS.
// Defaults: 100 requests / 15 minutes. Liveness probes (GET /api/health) are
// exempt so an orchestrator (Railway/Render/Vercel) can poll freely. Preflight
// OPTIONS is already short-circuited by CORS above, so it never reaches here.
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX) || 100;
const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true, // emit RateLimit-* headers
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path === '/api/health',
  message: { error: 'слишком много запросов', detail: 'превышен лимит запросов — повторите позже' },
});
app.use('/api', apiLimiter);

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
app.use('/api', watchRoutes);

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
