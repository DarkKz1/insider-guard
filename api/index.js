'use strict';
// api/index.js — Vercel serverless entry. Wraps the Express app (server/server.js)
// with serverless-http and exposes it as the function handler. The DB lives in
// /tmp (writable on Lambda) and is seeded on cold start via the bootstrap guard
// inside the Express app. Pre-warm the seed at module load so the first request
// is already fast.

const serverless = require('serverless-http');
const app = require('../server/server');
const { ensureSeed } = require('../server/bootstrap');

// Pre-warm: generate the deterministic seed corpus at cold-start module load so
// the first inbound request doesn't pay the generation cost (and so a bare
// /api/health on a fresh instance still reports a populated DB).
try {
  ensureSeed();
} catch (e) {
  // bootstrap guard will retry per-request; log and continue.
  // eslint-disable-next-line no-console
  console.error('[api] cold-start seed failed (will retry per-request):', e && e.message);
}

const handler = serverless(app);

module.exports = handler;
module.exports.default = handler;
