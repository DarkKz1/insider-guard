'use strict';
// api/index.js — Vercel serverless entry. Vercel's Node runtime invokes the
// exported function with native Node (req, res) — which is exactly what an
// Express app IS. So we export the Express app directly (no serverless-http
// adapter needed; that adapter expects an AWS Lambda event and hangs when
// handed Vercel's (req, res)). The DB is a pure-JS in-memory store seeded
// lazily on the first /api request inside the Express app.

const app = require('../server/server');

module.exports = app;
