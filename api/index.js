'use strict';
// api/index.js — Vercel serverless entry. Wraps the Express app (server/server.js)
// with serverless-http and exposes it as the function handler. The DB lives in
// /tmp (writable on Lambda) and is seeded lazily on the first /api request via
// the per-request bootstrap guard inside the Express app (server/server.js).

const serverless = require('serverless-http');
const app = require('../server/server');

const handler = serverless(app);

module.exports = handler;
module.exports.default = handler;
