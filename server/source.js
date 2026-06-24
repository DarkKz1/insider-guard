'use strict';
// source.js — picks the live DB source for the watcher. Driver-agnostic:
//   DB_DRIVER=pg  (or PG_URL set) → PostgreSQL (pglite embedded / pg server)
//   default                       → SQLite (node:sqlite, on-device)
// Both expose the SAME async-safe interface (init/insertEvents/count/maxId/
// maxDay/readAll/readSinceId/clear/sampleUsers/backend/DB_FILE).
module.exports = (process.env.DB_DRIVER === 'pg' || process.env.PG_URL)
  ? require('./pg-source')
  : require('./db-source');
