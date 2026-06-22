'use strict';
// init-db.js — standalone: create db + apply schema (idempotent).
const { db, applySchema, DB_PATH } = require('./db');

applySchema();
const tables = db
  .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
  .all()
  .map((r) => r.name);

console.log('[init-db] DB at', DB_PATH);
console.log('[init-db] tables:', tables.join(', '));
console.log('[init-db] done.');
