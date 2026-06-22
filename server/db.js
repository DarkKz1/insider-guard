'use strict';
// db.js — compatibility shim. The data layer is now a pure-JS in-memory store
// (server/store.js) with NO native modules — this removed the better-sqlite3
// native dependency that hung/timed out on Vercel serverless. This file keeps a
// minimal `db`-shaped surface for the few callers that only need a liveness
// check (server.js health) and exposes the store.

const store = require('./store');

// Minimal db-like object: only the surface still referenced after the SQLite
// removal. health uses db.prepare('SELECT 1').get() — emulate a truthy result.
const db = {
  prepare() {
    return {
      get: () => ({ 1: 1 }),
      all: () => [],
      run: () => ({ changes: 0 }),
    };
  },
  transaction(fn) {
    return (...args) => fn(...args);
  },
  pragma() {},
  exec() {},
};

function applySchema() {
  // no-op — in-memory store needs no DDL.
}

const DB_PATH = ':in-memory:';

module.exports = { db, prep: () => db.prepare(), applySchema, DB_PATH, store };
