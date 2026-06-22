'use strict';
// ingest.js — parse + normalize CSV / JSON-lines / JSON-array -> canonical events.
// Validates required fields (user, resource, action, ts); coerces ts -> ISO.

const { parse: parseCsv } = require('csv-parse/sync');

const ACTIONS = new Set([
  'LOGIN', 'SELECT', 'EXPORT', 'DOWNLOAD', 'GRANT', 'SUDO', 'ROLE_CHANGE',
  'INSERT', 'UPDATE', 'DELETE', 'LOGOUT', 'OTHER',
]);

// coerce a variety of ts inputs to ISO "YYYY-MM-DDTHH:MM:SS"
function coerceTs(raw) {
  if (!raw) return null;
  let s = String(raw).trim();
  // "YYYY-MM-DD HH:MM" or "YYYY-MM-DD HH:MM:SS" -> ISO with T
  if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) {
    s = s.replace(' ', 'T');
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(s)) s += ':00';
    return s;
  }
  // date only -> midnight
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) return s + 'T00:00:00';
  // epoch millis / seconds
  if (/^\d{10,13}$/.test(s)) {
    const n = Number(s);
    const ms = s.length === 13 ? n : n * 1000;
    return new Date(ms).toISOString().slice(0, 19);
  }
  // fallback: Date parse
  const d = new Date(s);
  if (!Number.isNaN(d.getTime())) return d.toISOString().slice(0, 19);
  return null;
}

function toInt(v, def = 0) {
  if (v == null || v === '') return def;
  const n = parseInt(String(v).replace(/[^0-9-]/g, ''), 10);
  return Number.isFinite(n) ? n : def;
}

// parse a boolean/label cell -> 1 (malicious) / 0 (benign) / null
function coerceLabel(v) {
  if (v == null || v === '') return null;
  const s = String(v).trim().toLowerCase();
  if (['1', 'true', 'yes', 'malicious', 'bad', 'illicit'].includes(s)) return 1;
  if (['0', 'false', 'no', 'benign', 'good', 'clean'].includes(s)) return 0;
  return null;
}

// normalize one raw row -> canonical event (or throw)
function normalizeRow(r, idx) {
  // accept several common key spellings
  const get = (...keys) => {
    for (const k of keys) {
      if (r[k] != null && r[k] !== '') return r[k];
      // case-insensitive
      const found = Object.keys(r).find((kk) => kk.toLowerCase() === k.toLowerCase());
      if (found && r[found] != null && r[found] !== '') return r[found];
    }
    return undefined;
  };

  const user = get('user', 'username', 'account', 'actor');
  const resource = get('resource', 'table', 'target', 'db_table', 'object');
  let action = get('action', 'event', 'op', 'operation');
  const ts = coerceTs(get('ts', 'timestamp', 'time', 'datetime', 'date'));

  const missing = [];
  if (!user) missing.push('user');
  if (!action) missing.push('action');
  if (!ts) missing.push('ts');
  // resource may be absent for pure LOGIN; require for non-login
  action = action ? String(action).toUpperCase() : action;
  if (!resource && action !== 'LOGIN') missing.push('resource');

  if (missing.length) {
    throw new Error(`строка ${idx + 1}: отсутствуют обязательные поля: ${missing.join(', ')}`);
  }
  if (!ACTIONS.has(action)) action = action || 'OTHER';

  const tsDay = ts.slice(0, 10);
  const tsHour = parseInt(ts.slice(11, 13), 10) || 0;

  const labelMal = coerceLabel(get('label', 'malicious', 'label_malicious', 'is_malicious'));

  return {
    user: String(user),
    role: get('role') != null ? String(get('role')) : null,
    resource: resource != null ? String(resource) : null,
    db: get('db', 'database') != null ? String(get('db', 'database')) : null,
    host: get('host', 'hostname') != null ? String(get('host', 'hostname')) : null,
    ip: get('ip', 'src_ip', 'source_ip') != null ? String(get('ip', 'src_ip', 'source_ip')) : null,
    geo: get('geo', 'location', 'country', 'city') != null ? String(get('geo', 'location', 'country', 'city')) : null,
    action,
    rows: toInt(get('rows', 'row_count', 'records', 'count'), 0),
    ts,
    ts_day: tsDay,
    ts_hour: tsHour,
    channel: get('channel', 'source', 'medium') != null ? String(get('channel', 'source', 'medium')) : null,
    from: get('from', 'edge_from', 'src') != null ? String(get('from', 'edge_from', 'src')) : null,
    to: get('to', 'edge_to', 'dst') != null ? String(get('to', 'edge_to', 'dst')) : null,
    label_malicious: labelMal,
    label_typology: get('label_typology', 'typology') != null ? String(get('label_typology', 'typology')) : null,
  };
}

/**
 * parseBuffer — detect format and normalize to canonical events[].
 * @param {Buffer|string} buf raw content
 * @param {string} filename (for extension hint)
 * @returns { events, hasGroundTruth }
 */
function parseBuffer(buf, filename = '') {
  const text = Buffer.isBuffer(buf) ? buf.toString('utf8') : String(buf);
  const ext = (filename.split('.').pop() || '').toLowerCase();
  let rawRows = [];

  const trimmed = text.trim();
  const looksJsonArray = trimmed.startsWith('[');
  const looksJsonObj = trimmed.startsWith('{');

  if (ext === 'json' || (looksJsonArray && ext !== 'csv')) {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) rawRows = parsed;
    else if (parsed.events && Array.isArray(parsed.events)) rawRows = parsed.events;
    else rawRows = [parsed];
  } else if (ext === 'jsonl' || ext === 'ndjson' || (looksJsonObj && !trimmed.includes(','))) {
    rawRows = trimmed
      .split(/\r?\n/)
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  } else if (looksJsonArray) {
    rawRows = JSON.parse(trimmed);
  } else if (trimmed.split(/\r?\n/)[0] && trimmed.split(/\r?\n/)[0].trim().startsWith('{')) {
    // jsonl without extension
    rawRows = trimmed
      .split(/\r?\n/)
      .filter((l) => l.trim())
      .map((l) => JSON.parse(l));
  } else {
    // CSV
    rawRows = parseCsv(trimmed, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      relax_column_count: true,
    });
  }

  if (!rawRows.length) throw new Error('Пустой или нераспознанный лог (0 строк).');

  const events = rawRows.map((r, i) => normalizeRow(r, i));
  const hasGroundTruth = events.some((e) => e.label_malicious != null);
  return { events, hasGroundTruth };
}

/** parse a pre-built events array (JSON body path) */
function normalizeArray(arr) {
  if (!Array.isArray(arr)) throw new Error('events должен быть массивом.');
  if (!arr.length) throw new Error('Пустой массив events.');
  const events = arr.map((r, i) => normalizeRow(r, i));
  const hasGroundTruth = events.some((e) => e.label_malicious != null);
  return { events, hasGroundTruth };
}

module.exports = { parseBuffer, normalizeArray, coerceTs, ACTIONS };
