'use strict';
const express = require('express');
const multer = require('multer');
const path = require('path');
const { parseBuffer, normalizeArray } = require('../ingest');
const { persistDataset } = require('../persist');

const router = express.Router();

// --- ingest auth (OWASP A01 Broken Access Control / A07 Auth Failures) -----
// The seed/demo corpus is what the judges see. An anonymous POST /api/ingest
// must NEVER deactivate or overwrite it (see persistDataset activate flag).
//
// Two layers of protection:
//   1. INGEST_TOKEN (env, optional). When set, every /api/ingest call MUST
//      carry `Authorization: Bearer <INGEST_TOKEN>` or it is rejected 401.
//      When unset (local/dev), uploads are allowed WITHOUT a token.
//   2. activation gating. ONLY a request that presented a valid bearer token
//      may make its uploaded dataset the GLOBAL active one (and thereby
//      replace the seed as the default view). An anonymous (no-token) upload
//      is still ingested + analysable by its own datasetId, but it is created
//      INACTIVE so the seed corpus stays active/untouched for everyone else.
//
// `req._ingestAuthed` is set true only when a valid token was presented.
function ingestAuth(req, res, next) {
  const token = process.env.INGEST_TOKEN || '';
  const header = req.headers['authorization'] || '';
  const m = /^Bearer\s+(.+)$/i.exec(header);
  const presented = m ? m[1].trim() : '';

  if (!token) {
    // No token configured (local/dev). Allow ingest, but treat it as
    // unauthenticated: it may NOT seize global-active from the seed.
    req._ingestAuthed = false;
    return next();
  }

  if (presented && presented === token) {
    req._ingestAuthed = true;
    return next();
  }

  return res.status(401).json({
    error: 'требуется авторизация',
    detail: 'POST /api/ingest требует заголовок Authorization: Bearer <INGEST_TOKEN>',
  });
}

// --- upload hardening (OWASP A04 Insecure Design / A05 Misconfig) ---------
// Limits cap the resources a single request can consume (DoS / memory-leak
// surface — multer < 2 had CVE-2025-47935 / CVE-2025-47944; we run multer 2.x
// AND constrain every dimension explicitly). memoryStorage keeps the buffer in
// RAM (never written to disk -> no path-traversal / temp-file surface).
const MAX_FILE_BYTES = 25 * 1024 * 1024; // 25 MB per file
const ALLOWED_EXT = new Set(['.csv', '.json', '.jsonl', '.ndjson', '.txt']);
const ALLOWED_MIME = new Set([
  'text/csv',
  'application/csv',
  'application/vnd.ms-excel', // browsers often label .csv as this
  'application/json',
  'application/x-ndjson',
  'application/jsonl',
  'text/plain',
  'application/octet-stream', // some clients send this for any upload
  '', // missing mimetype -> fall back to extension check below
]);

// fileFilter: reject anything that isn't an expected log format BEFORE the
// buffer is read. Validates both extension (authoritative) and mimetype.
function fileFilter(req, file, cb) {
  const ext = path.extname(file.originalname || '').toLowerCase();
  if (!ALLOWED_EXT.has(ext)) {
    return cb(new Error(`недопустимый тип файла «${ext || '?'}» — разрешены: CSV, JSON, JSONL, NDJSON, TXT`));
  }
  const mime = (file.mimetype || '').toLowerCase();
  if (!ALLOWED_MIME.has(mime)) {
    return cb(new Error(`недопустимый MIME-тип «${mime}»`));
  }
  return cb(null, true);
}

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter,
  limits: {
    fileSize: MAX_FILE_BYTES, // hard cap per file
    files: 1, // exactly one file accepted
    fields: 5, // a few text fields (name, hasGroundTruth) — no flooding
    parts: 10, // total multipart parts ceiling
    headerPairs: 100,
  },
});

// Upper bound on events in a JSON body path (the multipart path is bounded by
// fileSize above). Prevents an unbounded array from exhausting CPU/RAM in the
// detection engine.
const MAX_EVENTS = 200000;

// POST /api/ingest — multipart file OR application/json { name?, events:[...] }
// Wrap multer so its errors (file too large, wrong type, too many files) come
// back as a clean 400/413 JSON instead of bubbling to the generic 500 handler.
router.post(
  '/ingest',
  ingestAuth,
  (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (!err) return next();
      if (err instanceof multer.MulterError) {
        const tooBig = err.code === 'LIMIT_FILE_SIZE';
        return res.status(tooBig ? 413 : 400).json({
          error: tooBig ? 'файл слишком большой' : 'ошибка загрузки файла',
          detail: tooBig ? `максимальный размер ${MAX_FILE_BYTES / (1024 * 1024)} МБ` : err.message,
          code: err.code,
        });
      }
      // fileFilter rejections (custom Error) -> 415 Unsupported Media Type
      return res.status(415).json({ error: 'недопустимый файл', detail: err.message });
    });
  },
  async (req, res) => {
    try {
      let events;
      let hasGroundTruth;
      let name;

      if (req.file) {
        // size is already enforced by multer; defensive re-check
        if (req.file.size > MAX_FILE_BYTES) {
          return res.status(413).json({ error: 'файл слишком большой' });
        }
        const parsed = parseBuffer(req.file.buffer, req.file.originalname || 'upload.csv');
        events = parsed.events;
        hasGroundTruth = parsed.hasGroundTruth;
        name = (req.body && req.body.name) || req.file.originalname || 'Загруженный лог';
        // explicit hasGroundTruth override from form
        if (req.body && req.body.hasGroundTruth === 'false') hasGroundTruth = false;
      } else if (req.body && Array.isArray(req.body.events)) {
        if (req.body.events.length > MAX_EVENTS) {
          return res.status(413).json({
            error: 'слишком много событий',
            detail: `максимум ${MAX_EVENTS} событий за один запрос`,
          });
        }
        const parsed = normalizeArray(req.body.events);
        events = parsed.events;
        hasGroundTruth = parsed.hasGroundTruth;
        name = req.body.name || 'Загруженный лог (JSON)';
      } else {
        return res.status(400).json({
          error: 'нет данных для ingest',
          detail: 'ожидается multipart file=<csv|jsonl|json> или JSON-тело { events:[...] }',
        });
      }

      // sanitize the dataset name (used only as a display label) — strip control
      // chars and cap length so it can't carry an injection/oversized payload
      // downstream into reports/UI.
      name = String(name).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 200) || 'Загруженный лог';

      if (!events.length) return res.status(400).json({ error: 'лог пуст (0 событий)' });
      if (events.length > MAX_EVENTS) {
        return res.status(413).json({ error: 'слишком много событий', detail: `максимум ${MAX_EVENTS}` });
      }

      // ACTIVATION GATING: only an authenticated upload may seize the global
      // "active" dataset (and thus replace the seed corpus as the default view).
      // An anonymous upload is persisted + fully analysable by its own
      // datasetId, but stays INACTIVE so the seed corpus the judges see is
      // never deactivated/overwritten (the core demo-mutation fix).
      const activate = req._ingestAuthed === true;

      // AWAIT: persistDataset writes the durable snapshot (Supabase upsert) and
      // only resolves once it's persisted — so the response is sent AFTER the
      // dataset is safe on disk/Supabase (serverless freeze-after-res safety).
      const summary = await persistDataset({
        name,
        source: 'upload',
        events,
        hasGroundTruth,
        activate,
      });

      return res.status(201).json({
        datasetId: summary.datasetId,
        name: summary.name,
        eventCount: summary.eventCount,
        userCount: summary.userCount,
        dayCount: summary.dayCount,
        resourceCount: summary.resourceCount,
        hostCount: summary.hostCount,
        incidentCount: summary.incidentCount,
        hasGroundTruth: summary.hasGroundTruth,
        durationMs: summary.durationMs,
        summary: summary.summary,
        active: activate, // anonymous uploads are ingested but NOT made active
      });
    } catch (e) {
      return res.status(400).json({ error: 'ошибка разбора лога', detail: e.message });
    }
  }
);

module.exports = router;
