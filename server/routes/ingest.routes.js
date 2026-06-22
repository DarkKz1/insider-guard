'use strict';
const express = require('express');
const multer = require('multer');
const { parseBuffer, normalizeArray } = require('../ingest');
const { persistDataset } = require('../persist');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 64 * 1024 * 1024 } });

// POST /api/ingest — multipart file OR application/json { name?, events:[...] }
router.post('/ingest', upload.single('file'), (req, res) => {
  try {
    let events;
    let hasGroundTruth;
    let name;

    if (req.file) {
      const parsed = parseBuffer(req.file.buffer, req.file.originalname || 'upload.csv');
      events = parsed.events;
      hasGroundTruth = parsed.hasGroundTruth;
      name = (req.body && req.body.name) || req.file.originalname || 'Загруженный лог';
      // explicit hasGroundTruth override from form
      if (req.body && req.body.hasGroundTruth === 'false') hasGroundTruth = false;
    } else if (req.body && Array.isArray(req.body.events)) {
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

    if (!events.length) return res.status(400).json({ error: 'лог пуст (0 событий)' });

    const summary = persistDataset({
      name,
      source: 'upload',
      events,
      hasGroundTruth,
      activate: true,
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
    });
  } catch (e) {
    return res.status(400).json({ error: 'ошибка разбора лога', detail: e.message });
  }
});

module.exports = router;
