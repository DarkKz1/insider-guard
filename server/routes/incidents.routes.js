'use strict';
const express = require('express');
const { resolveDataset, listIncidents, incidentDetail } = require('../queries');

const router = express.Router();

// GET /api/incidents — triage queue
router.get('/incidents', (req, res) => {
  const d = resolveDataset(req.query.datasetId);
  if (!d) return res.status(404).json({ error: 'нет датасетов' });
  const opts = {
    minScore: req.query.minScore != null ? parseInt(req.query.minScore, 10) : null,
    priority: req.query.priority || null,
    typology: req.query.typology || null,
    limit: req.query.limit != null ? parseInt(req.query.limit, 10) : null,
    offset: req.query.offset != null ? parseInt(req.query.offset, 10) : null,
  };
  res.json(listIncidents(d, opts));
});

// GET /api/incidents/:id — full detail
router.get('/incidents/:id', (req, res) => {
  const d = resolveDataset(req.query.datasetId);
  if (!d) return res.status(404).json({ error: 'нет датасетов' });
  const inc = incidentDetail(d, req.params.id);
  if (!inc) return res.status(404).json({ error: 'инцидент не найден', detail: req.params.id });
  res.json(inc);
});

module.exports = router;
