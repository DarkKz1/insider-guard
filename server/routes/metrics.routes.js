'use strict';
const express = require('express');
const { resolveDataset, metrics } = require('../queries');

const router = express.Router();

// GET /api/metrics?datasetId=&threshold=
router.get('/metrics', (req, res) => {
  const d = resolveDataset(req.query.datasetId);
  if (!d) return res.status(404).json({ error: 'нет датасетов' });
  let threshold = req.query.threshold != null ? parseInt(req.query.threshold, 10) : 55;
  if (!Number.isFinite(threshold)) threshold = 55;
  threshold = Math.max(0, Math.min(100, threshold));
  res.json(metrics(d, threshold));
});

module.exports = router;
