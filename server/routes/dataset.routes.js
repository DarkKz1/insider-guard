'use strict';
const express = require('express');
const { db, prep } = require('../db');
const { resolveDataset, listDatasets, datasetDetail } = require('../queries');

const router = express.Router();

// GET /api/datasets — list all
router.get('/datasets', (req, res) => {
  res.json({ datasets: listDatasets() });
});

// GET /api/dataset — active (or ?id=)
router.get('/dataset', (req, res) => {
  const d = resolveDataset(req.query.id);
  if (!d) return res.status(404).json({ error: 'нет датасетов', detail: 'запустите npm run seed' });
  res.json(datasetDetail(d));
});

// POST /api/dataset/:id/activate
router.post('/dataset/:id/activate', (req, res) => {
  const d = prep('SELECT id FROM datasets WHERE id=?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'датасет не найден' });
  const tx = db.transaction(() => {
    prep('UPDATE datasets SET active=0').run();
    prep('UPDATE datasets SET active=1 WHERE id=?').run(req.params.id);
  });
  tx();
  res.json({ ok: true, activeId: req.params.id });
});

module.exports = router;
