'use strict';
const express = require('express');
const { resolveDataset, incidentDetail } = require('../queries');
const { mockReport, claudeReport } = require('../report');

const router = express.Router();

// POST /api/report/:id  { apiKey? } -> { id, mode, model?, text }
router.post('/report/:id', async (req, res) => {
  const d = resolveDataset(req.body && req.body.datasetId);
  if (!d) return res.status(404).json({ error: 'нет датасетов' });
  const inc = incidentDetail(d, req.params.id);
  if (!inc) return res.status(404).json({ error: 'инцидент не найден', detail: req.params.id });

  const apiKey = req.body && req.body.apiKey ? String(req.body.apiKey).trim() : '';
  // Validate the client-supplied key shape before forwarding it to Anthropic.
  // The key is NEVER stored server-side — it lives only for this request. An
  // obviously-malformed value falls back to the offline mock report.
  const validKey = apiKey && /^sk-ant-[A-Za-z0-9_-]{20,200}$/.test(apiKey);
  if (apiKey && !validKey) {
    return res.json({
      id: inc.id,
      mode: 'mock',
      text: 'Неверный формат API-ключа Anthropic (ожидается sk-ant-...).\n\n--- Показан mock-черновик ---\n\n' + mockReport(inc),
    });
  }
  if (validKey) {
    try {
      const text = await claudeReport(inc, apiKey);
      return res.json({ id: inc.id, mode: 'claude', model: 'claude-opus-4-8', text });
    } catch (e) {
      // graceful fallback — never hard-fail
      const fallback =
        'Ошибка вызова Claude API: ' + e.message + '\n\n--- Показан mock-черновик ---\n\n' + mockReport(inc);
      return res.json({ id: inc.id, mode: 'mock', text: fallback });
    }
  }
  return res.json({ id: inc.id, mode: 'mock', text: mockReport(inc) });
});

module.exports = router;
