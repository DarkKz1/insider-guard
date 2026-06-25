'use strict';
const express = require('express');
const { resolveDataset, incidentDetail } = require('../queries');
const { mockReport, ollamaReport, SOC_SYSTEM } = require('../report');
const { ollamaChat, ollamaModelReady, OLLAMA_MODEL } = require('../lib/llm');

const router = express.Router();

// Cap the client-supplied report context (abuse / DoS guard on the local proxy).
const MAX_PROMPT = 16000;

// POST /api/report/draft  { prompt } -> { mode, model?, text? }
// Thin on-prem proxy for the in-browser demo (which builds the incident context
// client-side). The browser NEVER talks to the model directly and holds no key —
// this forwards the incident-context message to the LOCAL Ollama daemon. The
// system prompt is fixed server-side (the client cannot inject the system role),
// and the prompt length is capped. On an unreachable daemon it returns
// mode:'unavailable' and the client falls back to its own deterministic mock.
//
// NOTE: declared BEFORE '/report/:id' so the literal 'draft' is not captured as
// an incident id by the parameterized route.
router.post('/report/draft', async (req, res) => {
  const prompt = req.body && typeof req.body.prompt === 'string' ? req.body.prompt.slice(0, MAX_PROMPT) : '';
  if (!prompt.trim()) return res.status(400).json({ error: 'пустой prompt' });
  // Fast-fail guard (serverless / no-Ollama / model-not-pulled): a quick 1.5s
  // probe of /api/tags so an unreachable daemon OR an absent model returns in
  // <3s instead of attempting a generation that 404s ("model not found") or
  // hanging until the full chat timeout (tripping the 30s Vercel ceiling).
  if (!(await ollamaModelReady())) {
    return res.json({ mode: 'unavailable', detail: `локальная модель ${OLLAMA_MODEL} не готова (демон недоступен или модель не скачана)` });
  }
  try {
    const text = await ollamaChat({ system: SOC_SYSTEM, user: prompt });
    return res.json({ mode: 'ollama', model: OLLAMA_MODEL, text });
  } catch (e) {
    return res.json({ mode: 'unavailable', detail: e.message });
  }
});

// POST /api/report/:id  { datasetId? } -> { id, mode, model?, text }
// Drafts the IR report for a server-side incident using the LOCAL model
// (Ollama). No API key, no external service. Falls back to the deterministic
// mock template if the local daemon is unreachable.
router.post('/report/:id', async (req, res) => {
  const d = resolveDataset(req.body && req.body.datasetId);
  if (!d) return res.status(404).json({ error: 'нет датасетов' });
  const inc = incidentDetail(d, req.params.id);
  if (!inc) return res.status(404).json({ error: 'инцидент не найден', detail: req.params.id });
  // Fast-fail guard: probe model readiness (1.5s) before the full report
  // generation so an unreachable Ollama OR an un-pulled model falls back to the
  // deterministic mock in <3s instead of a 404'd generation / chat timeout.
  if (!(await ollamaModelReady())) {
    return res.json({ id: inc.id, mode: 'mock', detail: `локальная модель ${OLLAMA_MODEL} не готова (демон недоступен или модель не скачана)`, text: mockReport(inc) });
  }
  try {
    const text = await ollamaReport(inc);
    return res.json({ id: inc.id, mode: 'ollama', model: OLLAMA_MODEL, text });
  } catch (e) {
    return res.json({ id: inc.id, mode: 'mock', detail: e.message, text: mockReport(inc) });
  }
});

module.exports = router;
