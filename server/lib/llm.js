'use strict';
// llm.js — local LLM access via Ollama (on-prem, no external services).
//
// The DETECTION pipeline never touches this. It is used ONLY to draft the
// human-readable IR report narrative. It talks to a LOCAL Ollama daemon over
// 127.0.0.1 — no cloud API, no API key, nothing leaves the perimeter. If the
// daemon is unreachable (e.g. serverless demo with no Ollama) the caller falls
// back to the deterministic mock template.

// Endpoint + model are env-overridable so an on-prem deployment can point at
// its own model host / model without code changes.
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://127.0.0.1:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:7b';
// Default chat ceiling. Kept modest (8s) so the report endpoint stays well under
// the 30s serverless function limit even if the liveness probe passed but the
// daemon then stalls mid-generation. On a real on-prem box a 7B model on CPU may
// need longer — raise OLLAMA_TIMEOUT_MS (or point OLLAMA_URL at a GPU host) there.
const OLLAMA_TIMEOUT_MS = Number(process.env.OLLAMA_TIMEOUT_MS) || 8000;
// Bound the generation so the draft stays concise AND finishes predictably.
const OLLAMA_NUM_PREDICT = Number(process.env.OLLAMA_NUM_PREDICT) || 700;

/**
 * ollamaChat — single-shot chat completion against the LOCAL model.
 * @param {{system?:string, user:string, model?:string}} args
 * @returns {Promise<string>} assistant text
 * Throws on unreachable daemon / non-200 / timeout / empty answer so callers
 * can fall back to the deterministic mock template.
 */
async function ollamaChat({ system, user, model = OLLAMA_MODEL }) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), OLLAMA_TIMEOUT_MS);
  try {
    const r = await fetch(`${OLLAMA_URL}/api/chat`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model,
        stream: false,
        options: { temperature: 0.2, num_predict: OLLAMA_NUM_PREDICT },
        messages: [
          ...(system ? [{ role: 'system', content: system }] : []),
          { role: 'user', content: user },
        ],
      }),
      signal: ctrl.signal,
    });
    if (!r.ok) {
      const txt = await r.text().catch(() => '');
      throw new Error('Ollama ' + r.status + ': ' + txt.slice(0, 200));
    }
    const j = await r.json();
    const text = j && j.message && j.message.content ? j.message.content : '';
    if (!text) throw new Error('пустой ответ локальной модели');
    return text;
  } finally {
    clearTimeout(timer);
  }
}

/** ollamaUp — quick liveness probe (label availability without a full gen). */
async function ollamaUp() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 1500);
  try {
    const r = await fetch(`${OLLAMA_URL}/api/version`, { signal: ctrl.signal });
    return r.ok;
  } catch (e) {
    return false;
  } finally {
    clearTimeout(timer); // also clears on the reject path (don't leave a live timer)
  }
}

/**
 * ollamaModelReady — true ONLY if the configured model is actually pulled, not
 * just that the daemon is up. ollamaUp() passing while the model is absent was
 * the trap: the report endpoint then attempted a generation that 404'd
 * ("model not found") before falling back. Checking /api/tags lets the report
 * fast-fail to the deterministic mock with a clear reason, and once the model is
 * pulled it flips to true and the report uses the local LLM.
 */
async function ollamaModelReady(model = OLLAMA_MODEL) {
  const want = String(model || '').trim().toLowerCase();
  if (!want) return false;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 1500);
  try {
    const r = await fetch(`${OLLAMA_URL}/api/tags`, { signal: ctrl.signal });
    if (!r.ok) return false;
    const j = await r.json();
    // normalize both sides (trim + lowercase) so an OLLAMA_MODEL with stray
    // whitespace/case still matches the daemon's canonical tag; a null entry is
    // coerced to '' rather than throwing inside .map.
    const names = (j && Array.isArray(j.models) ? j.models : [])
      .map((m) => String((m && (m.name || m.model)) || '').trim().toLowerCase());
    // exact tag match, OR (when the configured model has no explicit tag) a
    // family match so "qwen2.5" accepts the daemon's "qwen2.5:latest".
    return names.some((n) => n === want || (!want.includes(':') && n.split(':')[0] === want));
  } catch (e) {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = { ollamaChat, ollamaUp, ollamaModelReady, OLLAMA_MODEL, OLLAMA_URL };
