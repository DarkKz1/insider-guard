'use strict';
// report.js — IR incident report generation.
//   mockReport   — deterministic template (offline fallback, no model at all).
//   ollamaReport — narrative drafted by a LOCAL model via Ollama (on-prem, no
//                  external service, no API key). NEVER computes score/verdict —
//                  the verdict comes from the deterministic UEBA engine; the LLM
//                  only writes human-readable prose over already-computed facts.

const { fmt } = require('./lib/fmt');
const { ollamaChat, OLLAMA_MODEL } = require('./lib/llm');

// Fixed SOC system prompt. Also reused by the /api/report/draft proxy so the
// in-browser client cannot inject an arbitrary system role.
const SOC_SYSTEM = `Ты — SOC / инцидент-аналитик (информационная безопасность гос-органа РК). Составь сжатый, формальный черновик ИНЦИДЕНТ-ОТЧЁТА (Incident Response) на русском языке по данным детект-движка UEBA. Структура: резюме инцидента, хронология событий, затронутые ресурсы и объём данных, индикаторы компрометации, рекомендации по реагированию/сдерживанию. Без воды, технически-точный тон, не выдумывай фактов сверх данных. Это синтетические данные для прототипа.`;

// build a deterministic report from an incident object (offline, no model)
function mockReport(inc) {
  const factors = (inc.triggers || inc.shap || []).filter((t) => (t.weight || 0) > 0);
  const trg = factors.map((t) => `• ${t.label}: ${t.detail || ''}`).join('\n');
  const recs = (inc.playbook || []).map((r, i) => `${i + 1}. ${r}`).join('\n');
  const edges = inc.graph && inc.graph.edges ? inc.graph.edges : [];
  const timeline = edges
    .slice()
    .sort((a, b) => String(a.ts).localeCompare(String(b.ts)))
    .map(
      (e) =>
        `   ${e.ts} · ${inc.user} · ${e.action} · ${e.to} · ${e.rows ? fmt(e.rows) + ' строк' : '—'} · ${e.channel || ''}`
    )
    .join('\n');
  const nodeCount = inc.graph && inc.graph.nodes ? inc.graph.nodes.length : 0;
  const totalRows = edges.reduce((s, e) => s + (e.rows || 0), 0);
  const today = new Date().toISOString().slice(0, 10);

  return `ЧЕРНОВИК ИНЦИДЕНТ-ОТЧЁТА (Incident Response) — ${inc.id}
Дата формирования: ${today} | Сформировано автоматически SOC-движком UEBA, требует проверки аналитиком.

1. РЕЗЮМЕ ИНЦИДЕНТА. По учётной записи «${inc.user}» (роль: ${inc.role || '—'}, источник сигнала: ${inc.channel || '—'}) выявлены признаки несанкционированной/аномальной активности привилегированного пользователя за ${inc.windowDate}. Присвоен risk-score ${inc.score}/100, приоритет ${inc.priority.lvl}. Тип инцидента: ${inc.title}.

2. ХРОНОЛОГИЯ СОБЫТИЙ:
${timeline || '   (события не зафиксированы)'}

3. ЗАТРОНУТЫЕ РЕСУРСЫ И ОБЪЁМ ДАННЫХ. В графе доступа ${nodeCount} узлов (пользователи/ресурсы/хосты), ${edges.length} событий, совокупный объём доступа ${fmt(totalRows)} строк.${inc.graph && inc.graph.cycle ? ' Обнаружена цепочка бокового перемещения по инфраструктуре.' : ''} Baseline пользователя вычислен из истории: ${fmt(inc.baseline.avg_rows_per_day)} строк/день, рабочие часы ${inc.baseline.work_hours[0]}:00–${inc.baseline.work_hours[1]}:00.

4. ИНДИКАТОРЫ (триггеры детект-движка UEBA):
${trg || '• —'}

5. РЕКОМЕНДАЦИИ ПО РЕАГИРОВАНИЮ / СДЕРЖИВАНИЮ:
${recs || '   (плейбук не определён)'}

Примечание: документ — машинный черновик для ускорения работы SOC/инцидент-аналитика. Не является процессуальным решением. Все данные в прототипе синтетические (ИИН/ФИО/IP вымышлены).`;
}

// build the incident-context user message (server-side incident shape)
function buildUserPrompt(inc) {
  const edges = inc.graph && inc.graph.edges ? inc.graph.edges : [];
  const totalRows = edges.reduce((s, e) => s + (e.rows || 0), 0);
  return `Инцидент ${inc.id}. Тип: ${inc.title}. Источник сигнала: ${inc.channel || '—'}. Пользователь: ${inc.user} (роль ${inc.role || '—'}), окно ${inc.windowDate}.
Risk-score: ${inc.score}/100, приоритет ${inc.priority.lvl}.
Baseline (вычислен из истории): ${fmt(inc.baseline.avg_rows_per_day)} строк/день, рабочие часы ${inc.baseline.work_hours[0]}:00–${inc.baseline.work_hours[1]}:00.
Хронология:
${edges
  .slice()
  .sort((a, b) => String(a.ts).localeCompare(String(b.ts)))
  .map((e) => `- ${e.ts} ${inc.user} ${e.action} ${e.to} ${e.rows ? fmt(e.rows) + ' строк' : ''} ${e.channel || ''}`)
  .join('\n')}
Индикаторы (триггеры):
${(inc.triggers || inc.shap || []).filter((t) => (t.weight || 0) > 0).map((t) => `- ${t.label}: ${t.detail || ''}`).join('\n')}
Граф доступа: ${(inc.graph && inc.graph.nodes ? inc.graph.nodes.length : 0)} узлов, ${edges.length} событий, объём ${fmt(totalRows)} строк.`;
}

// ollamaReport — draft the narrative via the LOCAL model. Throws if the local
// daemon is unreachable; the route then falls back to mockReport.
async function ollamaReport(inc) {
  return ollamaChat({ system: SOC_SYSTEM, user: buildUserPrompt(inc) });
}

module.exports = { mockReport, ollamaReport, buildUserPrompt, SOC_SYSTEM, OLLAMA_MODEL };
