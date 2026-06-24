# Insider Guard — Submission · AFM AI Hackathon 2026

**Трек:** AI Shield (`id: ai-shield`) — защита данных / антихакинг.
**Live demo:** https://insider-guard.vercel.app · **Локально:** `npm install && npm run seed && npm start` → http://localhost:3000

> ⚠️ Всё на экране — синтетика, **0 реальных ИИН**.

---

## Проблема

Утечка **16,3 млн ИИН** (>75% взрослого населения РК, июнь 2025) — это **не взлом периметра**.
По заключению **МЦРИАП и КНБ — авторизованный доступ**: инсайдер ЛИБО скомпрометированные креды.
Вошли «через парадную дверь со своим ключом» — запрос к базе выглядит легально, поэтому
**DLP/SIEM/файрвол такое не видят**. Единственное, что выдаёт инсайдера, — аномалия его
собственного поведения. По IBM 2025 malicious insider — самый дорогой вектор ($4,92M),
средний MTTD — **241 день**.

## Решение — 4 столпа

1. **Объяснимость-by-design как доказательство.** Computed per-user UEBA baseline (leave-one-day-out) + exact-additive-attribution, где **Σ вкладов === score** математически. Glass-box, не чёрный ящик — воспроизводимо бит-в-бит.
2. **Attack-path / kill-chain нарратив.** Lateral-path DFS (≥3 хоста) + Play-скраббер во времени + MITRE ATT&CK-бейдж на каждом триггере. «Аномалия 0.87» → читаемая история атаки.
3. **Detect → Investigate → Respond → Prove.** Очередь P1–P4 → авто-IR-досье grounded в triggers/shap → tiered-response actions → **SHA-256-запечатанное досье** (chain-of-custody), человек в петле.
4. **Импакт + суверенитет + честность.** Якорь 16,3 млн + on-prem (Закон №94-V о локализации ПДн РК, в силе с 08.01.2025) + честные rare-event метрики + детерминированный honeytoken (0-FP).

## Что демонстрируем

**Live:** https://insider-guard.vercel.app — 5 wow-моментов:

1. **Kill-chain Play-скраббер** — открываем демо историей атаки, а не списком алертов; 5-хоповая цепочка собирается во времени, MITRE-бейджи T1078→T1021→T1530.
2. **SHA-256 tamper-seal** — «Запечатать досье» → меняем одно число → хеш краснеет `INTEGRITY BROKEN`. Алерт превращается в доказательство, работает offline.
3. **Honeytoken 0-FP** — касание decoy-ресурса → score 100, `DECEPTION_TRIPPED — детерминированный, 0% ложных`.
4. **Exact-attribution waterfall** — SHAP-водопад + бейдж «Σ = score (exact)»: вклады складываются в score математически точно, проверяемо.
5. **Авто-IR-досье + реагирование видно сразу** — investigation-план grounded в shap/triggers + MITRE-маппинг + recommended actions с **tiered autonomy (AUTO/APPROVE/HIGH-RISK)**; действие сразу пишется в **append-only hash-chain audit-log**.

**Дополнительно (в продукте):**

- **Загрузка своего CSV access-лога → baseline из ваших данных** — судья перетаскивает свой лог во фронт (или `POST /api/ingest`), движок считает per-user baseline (leave-one-day-out) из *этих* событий и поднимает аномалию в топ — без предразметки. Готовый сэмпл: [`samples/insider-access-log.csv`](samples/insider-access-log.csv) (синтетика, 0 реальных ИИН; описание — [`samples/README.md`](samples/README.md)).
- **Real-time MTTD** — детект по потоку access-логов за секунды против **241 дня** среднего MTTD (IBM 2025); big-number счётчик «241 days → seconds».
- **Экспорт запечатанного досье** — выгрузка инцидента в `.json` с SHA-256 **chain-of-custody**: досье воспроизводимо бит-в-бит, пригодно как доказательство для следствия.

## Метрики (честно, на дисбалансе)

На размеченном корпусе (8 поведенческих типологий, benign hard-negatives):

| Метрика | Что показываем |
|---|---|
| recall@top-N | размеченные инциденты поднимаются в топ очереди (ранжирование) |
| precision | benign hard-negatives остаются ниже порога |
| AUPRC | качество ранжирования на дисбалансе (НЕ accuracy) |
| naive perimeter-DLP на том же корпусе | поднимает ложные тревоги → reduction% в пользу UEBA |
| benign-контроли (ночной ETL, плановый аудит) | НЕ помечены |

> **Точные числа фиксировать из live `/api/metrics` (или `npm run test:contract`) перед демо** — не хардкодим.
> Ползунок порога (what-if) пересчитывает confusion-matrix вживую.

**Формулируем как «N инцидентов / 8 типологий покрыто / benign не помечены» — НЕ «8/8 атак».**
Показываем **НЕ accuracy**: пустышка «всё чисто» на дисбалансе даёт ~99,9% accuracy и ловит ноль.
Метод leave-one-day-out, без утечки данных; на реальном логе цифры ниже — методология та же.

## Стек / архитектура

**Паттерн: детерминированное ядро + LLM строго поверх посчитанного вердикта** (anti-pattern «LLM as source of truth» исключён архитектурно).

- **Node + Express + pure-JS store** (без нативных модулей). `server/engine.js` — stateless pure-функции: per-user baseline (leave-one-day-out) + perRole median, батарея триггеров, score-сатурация.
- **`server/lib/shap.js`** — Hamilton/largest-remainder, Σ contribution === score EXACTLY.
- **`server/lib/graph.js`** — buildGraph + lateralPath DFS ≥3 хоста.
- **Канонический 12-полевой event-контракт + алиасы** = универсальный adapter-слой (новый источник РК ≈ 50 строк).
- **AI:** `claude-opus-4-8` — **только** для investigation-нарратива / IR-отчёта, **никогда** не считает score. По умолчанию детерминированный mock-fallback (offline), `claudeReport` обёрнут в try/catch → mock.

## Команда / трек

AFM AI Hackathon 2026 (Алматы, 24–25 июня) · трек **AI Shield** (`ai-shield`).
Полная документация — [README.md](README.md); метрики и Q&A — [METRICS.md](METRICS.md).
