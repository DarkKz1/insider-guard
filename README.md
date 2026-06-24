# Insider Guard — объяснимый AI-страж инсайдерских угроз

**Трек AI Shield** (`id: ai-shield`), AFM AI Hackathon 2026 (Алматы, 24–25 июня) — защита данных / антихакинг.

> **DLP видит периметр, SIEM видит сигнатуры — Insider Guard видит ПОВЕДЕНИЕ.**
> Поток access/audit-логов (кто → к какому ресурсу → с какого хоста) → детект **инсайдера
> и компрометации аккаунта** по отклонению от поведенческого baseline пользователя (**UEBA**)
> → **человекочитаемое объяснение, почему помечено** + рекомендация реагирования (IR-плейбук)
> + **приоритизированная очередь** инцидентов для SOC. Превенция следующей утечки 16,3 млн ИИН,
> а не разбор после.

🔗 **Live demo:** https://insider-guard.vercel.app · 🗂 [SUBMISSION.md](SUBMISSION.md) (одностраничник для жюри)

> ⚠️ Всё на экране — **синтетика, 0 реальных ИИН**. Privacy-by-design: псевдонимизация, per-user baseline, human-in-the-loop.

## Ключевые фичи

- **UEBA с computed baseline** — норма каждого пользователя считается из его истории (leave-one-day-out), а не хардкодится.
- **Exact-attribution (Σ SHAP === score)** — аддитивная декомпозиция «почему помечено», сумма вкладов бит-в-бит равна score.
- **Attack-path граф + Play-скраббер** — DFS-путь бокового перемещения ≥3 хоста, разворачивающийся во времени.
- **MITRE ATT&CK-бейджи** — каждый триггер маппится на технику (T1021/T1048/T1074/T1078/T1098/T1213/T1530/T1566).
- **Kill-chain ribbon** — тактики атаки от Initial Access до Exfiltration.
- **SHA-256 tamper-seal** — криптографическая печать досье; правка одного числа → `INTEGRITY BROKEN`.
- **Honeytoken / DECEPTION_TRIPPED** — детерминированный 0-FP слой поверх вероятностного UEBA.
- **Unsupervised robust-MAD** — z-сигнал «×N от своей нормы И от пиров».
- **Real-time MTTD** — детект по потоку access-логов за секунды (vs 241 день среднего MTTD по IBM 2025).
- **Реагирование видно сразу** — tiered-autonomy actions (AUTO/APPROVE/HIGH-RISK) + append-only hash-chain audit-log: ответ применяется и фиксируется в журнале мгновенно.
- **Экспорт запечатанного досье** — выгрузка инцидента в `.json` с SHA-256 chain-of-custody (правка одного числа → `INTEGRITY BROKEN`).
- **Честные rare-event метрики** — recall@topN / AUPRC / precision vs наивный DLP-порог, НЕ accuracy.
- **Загрузка своего CSV access-лога → baseline из ваших данных** — перетащить лог во фронт или `POST /api/ingest`; движок считает per-user baseline (leave-one-day-out) из *ваших* событий, без предразметки. Готовый сэмпл для жюри — [`samples/`](samples/) ([`insider-access-log.csv`](samples/insider-access-log.csv)).

## Быстрый старт

```bash
npm install          # express, multer, csv-parse, nanoid и т.д.
npm run seed         # корпус 40 пользователей × 30 дней + размеченные инциденты + benign-контроли
npm start            # http://localhost:3000
```

---

## Что это

Дашборд SOC / инцидент-аналитика. На вход — **access/audit-логи** (журналы доступа к БД,
аутентификации хостов, IAM-grant'ов, исходящих выгрузок). На выход — **приоритизированная
очередь инцидентов** с risk-score 0–100, **графом доступа** (пользователь → ресурс → хост),
**объяснением по факторам (SHAP-подобная аддитивная декомпозиция, Σ вкладов === score)**,
рекомендацией реагирования и кнопкой **«сформировать черновик инцидент-отчёта (IR report)»**.

Ключевая идея: продукт ловит угрозу, которую **периметровый DLP/SIEM не видит** — у инсайдера
доступ **легальный**. Детект строится не на сигнатурах атаки, а на **отклонении от
персонального baseline самого пользователя** (UEBA): объём, время, широта доступа, привилегии,
гео/устройство. Инструмент **не заменяет** аналитика, а **сортирует его работу** (самое опасное
наверх) и **объясняет каждое решение**, чтобы человек мог проверить.

## Якорь: зачем это нужно сейчас (16,3 млн)

**Утечка 16,3 млн записей РК (июнь 2025) — это был инсайдер с авторизованным доступом, а не взлом
периметра.** Файрвол, антивирус и DLP такое не ловят: запрос к базе выглядит «легально». Единственное,
что выдаёт инсайдера, — **аномалия его собственного поведения**: выгрузка в десятки раз больше нормы,
ночью, по таблице ПДн. Insider Guard построен ровно вокруг этого слепка.

Контекст (IBM 2025): malicious insider — самый дорогой вектор ($4,92M), средний MTTD — 241 день.
Мы сжимаем эти 241 день до секунд: движок считает норму сам и поднимает злоумышленника в топ очереди.

## Ключевой тезис

1. **UEBA с computed baseline (не хардкод).** Baseline каждого пользователя считается **из его
   собственной истории** методом **leave-one-day-out** — аномальный день не раздувает свой же baseline.
   Аномалия меряется относительно личной нормы И относительно коллег по роли (perRole median).
2. **Объяснимость = доказательство.** SHAP-подобная аддитивная декомпозиция (Hamilton /
   largest-remainder), где **сумма вкладов триггеров === score** математически точно. Glass-box,
   а не чёрный ящик — воспроизводимо и пригодно для проверки человеком.
3. **Attack-path / граф доступа.** DFS-поиск пути бокового перемещения через ≥3 хоста + привязка
   триггеров к **MITRE ATT&CK** (T1021/T1048/T1074/T1078/T1098/T1213/T1530/T1566).
4. **Честные метрики на дисбалансе.** НЕ accuracy (пустышка «всё чисто» даёт 99,9% accuracy и ловит
   ноль), а **recall@top-N / AUPRC / precision** против наивного объёмного порога DLP.

---

## Сервер / запуск

Node + Express + pure-JS store. Движок считает baseline пользователя из его истории
(leave-one-day-out) и скорит каждый user-day на **произвольном массиве событий любого размера** —
это реальный UEBA, а не захардкоженный mockup. Премиальный тёмный UI отдаётся из `public/` и читает
всё из API; вся логика детекта — на бэкенде.

### Quickstart (локально — гарантированный deliverable)

```bash
npm install          # express, multer, csv-parse, nanoid и т.д.
npm run seed         # генерит корпус 40 пользователей × 30 дней + размеченные инциденты + benign-контроли
npm start            # http://localhost:3000
```

Открыть `http://localhost:3000`. Health: `http://localhost:3000/api/health`.

Опционально:
```bash
npm run db:init          # создать стор + применить схему (идемпотентно), без данных
npm run test:contract    # доказать, что каждый эндпоинт отдаёт документированную форму (сервер должен быть запущен)
```

`npm run seed -- --keep` пропускает повторный seed, если seed-датасет уже есть (используется в deploy-командах).

### Что генерит seed

- ~12 300 нормальных событий по **40 пользователям** (analyst/support/clerk/junior/auditor/dba/admin
  + 1 ETL service-аккаунт) за **30 дней**, детерминированно (seeded PRNG → воспроизводимо).
- **Размеченные инсайдер-инциденты**, подложенные внутрь реального потока (чтобы baseline был
  *посчитан*, а не объявлен): mass-exfil, боковое перемещение, эскалация привилегий, off-hours-всплеск,
  staging-exfil, impossible-travel компрометация, broad scatter-gather, covert channel.
- **benign hard-negatives** (ETL service ночные 90k чтений; аудитор плановой проверки) — размечены
  `malicious=0`, чтобы precision был честным.

На дефолтном пороге на seed-корпусе достигается высокий recall@top-N при нулевых FP; наивный
периметровый DLP на том же корпусе поднимает ложные тревоги (reduction% в метриках). Двигаешь порог —
tradeoff честный. **Точные числа фиксировать из `npm run test:contract` / `/api/metrics` перед демо.**

### Формат ingest (CSV / JSON-lines / JSON-array)

Канонический event:
```
{ user, role, resource, db, host, ip, geo, action, rows, ts, channel, label? }
```
- **Обязательно:** `user`, `action`, `ts` (+ `resource` для не-`LOGIN`).
- `action` ∈ `LOGIN/SELECT/EXPORT/DOWNLOAD/GRANT/SUDO/ROLE_CHANGE/...`
- `ts` принимает ISO (`2026-06-12T02:14:00`), `YYYY-MM-DD HH:MM`, только дату или epoch.
- `rows` по умолчанию 0. Колонка `label`/`malicious` (1/0/true/false) — опциональный ground-truth.
- Принимаются типовые алиасы заголовков (`timestamp`/`time`, `table`/`target`, `username`/`account`,
  `src_ip`, `location`, …) → адаптер ~50 строк на новый источник (AD/Colvir/ЦФТ/СУБД-аудит/1С).

CSV-пример:
```csv
user,role,resource,db,host,ip,geo,action,rows,ts,channel,label
u1,analyst,DB-PERSONS,persons,WS1,10.0.0.1,Астана,SELECT,80000,2026-06-12T02:14:00,db,1
```

Готовый сэмпл для жюри (синтетика, 0 реальных ИИН): [`samples/insider-access-log.csv`](samples/insider-access-log.csv)
— перетащить во фронт или прогнать через `/api/ingest`; baseline посчитается из этих данных, аномальный
день (`aibek.analyst`) поднимется в топ очереди. Описание корпуса — [`samples/README.md`](samples/README.md).

Upload:
```bash
curl -X POST http://localhost:3000/api/ingest -F "file=@your-log.csv"
# или JSON-телом:
curl -X POST http://localhost:3000/api/ingest -H "content-type: application/json" \
  -d '{"name":"my-log","events":[{"user":"u1","action":"SELECT","resource":"DB-A","rows":50000,"ts":"2026-05-20T02:00:00"}]}'
```
Ответ несёт `durationMs` (runtime движка) и новый `datasetId` (авто-активируется).

### API

Полный контракт + примеры payload: [`docs/contract.md`](docs/contract.md) и [`docs/fixtures.json`](docs/fixtures.json).

| Method | Path | Назначение |
| --- | --- | --- |
| GET | `/api/health` | liveness `{ ok, db, version }` |
| POST | `/api/ingest` | upload лога → запуск движка → новый датасет |
| GET | `/api/datasets` | список датасетов (switcher) |
| GET | `/api/dataset?id=` | активный датасет (hero/shape) |
| POST | `/api/dataset/:id/activate` | переключить активный датасет |
| GET | `/api/incidents?...` | очередь триажа (score desc) |
| GET | `/api/incidents/:id` | полная деталь (граф + SHAP + baseline + playbook) |
| POST | `/api/report/:id` | IR-отчёт (mock, или Claude если передан `{apiKey}`) |
| GET | `/api/metrics?threshold=` | confusion / precision / recall / AUPRC + naive-DLP |

### Движок (для аудируемости)

`server/engine.js` — pure (без DB, без Express). Конвейер:
1. группировка событий → per-user → per-user-day окна (единица дневного триажа SOC);
2. baseline на пользователя из истории (**leave-one-day-out**; robust trimmed mean для объёма;
   p5–p95 padded полоса рабочих часов; ресурсы, виденные ≥2 предыдущих дня = «known»;
   habituation для выходных/off-hours; cold-start → fallback на role-median);
3. батарея триггеров **относительно этого baseline** (VOLUME_ANOMALY/SOFT, LATERAL_MOVEMENT,
   BROAD/SENSITIVE_ACCESS, BULK_EXFIL, OFF_HOURS_VELOCITY, PRIV_ESCALATION, COMPROMISE_INDICATORS,
   STAGING_EXFIL, COVERT_CHANNEL) с mutual-exclusion, чтобы один всплеск не считался дважды;
4. score `= round(100·(1−e^(−effRaw/38)))`, mitigation для established-аккаунтов только когда **все**
   триггеры soft;
5. Hamilton largest-remainder целочисленный SHAP (Σ === score);
6. per-user-day подграф (nodes/edges + lateral-path) для attack-path SVG.

Точный конфиг (веса, VOLUME_MULT, окно baseline, пороги) снапшотится в `run_meta` на датасет.

### Где Claude / AI

`claude-opus-4-8` используется **только** для investigation-нарратива / IR-отчёта — **никогда не
считает score/вердикт** (anti-pattern «LLM as source of truth» исключён архитектурно). По умолчанию
черновик генерится **детерминированным mock-шаблоном** (`report.js mockReport`, работает оффлайн);
`claudeReport` обёрнут в try/catch → mock-fallback, поэтому демо не зависит от сети/ключа.

### Persistence

Слой данных — **pure-JS store** (`server/store.js`), без нативных модулей и SQLite. Состояние
(датасеты / инциденты / clean-user-days / active flag) живёт в RAM и **снапшотится в один JSON-файл**,
чтобы переживать рестарты на долгоживущем хосте с примонтированным volume.

- **`DB_PATH`** — путь к JSON-снапшоту. По умолчанию `./data/store.json` локально; на Railway —
  `/data/store.json` (mounted volume).
- **На старте:** если `DB_PATH` есть → состояние грузится из него; если нет → `bootstrap.js` генерит
  детерминированный seed-корпус и первый save создаёт файл.
- **На каждой мутации** (ingest, активация датасета) → снапшот переписывается **атомарно**
  (temp-файл + `rename`), краш в середине записи не портит снапшот.
- **Graceful degradation:** на read-only / ephemeral FS (Vercel) неудачная запись логируется один раз,
  стор продолжает работать чисто in-memory — процесс не падает. Тот же код персистит на Railway и
  работает эфемерно на Vercel.

`PORT` читается из env с fallback `3000`; сервер биндит `0.0.0.0`.

### Deploy

- **Railway (primary, персистентный):** долгоживущий Node-процесс + mounted volume. `railway.json`
  пинит NIXPACKS, `startCommand: npm start`, healthcheck `/api/health`. `nixpacks.toml` / `.nvmrc` /
  `engines` = Node 20. Первый boot: снапшота нет → seed → пишется `/data/store.json`; дальше каждый
  рестарт грузит существующий снапшот.
  ```bash
  railway init
  railway volume add --mount-path /data
  railway variable set DB_PATH=/data/store.json
  railway up
  ```
- **Render (fallback):** `render.yaml` монтирует диск `/data`; задать `DB_PATH=/data/store.json`.
- **Fly.io (fallback):** `fly launch --now` (Dockerfile node:20-slim, `fly.toml` монтирует volume `/data`);
  `fly secrets set DB_PATH=/data/store.json`.
- **Heroku-style:** `Procfile` (`web: npm start`). FS эфемерный → без диска стор in-memory (re-seed на boot).
- **Vercel (поддерживается, эфемерно):** `api/index.js` экспортит Express-app напрямую; `vercel.json`
  рерайтит `/api/*`. Serverless FS не writable → стор in-memory, seed детерминированно на первом запросе.

**Если CLI/auth недоступны**, локальный запуск выше полностью функционален с реальным движком +
seeded-корпусом — это гарантированный deliverable.

---

## Маппинг на критерии жюри

ТЗ трека дословно: **«практичность, скорость обнаружения, объяснимость решений»** + риск-оценка/приоритизация.

- **Практичность** → готовая очередь инцидентов для SOC + черновик IR-отчёта (экономит ручную работу);
  привязка к реальной боли АФМ/гос-органов РК (утечка 16,3 млн = инсайдер, а не взлом).
- **Скорость обнаружения** → детект в реальном времени по потоку access-логов, мгновенный risk-score;
  241 день MTTD → секунды.
- **Объяснимость** → SHAP-подобная декомпозиция «почему помечено» относительно baseline + граф доступа
  + MITRE-привязка + RU-нарратив IR-отчёта. Центр продукта.
- **Приоритизация** → P1–P4, очередь по score, recall@top-N.
- **Язык метрик** (важно сказать жюри): **НЕ accuracy** — инсайдер-события редкие, классификатор-пустышка
  даёт ~99,9% accuracy и ловит ноль. Показываем **AUPRC** (ранжирование) + **recall@top-N** (реальные
  инциденты в топе) + **снижение ложных тревог** против наивного объёмного порога. benign-контроли
  (ETL, плановый аудит) остаются ниже порога — доказывают precision. Ползунок порога (what-if) пересчитывает
  confusion-matrix вживую.

> **Метрики говорить как «инциденты / типологии покрыто / benign не помечены»**, а НЕ «8/8 атак».
> Точные числа фиксировать из `/api/metrics` / `npm run test:contract` перед демо.

## Привязка к РК / ПДн

- **Кейс:** по заключению МЦРИАП и КНБ — **не взлом, а авторизованный доступ** (инсайдер ЛИБО
  скомпрометированные креды). Движок ловит ОБА вектора: insider-типологии + `COMPROMISE_INDICATORS`.
  Никогда не утверждать «доказанный инсайдер».
- **On-prem / суверенитет:** Закон №94-V (локализация ПДн РК, в силе с 08.01.2025) — данные не покидают
  периметр. On-prem — не «фича», а причина, по которой SaaS-UEBA гос-заказчику структурно непродаваем.
- **Privacy-by-design:** только синтетика на экране (ноль реальных ИИН), псевдонимизация, per-user
  baseline (anti-bias), human-in-the-loop — система приоритизирует, решает человек (EU AI Act Art.14).

## Честные ограничения

- Детект-«модель» — **детерминированные UEBA-эвристики + взвешенный scoring**, а не обученный
  XGBoost/IsolationForest/autoencoder. Осознанный выбор под imbalance 10⁻⁶ и аудируемость; точка
  интеграции ML заготовлена за флагом.
- SHAP здесь — **точная аддитивная декомпозиция** весов триггеров (Hamilton/largest-remainder),
  Σ===score бит-в-бит, а не вызов библиотеки `shap`. Семантика та же (вклад фактора в решение).
- Веса экспертно-калиброваны (не обучены) и снапшотятся в `run_meta` для воспроизводимости.
- Данные синтетические, подобраны так, чтобы каждая типология чисто срабатывала; benign-контроли
  добавлены специально против «детектора-перестраховщика».
- LLM-нарратив по умолчанию — mock; реальный Claude (`claude-opus-4-8`) — опционально по ключу.

> Историческая эволюция прототипа (AML → prescrubber → insider, один движок) сохранена в
> [`archive/`](archive/) как пруф pivot velocity.
