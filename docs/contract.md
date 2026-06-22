# Insider Guard — API contract (shared between backend + frontend agents)

Base: `http://localhost:3000`. All JSON unless noted. Errors: `{ error: string, detail?: string }` with 4xx/5xx. CORS open for local dev.

Example responses for every endpoint live in [`fixtures.json`](./fixtures.json) (generated from the live seeded server).

> **Core principle:** the engine computes each user's baseline **from their own history** (leave-one-day-out: avg rows/day, typical work hours, known resources/hosts/geo). This is real UEBA, not a hardcoded mockup. The server precomputes incidents at ingest/seed time, so reads are cheap; the browser no longer runs `analyze()`.

---

## INGEST

### `POST /api/ingest`
Upload an access log → parse → normalize → run engine → create a dataset (run) with incidents. The "real engine on an arbitrary array of any size" entrypoint.

Request (either):
- (a) `multipart/form-data`: `file=<.csv|.jsonl|.json>`, `name=<optional>`, `hasGroundTruth=<bool>`
- (b) `application/json`: `{ name?, events:[ {user,role,resource,db,host,ip,geo,action,rows,ts,channel, label?}, ... ] }`

Behaviour: detects format by extension/content; coerces `ts`→ISO; validates required fields (`user`,`action`,`ts`, and `resource` for non-LOGIN); `rows` defaults 0. Accepts common header aliases (timestamp/time, table/target, username/account, etc.).

Response **201**:
```
{ datasetId, name, eventCount, userCount, dayCount, resourceCount, hostCount,
  incidentCount, hasGroundTruth, durationMs, summary:{ critical, high, medium, low } }
```

---

## DATASETS

### `GET /api/datasets`
`{ datasets:[ { id, name, source:"seed"|"upload", eventCount, userCount, incidentCount, hasGroundTruth, createdAt, active } ] }`

### `GET /api/dataset?id=`  (default = active)
```
{ id, name, source, createdAt, active,
  eventCount, userCount, dayCount, resourceCount, hostCount, incidentCount, hasGroundTruth,
  summary:{ critical, high, medium, low },
  heroStat:{ threats, critical },
  window:{ from, to },
  baselineNote }
```

### `POST /api/dataset/:id/activate`
`{ ok:true, activeId }`

---

## INCIDENTS

### `GET /api/incidents?datasetId=&minScore=&priority=&typology=&limit=&offset=`
```
{ datasetId, total, incidents:[ {
  id, user, role, typology, title, channel,
  score, priority:{ lvl, color, note },
  primaryTrigger:{ code, label }, windowDate, rowsTouched, eventCount,
  label?:{ malicious, typology } } ] }
```
Sorted by score desc. `label` present only if dataset `hasGroundTruth`.
`priority.color` ∈ `crit|bad|warn|good`.

### `GET /api/incidents/:id`
Full detail — graph + factors + baseline + report inputs:
```
{ id, datasetId, user, role, typology, title, channel, windowDate,
  score, priority,
  baseline:{ avg_rows_per_day, work_hours:[s,e], known_resources, known_hosts, home_geo,
             dayCountObserved, established, volume_cv, source:"computed-from-history" },
  observed:{ rowsTouched, eventCount, hours, resources, hosts, exportRows, selectRows },
  triggers:[ { code, label, weight, detail, severity } ],
  shap:[ { code, label, severity, contribution } ],   // integer; Σ contribution === score
  mitigation:{ factor, note } | null,
  graph:{ nodes:[ { id, kind:"user"|"resource"|"host", label, sensitivity?, zone?, onPath, isHub, inRows, outRows } ],
          edges:[ { from, to, action, rows, ts, channel, crit } ],
          hub, cycle:[ids]|null },
  related:[ { id, title } ],
  playbook:[ "step1", ... ],
  label?:{ malicious, typology } }
```
Layout is computed client-side; the server only ships nodes+edges+cycle+kinds. `crit` edges = on the attack-path.

---

## REPORT

### `POST /api/report/:id`  body `{ apiKey? }`
`{ id, mode:"claude"|"mock", model?:"claude-sonnet-4-6", text }`. If a Claude call fails → graceful fallback `mode:"mock"` (never hard-fail).

---

## METRICS

### `GET /api/metrics?datasetId=&threshold=`  (threshold default 55)
Recomputes confusion under a what-if threshold from stored `incidents.score` + labels (no engine rerun):
```
{ datasetId, hasGroundTruth, threshold,
  corpus:{ total, illicit, benign, eventCount, userCount, dayCount },
  confusion:{ TP, FP, FN, TN },
  quality:{ precision, recall, f1, accuracy, auprc, recallTopN, alertsShown },
  naive:{ naiveTP, naiveFP, naiveFN, naiveAlerts, reduction },
  note }
```
If `!hasGroundTruth`: `confusion`/`quality`/`naive` are `null`; instead a `scoreDistribution:{p1,p2,p3,p4}` + the limited-metrics `note` are returned.

---

## HEALTH

### `GET /api/health` → `{ ok, db:"up", version }` (platform liveness probe)
