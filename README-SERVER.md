# Insider Guard — Server (real UEBA backend)

Node + Express + SQLite (better-sqlite3). The detection engine computes each
user's **baseline from their own history** (leave-one-day-out) and scores every
user-day on an **arbitrary event array of any size**. This is real UEBA, not the
hardcoded mockup — the original demo (`index.html`, `index_*_backup.html`) is
kept untouched as a backup.

> The premium dark UI is served from `public/` (built by the frontend agent) and
> reads everything from the API below. The browser no longer runs `analyze()`.

---

## Quickstart (local — guaranteed deliverable)

```bash
npm install          # installs express, better-sqlite3, multer, csv-parse, nanoid
npm run seed         # generate the 40-user × 30-day corpus + 8 malicious + 2 benign-hard-negative incidents
npm start            # http://localhost:3000
```

Open `http://localhost:3000`. Health: `http://localhost:3000/api/health`.

Optional:
```bash
npm run db:init          # create db + apply schema (idempotent), no data
npm run test:contract    # prove every endpoint returns the documented shape (server must be running)
```

`npm run seed -- --keep` skips re-seeding if a seed dataset already exists (used by deploy start commands).

---

## What the seed produces

- ~12,300 normal events across **40 users** (analyst/support/clerk/junior/auditor/dba/admin + 1 ETL service account) over **30 days**, deterministic (seeded PRNG → reproducible).
- **8 labeled insider incidents** planted inside the real stream (so the baseline is *computed*, not declared): mass-exfil, lateral movement, privilege escalation, off-hours burst, staging exfil, impossible-travel compromise, broad scatter-gather, covert channel.
- **2 benign hard-negatives** (ETL service nightly 90k reads; auditor planned-audit week) — labeled `malicious=0` to make precision honest.

At the default threshold (55) on the seeded corpus: **TP=8, FP=0, FN=0** → precision 1.0, recall 1.0, AUPRC 1.0; the naive perimeter-DLP baseline raises 5 false positives on the same corpus (100% FP reduction). Move the threshold and the tradeoff is honest (e.g. at 30: recall 1.0, precision 0.62).

---

## Ingest format (CSV / JSON-lines / JSON-array)

Canonical event:
```
{ user, role, resource, db, host, ip, geo, action, rows, ts, channel, label? }
```
- **Required:** `user`, `action`, `ts` (+ `resource` for non-`LOGIN`).
- `action` ∈ `LOGIN/SELECT/EXPORT/DOWNLOAD/GRANT/SUDO/ROLE_CHANGE/...`
- `ts` accepts ISO (`2026-06-12T02:14:00`), `YYYY-MM-DD HH:MM`, date-only, or epoch.
- `rows` defaults 0. `label`/`malicious` column (1/0/true/false) is optional ground-truth.
- Common header aliases are accepted (`timestamp`/`time`, `table`/`target`, `username`/`account`, `src_ip`, `location`, ...).

CSV example:
```csv
user,role,resource,db,host,ip,geo,action,rows,ts,channel,label
u1,analyst,DB-PERSONS,persons,WS1,10.0.0.1,Астана,SELECT,80000,2026-06-12T02:14:00,db,1
```

JSON-lines example (`.jsonl`):
```
{"user":"u1","role":"analyst","resource":"DB-PERSONS","action":"SELECT","rows":80000,"ts":"2026-06-12T02:14:00","channel":"db"}
```

Upload:
```bash
curl -X POST http://localhost:3000/api/ingest -F "file=@your-log.csv"
# or JSON body:
curl -X POST http://localhost:3000/api/ingest -H "content-type: application/json" \
  -d '{"name":"my-log","events":[{"user":"u1","action":"SELECT","resource":"DB-A","rows":50000,"ts":"2026-05-20T02:00:00"}]}'
```
The response carries `durationMs` (engine runtime) and the new `datasetId` (auto-activated).

---

## API

Full contract + example payloads: [`docs/contract.md`](docs/contract.md) and [`docs/fixtures.json`](docs/fixtures.json).

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | liveness `{ ok, db, version }` |
| POST | `/api/ingest` | upload log → run engine → new dataset |
| GET | `/api/datasets` | list datasets (switcher) |
| GET | `/api/dataset?id=` | active dataset hero/shape |
| POST | `/api/dataset/:id/activate` | switch active dataset |
| GET | `/api/incidents?...` | triage queue (score desc) |
| GET | `/api/incidents/:id` | full detail (graph + SHAP + baseline + playbook) |
| POST | `/api/report/:id` | IR report (mock, or Claude if `{apiKey}`) |
| GET | `/api/metrics?threshold=` | confusion / precision / recall / AUPRC + naive-DLP |

---

## Engine internals (for auditability)

`server/engine.js` is pure (no DB, no Express). Pipeline:
1. group events → per-user → per-user-day windows (SOC daily triage unit);
2. compute baseline per user from history (leave-one-day-out; robust trimmed mean for volume; p5–p95 padded work-hours band; resources seen on ≥2 prior days = "known"; weekend/off-hours habituation; cold-start → role-median fallback);
3. run the trigger battery **relative to that baseline** (VOLUME_ANOMALY/SOFT, LATERAL_MOVEMENT, BROAD/SENSITIVE_ACCESS, BULK_EXFIL, OFF_HOURS_VELOCITY, PRIV_ESCALATION, COMPROMISE_INDICATORS, STAGING_EXFIL, COVERT_CHANNEL) with mutual-exclusion to avoid double-counting the same node;
4. score `= round(100·(1−e^(−effRaw/38)))`, established-account mitigation only when **all** triggers are soft;
5. Hamilton largest-remainder integer SHAP (Σ === score);
6. per-user-day graph subgraph (nodes/edges + lateral-path cycle) for the attack-path SVG.

The exact config (weights, VOLUME_MULT, baseline window, thresholds) is snapshotted into `run_meta` per dataset.

---

## Deploy

`DB_PATH` env points SQLite at a persistent volume (defaults to `./data/insider.db`). `PORT` from env (Railway/Render inject it).

### Railway (primary)
Zero-config Node detection; `nixpacks.toml` pins Node 20 + native build toolchain for better-sqlite3; volume mounted at `/data`.
```bash
npx @railway/cli login && npx @railway/cli init && npx @railway/cli up
```
`railway.json` start = `npm run seed -- --keep && npm start`, healthcheck `/api/health`. Add a volume and set `DB_PATH=/data/insider.db`.

### Render (fallback)
Push to GitHub → New Blueprint → pick repo (`render.yaml` mounts a 1GB disk at `/data`, sets `DB_PATH`). Or `render blueprint launch`.

### Fly.io (fallback)
```bash
fly launch --now    # Dockerfile (node:20-slim + build-essential), fly.toml mounts a volume at /data
```

### Heroku-style hosts
`Procfile` provided (`web: npm run seed -- --keep && npm start`).

### Why not Vercel
Serverless filesystem is ephemeral — SQLite writes are lost between invocations. Use Railway/Render/Fly (persistent disk). For Vercel you'd need to swap SQLite for a hosted DB.

**If no CLI/auth is available**, the local run above is fully functional with the real engine + seeded corpus — that is the guaranteed deliverable.
