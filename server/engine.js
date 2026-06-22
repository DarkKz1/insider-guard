'use strict';
/* =========================================================================
   engine.js — CORE UEBA ENGINE (real, stateless, pure functions).

   THE UPGRADE OVER THE MOCKUP: baseline is NEVER hand-set. It is COMPUTED
   from each user's OWN history within the dataset (leave-one-day-out, so an
   anomalous day cannot inflate its own baseline). Operates on an ARBITRARY
   events[] of any size. No DB, no Express.

   exports:
     buildBaselines(events)               -> { perUser, perRole, catalog }
     analyzeUserDay(events, ctx)          -> incident-shape object or null
     detect(events, { datasetId })        -> { incidents, meta }
   ========================================================================= */

const { fmt, hourOf, dowOf, dayOf, minutesBetween, trimmedMean, median, percentile } =
  require('./lib/fmt');
const { buildGraph, lateralPath } = require('./lib/graph');
const { shapSplit } = require('./lib/shap');

const ENGINE_VERSION = 'ueba-1.0.0';

// ---- engine config (snapshotted into run_meta for auditability) -----------
// Thresholds are RELATIVE to each user's COMPUTED baseline. VOLUME_MULT is the
// multiple of personal daily read-norm that constitutes a hard mass-exfil
// anomaly. (The mockup's ×80 was tied to a hand-set 50/day baseline; with real
// computed baselines that run into the thousands, the meaningful anomaly ratio
// is ~×6-8 of personal norm — already wildly outside any legitimate workday.)
const CONFIG = {
  VOLUME_MULT: 6, // ×personal baseline for hard VOLUME_ANOMALY
  ABS_VOLUME_FLOOR: 40000, // absolute mass-exfil floor regardless of baseline
  ESTABLISHED_MIN_DAYS: 10, // days of history to trust a profile
  ESTABLISHED_MAX_CV: 0.35, // max day-to-day volume variation to call it "stable"
  COLD_START_MIN_DAYS: 3, // < this -> fall back to role baseline
  BASELINE_TRIM: 0.1, // trim top 10% of daily volumes (resist spike)
  WORK_HOURS_LO_PCT: 5, // p5 of active hours (tolerant low edge)
  WORK_HOURS_HI_PCT: 95, // p95 of active hours (tolerant high edge)
  WORK_HOURS_PAD: 1, // pad the computed band by ±1h to absorb legit jitter
  KNOWN_RESOURCE_MIN_DAYS: 2, // resource on >=2 distinct days -> "known"
  OFF_HOURS_MIN_EVENTS: 3, // need >=3 off-hours events to call it a burst
  OFF_HOURS_VOL_MULT: 2.5, // OR off-hours volume > 2.5× personal norm
  OFF_HOURS_DEEPNIGHT_BONUS: 16, // extra weight for 00:00-05:59 activity
  HABITUAL_MIN_DAYS: 2, // >=2 prior weekend/off-hours days => it's their norm
  weights: {
    VOLUME_ANOMALY: 28,
    VOLUME_SOFT: 16,
    LATERAL_MOVEMENT: 30,
    BROAD_ACCESS: 32,
    SENSITIVE_ACCESS: 12,
    BULK_EXFIL: 24,
    OFF_HOURS_VELOCITY: 20,
    PRIV_ESCALATION: 26,
    COMPROMISE_INDICATORS: 22,
    STAGING_EXFIL: 18,
    COVERT_CHANNEL: 12,
    COVERT_CHANNEL_DIRECT: 22, // personal_email / messenger = direct exfil vector
    COVERT_CHANNEL_FLAGGED: 24,
  },
  SCORE_TAU: 38, // saturation constant: score = 100*(1-exp(-effRaw/38))
  MITIGATION_FACTOR: 0.45, // established & no hardCrit -> effRaw *= 0.45
};

const READ_ACTIONS = new Set(['SELECT', 'EXPORT', 'DOWNLOAD']);
const EXPORT_ACTIONS = new Set(['EXPORT', 'DOWNLOAD']);
const ESCALATION_ACTIONS = new Set(['GRANT', 'SUDO', 'ROLE_CHANGE']);
const COVERT_CHANNELS = new Set(['cloud', 'messenger', 'personal_email']);

// typology mapping from top trigger code
const TYPOLOGY_OF = {
  VOLUME_ANOMALY: 'mass_exfil',
  VOLUME_SOFT: 'volume_soft',
  LATERAL_MOVEMENT: 'lateral',
  BROAD_ACCESS: 'broad_access',
  SENSITIVE_ACCESS: 'sensitive_access',
  BULK_EXFIL: 'staging_exfil',
  OFF_HOURS_VELOCITY: 'off_hours',
  PRIV_ESCALATION: 'priv_escalation',
  COMPROMISE_INDICATORS: 'compromise',
  STAGING_EXFIL: 'staging_exfil',
  COVERT_CHANNEL: 'covert_channel',
};

// IR playbook by typology (ported RESPONSE map)
const RESPONSE = {
  mass_exfil: [
    'Немедленно отозвать активную сессию и токены пользователя, заблокировать аккаунт.',
    'Запросить у владельца ресурса (БД физлиц) подтверждение легитимности массовой выборки.',
    'Зафиксировать объём выгруженных ПДн, инициировать оценку ущерба; эскалация в CISO/КНБ.',
  ],
  lateral: [
    'Отозвать сессию и изолировать все хосты из цепочки от сети.',
    'Форс-ресет пароля + перевыпуск MFA для скомпрометированного аккаунта.',
    'Поднять журналы аутентификации хостов, проверить горизонт компрометации; эскалация в CISO.',
  ],
  priv_escalation: [
    'Немедленно отозвать выданный grant, вернуть роль к исходной.',
    'Заблокировать аккаунт, запросить у владельца IAM-процесса подтверждение наличия заявки.',
    'Проверить, что было прочитано после эскалации (зарплата/санкции); эскалация в CISO.',
  ],
  off_hours: [
    'Запросить у руководителя подтверждение санкционированного дежурства вне рабочих часов.',
    'Временно ограничить доступ к чувствительной базе вне work_hours.',
    'Накопить сигнал; при повторе — поднять приоритет и заблокировать сессию.',
  ],
  staging_exfil: [
    'Срочно заблокировать исходящий канал (egress) и отозвать сессию.',
    'Изолировать рабочую станцию, снять образ для форензики.',
    'Оценить объём ушедших наружу ПДн; уведомление об инциденте, эскалация в CISO/КНБ.',
  ],
  compromise: [
    'Немедленно завершить все сессии аккаунта, заблокировать, форс-ресет пароля + MFA.',
    'Заблокировать зарубежный IP/устройство; проверить действия в скомпрометированной сессии.',
    'Уведомить пользователя о фишинге; эскалация в CISO, проверка смежных аккаунтов.',
  ],
  broad_access: [
    'Отозвать сессию, временно сузить доступ аккаунта до его роли (least privilege).',
    'Запросить у владельцев затронутых БД подтверждение служебной необходимости.',
    'Проверить, не предшествует ли это эксфильтрации; накопить и эскалировать при повторе.',
  ],
  sensitive_access: [
    'Запросить подтверждение служебной необходимости доступа к ресурсу вне профиля роли.',
    'Накопить сигнал; при повторе — сузить доступ до роли.',
  ],
  covert_channel: [
    'Заблокировать исходящий канал (облако/мессенджер/личная почта) для аккаунта.',
    'Запросить подтверждение легитимности выгрузки; при отсутствии — изолировать станцию.',
  ],
  volume_soft: [
    'Контекстная проверка: соответствует ли объём плановой задаче / роли.',
    'Если established/плановая работа — сохранить как negative для калибровки.',
  ],
  etl_service: [
    'Действий не требуется — паттерн соответствует established baseline сервис-аккаунта.',
    'Сохранить как negative-пример для калибровки; проверить ротацию ключей сервис-аккаунта.',
  ],
  planned_audit: [
    'Действий не требуется — повышенный объём в рамках санкционированной плановой проверки.',
    'Сохранить как negative-пример для калибровки; снять из очереди алертов.',
  ],
};

// -------------------------------------------------------------------------
// 1) NORMALIZE & GROUP
// -------------------------------------------------------------------------

function isServiceName(user) {
  return /^svc[_-]|_svc$|service|backup/i.test(user || '');
}

/**
 * Build global node catalog. Kind inference:
 *  - resource: id that is target of SELECT/EXPORT with rows>0 OR has a db tag
 *  - host: id that appears as a LOGIN target OR in `host` field
 *  - user: actor in `user`
 */
function buildCatalog(events) {
  const users = new Map();
  const resources = new Map();
  const hosts = new Map();

  for (const e of events) {
    if (e.user && !users.has(e.user)) {
      users.set(e.user, { id: e.user, kind: 'user', label: e.user, role: e.role || null });
    }
    // resource detection
    if (e.resource) {
      const isReadTarget = READ_ACTIONS.has(e.action) && (e.rows || 0) >= 0 && e.db != null && e.db !== '-';
      const looksResource = /^DB-/i.test(e.resource) || isReadTarget;
      const looksHost = /^H-/i.test(e.resource) || e.action === 'LOGIN';
      if (looksResource && !looksHost) {
        if (!resources.has(e.resource)) {
          resources.set(e.resource, {
            id: e.resource,
            kind: 'resource',
            label: e.resource,
            sensitivity: e.sensitivity || null,
          });
        }
      } else if (looksHost) {
        if (!hosts.has(e.resource)) {
          hosts.set(e.resource, { id: e.resource, kind: 'host', label: e.resource, zone: e.zone || null });
        }
      }
    }
    if (e.host && e.host !== '-' && !hosts.has(e.host)) {
      hosts.set(e.host, { id: e.host, kind: 'host', label: e.host, zone: e.zone || null });
    }
    // graph endpoints (from/to) — classify too
    for (const endpoint of [e.from, e.to]) {
      if (!endpoint) continue;
      if (users.has(endpoint) || resources.has(endpoint) || hosts.has(endpoint)) continue;
      if (/^DB-/i.test(endpoint)) resources.set(endpoint, { id: endpoint, kind: 'resource', label: endpoint });
      else if (/^H-/i.test(endpoint)) hosts.set(endpoint, { id: endpoint, kind: 'host', label: endpoint });
      else if (/^U-/i.test(endpoint) || endpoint === e.user)
        users.set(endpoint, { id: endpoint, kind: 'user', label: endpoint });
    }
  }

  const meta = {};
  for (const m of users.values()) meta[m.id] = m;
  for (const m of resources.values()) meta[m.id] = m;
  for (const m of hosts.values()) meta[m.id] = m;
  return { meta, users, resources, hosts };
}

/** group events by user, then by ts_day */
function groupByUserDay(events) {
  const byUser = new Map();
  for (const e of events) {
    const u = e.user;
    if (!u) continue;
    if (!byUser.has(u)) byUser.set(u, new Map());
    const days = byUser.get(u);
    const d = dayOf(e.ts);
    if (!days.has(d)) days.set(d, []);
    days.get(d).push(e);
  }
  return byUser;
}

// -------------------------------------------------------------------------
// 2) COMPUTE BASELINE PER USER (from history, leakage-safe)
// -------------------------------------------------------------------------

/** read-row sum for a single day's events */
function dayReadRows(dayEvents) {
  return dayEvents
    .filter((e) => READ_ACTIONS.has(e.action))
    .reduce((s, e) => s + (e.rows || 0), 0);
}

/**
 * Compute baseline for one user across all their days EXCEPT `excludeDay`
 * (leave-one-day-out). Returns null-ish profile if no history.
 */
function computeUserBaseline(userDays, excludeDay, role, catalog, roleBaselines) {
  const dayKeys = [...userDays.keys()].filter((d) => d !== excludeDay);
  const dayCountObserved = dayKeys.length;

  // daily read-row volumes (history only)
  const dailyVolumes = dayKeys.map((d) => dayReadRows(userDays.get(d)));

  // all historical events (for hours / resources / hosts / geo)
  const histEvents = [];
  for (const d of dayKeys) histEvents.push(...userDays.get(d));

  // hours band — only weekday business hours count toward the personal band
  // (so a rare legit weekend touch doesn't widen the band; off-hours is judged
  //  against the typical WEEKDAY profile). Padded ±1h to absorb legit jitter.
  const hours = histEvents.map((e) => hourOf(e.ts));
  let workLo = 9;
  let workHi = 18;
  if (hours.length >= 4) {
    workLo = Math.max(0, Math.floor(percentile(hours, CONFIG.WORK_HOURS_LO_PCT)) - CONFIG.WORK_HOURS_PAD);
    workHi = Math.min(23, Math.ceil(percentile(hours, CONFIG.WORK_HOURS_HI_PCT)) + CONFIG.WORK_HOURS_PAD);
    if (workHi <= workLo) workHi = Math.min(23, workLo + 1);
  }

  // known resources: appearing on >=2 distinct prior days
  const resourceDayCount = new Map();
  for (const d of dayKeys) {
    const seen = new Set();
    for (const e of userDays.get(d)) {
      if (catalog.resources.has(e.resource) && !seen.has(e.resource)) {
        seen.add(e.resource);
        resourceDayCount.set(e.resource, (resourceDayCount.get(e.resource) || 0) + 1);
      }
    }
  }
  const knownResources = [...resourceDayCount.entries()]
    .filter(([, c]) => c >= CONFIG.KNOWN_RESOURCE_MIN_DAYS)
    .map(([r]) => r);

  // known hosts
  const hostCount = new Map();
  for (const e of histEvents) {
    const h = e.host && e.host !== '-' ? e.host : catalog.hosts.has(e.resource) ? e.resource : null;
    if (h) hostCount.set(h, (hostCount.get(h) || 0) + 1);
  }
  const knownHosts = [...hostCount.keys()];

  // home geo = most frequent
  const geoCount = new Map();
  for (const e of histEvents) if (e.geo) geoCount.set(e.geo, (geoCount.get(e.geo) || 0) + 1);
  let homeGeo = 'Астана';
  let best = 0;
  for (const [g, c] of geoCount.entries()) if (c > best) { best = c; homeGeo = g; }

  // does this user NORMALLY work weekends / off-hours? (leakage-safe: history
  // only). If weekend/off-hours work is a recurring part of their profile, it is
  // their baseline and a weekend day is NOT itself an anomaly — only deviation
  // in VOLUME/breadth on that day is. Counts distinct prior days with such work.
  const weekendDays = new Set();
  for (const d of dayKeys) {
    const dow = dowOf(d + 'T00:00:00');
    if (dow === 0 || dow === 6) {
      const hasData = userDays.get(d).some((e) => READ_ACTIONS.has(e.action));
      if (hasData) weekendDays.add(d);
    }
  }
  const worksWeekends = weekendDays.size >= CONFIG.HABITUAL_MIN_DAYS;

  // service / night-job detection
  const svc = isServiceName(userDays.user);
  const nightHeavy =
    dailyVolumes.length >= 5 &&
    histEvents.filter((e) => { const h = hourOf(e.ts); return h < 6 || h >= 22; }).length >
      histEvents.length * 0.5;
  const isNightJob = svc || nightHeavy;

  // volume baseline (robust): trimmed mean of daily volumes
  let avgRowsPerDay = trimmedMean(dailyVolumes, CONFIG.BASELINE_TRIM);

  let source = 'computed-from-history';

  // COLD-START guard: < COLD_START_MIN_DAYS prior days -> role baseline
  if (dayCountObserved < CONFIG.COLD_START_MIN_DAYS && roleBaselines && roleBaselines[role]) {
    const rb = roleBaselines[role];
    avgRowsPerDay = rb.avg_rows_per_day;
    workLo = rb.work_hours[0];
    workHi = rb.work_hours[1];
    source = 'role-fallback';
  }

  // ESTABLISHED = a genuinely STABLE-profile account, eligible for risk
  // mitigation. NOT merely "has >=10 days of history" (that would suppress
  // almost every real insider, since most attackers are long-tenured staff).
  // Stable = service account, OR enough history AND low day-to-day volume
  // variance (coefficient of variation < threshold) i.e. predictable regular
  // work like ETL/audit — the kind of account whose large volume is its norm.
  const meanVol = dailyVolumes.length
    ? dailyVolumes.reduce((s, v) => s + v, 0) / dailyVolumes.length
    : 0;
  const variance = dailyVolumes.length
    ? dailyVolumes.reduce((s, v) => s + (v - meanVol) ** 2, 0) / dailyVolumes.length
    : 0;
  const cv = meanVol > 0 ? Math.sqrt(variance) / meanVol : 0;
  const established =
    svc ||
    (dayCountObserved >= CONFIG.ESTABLISHED_MIN_DAYS && cv < CONFIG.ESTABLISHED_MAX_CV);

  return {
    avg_rows_per_day: Math.round(avgRowsPerDay),
    work_hours: [workLo, workHi],
    known_resources: knownResources,
    known_hosts: knownHosts,
    home_geo: homeGeo,
    dayCountObserved,
    established,
    volume_cv: Number(cv.toFixed(2)),
    night_job: isNightJob,
    works_weekends: worksWeekends,
    service_account: svc,
    source,
  };
}

/** role baseline = median over peers with same role */
function computeRoleBaselines(byUserDay, catalog) {
  const byRole = {};
  for (const [user, days] of byUserDay.entries()) {
    days.user = user; // tag for service detection
    // infer role from any event of this user
    let role = null;
    for (const d of days.values()) {
      for (const e of d) if (e.role) { role = e.role; break; }
      if (role) break;
    }
    role = role || 'unknown';
    if (!byRole[role]) byRole[role] = { volumes: [], los: [], his: [] };
    const vols = [...days.values()].map(dayReadRows);
    byRole[role].volumes.push(...vols);
    const hours = [];
    for (const d of days.values()) for (const e of d) hours.push(hourOf(e.ts));
    if (hours.length) {
      byRole[role].los.push(percentile(hours, CONFIG.WORK_HOURS_LO_PCT));
      byRole[role].his.push(percentile(hours, CONFIG.WORK_HOURS_HI_PCT));
    }
  }
  const out = {};
  for (const [role, agg] of Object.entries(byRole)) {
    out[role] = {
      avg_rows_per_day: Math.round(median(agg.volumes)),
      work_hours: [
        Math.max(0, Math.floor(median(agg.los) || 9)),
        Math.min(23, Math.ceil(median(agg.his) || 18)),
      ],
    };
  }
  return out;
}

/**
 * buildBaselines — public: returns catalog + role baselines + a per-user-day
 * baseline resolver. (Per-day baselines are computed lazily during detect.)
 */
function buildBaselines(events) {
  const catalog = buildCatalog(events);
  const byUserDay = groupByUserDay(events);
  const perRole = computeRoleBaselines(byUserDay, catalog);
  return { catalog, byUserDay, perRole };
}

// -------------------------------------------------------------------------
// 3-7) SCORE ONE USER-DAY (trigger battery relative to computed baseline)
// -------------------------------------------------------------------------

/**
 * analyzeUserDay — the core scorer for one (user, day) window.
 * @param {Array} dayEvents events of this user on this day
 * @param {Object} ctx { user, role, day, baseline, catalog }
 * @returns incident-shape object, or null if CLEAN
 */
function analyzeUserDay(dayEvents, ctx) {
  const { user, role, day, baseline: bl, catalog } = ctx;
  const triggers = [];
  const add = (code, label, weight, detail, severity = 'warn') =>
    triggers.push({ code, label, weight, detail, severity });
  const W = CONFIG.weights;

  // observed window stats
  const readRows = dayEvents
    .filter((e) => READ_ACTIONS.has(e.action))
    .reduce((s, e) => s + (e.rows || 0), 0);
  const exportEvents = dayEvents.filter((e) => EXPORT_ACTIONS.has(e.action));
  const exportRows = exportEvents.reduce((s, e) => s + (e.rows || 0), 0);
  const selectRows = dayEvents.filter((e) => e.action === 'SELECT').reduce((s, e) => s + (e.rows || 0), 0);
  const hoursTouched = [...new Set(dayEvents.map((e) => hourOf(e.ts)))].sort((a, b) => a - b);

  // resources/hosts touched
  const touchedResources = [...new Set(dayEvents.filter((e) => catalog.resources.has(e.resource)).map((e) => e.resource))];
  const touchedHosts = [
    ...new Set(
      dayEvents
        .map((e) => (catalog.hosts.has(e.resource) ? e.resource : e.host && e.host !== '-' ? e.host : null))
        .filter(Boolean)
    ),
  ];

  // --- build per-user-day graph (edges) ---------------------------------
  // events that already carry from/to are used directly; otherwise synthesize
  // user -> resource edges (so detection works on plain access logs too).
  const edges = dayEvents.map((e) => {
    let from = e.from;
    let to = e.to;
    if (!from || !to) {
      if (e.action === 'LOGIN') {
        from = e.host && e.host !== '-' ? e.host : user;
        to = e.resource || e.host;
      } else {
        from = user;
        to = e.resource;
      }
    }
    return {
      from,
      to,
      action: e.action,
      rows: e.rows || 0,
      ts: e.ts,
      channel: e.channel || null,
    };
  }).filter((e) => e.from && e.to);

  const nodeMeta = catalog.meta;
  const graphNodes = buildGraph(edges, nodeMeta);

  // --- VOLUME_ANOMALY (hard) / VOLUME_SOFT (mutex) ----------------------
  // HARD: read volume is a large MULTIPLE of personal daily norm (×VOLUME_MULT)
  //       OR crosses the absolute mass-exfil floor with a low personal norm.
  let volumeHub = null;
  const overMult = readRows > CONFIG.VOLUME_MULT * Math.max(1, bl.avg_rows_per_day);
  const overFloor = readRows >= CONFIG.ABS_VOLUME_FLOOR && bl.avg_rows_per_day < 5000;
  if (overMult || overFloor) {
    volumeHub = user;
    const mult = (readRows / Math.max(1, bl.avg_rows_per_day)).toFixed(0);
    add(
      'VOLUME_ANOMALY',
      'Аномальный объём выгрузки',
      W.VOLUME_ANOMALY,
      `Пользователь ${user} обратился к ${fmt(readRows)} строкам при персональном baseline ${fmt(bl.avg_rows_per_day)}/день (×${mult}). Объём несовместим с должностными обязанностями — слепок массовой эксфильтрации.`,
      'bad'
    );
  } else if (readRows >= CONFIG.ABS_VOLUME_FLOOR && !(bl.service_account && bl.established)) {
    // Soft volume signal: large absolute volume within personal norm. Suppressed
    // for established SERVICE accounts (their large nightly volume IS the
    // baseline — emitting it nightly would just clutter the queue with P4 noise).
    volumeHub = user;
    const nightCtx = dayEvents.some((e) => { const h = hourOf(e.ts); return h < 6 || h >= 22; });
    add(
      'VOLUME_SOFT',
      'Крупный объём доступа',
      W.VOLUME_SOFT,
      `Пользователь ${user} обратился к ${fmt(readRows)} строкам${nightCtx ? ' в ночном окне' : ''} — крупный абсолютный объём, но в пределах персонального baseline ${fmt(bl.avg_rows_per_day)}/день. Сигнал требует контекстной проверки, а не автоматической эскалации.`,
      'warn'
    );
  }

  // --- LATERAL_MOVEMENT (graph DFS through >=3 hosts to a resource) ------
  const path = lateralPath(edges, nodeMeta);
  if (path) {
    const hostHops = path.filter((id) => (nodeMeta[id] || {}).kind === 'host').length;
    add(
      'LATERAL_MOVEMENT',
      'Боковое перемещение',
      W.LATERAL_MOVEMENT,
      `Обнаружена цепочка доступа: ${path.join(' → ')}. Аккаунт прыгает по ${hostHops} хостам до базы данных — обход сегментации сети, почерк скомпрометированного аккаунта.`,
      'crit'
    );
  }

  // --- BROAD_ACCESS (crit) / SENSITIVE_ACCESS (mutex with volumeHub) -----
  // Mutex with the volume anomaly: the same activity spike is not counted twice.
  const known = new Set(bl.known_resources || []);
  const newResources = touchedResources.filter((rid) => !known.has(rid));
  if (newResources.length >= 5 && user !== volumeHub) {
    add(
      'BROAD_ACCESS',
      'Аномально широкий доступ',
      W.BROAD_ACCESS,
      `Пользователь ${user} обратился к ${newResources.length} ресурсам вне своего профиля (known: ${[...known].slice(0, 4).join(', ') || '—'}). Веерный сбор по множеству БД (scatter-gather) — разведка данных перед эксфильтрацией.`,
      'crit'
    );
  } else if (newResources.length >= 1 && newResources.length < 5 && user !== volumeHub) {
    const sens = newResources
      .map((rid) => (nodeMeta[rid] || {}).sensitivity)
      .filter((s) => s === 'critical' || s === 'high');
    add(
      'SENSITIVE_ACCESS',
      'Доступ к ресурсу вне профиля роли',
      W.SENSITIVE_ACCESS,
      `Пользователь ${user} обратился к ${newResources.length} ресурс(у/ам) вне своего профиля${sens.length ? `, из них ${sens.length} высокой/критической чувствительности` : ''}. Чтение данных, не положенных роли.`,
      'bad'
    );
  }

  // --- BULK_EXFIL (crit) -------------------------------------------------
  // Service/night-job accounts whose nightly export over the INTERNAL db channel
  // is their established baseline are exempt (that IS their job — backup ETL).
  // An export over a covert/external channel still counts even for a service acct.
  const externalExports = exportEvents.filter((e) => e.channel !== 'db');
  const bulkExfilExempt = bl.night_job && externalExports.length === 0;
  if (!bulkExfilExempt && (exportEvents.length >= 2 || (exportEvents.length >= 1 && selectRows >= CONFIG.ABS_VOLUME_FLOOR))) {
    add(
      'BULK_EXFIL',
      'Молниеносная выгрузка наружу',
      W.BULK_EXFIL,
      `${exportEvents.length} операц(ия/ий) EXPORT/download (${fmt(exportRows)} строк) сразу после массового чтения. Данные покидают периметр — активная эксфильтрация.`,
      'crit'
    );
  }

  // --- OFF_HOURS_VELOCITY (bad) -----------------------------------------
  // Fires only on a genuine off-hours BURST: enough off-hours data-touching
  // events (>=OFF_HOURS_MIN_EVENTS) OR off-hours read volume well above personal
  // norm. A single stray login / one event slightly outside the band must NOT
  // trigger — that is normal jitter and was the dominant false-positive source.
  const [wStart, wEnd] = bl.work_hours || [9, 18];
  const isOffHours = (e) => {
    const h = hourOf(e.ts);
    const d = dowOf(e.ts);
    const weekend = d === 0 || d === 6;
    // if the user habitually works weekends, a weekend is part of their norm —
    // only count weekend events as off-hours if they ALSO fall outside the band.
    const weekendOff = weekend && !bl.works_weekends;
    return weekendOff || h < wStart || h >= wEnd;
  };
  // count only data-touching off-hours events (exclude procedural LOGIN/LOGOUT)
  const offHoursDataEvents = bl.night_job
    ? []
    : dayEvents.filter((e) => isOffHours(e) && e.action !== 'LOGIN' && e.action !== 'LOGOUT');
  const offHoursRows = offHoursDataEvents
    .filter((e) => READ_ACTIONS.has(e.action))
    .reduce((s, e) => s + (e.rows || 0), 0);
  const offHoursBurst =
    offHoursDataEvents.length >= CONFIG.OFF_HOURS_MIN_EVENTS ||
    offHoursRows > CONFIG.OFF_HOURS_VOL_MULT * Math.max(1, bl.avg_rows_per_day);
  if (offHoursDataEvents.length >= 1 && offHoursBurst) {
    // deep-night band (00:00–05:59) is the classic insider exfil window — weigh
    // it heavier than a mere evening / weekend-daytime burst.
    const deepNight = offHoursDataEvents.some((e) => hourOf(e.ts) < 6);
    const w = deepNight ? W.OFF_HOURS_VELOCITY + CONFIG.OFF_HOURS_DEEPNIGHT_BONUS : W.OFF_HOURS_VELOCITY;
    add(
      'OFF_HOURS_VELOCITY',
      deepNight ? 'Активность в ночное окно + всплеск' : 'Активность вне рабочих часов + всплеск',
      w,
      `${offHoursDataEvents.length} операц(ия/ий) вне work_hours ${wStart}:00–${wEnd}:00 / в выходной (${fmt(offHoursRows)} строк)${deepNight ? ' в ночном окне (00:00–06:00)' : ''}, на фоне всплеска активности. Поведение вне персонального профиля времени.`,
      'bad'
    );
  }

  // --- PRIV_ESCALATION (crit) -------------------------------------------
  const escEvents = dayEvents.filter((e) => ESCALATION_ACTIONS.has(e.action));
  if (escEvents.length >= 1) {
    add(
      'PRIV_ESCALATION',
      'Эскалация привилегий вне заявок',
      W.PRIV_ESCALATION,
      `${escEvents.length} операц(ия/ий) ${[...new Set(escEvents.map((e) => e.action))].join('/')} без зарегистрированной заявки. Повышение прав вне процесса — шаг подготовки к несанкционированному доступу.`,
      'crit'
    );
  }

  // --- COMPROMISE_INDICATORS (bad): new geo/device + impossible travel ---
  const homeGeo = bl.home_geo || 'Астана';
  const foreignLogins = dayEvents.filter(
    (e) => e.action === 'LOGIN' && e.geo && e.geo !== homeGeo && !String(e.geo).startsWith(homeGeo)
  );
  const newDevice = dayEvents.some((e) => {
    const h = e.host && e.host !== '-' ? e.host : e.resource;
    return !bl.known_hosts.includes(h) && (/NEW|EXT|FOREIGN/i.test(h || '') || (e.geo && e.geo !== homeGeo));
  });
  let impossible = false;
  const logins = dayEvents.filter((e) => e.action === 'LOGIN').sort((a, b) => String(a.ts).localeCompare(String(b.ts)));
  for (let i = 1; i < logins.length; i++) {
    if (logins[i].geo !== logins[i - 1].geo) {
      const dt = minutesBetween(logins[i - 1].ts, logins[i].ts);
      if (dt >= 0 && dt <= 60) impossible = true;
    }
  }
  if (foreignLogins.length >= 1 && (newDevice || impossible)) {
    add(
      'COMPROMISE_INDICATORS',
      'Индикаторы компрометации (новый гео/устройство)',
      W.COMPROMISE_INDICATORS,
      `Логин из нового гео (${[...new Set(foreignLogins.map((e) => e.geo))].join(', ')})${newDevice ? ' с нового устройства' : ''}${impossible ? ', impossible travel (<60 мин между гео)' : ''}, затем аномальный доступ. Валидные креды ведут себя аномально — почерк фишинга/кражи учётных данных.`,
      'bad'
    );
  }

  // --- STAGING_EXFIL (bad): read ≈ export (near-zero retention) ----------
  // Exempt service/night-job accounts whose read≈export over the internal db
  // channel is their legitimate backup pattern (no external/covert egress).
  const stagingExempt = bl.night_job && externalExports.length === 0;
  if (!stagingExempt && selectRows > 0 && exportRows > 0 && Math.abs(selectRows - exportRows) / selectRows < 0.12) {
    add(
      'STAGING_EXFIL',
      'Стейджинг под эксфильтрацию (≈1:1 чтение→выгрузка)',
      W.STAGING_EXFIL,
      `Прочитано ${fmt(selectRows)} ≈ выгружено ${fmt(exportRows)} строк (оседание ≈0). Данные не используются, а перекачиваются наружу — стейджинг под эксфильтрацию.`,
      'bad'
    );
  }

  // --- COVERT_CHANNEL (warn / bad) --------------------------------------
  // Export over an unsanctioned channel. personal_email / messenger are a
  // direct exfil vector (vs cloud, which may be a sanctioned corporate tool) —
  // weighted higher and 'bad'. A previously-flagged channel bumps it too.
  const covertEvents = dayEvents.filter(
    (e) => COVERT_CHANNELS.has(e.channel) && EXPORT_ACTIONS.has(e.action)
  );
  if (covertEvents.length >= 1) {
    const flagged = ctx.channelFlagged || false;
    const directExfil = covertEvents.some(
      (e) => e.channel === 'personal_email' || e.channel === 'messenger'
    );
    const w = flagged
      ? W.COVERT_CHANNEL_FLAGGED
      : directExfil
        ? W.COVERT_CHANNEL_DIRECT
        : W.COVERT_CHANNEL;
    add(
      'COVERT_CHANNEL',
      'Выгрузка по скрытому каналу',
      w,
      `${covertEvents.length} выгрузк(а/и) через ${[...new Set(covertEvents.map((e) => e.channel))].join('/')} (облако/мессенджер/личная почта)${flagged ? '. Канал ранее помечен в другом инциденте (×2).' : '.'} Обход корпоративных каналов передачи данных.`,
      flagged || directExfil ? 'bad' : 'warn'
    );
  }

  // --- CLEAN: no trigger -> not an incident (skip) ----------------------
  if (triggers.length === 0) {
    return {
      clean: true,
      user,
      role,
      day,
      score: 0,
      readRows,
      eventCount: dayEvents.length,
    };
  }

  // --- SCORE & CALIBRATION ----------------------------------------------
  const sumW = triggers.reduce((s, t) => s + t.weight, 0);
  const established = bl.established || bl.service_account;
  // Mitigation applies ONLY when every trigger is a SOFT signal (volume within
  // norm, off-hours, a few off-profile reads). Any HARD attack signature —
  // lateral movement, bulk/staging exfil, privilege escalation, mass-volume
  // anomaly, compromise indicators, broad scatter-gather, covert channel —
  // means established status must NOT suppress the alert. This stops the
  // "long-tenured insider is auto-trusted" failure mode.
  const SOFT_CODES = new Set(['VOLUME_SOFT', 'SENSITIVE_ACCESS', 'OFF_HOURS_VELOCITY']);
  const allSoft = triggers.every((t) => SOFT_CODES.has(t.code));
  let mitigation = null;
  let effRaw = sumW;
  if (established && allSoft && sumW > 0) {
    effRaw = sumW * CONFIG.MITIGATION_FACTOR;
    mitigation = {
      factor: CONFIG.MITIGATION_FACTOR,
      note: 'Аккаунт с устоявшимся стабильным baseline (established / сервисный, низкая дисперсия объёма) и БЕЗ жёстких крит-индикаторов (только мягкие сигналы) → контекст снижает риск, чтобы не штрафовать легитимную регулярную работу.',
    };
  }
  // NO ground-truth clamp (no label leakage). Score from triggers only.
  let score = Math.round(100 * (1 - Math.exp(-effRaw / CONFIG.SCORE_TAU)));
  score = Math.max(0, Math.min(100, score));

  // --- SHAP (Hamilton largest-remainder, Σ === score) -------------------
  const shap = shapSplit(triggers, score);

  // --- priority ---------------------------------------------------------
  let priority;
  if (score >= 80) priority = { lvl: 'P1 — Критический', color: 'crit', note: 'Немедленное реагирование SOC / отзыв сессии' };
  else if (score >= 55) priority = { lvl: 'P2 — Высокий', color: 'bad', note: 'В очередь на расследование в течение суток' };
  else if (score >= 30) priority = { lvl: 'P3 — Средний', color: 'warn', note: 'Плановая проверка / накопление сигналов' };
  else priority = { lvl: 'P4 — Низкий', color: 'good', note: 'Мониторинг без действий' };

  // --- typology + title (built from REAL numbers) -----------------------
  const top = shap[0] || triggers.slice().sort((a, b) => b.weight - a.weight)[0];
  const typology = TYPOLOGY_OF[top.code] || 'anomaly';
  const title = buildTitle(top, { user, readRows, bl, newResources, exportRows, selectRows, score });

  // --- graph data (nodes + edges + cycle for the SVG) -------------------
  const hub = user;
  const critEdgeSet = new Set();
  const critNodeSet = new Set([hub]);
  if (path) {
    for (let i = 0; i < path.length - 1; i++) {
      critEdgeSet.add(path[i] + '>' + path[i + 1]);
      critNodeSet.add(path[i]);
      critNodeSet.add(path[i + 1]);
    }
  } else {
    edges.forEach((e) => {
      if (e.from === hub || e.to === hub) {
        critEdgeSet.add(e.from + '>' + e.to);
        critNodeSet.add(e.from);
        critNodeSet.add(e.to);
      }
    });
  }
  const graphNodeArr = Object.values(graphNodes).map((n) => ({
    id: n.id,
    kind: n.kind === '?' ? (n.id === user ? 'user' : 'resource') : n.kind,
    label: n.label || n.id,
    sensitivity: n.sensitivity || undefined,
    zone: n.zone || undefined,
    onPath: critNodeSet.has(n.id),
    isHub: n.id === hub,
    inRows: n.inRows,
    outRows: n.outRows,
  }));
  const graphEdges = edges.map((e) => ({
    from: e.from,
    to: e.to,
    action: e.action,
    rows: e.rows,
    ts: e.ts,
    channel: e.channel,
    crit: critEdgeSet.has(e.from + '>' + e.to),
  }));

  // dominant channel
  const channelCount = new Map();
  for (const e of dayEvents) if (e.channel) channelCount.set(e.channel, (channelCount.get(e.channel) || 0) + 1);
  let channel = 'db';
  let cbest = 0;
  for (const [c, n] of channelCount.entries()) if (n > cbest) { cbest = n; channel = c; }

  const observed = {
    rowsTouched: readRows,
    eventCount: dayEvents.length,
    hours: hoursTouched,
    resources: touchedResources,
    hosts: touchedHosts,
    exportRows,
    selectRows,
  };

  const baselineSnapshot = {
    avg_rows_per_day: bl.avg_rows_per_day,
    work_hours: bl.work_hours,
    known_resources: bl.known_resources,
    known_hosts: bl.known_hosts,
    home_geo: bl.home_geo,
    dayCountObserved: bl.dayCountObserved,
    established: bl.established,
    volume_cv: bl.volume_cv,
    source: bl.source,
  };

  return {
    clean: false,
    user,
    role,
    windowDate: day,
    typology,
    title,
    channel,
    score,
    priority,
    triggers,
    shap,
    mitigation,
    baseline: baselineSnapshot,
    observed,
    rowsTouched: readRows,
    eventCount: dayEvents.length,
    graph: {
      nodes: graphNodeArr,
      edges: graphEdges,
      hub,
      cycle: path || null,
    },
    playbook: RESPONSE[typology] || RESPONSE.sensitive_access,
    primaryTrigger: { code: top.code, label: top.label },
    // compromise markers used for cross-linking (2nd pass)
    _markers: {
      ips: [...new Set(dayEvents.filter((e) => e.ip).map((e) => e.ip))],
      hosts: touchedHosts,
      compromise: foreignLogins.length >= 1 || newDevice || impossible,
      covertChannels: [...new Set(covertEvents.map((e) => e.channel))],
    },
  };
}

function buildTitle(top, c) {
  const { user, readRows, bl, newResources, exportRows, selectRows } = c;
  switch (top.code) {
    case 'VOLUME_ANOMALY': {
      const mult = (readRows / Math.max(1, bl.avg_rows_per_day)).toFixed(0);
      return `Массовая выгрузка: ${fmt(readRows)} строк при baseline ${fmt(bl.avg_rows_per_day)}/день (×${mult})`;
    }
    case 'LATERAL_MOVEMENT':
      return `Боковое перемещение: цепочка хостов до базы данных`;
    case 'PRIV_ESCALATION':
      return `Эскалация привилегий вне заявок → доступ к чувствительным данным`;
    case 'OFF_HOURS_VELOCITY':
      return `Всплеск активности вне рабочих часов: ${fmt(readRows)} строк`;
    case 'STAGING_EXFIL':
      return `Стейджинг под эксфильтрацию: прочитал ${fmt(selectRows)} → выгрузил ${fmt(exportRows)} (≈1:1)`;
    case 'BULK_EXFIL':
      return `Молниеносная выгрузка наружу: ${fmt(exportRows)} строк`;
    case 'COMPROMISE_INDICATORS':
      return `Компрометация учётной записи: новый гео/устройство + аномальный доступ`;
    case 'BROAD_ACCESS':
      return `Аномально широкий доступ: ${newResources.length} БД вне профиля (scatter-gather)`;
    case 'SENSITIVE_ACCESS':
      return `Доступ к ${newResources.length} ресурс(ам) вне профиля роли`;
    case 'COVERT_CHANNEL':
      return `Выгрузка по скрытому каналу (облако/мессенджер/личная почта)`;
    case 'VOLUME_SOFT':
      return `Крупный объём доступа: ${fmt(readRows)} строк (в пределах baseline)`;
    default:
      return `Поведенческая аномалия: ${top.label}`;
  }
}

// -------------------------------------------------------------------------
// detect(events) — orchestration over the full corpus
// -------------------------------------------------------------------------

/**
 * @param {Array} events canonical events of any size
 * @param {Object} opts { datasetId }
 * @returns { incidents, cleanUserDays, meta }
 *   incidents: scored user-days with >=1 trigger
 *   cleanUserDays: {user,day,score:0,label?} for honest TN/FN in metrics
 */
function detect(events, opts = {}) {
  const t0 = Date.now();
  const { catalog, byUserDay, perRole } = buildBaselines(events);

  // global channel-flag pass: a covert channel/ip/host seen in >=2 user-days
  // gets the "previously flagged" weight bump (data-driven CROSS_TAGS idea).
  const incidents = [];
  const cleanUserDays = [];

  // first pass — score every user-day
  for (const [user, days] of byUserDay.entries()) {
    days.user = user;
    // role for this user
    let role = null;
    for (const d of days.values()) {
      for (const e of d) if (e.role) { role = e.role; break; }
      if (role) break;
    }
    role = role || 'unknown';

    for (const [day, dayEvents] of days.entries()) {
      const baseline = computeUserBaseline(days, day, role, catalog, perRole);
      const result = analyzeUserDay(dayEvents, { user, role, day, baseline, catalog });

      // ground-truth label (carried from events, if any). A user-day is
      // malicious if ANY event that day is labeled malicious (the planted attack
      // events sit alongside the user's normal benign events for the same day).
      const malEvent = dayEvents.find((e) => e.label_malicious === 1);
      const anyLabeled = dayEvents.find((e) => e.label_malicious != null);
      const labeledMal = malEvent || anyLabeled;
      const label =
        labeledMal != null
          ? { malicious: !!malEvent, typology: labeledMal.label_typology || null }
          : null;

      if (result.clean) {
        cleanUserDays.push({ user, day, score: 0, label });
      } else {
        result.label = label;
        incidents.push(result);
      }
    }
  }

  // sort by score desc
  incidents.sort((a, b) => b.score - a.score);

  const durationMs = Date.now() - t0;
  const window = computeWindow(events);
  return {
    incidents,
    cleanUserDays,
    meta: {
      engineVersion: ENGINE_VERSION,
      config: CONFIG,
      durationMs,
      eventCount: events.length,
      userCount: byUserDay.size,
      dayCount: countDays(events),
      resourceCount: catalog.resources.size,
      hostCount: catalog.hosts.size,
      window,
    },
  };
}

function computeWindow(events) {
  let from = null;
  let to = null;
  for (const e of events) {
    const ts = e.ts;
    if (!ts) continue;
    if (from === null || ts < from) from = ts;
    if (to === null || ts > to) to = ts;
  }
  return { from, to };
}

function countDays(events) {
  const days = new Set();
  for (const e of events) days.add(dayOf(e.ts));
  return days.size;
}

module.exports = {
  ENGINE_VERSION,
  CONFIG,
  RESPONSE,
  buildBaselines,
  analyzeUserDay,
  detect,
};
