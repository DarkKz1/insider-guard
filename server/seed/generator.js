'use strict';
// generator.js — deterministic synthetic NORMAL activity generator.
// Seeded PRNG => reproducible corpus. Per-user behavioural profiles -> daily events.

const { ROLES, RESOURCES, HOSTS, HOME_GEO, WINDOW_DAYS, WINDOW_END } = require('./catalog');

// ---- seeded PRNG (mulberry32) ---------------------------------------------
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// poisson via Knuth
function poisson(rng, lambda) {
  const L = Math.exp(-lambda);
  let k = 0;
  let p = 1;
  do {
    k++;
    p *= rng();
  } while (p > L);
  return k - 1;
}

// log-normal-ish row volume around a center
function logNormalRows(rng, center, sigma) {
  // gaussian via Box-Muller
  const u1 = Math.max(1e-9, rng());
  const u2 = rng();
  const z = Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  const factor = Math.exp(z * sigma);
  return Math.max(1, Math.round(center * factor));
}

function pad2(n) {
  return String(n).padStart(2, '0');
}

// build the day list (business-day weighted: weekends sparse).
// Compute every day purely from the UTC calendar so the corpus is byte-identical
// on any host timezone (Vercel runs UTC; a local TZ would otherwise shift the
// window and day-of-week, changing weekend sparsity and the incident count).
// We anchor to noon-UTC to avoid any DST/rounding edge and read the date in UTC.
// This reproduces the documented demo deterministically: 12 344 events /
// 13 incidents (the 8 labeled threats all surface as P1/P2).
function buildDays() {
  const end = new Date(WINDOW_END + 'T12:00:00.000Z');
  const days = [];
  for (let i = WINDOW_DAYS - 1; i >= 0; i--) {
    const d = new Date(end.getTime() - i * 24 * 60 * 60 * 1000);
    const iso = d.toISOString().slice(0, 10);
    const dow = d.getUTCDay(); // 0 sun .. 6 sat, in UTC
    days.push({ iso, dow, weekend: dow === 0 || dow === 6 });
  }
  return days;
}

// assign a workstation + ip per user (stable)
function buildUsers() {
  const users = [];
  let wsIdx = 0;
  const wsHosts = HOSTS.filter((h) => h.zone === 'office');
  Object.entries(ROLES).forEach(([role, prof]) => {
    for (let n = 1; n <= prof.count; n++) {
      const host = wsHosts[wsIdx % wsHosts.length];
      wsIdx++;
      let id;
      if (prof.namePrefix) id = prof.namePrefix; // service account keeps its name
      else id = `U-${role.toUpperCase()}-${n}`;
      const ipBase = 10 + (wsIdx % 200);
      users.push({
        id,
        role,
        prof,
        host: host.id,
        ip: `10.20.${pad2(ipBase % 99)}.${pad2((wsIdx * 7) % 99)}`,
        geo: HOME_GEO,
      });
    }
  });
  return users;
}

/**
 * generateNormal — returns { users, events } for the NORMAL (benign) baseline corpus.
 * @param {number} seed
 */
function generateNormal(seed = 42) {
  const rng = mulberry32(seed);
  const days = buildDays();
  const users = buildUsers();
  const events = [];

  for (const u of users) {
    const { prof } = u;
    for (const day of days) {
      // weekend: most users inactive; service account always runs
      if (day.weekend && !prof.nightJob) {
        if (rng() > 0.12) continue; // ~12% chance someone works a weekend day, lightly
      }
      const lambda = prof.nightJob ? prof.eventsLambda : Math.max(2, prof.eventsLambda);
      let nEvents = poisson(rng, lambda);
      if (!prof.nightJob && day.weekend) nEvents = Math.min(nEvents, 4);
      if (nEvents <= 0) continue;

      // one LOGIN at the start of the day from home host/geo
      const [ws, we] = prof.workBand;
      const loginHour = prof.nightJob
        ? ws
        : Math.max(0, Math.min(23, ws + Math.floor(rng() * Math.max(1, we - ws - 2))));
      events.push(mkEvent(u, day.iso, loginHour, Math.floor(rng() * 60), 'LOGIN', null, 0, 'rdp'));

      for (let k = 0; k < nEvents; k++) {
        // hour within (or near) work band, with small jitter
        let hour;
        if (prof.nightJob) {
          hour = ws + Math.floor(rng() * Math.max(1, we - ws));
        } else {
          const span = Math.max(1, we - ws);
          hour = ws + Math.floor(rng() * span);
          // occasional legit off-by-a-bit (1h before/after)
          if (rng() < 0.06) hour += rng() < 0.5 ? -1 : 1;
          hour = Math.max(0, Math.min(23, hour));
        }
        const minute = Math.floor(rng() * 60);

        // pick a known resource for this role
        const db = prof.dbs[Math.floor(rng() * prof.dbs.length)];
        const rows = logNormalRows(rng, prof.avgRows, prof.rowsSpread);
        // mostly SELECT; service account also does occasional EXPORT to backup
        let action = 'SELECT';
        let channel = 'db';
        if (prof.nightJob && rng() < 0.3) {
          action = 'EXPORT';
          channel = 'db'; // legitimate internal backup channel (not covert)
        }
        events.push(mkEvent(u, day.iso, hour, minute, action, db, rows, channel));
      }
    }
  }

  return { users, events, days };
}

function mkEvent(u, dayIso, hour, minute, action, resource, rows, channel) {
  const ts = `${dayIso}T${pad2(hour)}:${pad2(minute)}:00`;
  return {
    user: u.id,
    role: u.role,
    resource: resource || u.host,
    db: resource && resource.startsWith('DB-') ? resource.toLowerCase() : null,
    host: u.host,
    ip: u.ip,
    geo: u.geo,
    action,
    rows: rows || 0,
    ts,
    ts_day: dayIso,
    ts_hour: hour,
    channel,
    from: action === 'LOGIN' ? u.host : u.id,
    to: resource || u.host,
    label_malicious: 0, // benign by default; attacks overwrite their own days
    label_typology: null,
  };
}

module.exports = { generateNormal, buildDays, buildUsers, mulberry32, mkEvent };
