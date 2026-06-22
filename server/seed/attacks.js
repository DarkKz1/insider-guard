'use strict';
// attacks.js — 8 labeled insider scenarios + 2 benign hard-negatives, injected
// into the NORMAL stream. Each is anchored to a REAL generated user so the engine
// computes their baseline from history (NOT declared). Deterministic placement.

const { HOME_GEO, FOREIGN_GEOS } = require('./catalog');

function pad2(n) {
  return String(n).padStart(2, '0');
}
function ev(o) {
  const ts = o.ts;
  return {
    user: o.user,
    role: o.role,
    resource: o.resource,
    db: o.resource && o.resource.startsWith('DB-') ? o.resource.toLowerCase() : null,
    host: o.host,
    ip: o.ip,
    geo: o.geo || HOME_GEO,
    action: o.action,
    rows: o.rows || 0,
    ts,
    ts_day: ts.slice(0, 10),
    ts_hour: parseInt(ts.slice(11, 13), 10),
    channel: o.channel,
    from: o.from || (o.action === 'LOGIN' ? o.host : o.user),
    to: o.to || o.resource || o.host,
    label_malicious: o.benign ? 0 : 1,
    label_typology: o.typology,
  };
}

/**
 * injectAttacks — given the generated users + day list, append attack events.
 * Returns { attackEvents, groundTruth:[{user,day,typology,malicious}] }
 * The attack DAY is chosen near the end of the window so each attacker has ~29
 * prior days of history => engine baseline is meaningfully computed.
 */
function injectAttacks(users, days) {
  const byRole = (role) => users.filter((u) => u.role === role);
  const pick = (role, n = 0) => byRole(role)[n];
  const attackEvents = [];
  const groundTruth = [];

  const lastDays = days.filter((d) => !d.weekend).slice(-8); // weekday slots near end
  const weekendDays = days.filter((d) => d.weekend).slice(-2);
  const dayAt = (i) => (lastDays[i] ? lastDays[i].iso : days[days.length - 1].iso);

  const record = (user, day, typology) => groundTruth.push({ user, day, typology, malicious: true });
  const recordBenign = (user, day, typology) => groundTruth.push({ user, day, typology, malicious: false });

  // 1. MASS_EXFIL — analyst, 80,000-row SELECT on DB-PERSONS at 02:14
  {
    const u = pick('analyst', 0);
    const day = dayAt(0);
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, resource: 'DB-PERSONS', action: 'SELECT', rows: 80000, ts: `${day}T02:14:00`, channel: 'db', typology: 'mass_exfil' }));
    record(u.id, day, 'mass_exfil');
  }

  // 2. LATERAL_MOVEMENT — support acct, LOGIN chain WS->jump->app->DB then SELECT
  {
    const u = pick('support', 0);
    const day = dayAt(1);
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'LOGIN', resource: 'H-JUMP-1', from: u.host, to: 'H-JUMP-1', ts: `${day}T21:02:00`, channel: 'rdp', typology: 'lateral' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: 'H-JUMP-1', ip: '10.30.2.7', action: 'LOGIN', resource: 'H-APP-7', from: 'H-JUMP-1', to: 'H-APP-7', ts: `${day}T21:09:00`, channel: 'ssh', typology: 'lateral' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: 'H-APP-7', ip: '10.30.3.1', action: 'LOGIN', resource: 'H-DB-1', from: 'H-APP-7', to: 'H-DB-1', ts: `${day}T21:15:00`, channel: 'ssh', typology: 'lateral' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: 'H-DB-1', ip: '10.30.3.1', action: 'SELECT', resource: 'DB-PERSONS', from: 'H-DB-1', to: 'DB-PERSONS', rows: 1500, ts: `${day}T21:21:00`, channel: 'db', typology: 'lateral' }));
    record(u.id, day, 'lateral');
  }

  // 3. PRIV_ESCALATION — junior, GRANT then SELECT DB-SALARY + DB-SANCTIONS
  {
    const u = pick('junior', 0);
    const day = dayAt(2);
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'GRANT', resource: 'DB-SALARY', ts: `${day}T15:40:00`, channel: 'iam', typology: 'priv_escalation' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-SALARY', rows: 3200, ts: `${day}T15:45:00`, channel: 'db', typology: 'priv_escalation' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-SANCTIONS', rows: 1800, ts: `${day}T15:52:00`, channel: 'db', typology: 'priv_escalation' }));
    record(u.id, day, 'priv_escalation');
  }

  // 4. OFF_HOURS_BURST — analyst, Sunday burst of 6 SELECTs ~9,600 rows on DB-TAX
  {
    const u = pick('analyst', 1);
    const day = (weekendDays[0] || days[days.length - 1]).iso;
    for (let i = 0; i < 6; i++) {
      attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-TAX', rows: 1600, ts: `${day}T0${i + 1}:1${i}:00`, channel: 'db', typology: 'off_hours' }));
    }
    record(u.id, day, 'off_hours');
  }

  // 5. STAGING_EXFIL — ops analyst, SELECT 60k -> EXPORT 58k (~1:1) DB-PERSONS via cloud
  {
    const u = pick('analyst', 2);
    const day = dayAt(3);
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-PERSONS', rows: 60000, ts: `${day}T19:40:00`, channel: 'db', typology: 'staging_exfil' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'EXPORT', resource: 'DB-PERSONS', rows: 58000, ts: `${day}T19:58:00`, channel: 'cloud', typology: 'staging_exfil' }));
    record(u.id, day, 'staging_exfil');
  }

  // 6. COMPROMISE / IMPOSSIBLE_TRAVEL — clerk, login Астана -> foreign+new device -> SELECT 15k
  {
    const u = pick('clerk', 0);
    const day = dayAt(4);
    const foreign = FOREIGN_GEOS[0];
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'LOGIN', resource: u.host, from: u.host, to: u.host, geo: HOME_GEO, ts: `${day}T10:02:00`, channel: 'rdp', typology: 'compromise' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: 'H-EXT-NEW', ip: '203.0.113.77', action: 'LOGIN', resource: 'H-EXT-NEW', from: 'H-EXT-NEW', to: 'H-EXT-NEW', geo: foreign, ts: `${day}T10:10:00`, channel: 'web', typology: 'compromise' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: 'H-EXT-NEW', ip: '203.0.113.77', action: 'SELECT', resource: 'DB-PERSONS', geo: foreign, rows: 15000, ts: `${day}T10:18:00`, channel: 'db', typology: 'compromise' }));
    record(u.id, day, 'compromise');
  }

  // 7. BROAD_ACCESS — support, touches 12 never-before-seen DBs in one hour
  {
    const u = pick('support', 1);
    const day = dayAt(5);
    const xs = [];
    for (let i = 1; i <= 11; i++) xs.push(`DB-X${i}`);
    xs.push('DB-SALARY');
    xs.forEach((db, i) => {
      attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: db, rows: 800 + i * 30, ts: `${day}T14:${pad2(i * 4)}:00`, channel: 'db', typology: 'broad_access' }));
    });
    record(u.id, day, 'broad_access');
  }

  // 8. COVERT_CHANNEL — clerk, moderate SELECT then EXPORT to personal_email/messenger
  {
    const u = pick('clerk', 1);
    const day = dayAt(6);
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-PERSONS', rows: 4200, ts: `${day}T17:30:00`, channel: 'db', typology: 'covert_channel' }));
    attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'EXPORT', resource: 'DB-PERSONS', rows: 4200, ts: `${day}T17:42:00`, channel: 'personal_email', typology: 'covert_channel' }));
    record(u.id, day, 'covert_channel');
  }

  // --- BENIGN HARD-NEGATIVES (labeled malicious=0) -------------------------

  // 9. ETL_SERVICE — svc account reads 85k-95k nightly EVERY night (its baseline IS that)
  // (already generated as normal nightly large volume; we only LABEL its last night
  //  as a benign hard-negative so it shows up in ground-truth metrics as a TN test.)
  {
    const u = users.find((x) => x.role === 'service');
    if (u) {
      const day = dayAt(0);
      // ensure a big nightly read exists on that day with explicit benign label
      attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-PERSONS', rows: 90000, ts: `${day}T02:00:00`, channel: 'db', benign: true, typology: 'etl_service' }));
      recordBenign(u.id, day, 'etl_service');
    }
  }

  // 10. PLANNED_AUDIT — auditor reads ~3x normal volume in work hours on own tables
  {
    const u = pick('auditor', 0);
    if (u) {
      const day = dayAt(1);
      for (let i = 0; i < 4; i++) {
        attackEvents.push(ev({ user: u.id, role: u.role, host: u.host, ip: u.ip, action: 'SELECT', resource: 'DB-TAX', rows: 2600, ts: `${day}T1${i}:15:00`, channel: 'db', benign: true, typology: 'planned_audit' }));
      }
      recordBenign(u.id, day, 'planned_audit');
    }
  }

  return { attackEvents, groundTruth };
}

module.exports = { injectAttacks };
