'use strict';
// catalog.js — static dimension data for the seed corpus:
// users/roles (with behavioural profiles), resources (DBs + sensitivity),
// hosts (zones), channels, geos. Deterministic — no randomness here.

// ---- ROLES & their behavioural envelopes (used by the generator) ----------
// avgRows = typical daily read volume center; rowsSpread = log-normal sigma-ish;
// workBand = typical [start,end] hours; eventsPerDay = poisson-ish lambda;
// knownDbs = the resources this role normally touches.
const ROLES = {
  analyst: { count: 12, avgRows: 600, rowsSpread: 0.5, workBand: [9, 18], eventsLambda: 14, dbs: ['DB-PERSONS', 'DB-TAX', 'DB-REF'] },
  support: { count: 8, avgRows: 220, rowsSpread: 0.6, workBand: [9, 19], eventsLambda: 18, dbs: ['DB-TICKETS', 'DB-REF'] },
  clerk: { count: 8, avgRows: 180, rowsSpread: 0.5, workBand: [9, 18], eventsLambda: 10, dbs: ['DB-REF', 'DB-TICKETS'] },
  junior: { count: 4, avgRows: 120, rowsSpread: 0.5, workBand: [10, 18], eventsLambda: 8, dbs: ['DB-REF'] },
  auditor: { count: 3, avgRows: 900, rowsSpread: 0.4, workBand: [9, 18], eventsLambda: 12, dbs: ['DB-AUDIT-LOG', 'DB-TAX', 'DB-SALARY'] },
  dba: { count: 2, avgRows: 1500, rowsSpread: 0.5, workBand: [8, 20], eventsLambda: 16, dbs: ['DB-PERSONS', 'DB-TAX', 'DB-SALARY', 'DB-REF', 'DB-AUDIT-LOG'] },
  admin: { count: 2, avgRows: 800, rowsSpread: 0.5, workBand: [8, 20], eventsLambda: 14, dbs: ['DB-REF', 'DB-AUDIT-LOG', 'DB-X1', 'DB-X2'] },
  service: { count: 1, avgRows: 90000, rowsSpread: 0.08, workBand: [1, 4], eventsLambda: 6, dbs: ['DB-PERSONS', 'DB-TAX', 'DB-SALARY'], nightJob: true, namePrefix: 'svc_etl_backup' },
};

// ---- RESOURCES (databases) with sensitivity --------------------------------
const RESOURCES = [
  { id: 'DB-PERSONS', label: 'Реестр физлиц: ФИО / ИИН / адрес / телефон', sensitivity: 'critical', tags: ['pii'] },
  { id: 'DB-TAX', label: 'Налоговые данные физлиц', sensitivity: 'high', tags: ['financial'] },
  { id: 'DB-SALARY', label: 'Зарплатная ведомость', sensitivity: 'high', tags: ['financial'] },
  { id: 'DB-SANCTIONS', label: 'Санкционный перечень', sensitivity: 'critical', tags: ['financial'] },
  { id: 'DB-TICKETS', label: 'Заявки службы поддержки', sensitivity: 'low', tags: [] },
  { id: 'DB-REF', label: 'Справочники', sensitivity: 'low', tags: [] },
  { id: 'DB-AUDIT-LOG', label: 'Журнал аудита', sensitivity: 'medium', tags: [] },
];
// DB-X1..DB-X11 mixed pii/financial
for (let i = 1; i <= 11; i++) {
  RESOURCES.push({
    id: `DB-X${i}`,
    label: `Ведомственная БД X${i}`,
    sensitivity: i % 3 === 0 ? 'high' : i % 3 === 1 ? 'medium' : 'low',
    tags: i % 2 === 0 ? ['pii'] : ['financial'],
  });
}

// ---- HOSTS (zones) ---------------------------------------------------------
const HOSTS = [];
// per-cluster АРМ workstations
for (let i = 1; i <= 12; i++) HOSTS.push({ id: `H-WS-${i}`, label: `АРМ ${i}`, zone: 'office' });
// jump hosts
HOSTS.push({ id: 'H-JUMP-1', label: 'Промежуточный хост 1', zone: 'dmz' });
HOSTS.push({ id: 'H-JUMP-2', label: 'Промежуточный хост 2', zone: 'dmz' });
// app servers
HOSTS.push({ id: 'H-APP-7', label: 'Сервер приложений 7', zone: 'internal' });
HOSTS.push({ id: 'H-APP-8', label: 'Сервер приложений 8', zone: 'internal' });
// DB servers (restricted)
HOSTS.push({ id: 'H-DB-1', label: 'Сервер БД физлиц', zone: 'restricted', tags: ['db_server'] });
HOSTS.push({ id: 'H-DB-2', label: 'Сервер БД 2', zone: 'restricted', tags: ['db_server'] });
// backup server
HOSTS.push({ id: 'H-BACKUP-1', label: 'Сервер бэкапов', zone: 'restricted' });
// external / new device (compromise)
HOSTS.push({ id: 'H-EXT-NEW', label: 'Внешнее устройство (новое)', zone: 'external', tags: ['new_device'] });

// ---- CHANNELS / GEOS -------------------------------------------------------
const CHANNELS = ['db', 'rdp', 'ssh', 'web', 'cloud', 'messenger', 'personal_email', 'iam'];
const HOME_GEO = 'Астана';
const FOREIGN_GEOS = ['Амстердам', 'Франкфурт', 'Стамбул'];

// ---- corpus window ---------------------------------------------------------
const WINDOW_DAYS = 30;
const WINDOW_END = '2026-06-20'; // inclusive last day

module.exports = {
  ROLES,
  RESOURCES,
  HOSTS,
  CHANNELS,
  HOME_GEO,
  FOREIGN_GEOS,
  WINDOW_DAYS,
  WINDOW_END,
};
