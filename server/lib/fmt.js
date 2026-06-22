'use strict';
// fmt.js — number formatting + ts helpers (ported from mockup index.html)

// ru-RU integer formatting: 80000 -> "80 000"
function fmt(n) {
  return new Intl.NumberFormat('ru-RU').format(Math.round(n || 0));
}

// hour 0-23 from an ISO-ish ts ("YYYY-MM-DDTHH:MM..." or "YYYY-MM-DD HH:MM")
function hourOf(ts) {
  if (!ts) return 0;
  // position 11..13 holds HH in both "YYYY-MM-DD HH:MM" and ISO "YYYY-MM-DDTHH:MM"
  const h = parseInt(String(ts).slice(11, 13), 10);
  return Number.isFinite(h) ? h : 0;
}

// day of week (0=Sun..6=Sat) from ts date part
function dowOf(ts) {
  if (!ts) return 1;
  const day = String(ts).slice(0, 10);
  const d = new Date(day + 'T00:00:00');
  const dow = d.getDay();
  return Number.isFinite(dow) ? dow : 1;
}

// YYYY-MM-DD from ts
function dayOf(ts) {
  return String(ts || '').slice(0, 10);
}

// minutes between two ts (b - a), tolerant of "T" vs " " separator
function minutesBetween(a, b) {
  const ta = new Date(String(a).replace(' ', 'T')).getTime();
  const tb = new Date(String(b).replace(' ', 'T')).getTime();
  if (!Number.isFinite(ta) || !Number.isFinite(tb)) return Infinity;
  return (tb - ta) / 60000;
}

// robust trimmed mean (drop top quantile to resist a single spike day)
function trimmedMean(values, trimTopFrac = 0.1) {
  const arr = values.filter((v) => Number.isFinite(v)).slice().sort((a, b) => a - b);
  if (arr.length === 0) return 0;
  if (arr.length <= 3) {
    // too few points to trim — plain mean
    return arr.reduce((s, v) => s + v, 0) / arr.length;
  }
  const drop = Math.floor(arr.length * trimTopFrac);
  const kept = drop > 0 ? arr.slice(0, arr.length - drop) : arr;
  return kept.reduce((s, v) => s + v, 0) / kept.length;
}

function median(values) {
  const arr = values.filter((v) => Number.isFinite(v)).slice().sort((a, b) => a - b);
  if (arr.length === 0) return 0;
  const mid = Math.floor(arr.length / 2);
  return arr.length % 2 ? arr[mid] : (arr[mid - 1] + arr[mid]) / 2;
}

// percentile (linear interpolation), p in [0,100]
function percentile(values, p) {
  const arr = values.filter((v) => Number.isFinite(v)).slice().sort((a, b) => a - b);
  if (arr.length === 0) return 0;
  if (arr.length === 1) return arr[0];
  const idx = (p / 100) * (arr.length - 1);
  const lo = Math.floor(idx);
  const hi = Math.ceil(idx);
  if (lo === hi) return arr[lo];
  const frac = idx - lo;
  return arr[lo] * (1 - frac) + arr[hi] * frac;
}

module.exports = { fmt, hourOf, dowOf, dayOf, minutesBetween, trimmedMean, median, percentile };
