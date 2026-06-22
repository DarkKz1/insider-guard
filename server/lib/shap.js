'use strict';
// shap.js — largest-remainder (Hamilton) integer SHAP split (ported verbatim from mockup).
// Splits `score` across score-bearing triggers so Σ contributions === score EXACTLY.

/**
 * @param {Array<{code,label,weight,detail,severity}>} triggers
 * @param {number} score   final 0-100 incident score
 * @returns {Array} triggers with integer `contribution`, sorted desc; Σ contribution === score
 */
function shapSplit(triggers, score) {
  const shapBase = triggers.filter((t) => t.weight > 0);
  const sumW = shapBase.reduce((s, t) => s + t.weight, 0);
  if (!shapBase.length || !sumW) return [];

  const quotas = shapBase.map((t) => ({ t, exact: (t.weight / sumW) * score }));
  quotas.forEach((q) => {
    q.floor = Math.floor(q.exact);
    q.rem = q.exact - q.floor;
  });
  let assigned = quotas.reduce((s, q) => s + q.floor, 0);
  let leftover = score - assigned; // remaining whole points to distribute

  // distribute leftover by descending fractional part (largest remainder)
  [...quotas]
    .sort((a, b) => b.rem - a.rem)
    .forEach((q) => {
      if (leftover > 0) {
        q.floor += 1;
        leftover -= 1;
      }
    });

  return quotas
    .map((q) => ({ ...q.t, contribution: q.floor }))
    .sort((a, b) => b.contribution - a.contribution);
}

module.exports = { shapSplit };
