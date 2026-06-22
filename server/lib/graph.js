'use strict';
// graph.js — buildGraph (in/out rows + deg aggregation) and lateral-path DFS,
// ported from the mockup's buildGraph()/hasCycle(). Operates on a per-user-day
// edge list. Pure: no DB, no framework.

/**
 * Build adjacency-aggregated node map from events.
 * Each event must carry { from, to, rows }. Node kind comes from `nodeMeta`.
 * @param {Array} events  edges with {from,to,rows}
 * @param {Object} nodeMeta  id -> { id, kind, label, sensitivity?, zone?, tags? }
 * @returns {Object} id -> { ...meta, inRows, outRows, inDeg, outDeg }
 */
function buildGraph(events, nodeMeta) {
  const nodes = {};
  const ensure = (id) => {
    if (!nodes[id]) {
      const meta = nodeMeta[id] || { id, kind: '?', label: id };
      nodes[id] = { ...meta, id, inRows: 0, outRows: 0, inDeg: 0, outDeg: 0 };
    }
    return nodes[id];
  };
  events.forEach((e) => {
    if (!e.from || !e.to) return;
    const f = ensure(e.from);
    const t = ensure(e.to);
    const rows = e.rows || 0;
    f.outRows += rows;
    f.outDeg += 1;
    t.inRows += rows;
    t.inDeg += 1;
  });
  return nodes;
}

/**
 * lateralPath — DFS finding a chain user/host -> host -> host -> ... -> resource
 * passing through >=3 hosts and ending at a resource (lateral movement to data).
 * Ported from mockup hasCycle(): same DFS mechanic, path semantics.
 * @param {Array} events  edges with {from,to}
 * @param {Object} nodeMeta  id -> { kind }
 * @returns {Array<string>|null} path of node ids, or null
 */
function lateralPath(events, nodeMeta) {
  const adj = {};
  events.forEach((e) => {
    if (!e.from || !e.to) return;
    (adj[e.from] = adj[e.from] || []).push(e.to);
  });
  const isHost = (id) => nodeMeta[id] && nodeMeta[id].kind === 'host';
  const isResource = (id) => nodeMeta[id] && nodeMeta[id].kind === 'resource';
  const starts = Object.keys(adj);
  for (const s of starts) {
    const stack = [[s, [s]]];
    while (stack.length) {
      const [n, path] = stack.pop();
      for (const m of adj[n] || []) {
        const hostsInPath = path.filter(isHost).length;
        // path through >=3 hosts ending at a resource = lateral movement to data
        if (isResource(m) && hostsInPath >= 3) return path.concat(m);
        if (!path.includes(m) && path.length < 6) stack.push([m, path.concat(m)]);
      }
    }
  }
  return null;
}

module.exports = { buildGraph, lateralPath };
