"use strict";

/* Análisis agregado en una sola pasada sobre los registros (sin DOM). */

const BRUTEFORCE_THRESHOLD = 20; // cantidad de 401 por IP

/**
 * Devuelve:
 *  ips:        Map ip -> {req, e400, e401, e403, e404, uris:Set}   (solo IPs públicas)
 *  alerts:     [{ip, type}]   primera aparición de cada par IP/tipo (solo IPs públicas)
 *  bruteforce: [{ip, count}]  IPs con más de `bruteforceThreshold` respuestas 401
 *  slow:       Map uri -> {uri, n, sum, max}   (requiere time-taken)
 *  err5:       Map uri -> {uri, n}             (respuestas 5xx)
 *  hasTimeTaken: boolean
 */
function analyze(rows, opts) {
  const threshold = (opts && opts.bruteforceThreshold) ?? BRUTEFORCE_THRESHOLD;
  const ips = new Map();
  const privCache = new Map();
  const seen = new Set();
  const alerts = [];
  const slow = new Map();
  const err5 = new Map();
  let hasTimeTaken = false;

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];

    if (r.tt >= 0) {
      hasTimeTaken = true;
      let s = slow.get(r.uri);
      if (!s) slow.set(r.uri, (s = {uri: r.uri, n: 0, sum: 0, max: 0}));
      s.n++;
      s.sum += r.tt;
      if (r.tt > s.max) s.max = r.tt;
    }

    if (r.status.length === 3 && r.status.charCodeAt(0) === 53) {
      // "5xx"
      let e = err5.get(r.uri);
      if (!e) err5.set(r.uri, (e = {uri: r.uri, n: 0}));
      e.n++;
    }

    let priv = privCache.get(r.cip);
    if (priv === undefined) privCache.set(r.cip, (priv = isPrivateIP(r.cip)));
    if (priv) continue;

    let s = ips.get(r.cip);
    if (!s) ips.set(r.cip, (s = {req: 0, e400: 0, e401: 0, e403: 0, e404: 0, uris: new Set()}));
    s.req++;
    if (r.status === "400") s.e400++;
    else if (r.status === "401") s.e401++;
    else if (r.status === "403") s.e403++;
    else if (r.status === "404") s.e404++;
    s.uris.add(r.uri);

    if (r.type) {
      const key = r.cip + "-" + r.type;
      if (!seen.has(key)) {
        seen.add(key);
        alerts.push({ip: r.cip, type: r.type});
      }
    }
  }

  const bruteforce = [];
  for (const [ip, s] of ips) if (s.e401 > threshold) bruteforce.push({ip, count: s.e401});

  return {ips, alerts, bruteforce, slow, err5, hasTimeTaken};
}

function scoreOf(s) {
  let score = 0;
  if (s.req > 50) score += 10;
  score += s.e401 * 3 + s.e400 + s.e403 * 2 + s.e404 * 2;
  if (s.uris.size > 20) score += 5;
  return score;
}

function riskOf(score) {
  if (score > 50) return {label: "High", cls: "risk-high"};
  if (score >= 20) return {label: "Medium", cls: "risk-medium"};
  return {label: "Low", cls: "risk-low"};
}

function buildRanking(ips) {
  const out = [];
  for (const [ip, s] of ips) {
    out.push({ip, req: s.req, e400: s.e400, e401: s.e401, e403: s.e403, e404: s.e404, uris: s.uris.size, score: scoreOf(s)});
  }
  return out;
}

function sortRanking(data, key, asc) {
  return [...data].sort((a, b) => {
    const cmp = key === "ip" ? a.ip.localeCompare(b.ip, undefined, {numeric: true}) : a[key] - b[key];
    return asc ? cmp : -cmp;
  });
}

function topSlow(slow, n = 10) {
  return Array.from(slow.values())
    .map((s) => ({uri: s.uri, n: s.n, avg: Math.round(s.sum / s.n), max: s.max}))
    .sort((a, b) => b.avg - a.avg)
    .slice(0, n);
}

function topErrors(err5, n = 10) {
  return Array.from(err5.values())
    .sort((a, b) => b.n - a.n)
    .slice(0, n);
}

if (typeof module !== "undefined") {
  // En Node (tests) isPrivateIP viene de utils.js
  module.exports = {analyze, scoreOf, riskOf, buildRanking, sortRanking, topSlow, topErrors, BRUTEFORCE_THRESHOLD};
}
