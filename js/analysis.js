"use strict";

/* Análisis agregado en una sola pasada sobre los registros (sin DOM). */

/* ===================== Parámetros configurables ===================== */

// Fuerza bruta: al menos N logins fallidos (401.1) de la misma IP dentro de la ventana
const BRUTEFORCE_THRESHOLD = 20;
const BRUTEFORCE_WINDOW_MS = 5 * 60 * 1000;

const SCORING = {
  // Puntos por cada TIPO distinto detectado para la IP
  typeWeights: {
    "SQL INJECTION": 40,
    "PATH TRAVERSAL": 40,
    "XSS ATTACK": 40,
    "EXPLOIT ATTEMPT": 50,
    "SECURITY TOOL": 30,
    "CONFIG SCAN": 15,
    "DB SCAN": 15,
    "WORDPRESS SCAN": 10,
    "ADMIN SCAN": 10,
    SCRIPT: 5,
    BOT: 0, // informativo: los bots legítimos (Googlebot, etc.) no suman
  },
  // Cualquiera de estos tipos fuerza riesgo Alto
  realAttackTypes: ["SQL INJECTION", "PATH TRAVERSAL", "XSS ATTACK", "EXPLOIT ATTEMPT"],

  // Amplitud de errores: muchas URIs DISTINTAS con 404 y alta proporción de errores (firma de escáner)
  breadthMinRatio: 0.3, // errores / requests mínimo
  breadthMinUris: 10, // URIs distintas con 404 mínimas
  breadthDivisor: 3, // 1 punto cada N URIs distintas
  breadthMax: 30,

  // Errores repetidos (poco peso: un link roto no es un ataque)
  repeatedErrorsDivisor: 10, // 1 punto cada N errores
  repeatedErrorsMax: 10,

  // Sondeo de accesos: 403 y 401 no-desafío (401.3/4/5) pesan 2; logins fallidos pesan 3
  deniedWeight: 2,
  failedLoginWeight: 3,
  accessProbeMax: 30,

  // Respuestas 400 (solicitud mal formada)
  badRequestMax: 10,

  bruteforceScore: 40, // y fuerza riesgo Alto

  riskHigh: 50,
  riskMedium: 20,
};

/* ===================== Tráfico legítimo ===================== */

/**
 * Tráfico "legítimo" (para medir el uso real del sistema): no fue clasificado como
 * ataque / escaneo / bot / script y la respuesta fue exitosa (2xx) o redirección/caché (3xx).
 */
function isLegitimate(r) {
  if (r.type !== "" || r.status.length !== 3) return false;
  const c = r.status.charCodeAt(0);
  return c === 50 || c === 51; // "2" o "3"
}

/* ===================== Análisis ===================== */

function newIpStats() {
  return {
    req: 0,
    e400: 0,
    e401: 0, // todos los 401 (solo informativo)
    e403: 0,
    e404: 0,
    failedLogins: 0, // 401.1 (credenciales inválidas) o 401 sin substatus
    deniedAuth: 0, // 401.3 / 401.4 / 401.5
    uris: new Set(),
    uris404: new Set(),
    types: new Map(),
    failedTs: [],
    bruteforceMax: 0,
  };
}

/** Máximo de eventos dentro de cualquier ventana de `windowMs` (ts ordenados ascendente). */
function maxInWindow(sortedTs, windowMs) {
  let best = 0;
  let j = 0;
  for (let i = 0; i < sortedTs.length; i++) {
    while (sortedTs[i] - sortedTs[j] > windowMs) j++;
    if (i - j + 1 > best) best = i - j + 1;
  }
  return best;
}

/**
 * Devuelve:
 *  ips:        Map ip -> estadísticas (solo IPs públicas)
 *  alerts:     [{ip, type}]   primera aparición de cada par IP/tipo (solo IPs públicas)
 *  bruteforce: [{ip, count}]  IPs con >= BRUTEFORCE_THRESHOLD logins fallidos en la ventana
 *  slow:       Map uri -> {uri, n, sum, max}   (requiere time-taken)
 *  err5:       Map uri -> {uri, n}             (respuestas 5xx)
 *  hasTimeTaken: boolean
 */
function analyze(rows, opts) {
  const threshold = (opts && opts.bruteforceThreshold) ?? BRUTEFORCE_THRESHOLD;
  const windowMs = (opts && opts.bruteforceWindowMs) ?? BRUTEFORCE_WINDOW_MS;
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
    if (!s) ips.set(r.cip, (s = newIpStats()));
    s.req++;

    if (r.status === "404") {
      s.e404++;
      s.uris404.add(r.uri);
    } else if (r.status === "403") {
      s.e403++;
    } else if (r.status === "400") {
      s.e400++;
    } else if (r.status === "401") {
      s.e401++;
      // 401.2 (y 401.0) es el desafío de autenticación de Windows: tráfico normal, no se penaliza
      const sub = r.sub || "";
      if (sub === "1" || sub === "") {
        s.failedLogins++;
        if (r.ts > 0) s.failedTs.push(r.ts);
      } else if (sub === "3" || sub === "4" || sub === "5") {
        s.deniedAuth++;
      }
    }

    s.uris.add(r.uri);

    if (r.type) {
      s.types.set(r.type, (s.types.get(r.type) || 0) + 1);
      const key = r.cip + "-" + r.type;
      if (!seen.has(key)) {
        seen.add(key);
        alerts.push({ip: r.cip, type: r.type});
      }
    }
  }

  const bruteforce = [];
  for (const [ip, s] of ips) {
    if (s.failedTs.length >= threshold) {
      s.failedTs.sort((a, b) => a - b);
      s.bruteforceMax = maxInWindow(s.failedTs, windowMs);
      if (s.bruteforceMax >= threshold) bruteforce.push({ip, count: s.bruteforceMax});
    }
    s.failedTs = null; // ya no se necesita
  }

  return {ips, alerts, bruteforce, slow, err5, hasTimeTaken};
}

/* ===================== Score de riesgo por IP ===================== */

const pct = (n, total) => (total ? Math.round((n / total) * 100) : 0);

/** Devuelve {score, reasons[], forceHigh} para las estadísticas de una IP. */
function evaluateIp(s) {
  const P = SCORING;
  let score = 0;
  let forceHigh = false;
  const reasons = [];

  // 1) Tipos detectados (lo más importante)
  for (const [type, count] of s.types) {
    score += P.typeWeights[type] || 0;
    if (P.realAttackTypes.includes(type)) forceHigh = true;
    reasons.push(`${type} ×${count}`);
  }

  // 2) Errores (los 401 de desafío no cuentan)
  const denied = s.e403 + s.deniedAuth;
  const errors = s.e400 + s.e404 + denied + s.failedLogins;
  const ratio = s.req ? errors / s.req : 0;

  if (ratio >= P.breadthMinRatio && s.uris404.size >= P.breadthMinUris) {
    score += Math.min(P.breadthMax, Math.floor(s.uris404.size / P.breadthDivisor));
    reasons.push(`${s.uris404.size} URIs distintas con 404 (${pct(errors, s.req)} % de errores)`);
  }

  const repeated = Math.min(P.repeatedErrorsMax, Math.floor(errors / P.repeatedErrorsDivisor));
  if (repeated > 0) {
    score += repeated;
    if (s.uris404.size < P.breadthMinUris) reasons.push(`${errors} respuestas de error (${pct(errors, s.req)} %)`);
  }

  const probe = Math.min(P.accessProbeMax, denied * P.deniedWeight + s.failedLogins * P.failedLoginWeight);
  if (probe > 0) {
    score += probe;
    if (s.failedLogins > 0) reasons.push(`${s.failedLogins} logins fallidos`);
    if (denied > 0) reasons.push(`${denied} accesos denegados`);
  }

  if (s.e400 > 0) score += Math.min(P.badRequestMax, s.e400);

  // 3) Fuerza bruta con ventana de tiempo
  if (s.bruteforceMax >= BRUTEFORCE_THRESHOLD) {
    score += P.bruteforceScore;
    forceHigh = true;
    reasons.push(`fuerza bruta: ${s.bruteforceMax} logins fallidos en ${BRUTEFORCE_WINDOW_MS / 60000} min`);
  }

  return {score, reasons, forceHigh};
}

function riskOf(score, forceHigh) {
  if (forceHigh || score >= SCORING.riskHigh) return {label: "High", cls: "risk-high"};
  if (score >= SCORING.riskMedium) return {label: "Medium", cls: "risk-medium"};
  return {label: "Low", cls: "risk-low"};
}

function buildRanking(ips) {
  const out = [];
  for (const [ip, s] of ips) {
    const ev = evaluateIp(s);
    out.push({
      ip,
      req: s.req,
      e400: s.e400,
      e401: s.e401,
      e403: s.e403,
      e404: s.e404,
      uris: s.uris.size,
      score: ev.score,
      risk: riskOf(ev.score, ev.forceHigh),
      reasons: ev.reasons,
    });
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
  module.exports = {
    analyze,
    isLegitimate,
    evaluateIp,
    riskOf,
    buildRanking,
    sortRanking,
    topSlow,
    topErrors,
    maxInWindow,
    SCORING,
    BRUTEFORCE_THRESHOLD,
    BRUTEFORCE_WINDOW_MS,
  };
}
