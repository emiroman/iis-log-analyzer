"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");

// analysis.js usa isPrivateIP como global (en el navegador viene de utils.js)
global.isPrivateIP = require("../js/utils.js").isPrivateIP;
const {analyze, isLegitimate, buildRanking, sortRanking, topSlow, topErrors, maxInWindow, riskOf, SCORING} = require("../js/analysis.js");

const T0 = Date.UTC(2026, 2, 7, 10, 0, 0);
const row = (o) => ({ts: T0, cip: "8.8.8.8", method: "GET", uri: "/", query: "", status: "200", sub: "", version: "", ua: "", type: "", host: "", tt: -1, ...o});
const many = (n, make) => Array.from({length: n}, (_, i) => row(make(i)));
const rank = (rows) => buildRanking(analyze(rows).ips);
const one = (rows) => rank(rows)[0];

/* ---------- isLegitimate ---------- */

test("isLegitimate: sin tipo sospechoso y status 2xx/3xx", () => {
  for (const status of ["200", "201", "204", "301", "302", "304"]) assert.equal(isLegitimate(row({status})), true, status);
  for (const status of ["400", "401", "403", "404", "500", "503", "", "20", "abc"]) assert.equal(isLegitimate(row({status})), false, status);
});

test("isLegitimate: se descartan ataques, escaneos, bots y scripts aunque respondan 200", () => {
  for (const type of ["SQL INJECTION", "XSS ATTACK", "PATH TRAVERSAL", "EXPLOIT ATTEMPT", "CONFIG SCAN", "ADMIN SCAN", "SECURITY TOOL", "BOT", "SCRIPT"]) {
    assert.equal(isLegitimate(row({status: "200", type})), false, type);
  }
});

/* ---------- analyze: agregados básicos ---------- */

test("excluye IPs privadas del ranking, alertas y fuerza bruta", () => {
  const rows = [row({cip: "10.0.0.1", type: "BOT", status: "401"}), row({cip: "8.8.8.8"})];
  const a = analyze(rows);
  assert.deepEqual([...a.ips.keys()], ["8.8.8.8"]);
  assert.equal(a.alerts.length, 0);
});

test("alertas: una por par IP/tipo", () => {
  const rows = [row({type: "BOT"}), row({type: "BOT"}), row({type: "SQL INJECTION"}), row({cip: "1.1.1.1", type: "BOT"})];
  assert.equal(analyze(rows).alerts.length, 3);
});

test("contadores de estados y URIs únicas", () => {
  const rows = [row({status: "400"}), row({status: "401", uri: "/a"}), row({status: "403", uri: "/b"}), row({status: "404", uri: "/c"}), row({status: "404", uri: "/c"})];
  const [s] = rank(rows);
  assert.deepEqual([s.req, s.e400, s.e401, s.e403, s.e404, s.uris], [5, 1, 1, 1, 2, 4]);
});

/* ---------- fuerza bruta ---------- */

test("fuerza bruta: 20 logins fallidos (401.1) en 5 minutos", () => {
  const rows = many(20, (i) => ({status: "401", sub: "1", ts: T0 + i * 10_000})); // 20 en ~3 min
  const a = analyze(rows);
  assert.deepEqual(a.bruteforce, [{ip: "8.8.8.8", count: 20}]);
});

test("fuerza bruta: 19 no alcanzan", () => {
  const rows = many(19, (i) => ({status: "401", sub: "1", ts: T0 + i * 1000}));
  assert.equal(analyze(rows).bruteforce.length, 0);
});

test("fuerza bruta: 21 intentos repartidos en horas NO es fuerza bruta (ventana de tiempo)", () => {
  const rows = many(21, (i) => ({status: "401", sub: "1", ts: T0 + i * 3_600_000}));
  assert.equal(analyze(rows).bruteforce.length, 0);
});

test("401.2 (desafío de autenticación de Windows) no cuenta como login fallido", () => {
  const rows = many(100, (i) => ({status: "401", sub: "2", ts: T0 + i * 1000}));
  const a = analyze(rows);
  assert.equal(a.bruteforce.length, 0);
  const [s] = buildRanking(a.ips);
  assert.equal(s.risk.label, "Low");
  assert.equal(s.score, 0);
});

test("401 sin substatus (log sin sc-substatus) se trata como login fallido", () => {
  const rows = many(20, (i) => ({status: "401", sub: "", ts: T0 + i * 1000}));
  assert.equal(analyze(rows).bruteforce.length, 1);
});

test("fuerza bruta fuerza riesgo Alto y lo explica", () => {
  const [s] = rank(many(25, (i) => ({status: "401", sub: "1", ts: T0 + i * 1000})));
  assert.equal(s.risk.label, "High");
  assert.ok(s.reasons.some((r) => r.includes("fuerza bruta")), s.reasons.join(" | "));
});

test("maxInWindow", () => {
  assert.equal(maxInWindow([0, 1, 2, 100], 5), 3);
  assert.equal(maxInWindow([0, 10, 20], 5), 1);
  assert.equal(maxInWindow([], 5), 0);
});

/* ---------- score y riesgo ---------- */

test("un ataque real (aunque sea una sola petición) fuerza riesgo Alto", () => {
  const [s] = rank([row({type: "PATH TRAVERSAL", status: "404", uri: "/../../win.ini"})]);
  assert.equal(s.risk.label, "High");
  assert.ok(s.reasons.includes("PATH TRAVERSAL ×1"));
});

test("cada tipo de ataque real fuerza riesgo Alto", () => {
  for (const type of SCORING.realAttackTypes) assert.equal(one([row({type})]).risk.label, "High", type);
});

test("herramienta de seguridad sola => Medio", () => {
  assert.equal(one([row({type: "SECURITY TOOL"})]).risk.label, "Medium");
});

test("un bot que repite el mismo 404 NO es riesgo alto (link roto / monitoreo)", () => {
  const [s] = rank(many(40, () => ({status: "404", uri: "/falta.js", type: "BOT"})));
  assert.equal(s.risk.label, "Low");
  assert.ok(s.score < SCORING.riskMedium, "score " + s.score);
});

test("un escáner (muchas URIs distintas con 404 + tipos de escaneo) => Alto", () => {
  const rows = many(170, (i) => ({status: i < 165 ? "404" : "200", uri: "/p" + i, type: i % 2 ? "CONFIG SCAN" : "ADMIN SCAN"}));
  const [s] = rank(rows);
  assert.equal(s.risk.label, "High");
  assert.ok(s.reasons.some((r) => r.includes("URIs distintas con 404")), s.reasons.join(" | "));
});

test("un usuario legítimo muy activo (muchas requests y URIs) => Bajo, score 0", () => {
  const rows = many(300, (i) => ({uri: "/static/f" + (i % 40) + ".js", status: i === 5 || i === 9 ? "404" : "200"}));
  const [s] = rank(rows);
  assert.equal(s.risk.label, "Low");
  assert.ok(s.score <= 1, "score " + s.score);
});

test("el volumen solo no sube el riesgo", () => {
  assert.equal(one(many(5000, () => ({}))).score, 0);
});

test("un 404 aislado entre muchas requests exitosas no es sospechoso", () => {
  const rows = [...many(200, () => ({})), row({status: "404", uri: "/favicon.ico"})];
  assert.equal(one(rows).risk.label, "Low");
});

test("403 y accesos denegados suman y se explican", () => {
  const [s] = rank(many(8, (i) => ({status: "403", uri: "/x" + i})));
  assert.ok(s.score >= 16);
  assert.ok(s.reasons.some((r) => r.includes("accesos denegados")));
});

test("riskOf: umbrales y forzado", () => {
  assert.equal(riskOf(0).label, "Low");
  assert.equal(riskOf(SCORING.riskMedium).label, "Medium");
  assert.equal(riskOf(SCORING.riskHigh).label, "High");
  assert.equal(riskOf(0, true).label, "High");
});

test("buildRanking: expone score, riesgo y motivos", () => {
  const [s] = rank([row({type: "BOT"})]);
  assert.deepEqual(Object.keys(s).sort(), ["e400", "e401", "e403", "e404", "ip", "reasons", "req", "risk", "score", "uris"]);
  assert.deepEqual(s.reasons, ["BOT ×1"]);
});

test("ordenamiento del ranking (numérico y por IP)", () => {
  const data = [{ip: "10.0.0.10", req: 5}, {ip: "10.0.0.2", req: 9}];
  assert.equal(sortRanking(data, "req", false)[0].ip, "10.0.0.2");
  assert.equal(sortRanking(data, "ip", true)[0].ip, "10.0.0.2", "orden numérico de IPs");
});

/* ---------- URIs lentas y 5xx ---------- */

test("URIs lentas: promedio, máximo y exclusión de filas sin time-taken", () => {
  const rows = [row({uri: "/slow", tt: 1000}), row({uri: "/slow", tt: 3000}), row({uri: "/fast", tt: 10}), row({uri: "/none", tt: -1})];
  const a = analyze(rows);
  assert.equal(a.hasTimeTaken, true);
  const top = topSlow(a.slow);
  assert.deepEqual(top[0], {uri: "/slow", n: 2, avg: 2000, max: 3000});
  assert.equal(top.length, 2);
});

test("sin time-taken => hasTimeTaken false", () => {
  assert.equal(analyze([row({})]).hasTimeTaken, false);
});

test("errores 5xx por URI (incluye IPs privadas)", () => {
  const rows = [row({uri: "/e", status: "500"}), row({uri: "/e", status: "502", cip: "10.0.0.1"}), row({uri: "/o", status: "503"}), row({status: "404"})];
  assert.deepEqual(topErrors(analyze(rows).err5), [{uri: "/e", n: 2}, {uri: "/o", n: 1}]);
});
