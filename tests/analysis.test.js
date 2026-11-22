"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");

// analysis.js usa isPrivateIP como global (en el navegador viene de utils.js)
global.isPrivateIP = require("../js/utils.js").isPrivateIP;
const {analyze, isLegitimate, scoreOf, riskOf, buildRanking, sortRanking, topSlow, topErrors} = require("../js/analysis.js");

const row = (o) => ({ts: 1, cip: "8.8.8.8", method: "GET", uri: "/", query: "", status: "200", version: "", ua: "", type: "", host: "", tt: -1, ...o});

test("isLegitimate: sin tipo sospechoso y status 2xx/3xx", () => {
  for (const status of ["200", "201", "204", "301", "302", "304"]) assert.equal(isLegitimate(row({status})), true, status);
  for (const status of ["400", "401", "403", "404", "500", "503", "", "20", "abc"]) assert.equal(isLegitimate(row({status})), false, status);
});

test("isLegitimate: se descartan ataques, escaneos, bots y scripts aunque respondan 200", () => {
  for (const type of ["SQL INJECTION", "XSS ATTACK", "PATH TRAVERSAL", "EXPLOIT ATTEMPT", "CONFIG SCAN", "ADMIN SCAN", "SECURITY TOOL", "BOT", "SCRIPT"]) {
    assert.equal(isLegitimate(row({status: "200", type})), false, type);
  }
});

test("excluye IPs privadas del ranking, alertas y fuerza bruta", () => {
  const rows = [row({cip: "10.0.0.1", type: "BOT", status: "401"}), row({cip: "8.8.8.8"})];
  const a = analyze(rows);
  assert.deepEqual([...a.ips.keys()], ["8.8.8.8"]);
  assert.equal(a.alerts.length, 0);
});

test("alertas: una por par IP/tipo", () => {
  const rows = [row({type: "BOT"}), row({type: "BOT"}), row({type: "SQL INJECTION"}), row({cip: "1.1.1.1", type: "BOT"})];
  const a = analyze(rows);
  assert.equal(a.alerts.length, 3);
});

test("fuerza bruta: más de 20 respuestas 401", () => {
  const rows = Array.from({length: 21}, () => row({status: "401"}));
  rows.push(...Array.from({length: 20}, () => row({cip: "9.9.9.9", status: "401"})));
  const a = analyze(rows);
  assert.deepEqual(a.bruteforce, [{ip: "8.8.8.8", count: 21}]);
});

test("contadores de estados y URIs únicas", () => {
  const rows = [row({status: "400"}), row({status: "401", uri: "/a"}), row({status: "403", uri: "/b"}), row({status: "404", uri: "/c"}), row({status: "404", uri: "/c"})];
  const s = analyze(rows).ips.get("8.8.8.8");
  assert.deepEqual([s.req, s.e400, s.e401, s.e403, s.e404, s.uris.size], [5, 1, 1, 1, 2, 4]);
});

test("score y riesgo", () => {
  // 3 (401) + 2 (403) + 4 (2x404) + 1 (400) = 10
  const rows = [row({status: "400"}), row({status: "401"}), row({status: "403"}), row({status: "404"}), row({status: "404"})];
  const [r] = buildRanking(analyze(rows).ips);
  assert.equal(r.score, 10);
  assert.equal(riskOf(10).label, "Low");
  assert.equal(riskOf(20).label, "Medium");
  assert.equal(riskOf(51).label, "High");
  assert.equal(scoreOf({req: 51, e400: 0, e401: 0, e403: 0, e404: 0, uris: new Set(Array.from({length: 21}, (_, i) => i))}), 15);
});

test("ordenamiento del ranking (numérico y por IP)", () => {
  const data = [{ip: "10.0.0.10", req: 5}, {ip: "10.0.0.2", req: 9}];
  assert.equal(sortRanking(data, "req", false)[0].ip, "10.0.0.2");
  assert.equal(sortRanking(data, "ip", true)[0].ip, "10.0.0.2", "orden numérico de IPs");
});

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
  const top = topErrors(analyze(rows).err5);
  assert.deepEqual(top, [{uri: "/e", n: 2}, {uri: "/o", n: 1}]);
});
