"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {createDetector} = require("../js/detect.js");
const {createParser, internRows} = require("../js/parser.js");

const parser = createParser(createDetector());

const HEADER = [
  "#Software: Microsoft Internet Information Services 10.0",
  "#Version: 1.0",
  "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs-host sc-status time-taken",
].join("\n");

const LINE_OK = "2026-03-07 10:15:32 10.0.0.5 GET /index.html - 443 - 203.0.113.15 Mozilla/5.0+(Windows) example.com 200 45";
const LINE_ATTACK = "2026-03-07 23:59:59 10.0.0.5 GET /a.aspx id=1'+OR+1=1-- 443 - 198.51.100.7 curl/8.0 example.com 500 1200";

test("parsea campos según la línea #Fields", () => {
  const [r] = parser.parseText(HEADER + "\n" + LINE_OK + "\n");
  assert.equal(r.cip, "203.0.113.15");
  assert.equal(r.method, "GET");
  assert.equal(r.uri, "/index.html");
  assert.equal(r.query, "", "'-' se convierte en vacío");
  assert.equal(r.status, "200");
  assert.equal(r.host, "example.com");
  assert.equal(r.ua, "Mozilla/5.0 (Windows)", "'+' se decodifica a espacio");
  assert.equal(r.tt, 45);
  assert.equal(r.ts, Date.UTC(2026, 2, 7, 10, 15, 32));
  assert.equal(r.type, "");
});

test("detecta ataques usando la query string", () => {
  const [r] = parser.parseText(HEADER + "\n" + LINE_ATTACK);
  assert.equal(r.type, "SQL INJECTION");
  assert.equal(r.status, "500");
});

test("ignora comentarios, líneas vacías y líneas antes de #Fields", () => {
  const rows = parser.parseText("2026-01-01 00:00:00 x\n\n" + HEADER + "\n\n" + LINE_OK + "\r\n");
  assert.equal(rows.length, 1);
});

test("soporta CRLF y última línea sin salto", () => {
  const rows = parser.parseText((HEADER + "\n" + LINE_OK + "\n" + LINE_OK).replace(/\n/g, "\r\n"));
  assert.equal(rows.length, 2);
});

test("fecha inválida => ts 0; campos faltantes => vacío; sin time-taken => -1", () => {
  const text = "#Fields: date time c-ip cs-method sc-status\nbasura xx 1.2.3.4 GET 200";
  const [r] = parser.parseText(text);
  assert.equal(r.ts, 0);
  assert.equal(r.tt, -1);
  assert.equal(r.uri, "");
  assert.equal(r.cip, "1.2.3.4");
});

test("la sesión incremental une líneas partidas entre trozos", () => {
  const full = HEADER + "\n" + LINE_OK + "\n" + LINE_ATTACK + "\n";
  const out = [];
  const s = parser.createSession((b) => out.push(...b), 1);
  for (let i = 0; i < full.length; i += 7) s.feed(full.slice(i, i + 7)); // trozos de 7 caracteres
  s.end();
  assert.equal(out.length, 2);
  assert.equal(out[0].uri, "/index.html");
  assert.equal(out[1].cip, "198.51.100.7");
});

test("un nuevo #Fields cambia el esquema (archivos concatenados)", () => {
  const text = HEADER + "\n" + LINE_OK + "\n#Fields: date time c-ip sc-status\n2026-03-08 00:00:00 9.9.9.9 404\n";
  const rows = parser.parseText(text);
  assert.equal(rows.length, 2);
  assert.equal(rows[1].cip, "9.9.9.9");
  assert.equal(rows[1].status, "404");
});

test("parseFile lee un File por trozos", async () => {
  const content = HEADER + "\n" + LINE_OK + "\n" + LINE_ATTACK + "\n";
  const file = new Blob([content]); // Blob tiene size/slice/arrayBuffer como File
  const out = [];
  await parser.parseFile(file, {onBatch: (b) => out.push(...b)});
  assert.equal(out.length, 2);
});

test("internRows comparte instancias de strings repetidos", () => {
  const rows = parser.parseText(HEADER + "\n" + LINE_OK + "\n" + LINE_OK);
  rows[1].ua = "Mozilla/5.0 (Windows)".slice(); // distinta instancia, mismo valor
  const pool = new Map();
  internRows(rows, pool);
  assert.equal(rows[0].ua, rows[1].ua);
  assert.ok(pool.has("example.com"));
});
