"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {esc, isPrivateIP, csvCell, toCsv} = require("../js/utils.js");

test("esc escapa HTML y atributos", () => {
  assert.equal(esc('<img src=x onerror="a()">'), "&lt;img src=x onerror=&quot;a()&quot;&gt;");
  assert.equal(esc("a&b'c"), "a&amp;b&#39;c");
  assert.equal(esc(null), "");
  assert.equal(esc(5), "5");
});

test("isPrivateIP", () => {
  for (const ip of ["10.1.1.1", "192.168.0.1", "172.16.0.1", "172.31.255.255", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "fd00::1", "", "no-es-ip"]) {
    assert.equal(isPrivateIP(ip), true, ip);
  }
  for (const ip of ["8.8.8.8", "172.15.0.1", "172.32.0.1", "203.0.113.5", "2001:db8::1"]) {
    assert.equal(isPrivateIP(ip), false, ip);
  }
});

test("csvCell: comillas, comas, saltos de línea", () => {
  assert.equal(csvCell("simple"), "simple");
  assert.equal(csvCell("a,b"), '"a,b"');
  assert.equal(csvCell('di "hola"'), '"di ""hola"""');
  assert.equal(csvCell("l1\nl2"), '"l1\nl2"');
});

test("csvCell neutraliza inyección de fórmulas pero respeta números", () => {
  assert.equal(csvCell("=HYPERLINK(\"http://x\")"), '"\'=HYPERLINK(""http://x"")"');
  assert.equal(csvCell("+1+1"), "'+1+1");
  assert.equal(csvCell("@SUM(A1)"), "'@SUM(A1)");
  assert.equal(csvCell(-5), "-5");
});

test("toCsv arma encabezado y filas", () => {
  assert.equal(toCsv(["a", "b"], [[1, "x,y"], [2, ""]]), 'a,b\r\n1,"x,y"\r\n2,');
});
