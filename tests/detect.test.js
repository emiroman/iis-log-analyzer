"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const {createDetector} = require("../js/detect.js");

const {detectType} = createDetector();
const UA = "Mozilla/5.0";

test("tráfico normal no se clasifica", () => {
  assert.equal(detectType(UA, "/index.html", ""), "");
  assert.equal(detectType(UA, "/api/orders", "page=2&sort=asc"), "");
});

test("SQL injection en query string (crudo y codificado)", () => {
  assert.equal(detectType(UA, "/a.aspx", "id=1'+OR+1=1--"), "SQL INJECTION");
  assert.equal(detectType(UA, "/a.aspx", "id=1+UNION+SELECT+null,null"), "SQL INJECTION");
  assert.equal(detectType(UA, "/a.aspx", "id=1%27%20or%201=1"), "SQL INJECTION");
  assert.equal(detectType(UA, "/a.aspx", "x=sleep(5)"), "SQL INJECTION");
});

test("XSS", () => {
  assert.equal(detectType(UA, "/s", "q=%3Cscript%3Ealert(1)%3C/script%3E"), "XSS ATTACK");
  assert.equal(detectType(UA, "/s", "q=<img src=x onerror=alert(1)>"), "XSS ATTACK");
});

test("path traversal", () => {
  assert.equal(detectType(UA, "/../../windows/win.ini", ""), "PATH TRAVERSAL");
  assert.equal(detectType(UA, "/x/%2e%2e/%2e%2e/etc", ""), "PATH TRAVERSAL");
});

test("exploits conocidos", () => {
  assert.equal(detectType(UA, "/x", "a=${jndi:ldap://evil/x}"), "EXPLOIT ATTEMPT");
  assert.equal(detectType(UA, "/x", "f=/etc/passwd"), "EXPLOIT ATTEMPT");
});

test("descubrimiento de archivos y paneles", () => {
  assert.equal(detectType(UA, "/.env", ""), "CONFIG SCAN");
  assert.equal(detectType(UA, "/.git/config", ""), "CONFIG SCAN");
  assert.equal(detectType(UA, "/web.config", ""), "CONFIG SCAN");
  assert.equal(detectType(UA, "/wp-login.php", ""), "WORDPRESS SCAN");
  assert.equal(detectType(UA, "/phpmyadmin/index.php", ""), "DB SCAN");
  assert.equal(detectType(UA, "/admin/", ""), "ADMIN SCAN");
});

test("sin falsos positivos que existían antes", () => {
  assert.equal(detectType(UA, "/dashboard", ""), "", "/dashboard es legítimo");
  assert.equal(detectType(UA, "/static/configuration.js", ""), "", "'config' suelto no basta");
  assert.equal(detectType(UA, "/products", "category=color+or+size"), "");
  assert.equal(detectType(UA, "/administracion-de-turnos", ""), "");
});

test("por User-Agent", () => {
  assert.equal(detectType("sqlmap/1.7", "/", ""), "SECURITY TOOL");
  assert.equal(detectType("Googlebot/2.1", "/", ""), "BOT");
  assert.equal(detectType("curl/8.0", "/", ""), "SCRIPT");
  assert.equal(detectType("python-requests/2.31", "/", ""), "SCRIPT");
});

test("la URL maliciosa tiene prioridad sobre el User-Agent de bot", () => {
  assert.equal(detectType("Googlebot", "/a", "id=1' or 1=1--"), "SQL INJECTION");
});

test("no lanza con porcentajes mal formados", () => {
  assert.doesNotThrow(() => detectType(UA, "/Login.aspx", "ReturnUrl=%E0%A4%A"));
  assert.equal(detectType(UA, "/Login.aspx", "ReturnUrl=%E0%A4%A"), "");
});
