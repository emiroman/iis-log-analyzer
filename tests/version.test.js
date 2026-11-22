"use strict";
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const {APP_VERSION, APP_REPO_URL} = require("../js/version.js");
const root = path.join(__dirname, "..");

test("APP_VERSION tiene formato semántico MAYOR.MENOR.PARCHE", () => {
  assert.match(APP_VERSION, /^\d+\.\d+\.\d+$/);
});

test("APP_VERSION coincide con la versión de package.json", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  assert.equal(APP_VERSION, pkg.version, "actualizá js/version.js y package.json juntos");
});

test("la página carga version.js y tiene el pie de página con la versión", () => {
  const html = fs.readFileSync(path.join(root, "index.html"), "utf8");
  assert.ok(html.includes('src="js/version.js"'), "index.html debe cargar js/version.js");
  assert.ok(html.includes('id="appVersion"'), "index.html debe tener el elemento #appVersion");
});

test("APP_REPO_URL es una URL https de GitHub", () => {
  assert.match(APP_REPO_URL, /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/);
});
