"use strict";

/*
 * Versión de la aplicación (se muestra en el pie de página).
 * Debe coincidir con "version" de package.json (lo verifica tests/version.test.js).
 * Formato semántico: MAYOR.MENOR.PARCHE
 */
const APP_VERSION = "1.2.0";
const APP_REPO_URL = "https://github.com/emiroman/iis-log-analyzer";

if (typeof module !== "undefined") module.exports = {APP_VERSION, APP_REPO_URL};
