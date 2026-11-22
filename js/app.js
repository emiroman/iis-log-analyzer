"use strict";

/* Controlador principal: eventos, filtros, tabla paginada, ranking, exportación y tema. */

const MAX_ALERTS = 1000;
const ATTACK_TYPES = new Set(["SQL INJECTION", "PATH TRAVERSAL", "XSS ATTACK", "EXPLOIT ATTEMPT"]);
const SCANNER_TYPES = new Set(["SECURITY TOOL", "CONFIG SCAN", "WORDPRESS SCAN", "ADMIN SCAN", "DB SCAN"]);

const $ = (id) => document.getElementById(id);
const nextTick = () => new Promise((r) => setTimeout(r, 0));

/* ===================== Estado ===================== */
let rows = [];
let filteredRows = [];
let analysis = null;
let rankingData = [];
let rankingSort = {key: "score", asc: false};
let page = 1;
let pageSize = 250;
let tz = "local"; // "local" | "utc"
let searchIndexBuilt = false;
let filterToken = 0;

/* ===================== UI básica ===================== */
function showLoading(text = "Procesando...") {
  $("loadingText").textContent = text;
  $("loadingOverlay").style.display = "flex";
}
function hideLoading() {
  $("loadingOverlay").style.display = "none";
}

const formatters = {};
function formatDate(ts) {
  if (!ts) return "";
  let f = formatters[tz];
  if (!f) {
    f = formatters[tz] = new Intl.DateTimeFormat("es-AR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      timeZone: tz === "utc" ? "UTC" : undefined,
    });
  }
  return f.format(ts);
}

/** Valor de <input type="datetime-local"> -> ms, interpretado en la zona elegida. */
function parseDateInput(v) {
  if (!v) return null;
  const ms = tz === "utc" ? Date.parse(v + "Z") : new Date(v).getTime();
  return isNaN(ms) ? null : ms;
}

/* ===================== Tema ===================== */
function applyTheme(theme) {
  document.documentElement.setAttribute("data-bs-theme", theme);
  try {
    localStorage.setItem("iisla.theme", theme);
  } catch (e) {
    /* sin persistencia */
  }
  $("btnTheme").textContent = theme === "dark" ? "☀️ Modo claro" : "🌙 Modo oscuro";
  applyChartTheme(theme === "dark");
  if (rows.length) renderCharts(filteredRows, tz);
}

function initTheme() {
  let theme = null;
  try {
    theme = localStorage.getItem("iisla.theme");
  } catch (e) {
    /* sin persistencia */
  }
  if (theme !== "dark" && theme !== "light") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  applyTheme(theme);
}

$("btnTheme").addEventListener("click", () => {
  applyTheme(document.documentElement.getAttribute("data-bs-theme") === "dark" ? "light" : "dark");
});

/* ===================== Carga de archivos ===================== */
$("fileInput").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  if (files.length === 0) return;

  showLoading("Leyendo archivo(s)...");
  try {
    const parsed = [];
    const pool = new Map();
    for (let i = 0; i < files.length; i++) {
      const label = `${files[i].name} (${i + 1}/${files.length})`;
      showLoading(`Analizando ${label}...`);
      await loadFile(
        files[i],
        (batch) => {
          internRows(batch, pool);
          for (let k = 0; k < batch.length; k++) parsed.push(batch[k]);
        },
        (p) => showLoading(`Analizando ${label}... ${Math.round(p * 100)}%`),
      );
    }

    if (parsed.length === 0) {
      alert("No se encontraron registros. Verificá que sea un log W3C de IIS con la línea #Fields.");
      return;
    }
    // Más reciente primero (también fusiona correctamente varios archivos)
    parsed.sort((a, b) => b.ts - a.ts);

    showLoading("Generando análisis...");
    await nextTick();

    rows = parsed;
    filteredRows = rows;
    searchIndexBuilt = false;
    page = 1;
    resetFilterInputs();
    populateFilters(rows);
    resetMapUi();
    $("dashboard").style.display = "block";

    renderTable();
    renderSummary();
    renderCharts(filteredRows, tz);
    updateAnalysis();
  } catch (err) {
    console.error("Error procesando el log:", err);
    alert("No se pudo procesar el archivo: " + err.message);
  } finally {
    hideLoading();
    e.target.value = ""; // permite volver a cargar el mismo archivo
  }
});

/* ===================== Filtros ===================== */
function resetFilterInputs() {
  $("searchBox").value = "";
  $("statusFilter").value = "";
  $("methodFilter").value = "";
  $("typeFilter").value = "";
  $("dateFrom").value = "";
  $("dateTo").value = "";
}

function populateFilters(logs) {
  const fill = (select, firstOptions, values) => {
    select.innerHTML = "";
    firstOptions.forEach(([label, value]) => select.add(new Option(label, value)));
    values.forEach((v) => select.add(new Option(v, v)));
  };
  const distinct = (key) => Array.from(new Set(logs.map((l) => l[key]))).filter((v) => v !== "").sort();
  fill($("statusFilter"), [["Todos los estados", ""]], distinct("status"));
  fill($("methodFilter"), [["Todos los metodos", ""]], distinct("method"));
  fill($("typeFilter"), [["Todos los tipos", ""], ["Solo detectados (cualquier tipo)", "__any"], ["Sin clasificar", "__none"]], distinct("type"));
}

function buildSearchIndex() {
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    r._s = (r.cip + " " + r.host + " " + r.method + " " + r.uri + " " + r.query + " " + r.status + " " + r.version + " " + r.type + " " + r.ua).toLowerCase();
  }
  searchIndexBuilt = true;
}

async function applyFilters() {
  const token = ++filterToken;
  const term = $("searchBox").value.trim().toLowerCase();
  const st = $("statusFilter").value;
  const me = $("methodFilter").value;
  const ty = $("typeFilter").value;
  const from = parseDateInput($("dateFrom").value);
  let to = parseDateInput($("dateTo").value);
  if (to !== null) to += 59999; // el input tiene resolución de minutos: incluir todo el minuto

  if (term && !searchIndexBuilt) {
    showLoading("Indexando registros para la búsqueda...");
    await nextTick();
    buildSearchIndex();
    hideLoading();
    if (token !== filterToken) return; // llegó otro filtro mientras indexaba
  }

  filteredRows = rows.filter(
    (r) =>
      (!st || r.status === st) &&
      (!me || r.method === me) &&
      (!ty || (ty === "__any" ? r.type !== "" : ty === "__none" ? r.type === "" : r.type === ty)) &&
      (from === null || r.ts >= from) &&
      (to === null || (r.ts > 0 && r.ts <= to)) &&
      (!term || r._s.includes(term)),
  );

  page = 1;
  renderTable();
  renderSummary();
  renderCharts(filteredRows, tz);
  scheduleAnalysis();
}

function filterIP(ip) {
  $("searchBox").value = ip;
  applyFilters();
  $("logTable").scrollIntoView({behavior: "smooth", block: "start"});
}

$("searchBox").addEventListener("input", debounce(applyFilters, 250));
["statusFilter", "methodFilter", "typeFilter", "dateFrom", "dateTo"].forEach((id) => $(id).addEventListener("change", applyFilters));
$("btnClearFilters").addEventListener("click", () => {
  resetFilterInputs();
  applyFilters();
});
$("tzSelect").addEventListener("change", (e) => {
  tz = e.target.value;
  applyFilters(); // reinterpreta fechas y recalcula horas
});

// Delegación: un único listener para los links de IP de todas las tablas
document.addEventListener("click", (e) => {
  const link = e.target.closest && e.target.closest(".ip-link");
  if (!link) return;
  e.preventDefault();
  filterIP(link.dataset.ip);
});

/* ===================== Tabla paginada ===================== */
function renderTable() {
  const total = filteredRows.length;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (page > pages) page = pages;

  const start = (page - 1) * pageSize;
  const end = Math.min(total, start + pageSize);
  const parts = [];

  for (let i = start; i < end; i++) {
    const r = filteredRows[i];

    let rowClass = "";
    if (ATTACK_TYPES.has(r.type)) rowClass = "attack";
    else if (SCANNER_TYPES.has(r.type)) rowClass = "scanner";
    else if (r.type === "BOT") rowClass = "bot";

    let statusColor = "bg-secondary";
    if (r.status.startsWith("2")) statusColor = "bg-success";
    else if (r.status.startsWith("4")) statusColor = "bg-warning text-dark";
    else if (r.status.startsWith("5")) statusColor = "bg-danger";

    const methodClass = {POST: "method-post", PUT: "method-put", DELETE: "method-delete", HEAD: "method-head"}[r.method] || "method-get";
    const fullUri = r.uri + (r.query ? "?" + r.query : "");

    parts.push(`<tr class="${rowClass}">
<td>${esc(formatDate(r.ts))}</td>
<td><a href="#" class="ip-link" data-ip="${esc(r.cip)}">${esc(r.cip).replace(/:/g, ":<wbr>")}</a></td>
<td>${esc(r.host).replace(/\./g, ".<wbr>")}</td>
<td><span class="badge ${methodClass}">${esc(r.method)}</span></td>
<td title="${esc(fullUri)}">${esc(fullUri)}</td>
<td><span class="badge ${statusColor}">${esc(r.status)}</span></td>
<td>${esc(r.version)}</td>
<td>${esc(r.type)}</td>
<td title="${esc(r.ua)}">${esc(r.ua)}</td>
</tr>`);
  }

  document.querySelector("#logTable tbody").innerHTML = parts.join("");
  $("totalRows").textContent = `Total registros: ${total.toLocaleString("es-AR")} (mostrando ${total ? start + 1 : 0}-${end})`;
  $("pageInfo").textContent = `Página ${page} de ${pages}`;
  $("btnPrev").disabled = page <= 1;
  $("btnNext").disabled = page >= pages;
}

$("pageSize").addEventListener("change", (e) => {
  pageSize = parseInt(e.target.value, 10);
  page = 1;
  renderTable();
});
$("btnPrev").addEventListener("click", () => {
  page--;
  renderTable();
});
$("btnNext").addEventListener("click", () => {
  page++;
  renderTable();
});

function renderSummary() {
  const ips = new Set();
  for (let i = 0; i < filteredRows.length; i++) ips.add(filteredRows[i].cip);
  $("summary").innerHTML = `
<div class="row text-center">
<div class="col-md-6">
<h6>Total Requests</h6>
<span class="badge bg-primary fs-6">${filteredRows.length.toLocaleString("es-AR")}</span>
</div>
<div class="col-md-6">
<h6>IPs Únicas</h6>
<span class="badge bg-success fs-6">${ips.size.toLocaleString("es-AR")}</span>
</div>
</div>`;
}

/* ===================== Análisis (ranking, alertas, lentas, 5xx) ===================== */
const scheduleAnalysis = debounce(updateAnalysis, 300);

function updateAnalysis() {
  analysis = analyze(filteredRows);
  renderAlerts();
  rankingData = buildRanking(analysis.ips);
  renderRanking();
  renderSlowAndErrors();
}

function alertHtml(ip, type, danger) {
  const color = danger || ATTACK_TYPES.has(type) ? "list-group-item-danger" : "list-group-item-warning";
  return `<li class="list-group-item ${color}"><strong>${esc(ip)}</strong> - ${esc(type)}</li>`;
}

function renderAlerts() {
  let html = analysis.bruteforce.map((b) => alertHtml(b.ip, `POSSIBLE BRUTEFORCE (${b.count} failed logins in ${BRUTEFORCE_WINDOW_MS / 60000} min)`, true)).join("");
  const list = analysis.alerts;
  const shown = Math.min(list.length, MAX_ALERTS);
  for (let i = 0; i < shown; i++) html += alertHtml(list[i].ip, list[i].type, false);
  if (list.length > MAX_ALERTS) html += `<li class="list-group-item">... y ${list.length - MAX_ALERTS} alertas más</li>`;
  $("alerts").innerHTML = html || '<li class="list-group-item">Sin alertas para los filtros actuales.</li>';
}

function renderRanking() {
  const {key, asc} = rankingSort;
  $("ipRanking").innerHTML = sortRanking(rankingData, key, asc)
    .map((s) => {
      const risk = s.risk;
      return `<tr class="text-center">
<td><a href="#" class="ip-link" data-ip="${esc(s.ip)}">${esc(s.ip)}</a></td>
<td>${s.req}</td><td>${s.e400}</td><td>${s.e401}</td><td>${s.e403}</td><td>${s.e404}</td>
<td>${s.uris}</td><td>${s.score}</td>
<td class="${risk.cls}"><span>${risk.label}</span></td>
<td class="text-start small">${esc(s.reasons.join(" · "))}</td>
</tr>`;
    })
    .join("");

  document.querySelectorAll("#tableRanking .sortable").forEach((th) => {
    th.setAttribute("aria-sort", th.dataset.key === key ? (asc ? "ascending" : "descending") : "none");
  });
}

function renderSlowAndErrors() {
  const slowBody = $("slowBody");
  if (analysis.hasTimeTaken) {
    slowBody.innerHTML =
      topSlow(analysis.slow)
        .map((s) => `<tr><td class="text-break">${esc(s.uri)}</td><td class="text-end">${s.n}</td><td class="text-end">${s.avg}</td><td class="text-end">${s.max}</td></tr>`)
        .join("") || '<tr><td colspan="4">Sin datos.</td></tr>';
  } else {
    slowBody.innerHTML = '<tr><td colspan="4">El log no incluye el campo <code>time-taken</code>.</td></tr>';
  }

  $("errBody").innerHTML =
    topErrors(analysis.err5)
      .map((e) => `<tr><td class="text-break">${esc(e.uri)}</td><td class="text-end">${e.n}</td></tr>`)
      .join("") || '<tr><td colspan="2">Sin errores 5xx.</td></tr>';
}

document.querySelectorAll("#tableRanking .sortable").forEach((th) => {
  const sort = () => {
    const key = th.dataset.key;
    rankingSort = rankingSort.key === key ? {key, asc: !rankingSort.asc} : {key, asc: key === "ip"};
    renderRanking();
  };
  th.addEventListener("click", sort);
  th.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      sort();
    }
  });
});

/* ===================== Exportación ===================== */
function downloadFile(name, content, mime) {
  const blob = new Blob([content], {type: mime});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const stamp = () => new Date().toISOString().replace(/[:T]/g, "-").slice(0, 19);
const isoDate = (ts) => (ts ? new Date(ts).toISOString() : "");

$("btnExportCsv").addEventListener("click", () => {
  if (!filteredRows.length) return;
  const headers = ["fecha_utc", "ip", "host", "metodo", "uri", "query", "status", "protocolo", "tipo", "user_agent", "time_taken_ms"];
  const records = filteredRows.map((r) => [isoDate(r.ts), r.cip, r.host, r.method, r.uri, r.query, r.status, r.version, r.type, r.ua, r.tt >= 0 ? r.tt : ""]);
  downloadFile(`iis-logs-${stamp()}.csv`, "﻿" + toCsv(headers, records), "text/csv;charset=utf-8");
});

$("btnExportJson").addEventListener("click", () => {
  if (!filteredRows.length) return;
  const data = filteredRows.map((r) => ({
    date_utc: isoDate(r.ts),
    ip: r.cip,
    host: r.host,
    method: r.method,
    uri: r.uri,
    query: r.query,
    status: r.status,
    version: r.version,
    type: r.type,
    user_agent: r.ua,
    time_taken_ms: r.tt >= 0 ? r.tt : null,
  }));
  downloadFile(`iis-logs-${stamp()}.json`, JSON.stringify(data, null, 1), "application/json");
});

$("btnExportRanking").addEventListener("click", () => {
  if (!rankingData.length) return;
  const sorted = sortRanking(rankingData, rankingSort.key, rankingSort.asc);
  const headers = ["ip", "requests", "e400", "e401", "e403", "e404", "uris", "score", "riesgo", "motivos"];
  const records = sorted.map((s) => [s.ip, s.req, s.e400, s.e401, s.e403, s.e404, s.uris, s.score, s.risk.label, s.reasons.join(" | ")]);
  downloadFile(`iis-ranking-ips-${stamp()}.csv`, "﻿" + toCsv(headers, records), "text/csv;charset=utf-8");
});

/* ===================== Mapa (opt-in) ===================== */
function resetMapUi() {
  resetMap();
  $("map").classList.add("d-none");
  $("mapStatus").textContent = "";
  $("btnLoadMap").textContent = "Cargar mapa";
}

$("btnLoadMap").addEventListener("click", async () => {
  if (!analysis) return;
  const btn = $("btnLoadMap");
  btn.disabled = true;
  $("map").classList.remove("d-none");
  try {
    await loadMap(analysis.ips, (t) => ($("mapStatus").textContent = t));
    btn.textContent = "Actualizar mapa con los filtros actuales";
  } catch (err) {
    console.error(err);
    $("mapStatus").textContent = "No se pudo cargar el mapa: " + err.message;
  } finally {
    btn.disabled = false;
  }
});

$("btnFullscreenMap").addEventListener("click", () => {
  if (!map) return;
  if (!document.fullscreenElement) $("map").requestFullscreen().catch(() => {});
  else document.exitFullscreen();
});
document.addEventListener("fullscreenchange", () => setTimeout(() => map && map.invalidateSize(), 300));

// Pie de página: versión y enlace al repositorio (js/version.js)
$("appVersion").textContent = "v" + APP_VERSION;
$("appRepoLink").href = APP_REPO_URL;
$("appRepoLink").title = "Notas de cada versión: " + APP_REPO_URL + "/releases";

initTheme();
