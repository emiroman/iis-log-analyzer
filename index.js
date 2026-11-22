"use strict";

/* ===================== Estado ===================== */
let rows = []; // todos los registros parseados
let filteredRows = []; // registros tras aplicar filtros
let charts = {};
let rankingData = []; // [{ip, req, e400, e401, e403, e404, uris, score}]
let rankingSort = {key: "score", asc: false};

let map;
let markerCluster;
let mapToken = 0; // evita condiciones de carrera al cargar un archivo nuevo

const MAX_ROWS = 20000; // máximo de filas dibujadas en la tabla
const MAX_ALERTS = 1000; // máximo de alertas dibujadas
const MAP_MAX_IPS = 100; // IPs más activas a geolocalizar
const GEO_BATCH_SIZE = 50; // IPs por request (evita URLs demasiado largas)
const BRUTEFORCE_THRESHOLD = 20; // cantidad de 401 por IP

const ATTACK_TYPES = new Set(["SQL INJECTION", "PATH TRAVERSAL", "XSS ATTACK", "EXPLOIT ATTEMPT"]);
const SCANNER_TYPES = new Set(["SECURITY TOOL", "CONFIG SCAN", "WORDPRESS SCAN", "ADMIN SCAN", "DB SCAN"]);

const $ = (id) => document.getElementById(id);

/* ===================== Utilidades ===================== */
function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function debounce(fn, ms) {
  let t;
  return (...args) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s.replace(/\+/g, " "));
  } catch {
    return s.replace(/\+/g, " ");
  }
}

function isPrivateIP(ip) {
  if (!ip) return true;
  ip = ip.toLowerCase();
  if (ip.includes(":")) {
    return ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80");
  }
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\./);
  if (!m) return true; // no es una IP válida: no se analiza
  const a = +m[1];
  const b = +m[2];
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

function showLoading(text = "Procesando...") {
  $("loadingText").innerText = text;
  $("loadingOverlay").style.display = "flex";
}

function hideLoading() {
  $("loadingOverlay").style.display = "none";
}

const nextTick = () => new Promise((r) => setTimeout(r, 0));

/* ===================== Eventos (se registran una sola vez) ===================== */
const searchBox = $("searchBox");
const statusFilter = $("statusFilter");
const methodFilter = $("methodFilter");

searchBox.addEventListener("input", debounce(applyFilters, 250));
statusFilter.addEventListener("change", applyFilters);
methodFilter.addEventListener("change", applyFilters);

// Delegación: un único listener para los links de IP de ambas tablas
document.addEventListener("click", (e) => {
  const link = e.target.closest && e.target.closest(".ip-link");
  if (!link) return;
  e.preventDefault();
  filterIP(link.dataset.ip);
});

$("btnFullscreenMap").addEventListener("click", () => {
  const mapContainer = $("map");
  if (!document.fullscreenElement) {
    mapContainer.requestFullscreen().then(() => {
      setTimeout(() => map && map.invalidateSize(), 300);
    });
  } else {
    document.exitFullscreen();
  }
});
document.addEventListener("fullscreenchange", () => setTimeout(() => map && map.invalidateSize(), 300));

$("fileInput").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  if (files.length === 0) return;

  showLoading("Leyendo archivo(s)...");
  try {
    const parsed = [];
    for (let i = 0; i < files.length; i++) {
      showLoading(`Leyendo ${files[i].name} (${i + 1}/${files.length})...`);
      const text = await files[i].text();
      await parseLog(text, parsed, files[i].name);
    }
    if (files.length > 1) parsed.sort((a, b) => a.ts - b.ts);
    rows = parsed;

    showLoading("Generando análisis...");
    await nextTick();

    resetFilters();
    populateFilters(rows);
    filteredRows = rows;
    $("dashboard").style.display = "block";

    renderAll();
    detectAttacks();
    detectBruteforce();
    buildIpRanking();
    buildMap(); // asíncrono, no bloquea la UI
  } catch (err) {
    console.error("Error procesando el log:", err);
    alert("No se pudo procesar el archivo: " + err.message);
  } finally {
    hideLoading();
    e.target.value = ""; // permite volver a cargar el mismo archivo
  }
});

/* ===================== Parseo ===================== */
async function parseLog(text, out, fileName) {
  let fields = [];
  const lines = text.split("\n");

  // Formatter creado una sola vez
  const formatter = new Intl.DateTimeFormat("es-AR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  const CHUNK = 20000;
  for (let n = 0; n < lines.length; n++) {
    // Ceder el hilo periódicamente para no congelar la UI
    if (n % CHUNK === 0 && n > 0) {
      showLoading(`Analizando ${fileName}... ${Math.round((n / lines.length) * 100)}%`);
      await nextTick();
    }

    const line = lines[n].trim();
    if (line === "") continue;

    if (line.startsWith("#Fields:")) {
      fields = line.slice(8).trim().split(/\s+/);
      continue;
    }
    if (line.startsWith("#")) continue;
    if (fields.length === 0) continue;

    const parts = line.split(" ");
    const obj = {};
    for (let i = 0; i < fields.length; i++) obj[fields[i]] = parts[i] || "";

    const clean = (v) => (v && v !== "-" ? v : "");

    let ua = obj["cs(User-Agent)"] || "";
    if (ua.includes("%") || ua.includes("+")) ua = safeDecode(ua);

    const uri = obj["cs-uri-stem"] || "";
    const query = clean(obj["cs-uri-query"]);
    const type = detectType(ua, uri, query);

    // Fecha en UTC (IIS registra en UTC por defecto)
    const utc = new Date(obj["date"] + "T" + obj["time"] + "Z");
    const validDate = !isNaN(utc.getTime());

    const row = {
      ts: validDate ? utc.getTime() : 0,
      date: validDate ? formatter.format(utc) : `${obj["date"] || ""} ${obj["time"] || ""}`.trim(),
      hour: validDate ? utc.getHours() : -1,
      cip: obj["c-ip"] || "",
      method: obj["cs-method"] || "",
      uri,
      query,
      status: obj["sc-status"] || "",
      version: obj["cs-version"] || "",
      ua,
      type,
      host: obj["cs-host"] || "",
    };
    // Cadena de búsqueda precalculada (evita JSON.stringify en cada tecla)
    row._s = [row.date, row.cip, row.host, row.method, row.uri, row.query, row.status, row.version, row.type, row.ua].join(" ").toLowerCase();
    out.push(row);
  }
}

/* ===================== Detección ===================== */
const RE = {
  traversal: /\.\.[\/\\]|%2e%2e|\.\.%2f|\.\.%5c/,
  sqli: /(?:'|%27)\s*(?:or|and|--|;|\)|=)|union\s+(?:all\s+)?select|\bor\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema|;\s*drop\s+table|\bselect\b.+\bfrom\b/,
  xss: /<script|%3cscript|javascript:|onerror\s*=|onload\s*=|<img[\s%]|%3cimg|<svg|%3csvg|alert\s*\(/,
  exploit: /\$\{jndi:|%24%7bjndi|\/etc\/passwd|cmd\.exe|powershell|\/bin\/(?:ba)?sh/,
  config: /\.env(?:\b|$)|\/\.git(?:\/|$)|web\.config|appsettings(?:\.[\w-]+)?\.json|wp-config|\.htaccess|\.htpasswd|\.ds_store/,
  wordpress: /wp-admin|wp-login|wp-content|wp-includes|xmlrpc\.php/,
  admin: /\/admin(?:istrator)?(?:\/|$|\.)/,
  db: /phpmyadmin|dbadmin|\/pma(?:\/|$)|\/mysql(?:\/|$)|adminer/,
};

function detectType(ua, uri, query) {
  const rawTarget = (uri + (query ? "?" + query : "")).toLowerCase();
  // Se revisa tanto el texto crudo como su versión decodificada
  const target = rawTarget + " " + safeDecode(rawTarget);
  ua = (ua || "").toLowerCase();

  // 1) Ataques sobre la URL (incluye query string)
  if (RE.traversal.test(target)) return "PATH TRAVERSAL";
  if (RE.exploit.test(target)) return "EXPLOIT ATTEMPT";
  if (RE.sqli.test(target)) return "SQL INJECTION";
  if (RE.xss.test(target)) return "XSS ATTACK";

  // 2) Herramientas de seguridad por User-Agent
  if (/sqlmap|nikto|nmap|acunetix|nessus|masscan|zgrab|dirbuster|gobuster|wpscan|nuclei/.test(ua)) return "SECURITY TOOL";

  // 3) Descubrimiento de archivos / paneles
  if (RE.config.test(target)) return "CONFIG SCAN";
  if (RE.wordpress.test(target)) return "WORDPRESS SCAN";
  if (RE.db.test(target)) return "DB SCAN";
  if (RE.admin.test(target)) return "ADMIN SCAN";

  // 4) Bots y automatización
  if (/bot|crawler|spider/.test(ua)) return "BOT";
  if (/curl|wget|python|go-http-client|libwww/.test(ua)) return "SCRIPT";

  return "";
}

function detectAttacks() {
  const ul = $("alerts");
  ul.innerHTML = "";
  const seen = new Set();
  let html = "";
  let count = 0;

  for (const r of rows) {
    if (!r.type || isPrivateIP(r.cip)) continue;
    const key = r.cip + "-" + r.type;
    if (seen.has(key)) continue;
    seen.add(key);
    if (count++ < MAX_ALERTS) html += alertHtml(r.cip, r.type);
  }
  if (count > MAX_ALERTS) html += `<li class="list-group-item">... y ${count - MAX_ALERTS} alertas más</li>`;
  ul.innerHTML = html;
}

function detectBruteforce() {
  const attempts = {};
  for (const r of rows) {
    if (r.status === "401" && !isPrivateIP(r.cip)) attempts[r.cip] = (attempts[r.cip] || 0) + 1;
  }
  let html = "";
  for (const [ip, count] of Object.entries(attempts)) {
    if (count > BRUTEFORCE_THRESHOLD) html += alertHtml(ip, `POSSIBLE BRUTEFORCE (${count} 401)`, true);
  }
  $("alerts").insertAdjacentHTML("afterbegin", html);
}

function alertHtml(ip, type, danger = false) {
  const color = danger || ATTACK_TYPES.has(type) ? "list-group-item-danger" : "list-group-item-warning";
  return `<li class="list-group-item ${color}"><strong>${esc(ip)}</strong> - ${esc(type)}</li>`;
}

/* ===================== Filtros ===================== */
function resetFilters() {
  searchBox.value = "";
  statusFilter.value = "";
  methodFilter.value = "";
}

function filterIP(ip) {
  searchBox.value = ip;
  applyFilters();
  $("logTable").scrollIntoView({behavior: "smooth", block: "start"});
}

function applyFilters() {
  const term = searchBox.value.trim().toLowerCase();
  const st = statusFilter.value;
  const me = methodFilter.value;

  filteredRows = rows.filter((r) => (!st || r.status === st) && (!me || r.method === me) && (!term || r._s.includes(term)));

  renderTable(filteredRows);
  renderSummary();
  renderCharts();
}

function populateFilters(logs) {
  const fill = (select, label, values) => {
    select.innerHTML = "";
    select.add(new Option(label, ""));
    values.forEach((v) => select.add(new Option(v, v)));
  };
  fill(statusFilter, "Todos los estados", Array.from(new Set(logs.map((l) => l.status))).sort());
  fill(methodFilter, "Todos los metodos", Array.from(new Set(logs.map((l) => l.method))).sort());
}

/* ===================== Render ===================== */
function renderAll() {
  renderTable(filteredRows);
  renderSummary();
  renderCharts();
}

function renderTable(data) {
  const tbody = document.querySelector("#logTable tbody");
  const parts = [];

  const limit = Math.min(data.length, MAX_ROWS);
  for (let i = 0; i < limit; i++) {
    const r = data[i];

    let rowClass = "";
    if (ATTACK_TYPES.has(r.type)) rowClass = "attack";
    else if (SCANNER_TYPES.has(r.type)) rowClass = "scanner";
    else if (r.type === "BOT") rowClass = "bot";

    let statusColor = "bg-secondary";
    if (r.status.startsWith("2")) statusColor = "bg-success";
    else if (r.status.startsWith("4")) statusColor = "bg-warning text-dark";
    else if (r.status.startsWith("5")) statusColor = "bg-danger";

    const methodClass =
      {POST: "method-post", PUT: "method-put", DELETE: "method-delete", HEAD: "method-head"}[r.method] || "method-get";

    const fullUri = r.uri + (r.query ? "?" + r.query : "");

    parts.push(`<tr class="${rowClass}">
<td style="min-width:160px;">${esc(r.date)}</td>
<td><a href="#" class="ip-link" data-ip="${esc(r.cip)}">${esc(r.cip)}</a></td>
<td>${esc(r.host)}</td>
<td><span class="badge ${methodClass}">${esc(r.method)}</span></td>
<td>${esc(fullUri)}</td>
<td><span class="badge ${statusColor}">${esc(r.status)}</span></td>
<td>${esc(r.version)}</td>
<td>${esc(r.type)}</td>
<td class="text-truncate" style="max-width:500px" title="${esc(r.ua)}">${esc(r.ua)}</td>
</tr>`);
  }

  tbody.innerHTML = parts.join("");
  $("totalRows").innerText = "Total registros: " + data.length + " (mostrando " + limit + ")";
}

function renderSummary() {
  const ips = new Set();
  filteredRows.forEach((r) => ips.add(r.cip));
  $("summary").innerHTML = `
<div class="row text-center">
<div class="col-md-6">
<h6>Total Requests</h6>
<span class="badge bg-primary fs-6">${filteredRows.length}</span>
</div>
<div class="col-md-6">
<h6>IPs Únicas</h6>
<span class="badge bg-success fs-6">${ips.size}</span>
</div>
</div>
`;
}

function renderCharts() {
  const status = {};
  const method = {};
  const attacks = {};
  const hours = {};
  for (let i = 0; i < 24; i++) hours[i.toString().padStart(2, "0")] = 0;

  for (const r of filteredRows) {
    status[r.status] = (status[r.status] || 0) + 1;
    method[r.method] = (method[r.method] || 0) + 1;
    if (r.type) attacks[r.type] = (attacks[r.type] || 0) + 1;
    if (r.hour >= 0) hours[r.hour.toString().padStart(2, "0")]++;
  }

  drawChart("statusChart", "pie", status);
  drawChart("methodChart", "bar", method);
  drawChart("timelineChart", "line", hours);
  drawChart("attackChart", "bar", attacks);
}

const CHART_LABELS = {
  statusChart: "Códigos de Estado",
  methodChart: "Métodos HTTP",
  timelineChart: "Peticiones por Hora",
  attackChart: "Tipos de Ataques",
};
const PALETTE = ["#0d6efd", "#198754", "#dc3545", "#ffc107", "#6f42c1", "#20c997", "#fd7e14", "#6c757d"];

function drawChart(id, type, data) {
  if (charts[id]) charts[id].destroy();

  const labels = Object.keys(data).sort();
  const values = labels.map((l) => data[l]);

  const dataset = {label: CHART_LABELS[id] || "", data: values};
  if (type === "line") {
    dataset.borderColor = "#0d6efd";
    dataset.backgroundColor = "rgba(13,110,253,0.15)";
    dataset.fill = true;
    dataset.tension = 0.4;
  } else {
    dataset.backgroundColor = labels.map((_, i) => PALETTE[i % PALETTE.length]);
  }

  const options = {responsive: true, plugins: {legend: {display: true}}};
  if (type === "line") {
    options.scales = {
      x: {title: {display: true, text: "Horas del día (hs)"}},
      y: {title: {display: true, text: "Cantidad"}, beginAtZero: true},
    };
  } else if (type === "bar") {
    options.scales = {y: {beginAtZero: true}};
  }

  charts[id] = new Chart($(id), {type, data: {labels, datasets: [dataset]}, options});
}

/* ===================== Ranking de IPs ===================== */
function buildIpRanking() {
  const stats = {};

  for (const r of rows) {
    const ip = r.cip;
    if (isPrivateIP(ip)) continue;
    let s = stats[ip];
    if (!s) s = stats[ip] = {ip, req: 0, e400: 0, e401: 0, e403: 0, e404: 0, uris: new Set()};
    s.req++;
    if (r.status === "400") s.e400++;
    else if (r.status === "401") s.e401++;
    else if (r.status === "403") s.e403++;
    else if (r.status === "404") s.e404++;
    s.uris.add(r.uri);
  }

  rankingData = Object.values(stats).map((s) => {
    let score = 0;
    if (s.req > 50) score += 10;
    score += s.e401 * 3 + s.e400 + s.e403 * 2 + s.e404 * 2;
    if (s.uris.size > 20) score += 5;
    return {ip: s.ip, req: s.req, e400: s.e400, e401: s.e401, e403: s.e403, e404: s.e404, uris: s.uris.size, score};
  });

  renderRanking();
}

function renderRanking() {
  const {key, asc} = rankingSort;
  const sorted = [...rankingData].sort((a, b) => {
    const cmp = key === "ip" ? a.ip.localeCompare(b.ip, undefined, {numeric: true}) : a[key] - b[key];
    return asc ? cmp : -cmp;
  });

  $("ipRanking").innerHTML = sorted
    .map((s) => {
      let risk = "Low";
      let riskClass = "risk-low";
      if (s.score > 50) {
        risk = "High";
        riskClass = "risk-high";
      } else if (s.score >= 20) {
        risk = "Medium";
        riskClass = "risk-medium";
      }
      return `<tr class="text-center">
<td><a href="#" class="ip-link" data-ip="${esc(s.ip)}">${esc(s.ip)}</a></td>
<td>${s.req}</td>
<td>${s.e400}</td>
<td>${s.e401}</td>
<td>${s.e403}</td>
<td>${s.e404}</td>
<td>${s.uris}</td>
<td>${s.score}</td>
<td class="${riskClass}"><span>${risk}</span></td>
</tr>`;
    })
    .join("");
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("#tableRanking .sortable").forEach((header) => {
    header.style.cursor = "pointer";
    header.addEventListener("click", () => {
      const key = header.dataset.key;
      rankingSort = rankingSort.key === key ? {key, asc: !rankingSort.asc} : {key, asc: key === "ip"};
      renderRanking();
    });
  });
});

/* ===================== Mapa ===================== */
function initMap() {
  if (map) map.remove();
  const argentinaCentro = [-38.4161, -63.6167];
  map = L.map("map").setView(argentinaCentro, 4);

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap",
  }).addTo(map);

  markerCluster = L.markerClusterGroup();
  map.addLayer(markerCluster);

  setTimeout(() => map.invalidateSize(), 0);
}

async function geolocateIPs(ips) {
  const results = [];
  for (let i = 0; i < ips.length; i += GEO_BATCH_SIZE) {
    const batch = ips.slice(i, i + GEO_BATCH_SIZE);
    try {
      const r = await fetch(`https://get.geojs.io/v1/ip/geo.json?ip=${batch.join(",")}`);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      (Array.isArray(data) ? data : [data]).forEach((item) =>
        results.push({
          ip: item.ip,
          latitude: parseFloat(item.latitude),
          longitude: parseFloat(item.longitude),
          city: item.city ?? "",
          country: item.country ?? "",
          isp: item.organization_name ?? "",
        }),
      );
    } catch (e) {
      console.warn("Error en geolocalización. Detalle:", e);
    }
  }
  return results;
}

async function buildMap() {
  const token = ++mapToken;
  initMap();

  const counts = {};
  for (const r of rows) {
    if (isPrivateIP(r.cip)) continue;
    counts[r.cip] = (counts[r.cip] || 0) + 1;
  }

  const ips = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, MAP_MAX_IPS)
    .map((x) => x[0]);

  if (ips.length === 0) return;

  const geo = await geolocateIPs(ips);
  if (token !== mapToken) return; // se cargó otro archivo mientras tanto

  const heatPoints = [];
  for (const g of geo) {
    if (isNaN(g.latitude) || isNaN(g.longitude)) continue;
    const marker = L.marker([g.latitude, g.longitude]).bindPopup(
      `<b>${esc(g.ip)}</b><br><span><b>ISP:</b> ${esc(g.isp)}</span><br>${g.city ? esc(g.city) + ", " : ""}${esc(g.country)}`,
    );
    markerCluster.addLayer(marker);
    heatPoints.push([g.latitude, g.longitude, 0.5]);
  }

  if (heatPoints.length > 0) {
    L.heatLayer(heatPoints, {radius: 25, blur: 20, maxZoom: 6}).addTo(map);
  } else {
    console.log("No hay coordenadas válidas para el mapa.");
  }
}
