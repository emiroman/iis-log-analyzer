let rows = [];
let filteredRows = [];
let charts = {};
let fields = [];

let map;
let markerCluster;
let heatPoints = [];
let geoCache = {};

const searchBox = document.getElementById("searchBox");
const statusFilter = document.getElementById("statusFilter");
const methodFilter = document.getElementById("methodFilter");

searchBox.addEventListener("input", applyFilters);
statusFilter.addEventListener("change", applyFilters);
methodFilter.addEventListener("change", applyFilters);

document.getElementById("fileInput").addEventListener("change", function (e) {
  console.log("*** Iniciando carga ***");
  const file = e.target.files[0];
  if (!file) {
    console.log("No hay archivo seleccionado.");
    return;
  }
  showLoading("Analizando archivo de log...");
  const reader = new FileReader();
  reader.onload = async function (evt) {
    await new Promise((r) => setTimeout(r, 10));
    parseLog(evt.target.result);
    document.getElementById("dashboard").style.display = "block";
    hideLoading();
    populateFilters(filteredRows);
  };
  reader.readAsText(file);
});

const searchInput = document.getElementById("searchBox");
searchInput.addEventListener("input", filterLogs);

function parseLog(text) {
  rows = [];
  fields = [];

  const lines = text.split("\n");

  // Crear formatter UNA sola vez (gran mejora)
  const formatter = new Intl.DateTimeFormat("es-AR", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  for (let line of lines) {
    line = line.trim();

    if (line.startsWith("#Fields:")) {
      fields = line.replace("#Fields:", "").trim().split(" ");
      continue;
    }

    if (line.startsWith("#") || line === "") continue;

    const parts = line.split(" ");
    const obj = {};

    fields.forEach((f, i) => {
      obj[f] = parts[i] || "";
    });

    let ua = obj["cs(User-Agent)"] || "";

    // Decodificar solo si es necesario
    if (ua.includes("%")) {
      ua = decodeURIComponent(ua.replace(/\+/g, " "));
    }

    const uri = obj["cs-uri-stem"] || "";
    const type = detectType(ua, uri);

    // Crear fecha UTC
    const utc = new Date(obj["date"] + "T" + obj["time"] + "Z");

    rows.push({
      date: formatter.format(utc), // reutiliza formatter
      cip: obj["c-ip"],
      method: obj["cs-method"],
      uri,
      status: obj["sc-status"],
      version: obj["cs-version"],
      ua,
      type,
      host: obj["cs-host"] || "",
    });
  }

  filteredRows = [...rows];

  renderAll();
  detectAttacks();
  buildAttackStats();
  detectBruteforce();
  buildIpRanking();
  buildMap();
}

function detectBruteforce() {
  let attempts = {};
  rows.forEach((r) => {
    if (r.status === "401") {
      attempts[r.cip] = (attempts[r.cip] || 0) + 1;
    }
  });
  Object.entries(attempts).forEach(([ip, count]) => {
    if (count > 20) {
      addAlert(ip, "POSSIBLE BRUTEFORCE (" + count + " 401)");
    }
  });
}

function buildAttackStats() {
  let stats = {};

  rows.forEach((r) => {
    if (!r.type) return;
    stats[r.type] = (stats[r.type] || 0) + 1;
  });

  drawChart("attackChart", "bar", stats);
}

function detectType(ua, uri) {
  ua = (ua || "").toLowerCase();
  uri = (uri || "").toLowerCase();

  // BOT
  if (ua.includes("bot") || ua.includes("crawler") || ua.includes("spider")) return "BOT";

  // SECURITY SCANNERS
  if (ua.includes("sqlmap") || ua.includes("nikto") || ua.includes("nmap") || ua.includes("acunetix") || ua.includes("nessus")) return "SECURITY TOOL";

  // PATH TRAVERSAL
  if (uri.includes("../") || uri.includes("..\\") || uri.includes("%2e%2e")) return "PATH TRAVERSAL";

  // SQL INJECTION
  if (uri.includes("'") || uri.includes("%27") || uri.includes(" or ") || uri.includes("union select") || uri.includes("sleep(") || uri.includes("benchmark(")) return "SQL INJECTION";

  // XSS
  if (uri.includes("<script") || uri.includes("%3cscript") || uri.includes("javascript:")) return "XSS ATTACK";

  // FILE DISCOVERY / CONFIG
  if (uri.includes(".env") || uri.includes(".git") || uri.includes("config") || uri.includes("web.config") || uri.includes("appsettings")) return "CONFIG SCAN";

  // CMS SCANNERS
  if (uri.includes("wp-admin") || uri.includes("wp-login") || uri.includes("xmlrpc.php")) return "WORDPRESS SCAN";

  // ADMIN DISCOVERY
  if (uri.includes("/admin") || uri.includes("/administrator") || uri.includes("/dashboard")) return "ADMIN SCAN";

  // SENSITIVE FILES
  if (uri.includes("phpmyadmin") || uri.includes("mysql") || uri.includes("dbadmin")) return "DB SCAN";

  // SCRIPT / AUTOMATION
  if (ua.includes("curl") || ua.includes("wget") || ua.includes("python")) return "SCRIPT";

  return "";
}

function renderAll() {
  renderTable(filteredRows);
  renderSummary();
  renderCharts();
}

function renderTable(data) {
  const tbody = document.querySelector("#logTable tbody");
  tbody.innerHTML = "";

  const fragment = document.createDocumentFragment();
  const MAX_ROWS = 20000;

  data.slice(0, MAX_ROWS).forEach((r) => {
    let rowClass = "";

    if (r.type === "ATTACK") rowClass = "attack";
    if (r.type === "SCANNER") rowClass = "scanner";
    if (r.type === "BOT") rowClass = "bot";

    let statusColor = "bg-secondary";

    if (r.status.startsWith("2")) statusColor = "bg-success";
    if (r.status.startsWith("4")) statusColor = "bg-warning text-dark";
    if (r.status.startsWith("5")) statusColor = "bg-danger";

    let methodClass = "method-get";

    if (r.method === "POST") methodClass = "method-post";
    if (r.method === "PUT") methodClass = "method-put";
    if (r.method === "DELETE") methodClass = "method-delete";
    if (r.method === "HEAD") methodClass = "method-head";

    const tr = document.createElement("tr");

    tr.innerHTML = `
<td style="min-width:160px;">${r.date}</td>
<td><a href="#" class="ip-link" data-ip="${r.cip}">${r.cip}</a></td>
<td>${r.host}</td>
<td><span class="badge ${methodClass}">${r.method}</span></td>
<td>${r.uri}</td>
<td><span class="badge ${statusColor}">${r.status}</span></td>
<td>${r.version || ""}</td>
<td>${r.type}</td>
<td class="text-truncate" style="max-width:500px">${r.ua}</td>
`;

    tr.className = rowClass;

    fragment.appendChild(tr);
  });

  tbody.appendChild(fragment);

  document.getElementById("totalRows").innerText = "Total registros: " + data.length + " (mostrando " + Math.min(data.length, MAX_ROWS) + ")";

  document.querySelector("#logTable").addEventListener("click", function (e) {
    if (e.target.classList.contains("ip-link")) {
      e.preventDefault();
      filterIP(e.target.dataset.ip);
    }
  });
}

function filterIP(ip) {
  document.getElementById("searchBox").value = ip;
  filterLogs();
  //populateFilters(filteredRows);
}

function buildIpRanking() {
  let stats = {};

  rows.forEach((r) => {
    let ip = r.cip;

    if (isPrivateIP(ip)) return;

    if (!stats[ip]) stats[ip] = {req: 0, e400: 0, e401: 0,e403: 0,e404: 0, uris: new Set()};

    stats[ip].req++;

    if (r.status === "400") stats[ip].e400++;
    if (r.status === "401") stats[ip].e401++;
    if (r.status === "403") stats[ip].e403++;
    if (r.status === "404") stats[ip].e404++;

    stats[ip].uris.add(r.uri);
  });

  //let ordenado = Object.entries(stats).sort((a, b) => b[1].req - a[1].req);

  let statsOrdenado = Object.fromEntries(Object.entries(stats).sort((a, b) => b[1].req - a[1].req));

  let tbody = document.getElementById("ipRanking");
  tbody.innerHTML = "";

  Object.entries(statsOrdenado).forEach(([ip, s]) => {
    let score = 0;

    if (s.req > 50) score += 10;
    score += s.e401 * 3;
    score += s.e400;
    score += s.e403 * 2;
    score += s.e404 * 2;

    if (s.uris.size > 20) score += 5;

    let risk = "Low";
    let riskClass = "risk-low";

    if (score > 50) {
      risk = "High";
      riskClass = "risk-high";
    } else if (score >= 20) {
      risk = "Medium";
      riskClass = "risk-medium";
    }

    let tr = document.createElement("tr");
    tr.classList.add("text-center");
    tr.innerHTML = `
<td><a href="#" class="ip-link" data-ip="${ip}">${ip}</a></td>
<td>${s.req}</td>
<td>${s.e400}</td>
<td>${s.e401}</td>
<td>${s.e403}</td>
<td>${s.e404}</td>
<td>${s.uris.size}</td>
<td>${score}</td>
<td class="${riskClass}">
<span>${risk}</span>
</td>
`;
    tbody.appendChild(tr);
  });

  document.querySelector("#tableRanking").addEventListener("click", function (e) {
    if (e.target.classList.contains("ip-link")) {
      e.preventDefault();
      filterIP(e.target.dataset.ip);
    }
  });
}

function renderSummary() {
  let ips = new Set();
  rows.forEach((r) => ips.add(r.cip));
  document.getElementById("summary").innerHTML = `
<div class="row text-center">
<div class="col-md-6">
<h6>Total Requests</h6>
<span class="badge bg-primary fs-6">${rows.length}</span>
</div>
<div class="col-md-6">
<h6>IPs Únicas</h6>
<span class="badge bg-success fs-6">${ips.size}</span>
</div>
</div>
`;
}

function renderCharts() {
  let status = {},
    method = {},
    hours = {};

  rows.forEach((r) => {
    // Conteo por status
    status[r.status] = (status[r.status] || 0) + 1;
    // Conteo por método
    method[r.method] = (method[r.method] || 0) + 1;
    // Obtener la hora (00-23)
    let h = r.date.substring(11, 13);
    hours[h] = (hours[h] || 0) + 1;
  });

  // Asegurar que existan todas las horas
  for (let i = 0; i < 24; i++) {
    let h = i.toString().padStart(2, "0");
    if (!hours[h]) hours[h] = 0;
  }

  // Ordenar las horas
  hours = Object.fromEntries(Object.entries(hours).sort((a, b) => a[0].localeCompare(b[0])));

  drawChart("statusChart", "pie", status);
  drawChart("methodChart", "bar", method);
  drawChart("timelineChart", "line", hours);
}

function drawChart(id, type, data) {
  if (charts[id]) {
    charts[id].destroy();
  }

  let label = "";

  if (id === "statusChart") label = "Códigos de Estado";
  if (id === "methodChart") label = "Métodos HTTP";
  if (id === "timelineChart") label = "Peticiones por Hora";
  if (id === "attackChart") label = "Tipos de Ataques";

  const labels = Object.keys(data).sort();
  const values = labels.map((l) => data[l]);

  charts[id] = new Chart(document.getElementById(id), {
    type,
    data: {
      labels: labels,
      datasets: [
        {
          label: label,
          //labels: labels,
          data: values,
          backgroundColor: ["#0d6efd", "#198754", "#dc3545", "#ffc107", "#6f42c1", "#20c997", "#fd7e14", "#6c757d"],
          borderColor: "#0d6efd",
          fill: false,
          tension: 0.2,
        },
      ],
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: true,
        },
      },
      scales:
        id === "timelineChart"
          ? {
              x: {
                title: {
                  display: true,
                  text: "Horas del día (hs)",
                },
              },
              y: {
                title: {
                  display: true,
                  text: "Cantidad",
                },
                beginAtZero: true,
              },
            }
          : {},
    },
  });
}

function filterLogs() {
  let term = document.getElementById("searchBox").value.toLowerCase();
  filteredRows = rows.filter((r) => JSON.stringify(r).toLowerCase().includes(term));
  renderTable(filteredRows);
}

function detectAttacks() {
  const ul = document.getElementById("alerts");
  ul.innerHTML = "";
  let seen = new Set();
  rows.forEach((r) => {
    if (!r.type) return;
    let key = r.cip + "-" + r.type;
    if (seen.has(key)) return;
    seen.add(key);
    addAlert(r.cip, r.type);
  });
}

function addAlert(ip, type) {
  const li = document.createElement("li");
  let color = "list-group-item-warning";
  if (type === "SQL INJECTION" || type === "PATH TRAVERSAL" || type === "XSS ATTACK") color = "list-group-item-danger";

  li.className = "list-group-item " + color;
  li.innerHTML = `<strong>${ip}</strong> - ${type}`;
  document.getElementById("alerts").appendChild(li);
}

function initMap() {
  if (map) {
    map.remove(); // destruye el mapa anterior
  }
  map = L.map("map").setView([20, 0], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "© OpenStreetMap",
  }).addTo(map);
  markerCluster = L.markerClusterGroup();
  map.addLayer(markerCluster);
  setTimeout(() => {
    map.invalidateSize();
  }, 500);
}

async function geolocateIP(ip) {
  if (geoCache[ip]) return geoCache[ip];

  try {
    let r = await fetch(`https://get.geojs.io/v1/ip/geo/${ip}.json`);
    let data = await r.json();
    if (data) {
      geoCache[ip] = data;
      return data;
    }
  } catch (e) {
    console.log("Geo lookup error:", ip);
  }

  return null;
}

function isPrivateIP(ip) {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("172.16.") ||
    ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") ||
    ip.startsWith("172.20.") ||
    ip.startsWith("172.21.") ||
    ip.startsWith("172.22.") ||
    ip.startsWith("172.23.") ||
    ip.startsWith("172.24.") ||
    ip.startsWith("172.25.") ||
    ip.startsWith("172.26.") ||
    ip.startsWith("172.27.") ||
    ip.startsWith("172.28.") ||
    ip.startsWith("172.29.") ||
    ip.startsWith("172.30.") ||
    ip.startsWith("172.31.") ||
    ip === "127.0.0.1" ||
    ip === "::1"
  );
}

async function buildMap() {
  heatPoints = [];
  initMap();
  //let ips = [...new Set(rows.map(r => r.cip))]
  let counts = {};

  rows.forEach((r) => {
    counts[r.cip] = (counts[r.cip] || 0) + 1;
  });

  let ips = Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map((x) => x[0]);

  for (let ip of ips) {
    if (isPrivateIP(ip)) continue;
    let geo = await geolocateIP(ip);
    if (!geo) continue;
    if (geo.latitude == "nil" && geo.longitude == "nil") continue;
    let lat = parseFloat(geo.latitude);
    let lon = parseFloat(geo.longitude);
    let marker = L.marker([lat, lon]).bindPopup(`
<b>${ip}</b><br>
${geo.city}, ${geo.country}
`);
    markerCluster.addLayer(marker);
    heatPoints.push([lat, lon, 0.5]);
  }

  if (heatPoints.length > 0) {
    const validPoints = heatPoints.filter((p) => p && !isNaN(p[0]) && !isNaN(p[1]));

    if (validPoints.length > 0) {
      var heat = L.heatLayer(validPoints, {
        radius: 25,
        blur: 20,
        maxZoom: 6,
      }).addTo(map);
    } else {
      console.log("No hay coordenadas válidas para el mapa.");
    }
  } else {
    console.log("No hay datos para el heatmap.");
  }
}

function showLoading(text = "Procesando...") {
  document.getElementById("loadingText").innerText = text;
  document.getElementById("loadingOverlay").style.display = "flex";
}

function hideLoading() {
  document.getElementById("loadingOverlay").style.display = "none";
}
function applyFilters() {
  const searchText = searchBox.value.toLowerCase();
  const selectedStatus = statusFilter.value;
  const selectedMethod = methodFilter.value;

  const filtered = filteredRows.filter((log) => {
    const matchesSearch = Object.values(log).join(" ").toLowerCase().includes(searchText);

    const matchesStatus = !selectedStatus || log.status == selectedStatus;

    const matchesMethod = !selectedMethod || log.method == selectedMethod;

    return matchesSearch && matchesStatus && matchesMethod;
  });
  //populateFilters(filtered);
  renderTable(filtered);
}

function populateFilters(logs) {
  const select = document.getElementById("statusFilter");
  const selectMethod = document.getElementById("methodFilter");

  select.innerHTML = "";
  selectMethod.innerHTML = "";

  const defaultOption = document.createElement("option");
  defaultOption.value = "";
  defaultOption.textContent = "Todos los estados";
  select.appendChild(defaultOption);
  
  const defaultOptionMethod = document.createElement("option");
  defaultOptionMethod.value = "";
  defaultOptionMethod.textContent = "Todos los metodos";
  selectMethod.appendChild(defaultOptionMethod);

  const statusSet = new Set(logs.map((l) => l.status));

  const methodSet = new Set(logs.map((l) => l.method));
  const sortedMethod = Array.from(methodSet).sort();

  const sortedStatus = Array.from(statusSet).sort();
  if (statusSet.size > 1) {
    sortedStatus.forEach((status) => {
      const option = document.createElement("option");
      option.value = status;
      option.textContent = status;
      select.appendChild(option);
    });
  }

  sortedMethod.forEach((method) => {
    const option = document.createElement("option");
    option.value = method;
    option.textContent = method;
    selectMethod.appendChild(option);
  });
}
