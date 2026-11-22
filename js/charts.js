"use strict";

const charts = {};

const CHART_LABELS = {
  statusChart: "Códigos de Estado",
  methodChart: "Métodos HTTP",
  timelineChart: "Peticiones legítimas por Hora",
  attackChart: "Tipos de Ataques",
};
const PALETTE = ["#0d6efd", "#198754", "#dc3545", "#ffc107", "#6f42c1", "#20c997", "#fd7e14", "#6c757d"];

function applyChartTheme(dark) {
  if (typeof Chart === "undefined") return;
  Chart.defaults.color = dark ? "#dee2e6" : "#212529";
  Chart.defaults.borderColor = dark ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.1)";
}

function drawChart(id, type, data) {
  if (typeof Chart === "undefined") return;
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

  charts[id] = new Chart(document.getElementById(id), {type, data: {labels, datasets: [dataset]}, options});
}

/** tz: "local" | "utc" */
function renderCharts(rows, tz) {
  const status = {};
  const method = {};
  const attacks = {};
  const hours = {};
  for (let i = 0; i < 24; i++) hours[i.toString().padStart(2, "0")] = 0;

  const d = new Date(0);
  const utc = tz === "utc";
  let legit = 0;

  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    status[r.status] = (status[r.status] || 0) + 1;
    method[r.method] = (method[r.method] || 0) + 1;
    if (r.type) attacks[r.type] = (attacks[r.type] || 0) + 1;
    // El gráfico por hora mide el uso real: solo tráfico legítimo (sin sospechosos ni errores)
    if (r.ts > 0 && isLegitimate(r)) {
      d.setTime(r.ts);
      hours[(utc ? d.getUTCHours() : d.getHours()).toString().padStart(2, "0")]++;
      legit++;
    }
  }

  const note = document.getElementById("hoursNote");
  if (note) {
    const pct = rows.length ? Math.round((legit / rows.length) * 100) : 0;
    note.textContent = `${legit.toLocaleString("es-AR")} de ${rows.length.toLocaleString("es-AR")} peticiones (${pct} %) consideradas`;
  }

  drawChart("statusChart", "pie", status);
  drawChart("methodChart", "bar", method);
  drawChart("timelineChart", "line", hours);
  drawChart("attackChart", "bar", attacks);
}
