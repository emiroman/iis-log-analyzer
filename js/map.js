"use strict";

/*
 * Mapa de origen de IPs. Es opt-in: solo se consulta GeoJS cuando el usuario
 * pulsa el botón. Las geolocalizaciones se cachean en localStorage.
 */

let map = null;
let markerCluster = null;
let mapToken = 0; // evita condiciones de carrera si cambia el análisis mientras se consulta

const MAP_MAX_IPS = 100; // IPs más activas a geolocalizar
const GEO_BATCH_SIZE = 50; // IPs por request (evita URLs demasiado largas)
const GEO_CACHE_KEY = "iisla.geo.v1";
const GEO_TTL = 30 * 24 * 3600 * 1000; // 30 días
const GEO_CACHE_MAX = 5000;

function loadGeoCache() {
  try {
    const raw = localStorage.getItem(GEO_CACHE_KEY);
    if (!raw) return {};
    const cache = JSON.parse(raw);
    const now = Date.now();
    for (const ip of Object.keys(cache)) if (!cache[ip] || now - cache[ip].t > GEO_TTL) delete cache[ip];
    return cache;
  } catch (e) {
    return {};
  }
}

function saveGeoCache(cache) {
  try {
    const keys = Object.keys(cache);
    if (keys.length > GEO_CACHE_MAX) {
      keys.sort((a, b) => cache[a].t - cache[b].t);
      keys.slice(0, keys.length - GEO_CACHE_MAX).forEach((k) => delete cache[k]);
    }
    localStorage.setItem(GEO_CACHE_KEY, JSON.stringify(cache));
  } catch (e) {
    /* localStorage no disponible o lleno: el mapa funciona igual sin caché */
  }
}

function resetMap() {
  mapToken++;
  if (map) {
    map.remove();
    map = null;
    markerCluster = null;
  }
}

function initMap() {
  resetMap();
  const argentinaCentro = [-38.4161, -63.6167];
  map = L.map("map").setView(argentinaCentro, 4);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {attribution: "© OpenStreetMap"}).addTo(map);
  markerCluster = L.markerClusterGroup();
  map.addLayer(markerCluster);
  setTimeout(() => map && map.invalidateSize(), 0);
}

async function geolocateIPs(ips, cache, stats) {
  const results = [];
  const missing = [];
  for (const ip of ips) {
    if (cache[ip]) {
      results.push(cache[ip].d);
      stats.cached++;
    } else {
      missing.push(ip);
    }
  }

  for (let i = 0; i < missing.length; i += GEO_BATCH_SIZE) {
    const batch = missing.slice(i, i + GEO_BATCH_SIZE);
    try {
      const r = await fetch(`https://get.geojs.io/v1/ip/geo.json?ip=${batch.join(",")}`);
      if (!r.ok) throw new Error("HTTP " + r.status);
      const data = await r.json();
      for (const item of Array.isArray(data) ? data : [data]) {
        const d = {
          ip: item.ip,
          latitude: parseFloat(item.latitude),
          longitude: parseFloat(item.longitude),
          city: item.city ?? "",
          country: item.country ?? "",
          isp: item.organization_name ?? "",
        };
        if (isNaN(d.latitude) || isNaN(d.longitude)) continue;
        cache[d.ip] = {d, t: Date.now()};
        results.push(d);
        stats.fetched++;
      }
    } catch (e) {
      stats.failed += batch.length;
      console.warn("Error en geolocalización. Detalle:", e);
    }
  }
  return results;
}

/**
 * ipsMap: Map ip -> {req, ...} (solo IPs públicas).
 * setStatus(texto): callback para informar el progreso.
 */
async function loadMap(ipsMap, setStatus) {
  initMap();
  const token = mapToken;

  const ips = Array.from(ipsMap.entries())
    .sort((a, b) => b[1].req - a[1].req)
    .slice(0, MAP_MAX_IPS)
    .map((x) => x[0]);

  if (ips.length === 0) {
    setStatus("No hay IPs públicas para ubicar.");
    return;
  }

  setStatus(`Ubicando ${ips.length} IPs...`);
  const cache = loadGeoCache();
  const stats = {cached: 0, fetched: 0, failed: 0};
  const geo = await geolocateIPs(ips, cache, stats);
  saveGeoCache(cache);
  if (token !== mapToken) return; // el mapa se reinició mientras se consultaba

  const heatPoints = [];
  for (const g of geo) {
    const marker = L.marker([g.latitude, g.longitude]).bindPopup(
      `<b>${esc(g.ip)}</b><br><span><b>ISP:</b> ${esc(g.isp)}</span><br>${g.city ? esc(g.city) + ", " : ""}${esc(g.country)}`,
    );
    markerCluster.addLayer(marker);
    heatPoints.push([g.latitude, g.longitude, 0.5]);
  }
  if (heatPoints.length > 0) L.heatLayer(heatPoints, {radius: 25, blur: 20, maxZoom: 6}).addTo(map);

  setStatus(`${geo.length} de ${ips.length} IPs ubicadas (${stats.cached} desde caché, ${stats.fetched} consultadas${stats.failed ? ", " + stats.failed + " con error" : ""}).`);
}
