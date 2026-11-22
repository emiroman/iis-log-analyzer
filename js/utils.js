"use strict";

/* Utilidades puras compartidas (sin dependencias del DOM). */

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

/**
 * Celda CSV segura. Los textos que empiezan con = + - @ se prefijan con una
 * comilla simple para evitar inyección de fórmulas al abrir el CSV en Excel
 * (los datos del log los controla el atacante).
 */
function csvCell(v) {
  let s = String(v ?? "");
  if (typeof v !== "number" && /^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

function toCsv(headers, records) {
  const out = [headers.map(csvCell).join(",")];
  for (const r of records) out.push(r.map(csvCell).join(","));
  return out.join("\r\n");
}

if (typeof module !== "undefined") module.exports = {esc, debounce, isPrivateIP, csvCell, toCsv};
