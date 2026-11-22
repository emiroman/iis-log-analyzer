"use strict";

/*
 * Parser de logs W3C de IIS. Fábrica autocontenida (se serializa dentro del Web Worker).
 *
 * Cada registro: {ts, cip, method, uri, query, status, version, ua, type, host, tt}
 *   ts: milisegundos UTC (0 si la fecha es inválida) | tt: time-taken en ms (-1 si no existe)
 *   sub: sc-substatus ("" si el log no lo incluye)
 */
function createParser(detector) {
  const {detectType, safeDecode} = detector;
  const DEFAULT_BATCH = 20000;
  const READ_CHUNK = 8 * 1024 * 1024; // bytes por lectura de archivo

  const at = (parts, i) => (i >= 0 && i < parts.length ? parts[i] : "");

  /** Sesión incremental: se alimenta con texto en trozos arbitrarios. */
  function createSession(onBatch, batchSize) {
    batchSize = batchSize || DEFAULT_BATCH;
    let idx = null;
    let leftover = "";
    let batch = [];

    function setFields(line) {
      const f = line.slice(8).trim().split(/\s+/);
      const pos = (name) => f.indexOf(name);
      idx = {
        date: pos("date"),
        time: pos("time"),
        ip: pos("c-ip"),
        method: pos("cs-method"),
        uri: pos("cs-uri-stem"),
        query: pos("cs-uri-query"),
        status: pos("sc-status"),
        sub: pos("sc-substatus"),
        version: pos("cs-version"),
        ua: pos("cs(User-Agent)"),
        host: pos("cs-host"),
        tt: pos("time-taken"),
      };
    }

    function processLine(raw) {
      const line = raw.trim();
      if (line === "") return;
      if (line.charCodeAt(0) === 35) {
        // "#"
        if (line.startsWith("#Fields:")) setFields(line);
        return;
      }
      if (!idx) return;

      const p = line.split(" ");

      let ua = at(p, idx.ua);
      if (ua.includes("%") || ua.includes("+")) ua = safeDecode(ua);

      const uri = at(p, idx.uri);
      const q = at(p, idx.query);
      const query = q === "-" ? "" : q;

      let ts = Date.parse(at(p, idx.date) + "T" + at(p, idx.time) + "Z");
      if (isNaN(ts)) ts = 0;

      const ttRaw = at(p, idx.tt);
      let tt = ttRaw && ttRaw !== "-" ? parseInt(ttRaw, 10) : -1;
      if (isNaN(tt)) tt = -1;

      const subRaw = at(p, idx.sub);

      batch.push({
        ts,
        cip: at(p, idx.ip),
        method: at(p, idx.method),
        uri,
        query,
        status: at(p, idx.status),
        sub: subRaw === "-" ? "" : subRaw, // sc-substatus (ej. 401.1 vs 401.2)
        version: at(p, idx.version),
        ua,
        type: detectType(ua, uri, query),
        host: at(p, idx.host),
        tt,
      });

      if (batch.length >= batchSize) flush();
    }

    function flush() {
      if (batch.length > 0) {
        const b = batch;
        batch = [];
        onBatch(b);
      }
    }

    function feed(text) {
      const lines = (leftover + text).split("\n");
      leftover = lines.pop();
      for (let i = 0; i < lines.length; i++) processLine(lines[i]);
    }

    function end() {
      if (leftover) processLine(leftover);
      leftover = "";
      flush();
    }

    return {feed, end};
  }

  /** Parseo sincrónico de un texto completo (tests y archivos pequeños). */
  function parseText(text) {
    const out = [];
    const s = createSession((b) => {
      for (let i = 0; i < b.length; i++) out.push(b[i]);
    });
    s.feed(text);
    s.end();
    return out;
  }

  /** Lee un File por trozos (soporta archivos mucho mayores que el límite de un string). */
  async function parseFile(file, opts) {
    const {onBatch, onProgress, yieldFn, batchSize} = opts;
    const session = createSession(onBatch, batchSize);
    const decoder = new TextDecoder("utf-8");

    for (let off = 0; off < file.size; off += READ_CHUNK) {
      const buf = await file.slice(off, off + READ_CHUNK).arrayBuffer();
      session.feed(decoder.decode(buf, {stream: true}));
      if (onProgress) onProgress(Math.min(1, (off + READ_CHUNK) / file.size));
      if (yieldFn) await yieldFn();
    }
    session.feed(decoder.decode());
    session.end();
  }

  return {createSession, parseText, parseFile};
}

/** Reemplaza ua/host/etc. por una única instancia compartida (ahorra memoria). */
function internRows(batch, pool) {
  const keys = ["cip", "method", "status", "sub", "version", "ua", "type", "host"];
  for (let i = 0; i < batch.length; i++) {
    const r = batch[i];
    for (let k = 0; k < keys.length; k++) {
      const v = r[keys[k]];
      const prev = pool.get(v);
      if (prev === undefined) pool.set(v, v);
      else r[keys[k]] = prev;
    }
  }
}

if (typeof module !== "undefined") module.exports = {createParser, internRows};
