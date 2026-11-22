"use strict";

/*
 * Carga de archivos: parseo en un Web Worker (no bloquea la UI).
 * El worker se crea desde un Blob con el código de detect.js + parser.js, para que
 * funcione también abriendo index.html directamente (file://), donde un Worker
 * desde archivo externo estaría bloqueado. Si el Worker no está disponible se
 * parsea en el hilo principal cediendo el control periódicamente.
 */

function workerSource() {
  return `"use strict";
const createDetector = ${createDetector.toString()};
const createParser = ${createParser.toString()};
const parser = createParser(createDetector());
self.onmessage = async (e) => {
  try {
    await parser.parseFile(e.data.file, {
      onBatch: (rows) => self.postMessage({type: "batch", rows}),
      onProgress: (p) => self.postMessage({type: "progress", p}),
    });
    self.postMessage({type: "done"});
  } catch (err) {
    self.postMessage({type: "error", message: String((err && err.message) || err)});
  }
};`;
}

function runInWorker(file, onBatch, onProgress) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(new Blob([workerSource()], {type: "text/javascript"}));
    let worker;
    try {
      worker = new Worker(url);
    } catch (e) {
      URL.revokeObjectURL(url);
      reject(e);
      return;
    }
    const cleanup = () => {
      worker.terminate();
      URL.revokeObjectURL(url);
    };
    worker.onmessage = (e) => {
      const m = e.data;
      if (m.type === "batch") onBatch(m.rows);
      else if (m.type === "progress") onProgress(m.p);
      else if (m.type === "done") {
        cleanup();
        resolve();
      } else if (m.type === "error") {
        cleanup();
        reject(new Error(m.message));
      }
    };
    worker.onerror = (e) => {
      cleanup();
      reject(new Error(e.message || "Error en el worker"));
    };
    worker.postMessage({file});
  });
}

async function runInMainThread(file, onBatch, onProgress) {
  const parser = createParser(createDetector());
  await parser.parseFile(file, {
    onBatch,
    onProgress,
    yieldFn: () => new Promise((r) => setTimeout(r, 0)),
  });
}

/** Parsea un File entregando lotes de registros mediante onBatch. */
async function loadFile(file, onBatch, onProgress) {
  let received = false;
  const wrapped = (rows) => {
    received = true;
    onBatch(rows);
  };
  try {
    await runInWorker(file, wrapped, onProgress);
  } catch (e) {
    if (received) throw e; // ya se entregaron datos parciales: no reintentar (duplicaría filas)
    console.warn("Web Worker no disponible, se parsea en el hilo principal:", e);
    await runInMainThread(file, onBatch, onProgress);
  }
}
