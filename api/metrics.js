// api/metrics.js — Vercel Serverless Function (Node 18+)
//
// Qué hace:
//   1) Pide la clave del panel (header X-Panel-Key) y la compara con PANEL_PASSWORD.
//   2) Llama al webhook de n8n con un token secreto que el navegador nunca ve.
//   3) Devuelve solo los campos agregados del contrato (lista blanca), aunque n8n mande de más.
//
// Variables de entorno (Vercel → Project → Settings → Environment Variables):
//   PANEL_PASSWORD     Clave compartida del panel (larga y aleatoria)
//   N8N_WEBHOOK_URL    URL de producción del webhook de n8n
//   N8N_TOKEN          Token secreto que n8n exige en el header
//   N8N_TOKEN_HEADER   Opcional. Nombre del header (por defecto X-PIA-Token)

const crypto = require("crypto");

const {
  PANEL_PASSWORD,
  N8N_WEBHOOK_URL,
  N8N_TOKEN,
  N8N_TOKEN_HEADER = "X-PIA-Token",
} = process.env;

// Comparación en tiempo constante (no revela cuántos caracteres coinciden).
function safeEqual(a, b) {
  const ha = crypto.createHash("sha256").update(String(a)).digest();
  const hb = crypto.createHash("sha256").update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Lista blanca: solo pasan estos campos (y solo como números) hacia el navegador.
// Así, aunque n8n devuelva de más (filas, IDs, riesgo), no sale nada fuera del contrato.
const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

function pick(body) {
  const b = Array.isArray(body) ? body[0] : body;
  if (!b || typeof b !== "object") return {};
  const out = {};

  if (typeof b.updatedAt === "string") out.updatedAt = b.updatedAt.slice(0, 40);

  if (b.totals && typeof b.totals === "object") {
    out.totals = {};
    for (const k of ["messages", "uniqueUsers", "returning", "private", "headcount"]) {
      if (b.totals[k] != null) out.totals[k] = num(b.totals[k]);
    }
  }
  if (Array.isArray(b.daily)) {
    out.daily = b.daily.slice(-366).map((d) => ({
      date: String(d.date).slice(0, 10),
      messages: num(d.messages),
      users: d.users == null ? null : num(d.users),
    }));
  }
  if (b.byChannel && typeof b.byChannel === "object") {
    out.byChannel = { dm: num(b.byChannel.dm), canal: num(b.byChannel.canal) };
  }
  if (b.byFrequency && typeof b.byFrequency === "object") {
    out.byFrequency = { "1": num(b.byFrequency["1"]), "2-3": num(b.byFrequency["2-3"]), "4+": num(b.byFrequency["4+"]) };
  }
  if (Array.isArray(b.heat) && b.heat.length === 7 && b.heat.every((r) => Array.isArray(r) && r.length === 24)) {
    out.heat = b.heat.map((r) => r.map(num));
  }
  return out;
}

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "private, no-store");

  if (req.method !== "GET") return res.status(405).json({ error: "method_not_allowed" });
  if (!PANEL_PASSWORD || !N8N_WEBHOOK_URL || !N8N_TOKEN) {
    return res.status(500).json({ error: "server_not_configured" });
  }

  const key = req.headers["x-panel-key"];
  if (!key || !safeEqual(key, PANEL_PASSWORD)) {
    await sleep(500); // frena intentos repetidos
    return res.status(401).json({ error: "invalid_key" });
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    const r = await fetch(N8N_WEBHOOK_URL, {
      headers: { [N8N_TOKEN_HEADER]: N8N_TOKEN, Accept: "application/json" },
      signal: ctrl.signal,
    });
    if (!r.ok) return res.status(502).json({ error: "upstream_error" });
    return res.status(200).json(pick(await r.json()));
  } catch (_) {
    return res.status(502).json({ error: "upstream_unreachable" });
  } finally {
    clearTimeout(timer);
  }
};
