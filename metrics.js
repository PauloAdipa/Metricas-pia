// api/metrics.js — Vercel Serverless Function (Node 18+)
//
// Qué hace:
//   1) Verifica que quien llama inició sesión con Google (token ID) y que su cuenta es de ADIPA.
//   2) Llama al webhook de n8n con un token secreto que el navegador nunca ve.
//   3) Devuelve solo los campos agregados del contrato (lista blanca), aunque n8n mande de más.
//
// Variables de entorno (Vercel → Project → Settings → Environment Variables):
//   GOOGLE_CLIENT_ID   Client ID de OAuth (el mismo que va en index.html)
//   ALLOWED_DOMAINS    Dominios de Workspace con acceso, separados por coma (ej: adipa.cl)
//   ALLOWED_EMAILS     Opcional. Si existe, SOLO esos correos entran (además de ser de ADIPA)
//   N8N_WEBHOOK_URL    URL de producción del webhook de n8n
//   N8N_TOKEN          Token secreto que n8n exige en el header
//   N8N_TOKEN_HEADER   Opcional. Nombre del header (por defecto X-PIA-Token)

const {
  GOOGLE_CLIENT_ID,
  ALLOWED_DOMAINS = "",
  ALLOWED_EMAILS = "",
  N8N_WEBHOOK_URL,
  N8N_TOKEN,
  N8N_TOKEN_HEADER = "X-PIA-Token",
} = process.env;

const list = (s) => s.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);

async function verifyGoogleToken(idToken) {
  // Google valida firma y expiración del token en este endpoint.
  const r = await fetch(
    "https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(idToken)
  );
  if (!r.ok) return null;
  const p = await r.json();
  const issOk = p.iss === "accounts.google.com" || p.iss === "https://accounts.google.com";
  const verified = p.email_verified === true || p.email_verified === "true";
  if (p.aud !== GOOGLE_CLIENT_ID || !issOk || !verified || !p.email) return null;
  if (Number(p.exp) * 1000 < Date.now()) return null;
  return p;
}

// Exige que la cuenta pertenezca a un Workspace permitido (claim "hd"), no solo que el correo termine en @adipa.cl.
function isAllowed(p) {
  const domains = list(ALLOWED_DOMAINS);
  const emails = list(ALLOWED_EMAILS);
  const email = String(p.email).toLowerCase();
  const hd = String(p.hd || "").toLowerCase();
  if (!domains.includes(hd) || !domains.includes(email.split("@")[1])) return false;
  if (emails.length) return emails.includes(email);
  return true;
}

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
  if (!GOOGLE_CLIENT_ID || !N8N_WEBHOOK_URL || !N8N_TOKEN || !list(ALLOWED_DOMAINS).length) {
    return res.status(500).json({ error: "server_not_configured" });
  }

  const m = /^Bearer (.+)$/.exec(req.headers.authorization || "");
  if (!m) return res.status(401).json({ error: "missing_token" });

  let payload = null;
  try {
    payload = await verifyGoogleToken(m[1]);
  } catch (_) {
    return res.status(502).json({ error: "auth_provider_unreachable" });
  }
  if (!payload) return res.status(401).json({ error: "invalid_token" });
  if (!isAllowed(payload)) return res.status(403).json({ error: "not_allowed" });

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
