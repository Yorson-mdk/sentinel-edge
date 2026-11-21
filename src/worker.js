const EVENT_INDEX = "events:index";
const AUDIT_INDEX = "audit:index";
const MAX_EVENTS = 500;
const suspiciousPath = /(?:\.\.|%2e%2e|wp-admin|wp-login|\.env|\.git|phpmyadmin|/etc/passwd|<script)/i;
const suspiciousAgent = /(?:sqlmap|nikto|masscan|nmap|acunetix|nessus|zgrab|gobuster|dirbuster)/i;
const validMethods = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]);

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, env, ctx);
    if (url.pathname === "/_sentinel" || url.pathname === "/_sentinel/") {
      return env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
    }
    if (["/_sentinel/styles.css", "/_sentinel/app.js"].includes(url.pathname)) {
      const assetPath = url.pathname.endsWith("styles.css") ? "/styles.css" : "/app.js";
      return env.ASSETS.fetch(new Request(new URL(assetPath, request.url), request));
    }
    if (url.pathname === "/favicon.ico") return new Response(null, { status: 204 });
    return inspectAndProxy(request, env, ctx);
  }
};

async function api(request, env, ctx) {
  const url = new URL(request.url);
  if (url.pathname === "/api/health" && request.method === "GET") return json({ ok: true, service: "sentinel-edge" });
  if (url.pathname === "/api/ingest" && request.method === "POST") return ingestAudit(request, env);
  if (!authorized(request, env)) return json({ error: "Unauthorized" }, 401);
  if (!env.IDS_KV) return json({ error: "IDS_KV binding is not configured" }, 503);
  if (url.pathname === "/api/events" && request.method === "GET") {
    const ids = await env.IDS_KV.get(EVENT_INDEX, "json") || [];
    const events = (await Promise.all(ids.slice(0, 150).map(id => env.IDS_KV.get(`event:${id}`, "json")))).filter(Boolean);
    const since = Date.now() - 24 * 60 * 60 * 1000;
    return json({ events, stats: summarize(events.filter(e => e.timestamp >= since)) });
  }
  if (url.pathname === "/api/audit" && request.method === "GET") {
    const ids = await env.IDS_KV.get(AUDIT_INDEX, "json") || [];
    const records = (await Promise.all(ids.slice(0, 200).map(id => env.IDS_KV.get(`audit:${id}`, "json")))).filter(Boolean);
    return json({ records });
  }
  if (url.pathname === "/api/config" && request.method === "GET") {
    return json({ blockMode: env.BLOCK_MODE === "true", rateLimit: Number(env.RATE_LIMIT || 90), windowSeconds: Number(env.WINDOW_SECONDS || 60), origin: safeOrigin(env.ORIGIN_URL) });
  }
  if (url.pathname === "/api/alerts/ack" && request.method === "POST") {
    const body = await request.json().catch(() => ({}));
    if (!body.id) return json({ error: "Event id required" }, 400);
    const event = await env.IDS_KV.get(`event:${body.id}`, "json");
    if (!event) return json({ error: "Event not found" }, 404);
    event.acknowledged = true;
    await env.IDS_KV.put(`event:${body.id}`, JSON.stringify(event), { expirationTtl: retention(env) });
    return json({ ok: true });
  }
  return json({ error: "Not found" }, 404);
}

async function ingestAudit(request, env) {
  if (!env.IDS_KV) return json({ error: "IDS_KV binding is not configured" }, 503);
  if (!tokenMatches(request, env.AUDIT_INGEST_TOKEN)) return json({ error: "Unauthorized" }, 401);
  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > 8192) return json({ error: "Payload exceeds 8 KB" }, 413);
  let input;
  try { input = JSON.parse(raw || "null"); } catch { return json({ error: "Malformed JSON" }, 400); }
  if (!input || typeof input !== "object" || Array.isArray(input)) return json({ error: "Expected one audit event object" }, 400);
  if (typeof input.action !== "string" || !input.action.trim()) return json({ error: "action is required" }, 400);
  const entry = {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    actor: cleanText(input.actor, 120) || "system",
    action: cleanText(input.action, 160),
    target: cleanText(input.target, 240) || "—",
    outcome: ["success", "failure", "denied"].includes(input.outcome) ? input.outcome : "success",
    sourceIp: request.headers.get("CF-Connecting-IP") || "—",
    requestId: cleanText(input.requestId, 100) || request.headers.get("CF-Ray") || "—",
    metadata: cleanMetadata(input.metadata)
  };
  const ttl = retention(env);
  const index = await env.IDS_KV.get(AUDIT_INDEX, "json") || [];
  await env.IDS_KV.put(`audit:${entry.id}`, JSON.stringify(entry), { expirationTtl: ttl });
  await env.IDS_KV.put(AUDIT_INDEX, JSON.stringify([entry.id, ...index.filter(id => id !== entry.id)].slice(0, 500)), { expirationTtl: ttl });
  return json({ ok: true, id: entry.id, timestamp: entry.timestamp }, 202);
}

async function inspectAndProxy(request, env, ctx) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const url = new URL(request.url);
  const ua = request.headers.get("User-Agent") || "(missing)";
  const signals = [];
  if (!validMethods.has(request.method)) signals.push("Unusual HTTP method");
  if (suspiciousPath.test(decodeURIComponentSafe(url.pathname + url.search))) signals.push("Sensitive path or traversal probe");
  if (suspiciousAgent.test(ua)) signals.push("Known scanning user agent");
  if (ua === "(missing)") signals.push("Missing user agent");

  const windowSeconds = bounded(env.WINDOW_SECONDS, 60, 10, 3600);
  const limit = bounded(env.RATE_LIMIT, 90, 10, 10000);
  const bucket = Math.floor(Date.now() / (windowSeconds * 1000));
  const rateKey = `rate:${hash(ip)}:${bucket}`;
  const count = await env.IDS_KV.get(rateKey, "text").then(Number).catch(() => 0);
  const nextCount = (Number.isFinite(count) ? count : 0) + 1;
  ctx.waitUntil(env.IDS_KV.put(rateKey, String(nextCount), { expirationTtl: windowSeconds * 2 }));
  if (nextCount > limit) signals.push(`Request rate exceeded (${nextCount}/${windowSeconds}s)`);

  const severe = signals.some(s => s.includes("Sensitive path") || s.includes("Known scanning"));
  if (signals.length) {
    const event = {
      id: crypto.randomUUID(), timestamp: Date.now(), severity: severe ? "high" : signals.some(s => s.includes("rate")) ? "medium" : "low",
      sourceIp: ip, method: request.method, path: url.pathname, userAgent: ua.slice(0, 180),
      country: request.cf?.country || "—", signals, action: env.BLOCK_MODE === "true" && severe ? "blocked" : "logged", acknowledged: false
    };
    ctx.waitUntil(saveEvent(env.IDS_KV, event, retention(env)));
    if (event.action === "blocked") return new Response("Request blocked by Sentinel Edge", { status: 403, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
  }

  const originText = env.ORIGIN_URL;
  if (!originText || originText.includes("your-origin.example.com")) {
    if (url.pathname === "/" || url.pathname === "/index.html") return env.ASSETS.fetch(new Request(new URL("/index.html", request.url), request));
    return new Response("Set ORIGIN_URL to your website origin in wrangler.jsonc.", { status: 502 });
  }
  let origin;
  try { origin = new URL(originText); } catch { return new Response("Invalid ORIGIN_URL configuration.", { status: 500 }); }
  const target = new URL(url.pathname + url.search, origin);
  const headers = new Headers(request.headers);
  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.slice(0, -1));
  const proxyRequest = new Request(target, request);
  return fetch(new Request(proxyRequest, { headers }));
}

async function saveEvent(kv, event, ttl) {
  const key = `event:${event.id}`;
  const index = await kv.get(EVENT_INDEX, "json") || [];
  await kv.put(key, JSON.stringify(event), { expirationTtl: ttl });
  await kv.put(EVENT_INDEX, JSON.stringify([event.id, ...index.filter(id => id !== event.id)].slice(0, MAX_EVENTS)), { expirationTtl: ttl });
}
function authorized(request, env) {
  return tokenMatches(request, env.DASHBOARD_TOKEN);
}
function tokenMatches(request, expected) {
  const provided = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "");
  return Boolean(expected && provided && constantTimeEqual(expected, provided));
}
function cleanText(value, max) { return typeof value === "string" ? value.replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, max) : ""; }
function cleanMetadata(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const clean = {};
  for (const [key, item] of Object.entries(value).slice(0, 20)) {
    const name = cleanText(key, 60);
    if (!name || /password|secret|token|authorization|cookie|credential/i.test(name)) continue;
    if (["string", "number", "boolean"].includes(typeof item)) clean[name] = typeof item === "string" ? cleanText(item, 240) : item;
  }
  return clean;
}
function constantTimeEqual(a, b) {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return out === 0;
}
function json(body, status = 200) { return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } }); }
function summarize(events) {
  return { total: events.length, high: events.filter(e => e.severity === "high").length, blocked: events.filter(e => e.action === "blocked").length, ips: new Set(events.map(e => e.sourceIp)).size };
}
function safeOrigin(value) { try { return new URL(value).host; } catch { return "Not configured"; } }
function bounded(raw, fallback, min, max) { const value = Number(raw); return Number.isFinite(value) ? Math.max(min, Math.min(max, value)) : fallback; }
function retention(env) { return bounded(env.RETENTION_HOURS, 72, 1, 720) * 3600; }
function hash(value) { let h = 2166136261; for (const c of value) h = Math.imul(h ^ c.charCodeAt(0), 16777619); return (h >>> 0).toString(36); }
function decodeURIComponentSafe(value) { try { return decodeURIComponent(value); } catch { return value; } }
