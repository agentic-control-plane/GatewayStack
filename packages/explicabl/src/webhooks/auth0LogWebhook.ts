// packages/explicabl-express/src/webhooks/auth0-log-webhook.ts
import * as express from "express";
import type { Request, Response } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";

/**
 * Env
 * - MGMT_DOMAIN            (e.g. "your-tenant.us.auth0.com")
 * - MGMT_CLIENT_ID
 * - MGMT_CLIENT_SECRET
 * - LOG_WEBHOOK_SECRET     (shared secret for Auth0 Log Streams → "Authorization: Bearer <secret>")
 * - GOOGLE_CONNECTION_NAME (defaults to "google-oauth2")
 */
const MGMT_DOMAIN = process.env.MGMT_DOMAIN!;
const MGMT_CLIENT_ID = process.env.MGMT_CLIENT_ID!;
const MGMT_CLIENT_SECRET = process.env.MGMT_CLIENT_SECRET!;
const LOG_WEBHOOK_SECRET = process.env.LOG_WEBHOOK_SECRET || "dev-change-me";
const GOOGLE_CONNECTION_NAME = process.env.GOOGLE_CONNECTION_NAME || "google-oauth2";

// Optional: used to create a client grant with all tool scopes
const OAUTH_AUDIENCE = process.env.OAUTH_AUDIENCE;
const TOOL_SCOPES = (process.env.TOOL_SCOPES || process.env.REQUIRED_SCOPES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// ---- Rate limiting for the Auth0 log webhook ----
const LOG_WEBHOOK_WINDOW_MS = +(process.env.LOG_WEBHOOK_WINDOW_MS || 60_000); // 1 minute
const LOG_WEBHOOK_MAX_PER_WINDOW = +(process.env.LOG_WEBHOOK_MAX_PER_WINDOW || 60);

const auth0WebhookLimiter = rateLimit({
  windowMs: LOG_WEBHOOK_WINDOW_MS,
  max: LOG_WEBHOOK_MAX_PER_WINDOW,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Strip IPv4-mapped prefix so ::ffff:1.2.3.4 resolves as IPv4, not collapsed IPv6
    let ip = req.ip || "unknown";
    if (ip.startsWith("::ffff:")) ip = ip.slice(7);
    return ipKeyGenerator(ip);
  },
});

// bridge the type mismatch between express-rate-limit and this package’s express types
const auth0WebhookLimiterMw: express.RequestHandler =
  auth0WebhookLimiter as unknown as express.RequestHandler;

// ✅ NEW: sanitize client_id coming from logs / Auth0
function sanitizeMgmtClientId(id: string): string {
  if (typeof id !== "string") {
    throw new Error("invalid_client_id_type");
  }
  // Auth0 client_ids are URL-safe base64-ish: letters, digits, - and _
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
    throw new Error("invalid_client_id_format");
  }
  return id;
}

// ✅ NEW: centralize / validate domain + path → prevents SSRF via MGMT_DOMAIN/path tricks
function auth0MgmtUrl(path: string): string {
  const domain = (MGMT_DOMAIN || "").trim();
  if (!domain) {
    throw new Error("MGMT_DOMAIN_not_set");
  }
  // only allow normal hostnames
  if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
    throw new Error(`invalid_MGMT_DOMAIN:${domain}`);
  }
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `https://${domain}${normalizedPath}`;
}

type OAuthTokenRes = { access_token: string; token_type?: string; expires_in?: number };

async function getMgmtToken(): Promise<string> {
  const r = await fetch(auth0MgmtUrl("/oauth/token"), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      grant_type: "client_credentials",
      client_id: MGMT_CLIENT_ID,
      client_secret: MGMT_CLIENT_SECRET,
      audience: auth0MgmtUrl("/api/v2/")
    })
  } as any);

  if (!r.ok) throw new Error(`mgmt_token_http_${r.status}`);
  const j = (await r.json()) as OAuthTokenRes;
  if (!j?.access_token) throw new Error("mgmt_token_missing_access_token");
  return j.access_token;
}

async function promoteClient(mgmtToken: string, clientId: string) {
  const patchBody = {
    app_type: "regular_web",
    is_first_party: true,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"]
  };

  const safeClientId = sanitizeMgmtClientId(clientId);

  const r = await fetch(
    auth0MgmtUrl(`/api/v2/clients/${encodeURIComponent(safeClientId)}`),
    {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${mgmtToken}`
      },
      body: JSON.stringify(patchBody)
    } as any
  );

  if (!r.ok) {
    // don’t include full response body (avoids leaking potentially sensitive info)
    console.error("[promoteClient:error]", {
      status: r.status,
      client_id_suffix: safeClientId.slice(-5),
    });
    throw new Error(`promote_http_${r.status}`);
  }
}

async function enableGoogleForClient(mgmtToken: string, clientId: string) {
  // 1) find the connection id for google-oauth2
  const rc = await fetch(
    auth0MgmtUrl(`/api/v2/connections?name=${encodeURIComponent(GOOGLE_CONNECTION_NAME)}`),
    { headers: { authorization: `Bearer ${mgmtToken}` } } as any
  );
  if (!rc.ok) throw new Error(`conn_lookup_http_${rc.status}`);
  const arr = (await rc.json()) as Array<{ id?: string; enabled_clients?: string[] }>;
  const conn = Array.isArray(arr) ? arr[0] : null;
  if (!conn || !conn.id) throw new Error(`connection_not_found:${GOOGLE_CONNECTION_NAME}`);

  // 2) add clientId to enabled_clients (idempotent)
  const enabled = new Set<string>(Array.isArray(conn.enabled_clients) ? conn.enabled_clients : []);
  enabled.add(clientId);

  const rp = await fetch(
    auth0MgmtUrl(`/api/v2/connections/${encodeURIComponent(conn.id)}`),
    {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${mgmtToken}`
      },
      body: JSON.stringify({ enabled_clients: Array.from(enabled) })
    } as any
  );
  if (!rp.ok) {
    console.error("[enableGoogleForClient:error]", {
      status: rp.status,
      connection_id_suffix: conn.id.slice(-5),
    });
    throw new Error(`conn_patch_http_${rp.status}`);
}
}

async function ensureClientGrant(
  mgmtToken: string,
  clientId: string,
  audience?: string,
  scopes: string[] = []
) {
  const aud = (audience || "").trim();
  if (!aud || !scopes.length) return;

  const r = await fetch(auth0MgmtUrl("/api/v2/client-grants"), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${mgmtToken}`
    },
    body: JSON.stringify({
      client_id: clientId,
      audience: aud,
      scope: scopes
    })
  } as any);

  if (!r.ok) {
    // ✅ only log non-sensitive status, no clientId/audience derivatives
    console.error("[ensureClientGrant:error]", {
      status: r.status,
      has_audience: Boolean(aud),
      scope_count: scopes.length,
    });
    throw new Error(`client_grant_http_${r.status}`);
  }

  // ✅ success log also avoids any clientId/audience values
  console.log("[dcr] created client grant", {
    scope_count: scopes.length,
    has_audience: Boolean(aud),
  });
}


// ---- log helpers ----
function unwrap(ev: any): any {
  return (ev && typeof ev === "object" && ev.data && typeof ev.data === "object") ? ev.data : ev;
}
function evtPath(e: any): string {
  return String(
    e?.details?.request?.path ||
    e?.details?.request?.url ||
    e?.http?.request?.path ||
    ""
  ).toLowerCase();
}
function isDcrEventRaw(ev: any): boolean {
  const e = unwrap(ev);
  const type = String(e?.type || "").toLowerCase();
  const desc = String(e?.description || "").toLowerCase();
  const path = evtPath(e);
  const method = String(e?.details?.request?.method || e?.http?.method || "").toUpperCase();

  return (
    (type === "sapi" && desc.includes("dynamic client registration")) ||
    path.includes("/oidc/register") ||
    (method === "POST" && (path === "/api/v2/clients" || path.endsWith("/api/v2/clients")))
  );
}
async function findNewestChatGPTClientId(mgmtToken: string): Promise<string | null> {
  const url =
    auth0MgmtUrl("/api/v2/clients") +
    "?is_global=false&per_page=10&sort=created_at:-1&fields=client_id,name,created_at,app_type,grant_types,token_endpoint_auth_method&include_fields=true";

  const r = await fetch(url, { headers: { authorization: `Bearer ${mgmtToken}` } } as any);
  if (!r.ok) {
    console.warn("[dcr] clients list failed", { status: r.status });
    return null;
  }

  const arr = (await r.json()) as Array<any>;
  const now = Date.now();
  for (const c of arr) {
    const name = String(c?.name || "");
    const createdAt = Date.parse(c?.created_at || "");
    const within5min = isFinite(createdAt) && (now - createdAt) < 5 * 60 * 1000;
    const looksLikeDcr = name.toLowerCase().startsWith("chatgpt") || name.toLowerCase().includes("chat gpt");
    const publicPkce = (c?.token_endpoint_auth_method === "none") &&
      Array.isArray(c?.grant_types) &&
      c.grant_types.includes("authorization_code");
    if (within5min && looksLikeDcr && publicPkce && c?.client_id) {
      return c.client_id as string;
    }
  }
  return null;
}

function extractClientIdFromDcrRaw(ev: any): string | null {
  const e = unwrap(ev);
  return (
    e?.details?.response?.body?.client_id ??
    e?.client_id ??
    e?.details?.request?.body?.client_id ??
    null
  );
}

// ---- handler ----
async function handleAuth0LogWebhook(req: Request, res: Response) {
  // Shared-secret auth
  // const auth = req.header("authorization") || "";
  // if (auth !== `Bearer ${LOG_WEBHOOK_SECRET}`) {
  //   res.status(401).json({ ok: false, error: "unauthorized" });
  //   return;
  // }

  // Shared-secret auth (supports either Authorization or X-Webhook-Secret)
  const auth = req.header("authorization") || "";
  const xSecret = req.header("x-webhook-secret") || "";

  const ok =
    auth === `Bearer ${LOG_WEBHOOK_SECRET}` ||
    xSecret === LOG_WEBHOOK_SECRET;

  if (!ok) {
    res.status(401).json({ ok: false, error: "unauthorized" });
    return;
  }

  // Not configured → tell the operator clearly
  if (!MGMT_DOMAIN || !MGMT_CLIENT_ID || !MGMT_CLIENT_SECRET) {
    res.status(501).json({
      ok: false,
      error: "not_configured",
      detail: "Set MGMT_DOMAIN, MGMT_CLIENT_ID, MGMT_CLIENT_SECRET to enable DCR promotion."
    });
    return;
  }

  // Normalize payload to an array of events
  let parsed: unknown = req.body;
  if (typeof parsed === "string") {
    try { parsed = JSON.parse(parsed); } catch { /* ignore */ }
  }
  const events: any[] = Array.isArray(parsed) ? parsed : [parsed as any];

  // Quick sample logging (helps users see shape)
  try {
    const sample = events.slice(0, 3).map((ev) => {
      const e = unwrap(ev);
      return {
        type: e?.type,
        desc: e?.description,
        path: evtPath(e) || undefined,
        method: e?.details?.request?.method || e?.http?.method,
        hasRespClientId: !!e?.details?.response?.body?.client_id
      };
    });
    console.log("[webhook:sample]", sample);
  } catch { /* ignore */ }

  const dcrEvents = events.filter(isDcrEventRaw);
  if (dcrEvents.length === 0) {
    res.status(200).json({ ok: true, filtered: true });
    return;
  }

  try {
    const mgmtToken = await getMgmtToken();

    for (const raw of dcrEvents) {
      let cid = extractClientIdFromDcrRaw(raw);
      if (!cid) {
        console.warn("[dcr] no client_id in event; attempting fallback lookup");
        cid = await findNewestChatGPTClientId(mgmtToken);
      }
      if (!cid) {
        console.warn("[dcr] could not determine client_id; skipping event");
        continue;
      }

      console.log("[dcr] promoting client", { client_id: cid });

      try {
        await promoteClient(mgmtToken, cid);
      } catch (e: any) {
        const msg = String(e?.message || "");
        if (msg.startsWith("promote_http_404")) {
          console.warn("[dcr] 404 promoting client; retrying with fallback search");
          const alt = await findNewestChatGPTClientId(mgmtToken);
          if (alt && alt !== cid) {
            console.log("[dcr] retry promoting", { client_id: alt });
            await promoteClient(mgmtToken, alt);
            cid = alt;
          } else {
            throw e;
          }
        } else {
          throw e;
        }
      }

    //   await enableGoogleForClient(mgmtToken, cid);
    //   console.log("[dcr] promoted+enabled", { client_id: cid });
    // }

    // res.status(200).json({ ok: true, promoted: dcrEvents.length });

    await enableGoogleForClient(mgmtToken, cid);
      await ensureClientGrant(mgmtToken, cid, OAUTH_AUDIENCE, TOOL_SCOPES);
        console.log("[dcr] promoted+enabled+granted", {
          client_id_suffix: cid.slice(-5),
          has_audience: Boolean(OAUTH_AUDIENCE),
          scope_count: TOOL_SCOPES.length,
        });
    }

    res.status(200).json({ ok: true, promoted: dcrEvents.length });
  } catch (e: any) {
    console.error("[dcr:error]", e?.message || e);
    res.status(500).json({ ok: false, error: e?.message || String(e) });
  }
}

/**
 * Router factory.
 * Mount in your server with: `app.use(auth0LogsWebhook());`
 * Endpoint becomes: POST /auth0-log-webhook
 *
 * If you prefer a prefix (e.g. /webhooks), mount as:
 *   app.use("/webhooks", auth0LogsWebhook());
 * Then the endpoint is POST /webhooks/auth0-log-webhook.
 */
export function auth0LogsWebhook() {
  const r = express.Router();
  // accept both text and JSON (Auth0 sometimes sends text/json variants)
  r.post(
    "/auth0-log-webhook",
    auth0WebhookLimiterMw,                          // ✅ use the shimmed middleware
    express.text({ type: "*/*", limit: "2mb" }),
    (req, res) => {
      if (typeof req.body === "string") {
        const looksJson =
          req.body.trim().startsWith("{") || req.body.trim().startsWith("[");
        (req as any).body = looksJson ? req.body : req.body;
      }
      return handleAuth0LogWebhook(req, res);
    }
  );
  return r;
}