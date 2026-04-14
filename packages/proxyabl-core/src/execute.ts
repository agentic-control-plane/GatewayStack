// packages/proxyabl-core/src/execute.ts
//
// Core HTTP proxy forwarding.
// Extracted from gatewaystack-connect executor.ts executeCustomHttpTool().

import type { ResolvedAuth } from "./auth-modes.js";
import { assertUrlSafe, sanitizeHeaderValue } from "./security.js";

export interface ProxyRequestConfig {
  baseUrl: string;
  path: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  headers?: Record<string, string>;
  body?: unknown;
  auth: ResolvedAuth;
  timeoutMs?: number;
  maxResponseBytes?: number;
  allowedHosts: string[];
  allowHttp?: boolean;
}

export interface ProxyResponse {
  ok: boolean;
  status: number;
  contentType: string;
  body: unknown;
  bytes: number;
}

// Headers that should not be forwarded to upstream
const BLOCKED_HEADERS = new Set([
  "host", "connection", "keep-alive", "transfer-encoding",
  "te", "trailer", "upgrade", "proxy-authorization",
  "proxy-connection",
]);

function buildUrl(baseUrl: string, path: string): URL {
  if (!path.startsWith("/")) throw new Error(`Path must start with "/": ${path}`);
  return new URL(path, baseUrl.endsWith("/") ? baseUrl : baseUrl + "/");
}

function clampNumber(value: number | undefined, min: number, max: number, fallback: number): number {
  if (value == null) return fallback;
  return Math.max(min, Math.min(Number(value), max));
}

/**
 * Execute a proxy HTTP request with SSRF protection, auth injection,
 * timeout, redirect blocking, and response size capping.
 */
export async function executeProxyRequest(cfg: ProxyRequestConfig): Promise<ProxyResponse> {
  const url = buildUrl(cfg.baseUrl, cfg.path);

  // SSRF check — async because it resolves DNS to validate every A/AAAA
  // record against private-IP ranges, closing the hostname-hiding bypass
  // where an allowlisted name resolves to e.g. 169.254.169.254.
  await assertUrlSafe({
    url,
    allowedHosts: cfg.allowedHosts,
    allowHttp: cfg.allowHttp ?? false,
  });

  const timeoutMs = clampNumber(cfg.timeoutMs, 1_000, 120_000, 10_000);
  const maxBytes = clampNumber(cfg.maxResponseBytes, 10_000, 5_000_000, 512_000);

  // Build headers
  const headers: Record<string, string> = {
    "user-agent": "gatewaystack/proxyabl-core",
    accept: "application/json, text/plain;q=0.9, */*;q=0.1",
  };

  // Merge custom headers (filter out blocked ones)
  if (cfg.headers) {
    for (const [k, v] of Object.entries(cfg.headers)) {
      const lower = k.toLowerCase();
      if (!BLOCKED_HEADERS.has(lower)) {
        headers[lower] = sanitizeHeaderValue(String(v));
      }
    }
  }

  // Auth injection
  if (cfg.auth.kind === "api_key") {
    headers[cfg.auth.headerName.toLowerCase()] = sanitizeHeaderValue(cfg.auth.value);
  } else if (cfg.auth.kind === "bearer") {
    headers["authorization"] = `Bearer ${sanitizeHeaderValue(cfg.auth.token)}`;
  }
  // kind === "none" → no auth headers

  // Body handling
  const method = cfg.method.toUpperCase();
  let body: string | undefined;

  if (method !== "GET" && method !== "DELETE" && cfg.body != null) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(cfg.body);
  }

  // Fetch with timeout
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new Error("timeout")), timeoutMs);

  let resp: Response;
  try {
    resp = await fetch(url.toString(), {
      method,
      headers,
      body,
      redirect: "manual",
      signal: ac.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  // Block redirects
  if (resp.status >= 300 && resp.status < 400) {
    const loc = resp.headers.get("location") ?? "";
    throw new Error(`Upstream redirect blocked (${resp.status}). Location=${loc}`);
  }

  // Cap response size
  const buf = new Uint8Array(await resp.arrayBuffer());
  const clipped = buf.length > maxBytes ? buf.slice(0, maxBytes) : buf;
  const text = new TextDecoder().decode(clipped);
  const contentType = (resp.headers.get("content-type") ?? "").toLowerCase();

  if (!resp.ok) {
    throw new Error(`Upstream error ${resp.status}: ${text.slice(0, 1200)}`);
  }

  // Parse JSON if indicated
  let parsedBody: unknown = text;
  if (contentType.includes("application/json")) {
    try {
      parsedBody = JSON.parse(text);
    } catch {
      // fall back to text
    }
  }

  return {
    ok: true,
    status: resp.status,
    contentType,
    body: parsedBody,
    bytes: clipped.length,
  };
}
