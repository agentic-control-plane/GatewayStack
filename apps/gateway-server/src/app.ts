import express, { type RequestHandler } from "express";
import bodyParser from "body-parser";

import { runWithGatewayContext } from "@gatewaystack/request-context";
import { identifiabl } from "@gatewaystack/identifiabl";
import { transformabl } from "@gatewaystack/transformabl";
import {
  protectedResourceRouter,
  requireScope,
} from "@gatewaystack/validatabl";
import { limitabl } from "@gatewaystack/limitabl";
import {
  createProxyablRouter,
  configFromEnv as proxyablConfigFromEnv,
} from "@gatewaystack/proxyabl";
import {
  explicablRouter,
  createConsoleLogger,
  explicablLoggingMiddleware,
} from "@gatewaystack/explicabl";


import { testEchoRoutes } from "./routes/testEcho";

import rateLimit from "express-rate-limit";

function trimTrailingSlashes(input: string): string {
  let out = input;
  while (out.endsWith("/")) {
    out = out.slice(0, -1);
  }
  return out;
}

export function buildApp(env: NodeJS.ProcessEnv) {
  // -----------------------------
  // Boot & configuration
  // -----------------------------
  console.log("[boot] ENABLE_TEST_ROUTES=%s", env.ENABLE_TEST_ROUTES);
  console.log("[boot] ROUTE_ALLOWLIST=%s", env.ROUTE_ALLOWLIST);

  const DEMO = env.DEMO_MODE === "true";

  // OIDC / OAuth config (used by Identifiabl + Validatabl)
  const OAUTH_ISSUER =
    (DEMO ? env.OAUTH_ISSUER_DEMO : env.OAUTH_ISSUER) || "";
  const OAUTH_AUDIENCE =
    (DEMO ? env.OAUTH_AUDIENCE_DEMO : env.OAUTH_AUDIENCE) || "";
  const OAUTH_JWKS_URI =
    (DEMO ? env.OAUTH_JWKS_URI_DEMO : env.OAUTH_JWKS_URI) ||
    env.JWKS_URI_FALLBACK ||
    "";
  const OAUTH_SCOPES = (
    (DEMO ? env.OAUTH_SCOPES_DEMO : env.OAUTH_SCOPES) ||
    "openid email profile"
  )
    .trim()
    .split(/\s+/);

  // 🔐 Avoid logging sensitive values directly
  console.log("[boot] DEMO_MODE=%s", DEMO);
  console.log("[boot] OAUTH_ISSUER_SET=%s", Boolean(OAUTH_ISSUER));
  console.log("[boot] OAUTH_AUDIENCE_SET=%s", Boolean(OAUTH_AUDIENCE));
  console.log("[boot] OAUTH_JWKS_URI_SET=%s", Boolean(OAUTH_JWKS_URI));

  // Fail fast in demo if required vars are missing
  if (DEMO && (!OAUTH_ISSUER || !OAUTH_AUDIENCE)) {
    throw new Error(
      "[demo] Missing OAUTH_*_DEMO envs. Set OAUTH_ISSUER_DEMO and OAUTH_AUDIENCE_DEMO."
    );
  }

  // Rate limiting config (limitabl)
  const windowMs = +(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000);
  const limit = +(process.env.RATE_LIMIT_MAX ?? 10);

  // Very loose limiter for PRM metadata (satisfies CodeQL, effectively no impact)
  const prmLimiter = rateLimit({
    windowMs,
    max: limit * 100, // extremely generous
  });

  // -----------------------------
  // Core Express setup
  // -----------------------------
  const app = express();
  app.use(bodyParser.json({ limit: "2mb" }));

  // 🔹 NEW: create a GatewayContext for every incoming request
  app.use((req, _res, next) => {
    runWithGatewayContext(
      {
        request: {
          method: req.method,
          path: req.path,
          ip: (req as any).ip,
          userAgent: req.get("user-agent") ?? undefined,
        },
      },
      () => next()
    );
  });

  const explicablLogger = createConsoleLogger({
    serviceName: "gateway-server",
    environment: env.NODE_ENV ?? process.env.NODE_ENV ?? "dev",
  });

  app.use(
    explicablLoggingMiddleware(explicablLogger) as unknown as RequestHandler,
  );

  // Simple root health check (extra; explicabl has richer health)
  app.get("/", (_req, res) => res.status(200).json({ ok: true }));

  // Optional test-only routes (public)
  if (env.ENABLE_TEST_ROUTES === "true") {
    console.log("[__test__] routes enabled");
    app.use("/__test__", testEchoRoutes(env));
  }

  // -----------------------------
  // Layer 1: identifiabl (JWT → req.user)
  // -----------------------------
  const identifiablMiddleware = identifiabl({
    issuer: OAUTH_ISSUER,
    audience: OAUTH_AUDIENCE,
    jwksUri: OAUTH_JWKS_URI || undefined,
  });

  // -----------------------------
  // Layer 2: transformabl (currently a no-op)
  // -----------------------------
  const transformablMiddleware = transformabl({});

  // -----------------------------
  // Layer 3: Mount validatabl’s PRM router early for public metadata
  // validatabl is added as added via requireScope() in the protected area below
  // -----------------------------

  app.use(
    "/prm",
    prmLimiter,
    protectedResourceRouter({
      issuer: trimTrailingSlashes(OAUTH_ISSUER),
      audience: OAUTH_AUDIENCE,
      scopes: OAUTH_SCOPES,
    }) as unknown as RequestHandler
  );

  // -----------------------------
  // Layer 4: limitabl (per-identity rate limiting)
  // -----------------------------
  const limitablMiddleware = limitabl({
    rateLimit: { windowMs, maxRequests: limit },
  });

  // -----------------------------
  // Protected area pipeline:
  // identifiabl → limitabl → transformabl → Handlers
  //
  // Order matters for security: identifiabl must run first so req.user.sub is
  // populated before limitabl derives its rate-limit key. Otherwise limitabl
  // falls back to IP-based keying, which means authenticated users sharing a
  // NAT/proxy IP with unauthenticated traffic share a rate-limit bucket.
  // -----------------------------
  app.use(
    "/protected",
    identifiablMiddleware,
    limitablMiddleware,
    transformablMiddleware
  );

  // READ example (no extra scope)
  app.get("/protected/ping", (_req, res) => res.json({ ok: true }));

  // WRITE example (requires tool:write via validatabl)
  app.post("/protected/echo", requireScope("tool:write"), (req: any, res) => {
    res.json({
      ok: true,
      sub: req.user?.sub ?? null,
      body: req.body ?? null,
    });
  });

  // -----------------------------
  // Layer 5: proxyabl (tool / MCP gateway)
  // -----------------------------
  const proxyablConfig = proxyablConfigFromEnv(env);

  // Rate limiter for /tools (satisfies CodeQL, reasonable defaults)
  const toolsRateLimiter = rateLimit({
    windowMs,
    max: limit * 10, // more generous than per-user limitabl
    standardHeaders: true,
    legacyHeaders: false,
  });

  // /tools pipeline:
  //   GatewayContext (already set globally)
  //   → toolsRateLimiter
  //   → identifiabl (JWT → ctx.identity)
  //   → proxyabl router (scopes + routing)
  app.use(
    "/tools",
    toolsRateLimiter,
    identifiablMiddleware,
    createProxyablRouter(proxyablConfig) as unknown as RequestHandler
  );

  // -----------------------------
  // Layer 6: explicabl (health, logs, webhooks)
  // -----------------------------
  app.use(explicablRouter(env) as unknown as RequestHandler);

  return app;
}
