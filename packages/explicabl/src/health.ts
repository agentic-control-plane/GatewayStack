import { Router, type Request } from "express";
import fetch from "node-fetch";
import { timingSafeEqual } from "node:crypto";

function timingSafeEqualStr(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

// Admin-only: compares a caller-supplied secret (Authorization: Bearer <s>
// or X-Admin-Secret: <s>) against HEALTH_ADMIN_SECRET in constant time.
// If the env var is unset, returns false — callers treat that as "feature
// disabled" and respond 404 so the endpoint is not discoverable by scanning.
function isAdminAuthorized(req: Request): boolean {
  const expected = process.env.HEALTH_ADMIN_SECRET || "";
  if (!expected) return false;

  const auth = req.header("authorization") || "";
  const xAdmin = req.header("x-admin-secret") || "";

  const BEARER = "Bearer ";
  const authSecret = auth.startsWith(BEARER) ? auth.slice(BEARER.length) : "";

  return (
    (authSecret.length > 0 && timingSafeEqualStr(authSecret, expected)) ||
    (xAdmin.length > 0 && timingSafeEqualStr(xAdmin, expected))
  );
}

export function healthRoutes(env: NodeJS.ProcessEnv) {
  const r = Router();

  r.get("/", (_req, res) => {
    res.json({
      ok: true,
      mode: env.MODE || "firebase",
      version: process.env.COMMIT_SHA || "dev",
      time: new Date().toISOString(),
    });
  });

  r.get("/auth0", async (req, res) => {
    // Gate behind HEALTH_ADMIN_SECRET. Unauthenticated callers get 404 so
    // the endpoint is not discoverable and cannot be used to amplify
    // outbound requests against Auth0's Management API.
    if (!isAdminAuthorized(req)) {
      res.status(404).json({ ok: false, error: "not_found" });
      return;
    }

    const issuer = env.AUTH0_ISSUER;
    const audience = env.AUTH0_AUDIENCE;
    const jwksUri = env.AUTH0_JWKS_URI;
    const out: any = { issuer, audience, jwksUri, jwksReachable: false };

    if (jwksUri) {
      try {
        const resp = await fetch(jwksUri);
        out.jwksReachable = resp.ok;
        if (!resp.ok) out.jwksError = `bad_status_${resp.status}`;
      } catch {
        out.jwksError = "unreachable";
      }
    } else {
      out.jwksError = "not_configured";
    }

    if (env.MGMT_DOMAIN && env.MGMT_CLIENT_ID && env.MGMT_CLIENT_SECRET) {
      out.managementConfigured = true;
      try {
        const tokenResp = await fetch(`https://${env.MGMT_DOMAIN}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client_id: env.MGMT_CLIENT_ID,
            client_secret: env.MGMT_CLIENT_SECRET,
            audience: `https://${env.MGMT_DOMAIN}/api/v2/`,
            grant_type: "client_credentials",
          }),
        });
        out.managementTokenOk = tokenResp.ok;
        if (!tokenResp.ok) out.managementError = `bad_status_${tokenResp.status}`;
      } catch {
        out.managementTokenOk = false;
        out.managementError = "unreachable";
      }
    } else {
      out.managementConfigured = false;
    }

    res.json(out);
  });

  return r;
}
