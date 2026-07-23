# Environment & Health Endpoints


## Environment Variables

Core OAuth config uses the `OAUTH_*` prefix:
- `OAUTH_ISSUER`, `OAUTH_AUDIENCE`, `OAUTH_JWKS_URI`, `OAUTH_ENFORCE_ALG`

Auth0-specific features use `AUTH0_*`:
- `AUTH0_DOMAIN`, `AUTH0_MGMT_CLIENT_ID`, `AUTH0_MGMT_CLIENT_SECRET` (for DCR webhook and `/health/auth0`)

Demo mode uses `OAUTH_*_DEMO` variants:
- `OAUTH_ISSUER_DEMO`, `OAUTH_AUDIENCE_DEMO`, etc.

See `apps/gateway-server/.env.example` for the full reference, including:
- Rate limiting (`RATE_LIMIT_*`)
- Proxy config (`PROXY_TARGET`, `PROXY_INJECT_*`)
- Tool scopes (`TOOL_SCOPES_JSON`)
- DCR webhook (`MGMT_*`, `LOG_WEBHOOK_SECRET`)

### Start the Test Backends (Echo Servers)

These help prove proxy + header injection:

```bash
# Echo server that returns headers, query, and body
npm run -w @gatewaystack/echo-server dev
# default: http://localhost:3333
```

These tests are your **governance smoke test**.

The echo server simply returns the headers, query, and body it receives. Combined with the `/proxy` routes in `proxyabl`, this lets you prove that the authenticated subject has been injected as a **verified, canonical user identifier** (for example `X-User-Id`) — so downstream services can enforce per-user/per-tenant data filtering without ever seeing upstream API keys.

Need a fake tool backend instead of an echo? Run `tsx tools/mock-tools-server/index.ts` to spin up JSON handlers (on :9090 by default) that mimic `generateDreamSummary`, `chatWithEmbeddingsv3`, etc. for end-to-end proxy tests.

---

### Run the Gateway (dev)

From the repo root:

```bash
# Or individually:
npm run dev:server   # apps/gateway-server
npm run dev:admin    # apps/admin-ui
```

- `npm run dev` starts the gateway and Admin UI together.
- `npm run dev:server` starts the Express gateway only.
- `npm run dev:admin` starts the Admin UI, which is primarily used to visualize `/health` and related outputs.

---

### Health & Basic Smoke Tests

```bash
# Health (served by healthRoutes at /health)
curl -s http://localhost:8080/health | jq .

# Auth0 checks (JWKS reachability, mgmt token if set)
curl -s http://localhost:8080/health/auth0 | jq .

# Protected resource metadata (expect 401 without token + WWW-Authenticate)
curl -i http://localhost:8080/.well-known/oauth-protected-resource
```

When called **without** a token, you should see a `401` with a `WWW-Authenticate` header that points ChatGPT / MCP to this URL as the **Protected Resource Metadata (PRM)** endpoint.

When called **with** a valid token, you should see JSON similar to:

```json
{
  "authorization_servers": ["https://<TENANT>.auth0.com/"],
  "scopes_supported": [
    "openid",
    "email",
    "profile",
    "tool:read",
    "tool:write"
  ],
  "resource": "https://gateway.local/api"
}
```

Where:

- `authorization_servers` tells the client which issuer(s) can mint access tokens.
- `scopes_supported` is derived from your configured tool scopes (`TOOL_SCOPES` → `REQUIRED_SCOPES` in the gateway).
- `resource` is your API Identifier / audience (`AUTH_AUDIENCE` / `OAUTH_AUDIENCE`).

When you add a new tool scope in `TOOL_SCOPES`, the gateway automatically:

- Updates `REQUIRED_SCOPES`
- Exposes it in `scopes_supported`
- Includes it in the `scope=` parameter of the `WWW-Authenticate` header
- Ensures the client grant includes the new scope (if using the Auth0 DCR helper)

* `/health` → `{ ok: true, ... }`
* `/health/auth0` → issuer/audience OK, JWKS reachable
* Protected resource → **401** w/o token, **200** w/ token

## Testing

Run the full test suite:
```bash
npm test
```

This runs the Vitest suite across the gateway and core packages.

For detailed testing workflows, see:
- `docs/testing.md` — `/__test__/echo` routes, scope checks, proxy validation
- `CONTRIBUTING.md` — Pre-PR checklist

### Reference server (apps/gateway-server)

`apps/gateway-server/src/app.ts` composes the six governance layers in order:

1. Public **Protected Resource Metadata** via `protectedResourceRouter`.
2. `/protected/*` pipeline → `identifiabl` (JWT) → `limitabl` → `transformabl`.
3. Sample handlers (`GET /protected/ping`, `POST /protected/echo`) with `requireScope("tool:write")`.
4. `toolGatewayRouter` for PRM/OIDC well-knowns, MCP/Apps JSON-RPC, `/proxy`, and the Auth0 log webhook.
5. `explicablRouter` for `/health`, `/health/auth0`, and `/webhooks/auth0`.

Toggles worth noting:

- `DEMO_MODE=true` swaps in `OAUTH_*_DEMO` overrides so demos can mint JWTs locally.
- `ENABLE_TEST_ROUTES=true` + `TOOL_SCOPE_ALLOWLIST_JSON` expose `/__test__/echo` for scope/proxy validation runs.
- `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` tune limitabl without editing TypeScript.
- `.env.example` plus `apps/gateway-server/.env.example` enumerate every knob.

---
### Admin UI (apps/admin-ui)

`npm run dev:admin` launches a tiny Vite/React panel (`apps/admin-ui/src/App.tsx`) that fetches `/health` and renders the JSON so you can keep gateway status visible while iterating.

---

### Conformance summary

Verified against Apps SDK / MCP OAuth 2.1 + RS256 flow.  
- ✅ JWT validation (iss/aud/sub/exp/nbf)  
- ✅ Scope allowlist / deny-by-default  
- ✅ Expiry handling  
- ✅ Health & protected resource endpoints  

---

### ⚙️ Implementation Notes

* Always validate `iss`, **pin `aud`**, enforce `alg = RS256`, and honor `exp`/`nbf`.
* Keep tokens **short-lived**; rotate/revoke via your IdP.
* Use gateway **identity injection** (e.g. `X-User-Id`) to pass user context downstream — never expose upstream API keys to the LLM client.
