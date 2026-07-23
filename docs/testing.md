# Gatewaystack Testing & Parity Guide

This document covers:
- How to enable internal `/__test__` routes
- Scope/RBAC parity checks
- Running the Vitest suite

---

## 1. Enabling Test Routes

Test endpoints under `"/__test__"` are **disabled by default**.

To enable them in development:
```bash
# apps/gateway-server/.env
ENABLE_TEST_ROUTES=true
```

These routes are guarded by:
- `TOOL_SCOPE_ALLOWLIST_JSON` (allowed scopes per test route)
- The `X-Required-Scope` header (per-request scope requirement you pass in curl)

They are for validation and scope/proxy testing only, not for production traffic.

---

## 2. Scope/RBAC Checks (Parity)

💡 You'll usually want two tokens to see the 403s in action:
- `$READER` → minted with only `tool:read`
- `$WRITER` → minted with `tool:read tool:write`
```bash
# Endpoint that requires read scope
curl -i \
  -H "Authorization: Bearer $READER" \
  -H "X-Required-Scope: tool:read" \
  http://localhost:8080/__test__/echo

# Endpoint that requires write scope (should fail for Reader)
curl -i -X POST \
  -H "Authorization: Bearer $READER" \
  -H "X-Required-Scope: tool:write" \
  http://localhost:8080/__test__/echo
# expect 403

# Same endpoint with Writer (should succeed)
curl -i -X POST \
  -H "Authorization: Bearer $WRITER" \
  -H "Content-Type: application/json" \
  -H "X-Required-Scope: tool:write" \
  --data '{"msg":"hello"}' \
  http://localhost:8080/__test__/echo
# expect 200 + echo body
```

**Implementation:**
- Routes live in `apps/gateway-server/src/routes/testEcho.ts`
- Scope enforcement uses `validatabl` + the `TOOL_SCOPE_ALLOWLIST_JSON` configuration

---

## 3. Proxy Mode + Echo Server

The bundled echo server in `tools/echo-server` simply returns the headers, query, and body it receives.

Start it via:
```bash
npm run -w @gatewaystack/echo-server dev
# default: http://localhost:3333
```

Combined with the `/proxy` routes in `proxyabl`, this lets you confirm that the authenticated subject is injected into headers and query params:
```bash
curl -s \
  -H "Authorization: Bearer $READER" \
  "http://localhost:8080/proxy/echo?foo=bar" | jq .
```

You should see:
- `headers["x-user-id"]` set to the token `sub` (if `PROXY_INJECT_HEADER=X-User-Id`)
- `query.userId` set to the same value (if `PROXY_INJECT_QUERY=userId`)
- Your original `foo=bar` preserved

Proxy behavior is implemented in `packages/proxyabl/src/tool-gateway.ts`.

---

## 4. Vitest + Conformance Report

From the repo root:
```bash
npm test
```

This runs:
- Vitest against the gateway and core packages (see `vitest.config.mts`)

**Key files:**
- `package.json` → test script
- `vitest.config.mts` → shared test config
- `tests/smoke.test.ts` → placeholder smoke test

---