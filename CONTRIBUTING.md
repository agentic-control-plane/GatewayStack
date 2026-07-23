# Contributing to Gatewaystack

Thanks for your interest in improving Gatewaystack! This doc covers local setup, development workflows, and test conventions.

---

## 1. Local Setup
```bash
git clone https://github.com/<you>/gatewaystack.git
cd gatewaystack

# Install all workspaces
npm install
```

---

## 2. Running the Gateway

From the repo root:
```bash
# Gateway server + admin UI together
npm run dev

# Individually:
npm run dev:server   # apps/gateway-server
npm run dev:admin    # apps/admin-ui
```

The Admin UI is primarily used to visualize `/health` and related outputs.

---

## 3. Environment Files

Use the example env as a starting point:
```bash
cp apps/gateway-server/.env.example apps/gateway-server/.env
```

**Core variables:**
- `OAUTH_ISSUER`, `OAUTH_AUDIENCE`, `OAUTH_JWKS_URI`, `OAUTH_ENFORCE_ALG`
- `OAUTH_DEMO_MODE` and related `OAUTH_*_DEMO` vars for demos
- `AUTH0_DOMAIN`, `AUTH0_MGMT_CLIENT_ID`, `AUTH0_MGMT_CLIENT_SECRET` for DCR/log-stream helpers

See `.env.example` for the full reference.

---

## 4. Tests & Conformance

Run the full test suite:
```bash
npm test
```

This runs the Vitest suite. See `docs/testing.md` for:
- `/__test__/echo` routes
- Scope/RBAC parity checks
- Proxy + echo server validation

---

## 5. Coding Style & Layout

- **TypeScript** throughout (strict preferred)
- Each logical concern lives in its own package under `packages/`:
  - `identifiabl`, `transformabl`, `validatabl`, `limitabl`, `proxyabl`, `explicabl`
- Shared tooling (lint, test, build) is wired via the root `package.json`

**Before opening a PR:**
- Run `npm test`
- Confirm the gateway starts locally with `npm run dev`
- (Optional) Run `npm run demo:mcp` and/or `npm run demo:apps` to validate end-to-end flows

---