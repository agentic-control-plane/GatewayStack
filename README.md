<p align="center">
  <img src="./assets/gatewaystack-banner.png" alt="GatewayStack banner" />
</p>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License" />
  </a>
  <img src="https://img.shields.io/badge/TypeScript-5.x-blue" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Cloud%20Run-ready-4285F4" alt="Cloud Run" />
  <img src="https://img.shields.io/badge/Auth0-RS256-orange" alt="Auth0 RS256" />
  <a href="https://github.com/davidcrowe/gatewaystack/tree/main/docs/conformance.json">
    <img
      src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fdavidcrowe%2Fgatewaystack%2Fmain%2Fdocs%2Fconformance.json&query=$.version&label=MCP%2FAuth%20Conformance"
      alt="MCP Auth Conformance"
    />
  </a>
</p>

<p align="center"><strong>Stop shipping AI integrations with shared API keys and no audit trail</strong></p>

<p align="center">
  <a href="https://github.com/davidcrowe/gatewaystack-chatgpt-starter">Reference implementation</a> · <a href="https://github.com/davidcrowe/gatewaystack-chatgpt-starter/blob/main/docs/live-demo.md">Live demo in ChatGPT</a> · <a href="https://agenticcontrolplane.com">agenticcontrolplane.com</a>
</p>

## The problem

AI apps have three actors — user, LLM, and backend — but no shared identity layer. The user authenticates with the LLM, then the LLM calls your backend with a shared API key. Your backend can't tell who the request is for.

```
      Without GatewayStack              With GatewayStack

        USER (Alice)                      USER (Alice)
           │                                 │
           │ ✓ Authenticated                 │ ✓ Authenticated
           ▼                                 ▼
         LLM                               LLM
           │                                 │
           │ ❌ Shared API key               │ ✓ RS256 JWT
           ▼                                 ▼
       BACKEND                         GATEWAYSTACK
           │                          (Verify & Inject)
           │ ❓ Who is this?                 │
           │ ❓ What can they do?            │ ✓ X-User-Id, scopes
                                             ▼
                                         BACKEND
                                             │
                                             │ ✅ Knows: Alice, scopes
                                             │ ✅ Enforces policy
```

GatewayStack sits between the LLM and your backend. It verifies OAuth tokens, enforces per-user policies, and injects verified identity — so every AI request is attributable, authorized, and auditable. [Full explanation →](docs/three-party-problem.md)

## Quickstart

```bash
npm install @gatewaystack/identifiabl express
```

```ts
import express from "express";
import { identifiabl } from "@gatewaystack/identifiabl";

const app = express();

app.use(identifiabl({
  issuer: process.env.OAUTH_ISSUER!,
  audience: process.env.OAUTH_AUDIENCE!,
}));

app.get("/api/me", (req, res) => {
  res.json({ user: req.user.sub, scopes: req.user.scope });
});

app.listen(8080);
```

Every request now requires a valid RS256 JWT. `req.user` contains the verified identity.

## Modules

All six governance layers are live on npm. Each has a `-core` package (framework-agnostic) and an Express middleware wrapper. [Detailed breakdown →](docs/packages.md)

| Module | npm | What it does |
|--------|-----|-------------|
| `@gatewaystack/identifiabl` | [![npm](https://img.shields.io/npm/v/@gatewaystack/identifiabl)](https://www.npmjs.com/package/@gatewaystack/identifiabl) | RS256 JWT verification, identity normalization |
| `@gatewaystack/transformabl` | [![npm](https://img.shields.io/npm/v/@gatewaystack/transformabl)](https://www.npmjs.com/package/@gatewaystack/transformabl) | PII detection, redaction, safety classification |
| `@gatewaystack/validatabl` | [![npm](https://img.shields.io/npm/v/@gatewaystack/validatabl)](https://www.npmjs.com/package/@gatewaystack/validatabl) | Deny-by-default policy engine, scope/permission enforcement |
| `@gatewaystack/limitabl` | [![npm](https://img.shields.io/npm/v/@gatewaystack/limitabl)](https://www.npmjs.com/package/@gatewaystack/limitabl) | Rate limits, budget tracking, agent guard |
| `@gatewaystack/proxyabl` | [![npm](https://img.shields.io/npm/v/@gatewaystack/proxyabl)](https://www.npmjs.com/package/@gatewaystack/proxyabl) | Auth mode routing, SSRF protection, identity-aware proxy |
| `@gatewaystack/explicabl` | [![npm](https://img.shields.io/npm/v/@gatewaystack/explicabl)](https://www.npmjs.com/package/@gatewaystack/explicabl) | Structured audit logging, health endpoints |

## Full stack example

Wire all six layers together. Each is optional — use only what you need.

```bash
npm install @gatewaystack/identifiabl @gatewaystack/transformabl @gatewaystack/validatabl \
  @gatewaystack/limitabl @gatewaystack/proxyabl @gatewaystack/explicabl @gatewaystack/request-context express
```

```ts
import express from "express";
import { runWithGatewayContext } from "@gatewaystack/request-context";
import { identifiabl } from "@gatewaystack/identifiabl";
import { transformabl } from "@gatewaystack/transformabl";
import { validatabl } from "@gatewaystack/validatabl";
import { limitabl } from "@gatewaystack/limitabl";
import { createProxyablRouter, configFromEnv } from "@gatewaystack/proxyabl";
import { createConsoleLogger, explicablLoggingMiddleware } from "@gatewaystack/explicabl";

const app = express();
app.use(express.json());

// 1. Establish request context for downstream layers
app.use((req, _res, next) => {
  runWithGatewayContext(
    { request: { method: req.method, path: req.path } },
    () => next()
  );
});

// 2. Log every request
app.use(explicablLoggingMiddleware(createConsoleLogger()));

// 3. Require verified RS256 token
app.use(identifiabl({
  issuer: process.env.OAUTH_ISSUER!,
  audience: process.env.OAUTH_AUDIENCE!,
}));

// 4. Detect PII and classify content safety
app.use("/tools", transformabl({ blockThreshold: 80 }));

// 5. Enforce authorization policies
app.use("/tools", validatabl({
  requiredPermissions: ["tool:read"],
}));

// 6. Apply rate limits and budget caps
app.use("/tools", limitabl({
  rateLimit: { windowMs: 60_000, maxRequests: 100 },
  budget: { maxSpend: 500, periodMs: 86_400_000 },
}));

// 7. Route /tools to your tool/model backends
app.use("/tools", createProxyablRouter(configFromEnv(process.env)));

app.listen(8080, () => {
  console.log("GatewayStack running on :8080");
});
```

Or clone and run the reference gateway directly:

```bash
git clone https://github.com/davidcrowe/GatewayStack
cd GatewayStack
npm install
npm run dev   # gateway on :8080, admin UI on :5173
```

## GatewayStack vs traditional API gateways

| Feature | Kong / Apigee / AWS API Gateway | GatewayStack |
|---------|--------------------------------|--------------|
| JWT validation | Built-in | Built-in |
| Rate limiting | Built-in | Built-in |
| Path/method routing | Built-in | Built-in |
| User identity normalization | Manual (custom plugin) | Built-in |
| Three-party identity binding (LLM → backend) | Manual (custom logic) | Built-in |
| Per-tool scope enforcement | Manual (custom policy) | Built-in |
| PII detection & redaction | Not available | Built-in |
| Content safety classification | Not available | Built-in |
| Pre-flight budget checks | Manual (custom plugin) | Built-in |
| Agent runaway prevention | Not available | Built-in |
| Apps SDK / MCP compliance | Manual (PRM endpoint) | Built-in |
| AI audit trails | Manual (log forwarding) | Built-in |

## Repository layout

| Path | Description |
| ---- | ----------- |
| `packages/` | Six `-core` packages (framework-agnostic) + six Express middleware wrappers, plus `request-context`, `compat`, and `integrations` |
| `apps/gateway-server` | Express reference server wiring all six layers, `/protected/*` samples, Docker image |
| `apps/admin-ui` | Vite/React dashboard that polls `/health` |
| `demos/` | MCP issuer + ChatGPT Apps SDK connectors that mint demo JWTs |
| `tools/` | Echo server, mock tool backend, Cloud Run deploy helper |
| `tests/` | Vitest smoke tests |
| `docs/` | Auth0 walkthroughs, conformance output, endpoint references, troubleshooting |

## Testing

```bash
npm test
```

135 tests across 17 test files covering all five core packages.

## Prerequisites

- Node.js **20+**
- npm **10+** (or pnpm 9)
- An OIDC provider issuing RS256 access tokens (Auth0, Okta, Entra ID, Keycloak, etc.)

## Docs

- [The Three-Party Problem](docs/three-party-problem.md)
- [Package Breakdown](docs/packages.md)
- [Examples](docs/examples.md)
- [Demos](docs/demo.md)
- [Environment & Health Endpoints](docs/operations.md)
- [Deployment](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Production Checklist](docs/production-checklist.md)

## Contributing

- Run the tests: `npm test`
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Report issues on [GitHub Issues](https://github.com/davidcrowe/GatewayStack/issues)

For the enterprise and leadership pitch, see [agenticcontrolplane.com](https://agenticcontrolplane.com).
