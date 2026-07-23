<p align="center">
  <img src="./assets/gatewaystack-banner.png" alt="GatewayStack banner" />
</p>

<p align="center">
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License" />
  </a>
  <img src="https://img.shields.io/badge/TypeScript-5.x-blue" alt="TypeScript" />
  <img src="https://img.shields.io/badge/Cloud%20Run-ready-4285F4" alt="Cloud Run" />
  <a href="https://github.com/agentic-control-plane/GatewayStack/tree/main/docs/conformance.json">
    <img
      src="https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fagentic-control-plane%2FGatewayStack%2Fmain%2Fdocs%2Fconformance.json&query=$.version&label=MCP%2FAuth%20Conformance"
      alt="MCP Auth Conformance"
    />
  </a>
</p>

<p align="center"><strong>See, price, and control every tool call your AI agents make.</strong></p>

<p align="center">
  <a href="https://agenticcontrolplane.com">agenticcontrolplane.com</a> · <a href="https://agenticcontrolplane.com/data">the data</a> · <a href="https://github.com/agentic-control-plane/acp-install">one-command install</a>
</p>

GatewayStack is the MIT-licensed open core of [Agentic Control Plane](https://agenticcontrolplane.com). It runs in your infrastructure, in the agent's runtime call path, and makes every tool and model call identified, policy-checked, and logged — whatever framework the agent runs on.

> **Which one do I want?**
> **GatewayStack (this repo)** is the runtime: MIT-licensed npm modules — identity, policy, limits, PII redaction, audit — you compose into your own gateway and run yourself. No account, no phone-home.
> **Agentic Control Plane** is the hosted product built on it: the console, the priced cost X-ray, team policy UI, approvals — [free for individuals](https://cloud.agenticcontrolplane.com). Most people start there and reach for this repo when they want the enforcement layer in their own infra.

## Install

Coding agents (Claude Code, Cursor, Codex, OpenClaw) — one command, no code changes:

```bash
curl -sf https://agenticcontrolplane.com/install.sh | bash
```

First controlled call in about thirty seconds. The script documents [what it does and won't do](https://github.com/agentic-control-plane/acp-install).

Hermes Agent uses a native Python plugin instead ([why](https://agenticcontrolplane.com/integrations/hermes)):

```bash
pip install hermes-acp && hermes plugins enable acp
```

**Prefer to see the guarantees work first — zero config, no IdP, no backend?**

```bash
git clone https://github.com/agentic-control-plane/GatewayStack
cd GatewayStack/examples/quickstart && npm install && npm start
```

Prints three real decisions — a deny-by-default policy, PII redaction, and a
rate limit — as pure local library code ([`examples/quickstart`](examples/quickstart)).

Your own framework code — drop in a package:

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

Every request now requires a valid RS256 JWT. `req.user` is the verified identity.

## What you get

- **Cost control.** Budget caps and rate limits enforced per call (`limitabl`), with every call's usage logged and attributable. The priced cost X-ray — runs split into the orchestration loop vs leaf sub-tasks, per-model spend — is the [hosted console](https://agenticcontrolplane.com/cost-tracking) built on this telemetry.
- **Tool-surface control.** Allow / ask / redact / deny, per operation, scoped by agent, role, or user. Deny-by-default on the destructive stuff. Enforced at the call, outside the model — a prompt-injected agent can't talk its way past it.
- **Audit.** Every tool and model call logged: who triggered it, which agent, what it returned, what it cost, how long it took. Attributable and exportable.

Every number we publish is metered from our own production workspaces, not estimated: [agenticcontrolplane.com/data](https://agenticcontrolplane.com/data).

## Modules

Each layer ships as a framework-agnostic `-core` package plus an Express middleware wrapper. Use one or all. [Detailed breakdown →](docs/packages.md)

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
git clone https://github.com/agentic-control-plane/GatewayStack
cd GatewayStack
npm install
npm run dev   # gateway on :8080, admin UI on :5173
```

## Why this is a separate layer

AI apps have three actors — user, LLM, backend — and no shared identity layer. The backend sees a service token, not a person, so it can't tell who the agent is acting for, whether the action was authorized, or what it cost. GatewayStack closes that gap at the tool-call boundary. [The full argument →](docs/three-party-problem.md)

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

185 tests across 17 test files covering all six core packages.

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

## Related repos

- [acp-install](https://github.com/agentic-control-plane/acp-install) — the one-command installer for coding agents and MCP clients
- [acp-governance-sdks](https://github.com/agentic-control-plane/acp-governance-sdks) — TypeScript + Python SDKs for scoped subagents and delegation chains
- [delegation-chain-spec](https://github.com/agentic-control-plane/delegation-chain-spec) — ADCS, the open spec for agent-to-agent delegation
- [hermes-acp-plugin](https://github.com/agentic-control-plane/hermes-acp-plugin) — the pip-installed governance plugin for Nous Research's Hermes Agent
- [agentgovbench](https://github.com/agentic-control-plane/agentgovbench) — 48-scenario benchmark across agent runtimes

## Contributing

- Run the tests: `npm test`
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Report issues on [GitHub Issues](https://github.com/agentic-control-plane/GatewayStack/issues)

GatewayStack is the runtime. The hosted console — dashboard, team management, cost X-ray, policy UI — is [Agentic Control Plane](https://agenticcontrolplane.com). Free for individuals.
