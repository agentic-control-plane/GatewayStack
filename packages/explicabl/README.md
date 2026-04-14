# @gatewaystack/explicabl

**Explicabl** is GatewayStack’s **explainability & audit layer**.  
It emits a **structured JSON event for every request** flowing through the GatewayStack pipeline, enabling:

- request-level audit trails  
- debugging & developer visibility  
- future SIEM / OTEL / Cloud Logging sinks  
- full traceability across Identifiabl → Proxyabl → Explicabl  

This is the **MVP implementation**, focused on being simple, predictable, and production-safe.

---

## Features

- **Single structured JSON event per request**
- Includes HTTP metadata (method, path, status, latency), request ID, and context (identity, routing, limits)
- **Safe** — logging failures never break responses
- **Zero dependencies** beyond Express
- **Pluggable logger function** with built-in console logger (`createConsoleLogger`)
- Compatible with `@gatewaystack/request-context`, `@gatewaystack/identifiabl`, `@gatewaystack/proxyabl`

---

## Installation

```bash
npm install @gatewaystack/explicabl
```

---

## Quick Start

### 1. Create a logger

```ts
import { createConsoleLogger } from "@gatewaystack/explicabl";

const logger = createConsoleLogger({
  serviceName: "gateway-server",
  environment: process.env.NODE_ENV,
});
```

### 2. Add the middleware *after* you create request context

```ts
import { explicablLoggingMiddleware } from "@gatewaystack/explicabl";

app.use(explicablLoggingMiddleware(logger));
```

Explicabl will now emit one event for every request:

```text
[explicabl] {"ts":"2025-01-01T00:00:00.000Z","kind":"gateway.request", ...}
```

---

## API

### `createConsoleLogger(config)`

Creates a logger that writes one JSON line per event to `stdout`.

```ts
const logger = createConsoleLogger({
  serviceName?: string;
  environment?: string;
});
```

### `explicablLoggingMiddleware(logger)`

Express middleware that emits one `ExplicablEvent` after every response.

```ts
app.use(explicablLoggingMiddleware(logger));
```

### `explicablRouter(env)`

Optional router that exposes:

- `/health` endpoints
- `/webhooks/auth0` for ingesting Auth0 log events

```ts
app.use("/explicabl", explicablRouter(process.env));
```

> **Breaking change in 0.0.7 (security):** both the Auth0 log webhook and the detailed Auth0 health endpoint now require explicit secrets — no hardcoded defaults — and compare them in constant time.
>
> | Env var | Purpose | If unset |
> |---|---|---|
> | `LOG_WEBHOOK_SECRET` | Authenticates calls to `POST /auth0-log-webhook` (via `Authorization: Bearer <s>` or `X-Webhook-Secret: <s>`) | Webhook returns `503 not_configured` |
> | `HEALTH_ADMIN_SECRET` | Authenticates calls to `GET /health/auth0` (via `Authorization: Bearer <s>` or `X-Admin-Secret: <s>`) | Endpoint returns `404` (not even acknowledged, to reduce scan signal) |
>
> Prior versions shipped with `LOG_WEBHOOK_SECRET` defaulting to `"dev-change-me"` and a publicly-readable `/health/auth0` endpoint that leaked issuer/audience/JWKS URLs and performed outbound Auth0 Management API token requests on every hit (amplification risk). Operators upgrading from 0.0.6 must set both env vars before exposing these endpoints.

---

## Event Format (`ExplicablEvent`)

```ts
interface ExplicablEvent {
  ts: string;               // timestamp
  kind: "gateway.request";
  serviceName?: string;
  environment?: string;
  requestId?: string;

  http: {
    method: string;
    path: string;
    status: number;
    latencyMs?: number;
  };

  context?: unknown; // identity, authz, limits, routing...
}
```

Future versions will expand this with:

- token usage
- policy decisions
- rate-limit metadata
- model/tool routing info
- richer sinks (OTEL, Cloud Logging, ClickHouse, etc.)

---

## Testing

Explicabl ships with full unit tests:

- logger enrichment  
- middleware events  
- error handling  
- context propagation  

Run:

```bash
npm test
```

---

## Roadmap

- `explicabl-core` package with shared event schema (non-Express)
- OTEL/trace/span support
- Token usage + cost attribution
- Policy explainability integration (Validatabl)
- ClickHouse / BigQuery / Cloud Logging sinks
- GatewayStack UI integration for audit trails
- “Replay this request” developer tools

---

## License

MIT © GatewayStack
