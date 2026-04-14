# @gatewaystack/limitabl

Express middleware for AI gateway rate limiting, budget tracking, and agent guard.

Wraps [@gatewaystack/limitabl-core](https://www.npmjs.com/package/@gatewaystack/limitabl-core) with a two-phase HTTP middleware model for Express applications.

## Installation

```bash
npm install @gatewaystack/limitabl
```

## Features

- **Phase 1: Pre-flight** — check rate limits, budgets, and agent guard before execution
- **Phase 2: Record** — record actual usage after execution
- Standard `429` / `Retry-After` headers for rate limits
- `X-RateLimit-Remaining` and `X-RateLimit-Reset` response headers
- Automatic key resolution from `req.user` (sub > orgId > IP)
- Re-exports all `@gatewaystack/limitabl-core` classes for direct use

## Behind a proxy / load balancer

> **Behavior change in 0.2.0:** the middleware no longer reads `X-Forwarded-For` directly. It relies on Express's `req.ip`, which is only trustworthy when the application has configured `trust proxy` for its deployment. If you run behind a load balancer or reverse proxy, set:
>
> ```ts
> app.set("trust proxy", 1); // or the number of trusted hops in front of you
> ```
>
> Without this setting, `req.ip` resolves to the proxy's own IP, so all requests through that proxy share a single rate-limit bucket. Prior versions read the leftmost `X-Forwarded-For` value directly — which any caller can forge, letting an attacker rotate the rate-limit key per request or exhaust a victim's bucket. See [Express behind proxies](https://expressjs.com/en/guide/behind-proxies.html).

## Quick Start

### Basic rate limiting + budget

```ts
import express from "express";
import { limitabl, recordUsage } from "@gatewaystack/limitabl";

const app = express();

// Requires identifiabl middleware upstream (populates req.user)
app.use("/api/tools", limitabl({
  rateLimit: { windowMs: 60_000, maxRequests: 100 },
  budget: { maxSpend: 500, periodMs: 86_400_000 },   // $5/day
  agentGuard: { maxToolCalls: 50, maxDurationMs: 300_000 },
}));

app.post("/api/tools/invoke", async (req, res) => {
  const result = await callTool(req.body);

  // Phase 2: record actual cost
  recordUsage(req, { cost: result.cost, tokens: result.tokens });

  res.json(result);
});
```

### With workflow tracking

```ts
app.use("/api/tools", limitabl({
  rateLimit: { windowMs: 60_000, maxRequests: 100 },
  agentGuard: { maxToolCalls: 30 },
  // Custom workflow ID extraction
  extractWorkflowId: (req) => req.headers["x-workflow-id"] as string,
}));
```

## How It Works

**Phase 1 (pre-flight):** The `limitabl()` middleware runs before your handler. It:
1. Extracts the user key from `req.user` (sub, orgId, or IP)
2. Reads the workflow ID from `x-workflow-id` header (or custom extractor)
3. Runs `engine.preflight()` — checks rate limit, budget, and agent guard
4. Returns `429` (rate limit) or `403` (budget/agent) on denial
5. Sets `X-RateLimit-Remaining` and `X-RateLimit-Reset` headers
6. Attaches the engine to the request for Phase 2

**Phase 2 (record):** Call `recordUsage(req, { cost, tokens })` after execution to track actual spend.

## Error Responses

```json
// Rate limit exceeded (429)
{
  "error": "limit_exceeded",
  "message": "Rate limit exceeded",
  "rateLimit": { "remaining": 0, "retryAfterSec": 45 }
}

// Budget exceeded (403)
{
  "error": "limit_exceeded",
  "message": "Budget exceeded: 95 / 100 (estimated +10)",
  "budget": { "currentSpend": 95, "maxSpend": 100, "percentUsed": 95 }
}
```

## Configuration

```ts
interface LimitablConfig {
  rateLimit?: { windowMs: number; maxRequests: number };
  budget?: { maxSpend: number; periodMs: number };
  agentGuard?: { maxToolCalls?: number; maxWorkflowCost?: number; maxDurationMs?: number };
  extractWorkflowId?: (req: any) => string | undefined;
}
```

All three components are optional. Configure any combination.

## Related Packages

- [@gatewaystack/limitabl-core](https://www.npmjs.com/package/@gatewaystack/limitabl-core) — Framework-agnostic engine
- [@gatewaystack/identifiabl](https://www.npmjs.com/package/@gatewaystack/identifiabl) — JWT identity (upstream, provides req.user)
- [@gatewaystack/validatabl](https://www.npmjs.com/package/@gatewaystack/validatabl) — Authorization middleware

## License

MIT
