# @gatewaystack/validatabl

Express middleware for AI gateway authorization. Scope checking, permission enforcement, policy evaluation, and input validation.

Wraps [@gatewaystack/validatabl-core](https://www.npmjs.com/package/@gatewaystack/validatabl-core) with HTTP-aware middleware for Express applications.

## Installation

```bash
npm install @gatewaystack/validatabl
```

## Features

- **`requireScope()`** — guard routes by OAuth scope
- **`requirePermissions()`** — guard routes by permissions/roles
- **`validatabl()`** — full decision engine middleware (permissions + policies + schema)
- **Protected resource metadata** — OAuth 2.0 protected resource endpoint
- Re-exports all `@gatewaystack/validatabl-core` functions for direct use

## Quick Start

### Require a scope

```ts
import express from "express";
import { requireScope } from "@gatewaystack/validatabl";

const app = express();

// Requires identifiabl middleware upstream (populates req.user)
app.post("/api/tools/invoke", requireScope("tool:write"), (req, res) => {
  // Only reaches here if req.user has "tool:write" scope
  res.json({ ok: true });
});
```

### Require permissions

```ts
import { requirePermissions } from "@gatewaystack/validatabl";

app.delete("/api/admin/users/:id",
  requirePermissions("admin", "users:delete"),
  (req, res) => {
    // Only reaches here if req.user has BOTH "admin" AND "users:delete"
    res.json({ deleted: true });
  }
);
```

### Full decision engine

```ts
import { validatabl } from "@gatewaystack/validatabl";

app.use("/api/tools", validatabl({
  requiredPermissions: ["tool:read"],
  policies: {
    defaultEffect: "deny",
    rules: [
      {
        id: "allow-search",
        effect: "allow",
        priority: 10,
        conditions: [
          { field: "tool", operator: "equals", value: "search" },
          { field: "scope", operator: "contains", value: "tool:read" },
        ],
      },
    ],
  },
  inputSchema: {
    type: "object",
    required: ["query"],
  },
}));
```

> **Behavior change in 0.2.0:** `validatabl()` throws at factory time if you pass it an empty config (no `requiredPermissions`, no `policies`, no `inputSchema`). The middleware is sold as deny-by-default, and silently allowing every request when misconfigured was the opposite of that promise. Configure at least one check — or use the `requireScope()` / `requirePermissions()` helpers below for simpler route-level guards.

## How It Works

1. Reads identity from `req.user` (populated by `@gatewaystack/identifiabl`)
2. Extracts tool/model/input from the request body
3. Runs the `decision()` engine from validatabl-core
4. Returns `403` with details on denial, or calls `next()` on success
5. Attaches `req.validatablDecision` for downstream middleware (e.g., audit logging)

## Error Responses

```json
// requireScope
{ "error": "insufficient_scope", "needed": "tool:write" }

// requirePermissions
{ "error": "insufficient_permissions", "message": "Missing permissions: admin", "missing": ["admin"] }

// validatabl (full engine)
{ "error": "policy_denied", "message": "...", "checks": { ... } }
```

## Related Packages

- [@gatewaystack/validatabl-core](https://www.npmjs.com/package/@gatewaystack/validatabl-core) — Framework-agnostic engine
- [@gatewaystack/identifiabl](https://www.npmjs.com/package/@gatewaystack/identifiabl) — JWT identity (upstream)
- [@gatewaystack/limitabl](https://www.npmjs.com/package/@gatewaystack/limitabl) — Rate limiting middleware

## License

MIT
