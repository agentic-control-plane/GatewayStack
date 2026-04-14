# @gatewaystack/identifiabl-core

Core identity verification for GatewayStack.
Verifies RS256 JWTs against a JWKS endpoint and maps them into a normalized `GatewayIdentity` object.

`@gatewaystack/identifiabl-core` is a small, framework-agnostic helper for:

- Verifying RS256 JWTs with `jose` and a remote JWKS URL
- Enforcing `iss` (issuer) and `aud` (audience)
- Normalizing identity claims (`sub`, `email`, `name`, tenant, roles, scopes, plan)
- Returning a consistent `VerifyResult` you can plug into gateways, middlewares, or Firebase Functions
- Multi-audience support (verify tokens for different API identifiers)

---

`@gatewaystack/identifiabl-core` is the low-level verifier behind
[identifiabl](https://www.npmjs.com/package/identifiabl) and the broader
[GatewayStack](https://agenticcontrolplane.com) modules.

If you want an opinionated HTTP/middleware layer for Apps SDK / MCP backends,
start with `identifiabl`. If you just need a small, framework-agnostic verifier
that returns a normalized identity object, use `@gatewaystack/identifiabl-core` directly.

## Installation

```bash
npm install @gatewaystack/identifiabl-core jose
# or
yarn add @gatewaystack/identifiabl-core jose
# or
pnpm add @gatewaystack/identifiabl-core jose
```

## Quick Start

```typescript
import { createIdentifiablVerifier } from "@gatewaystack/identifiabl-core";

const verify = createIdentifiablVerifier({
  issuer: "https://dev-xxxxx.us.auth0.com/",
  audience: "https://inner.app/api",
  // optional mappings:
  source: "auth0",
  tenantClaim: "https://inner.app/tenant_id",
  roleClaim: "https://inner.app/roles",
  scopeClaim: "scope",
  planClaim: "https://inner.app/plan"
});

async function handleRequest(bearerToken: string) {
  const token = bearerToken.replace(/^Bearer\s+/i, "");

  const result = await verify(token);

  if (!result.ok) {
    console.error("JWT verification failed:", result.error, result.detail);
    // return 401 / throw / etc.
    return;
  }

  const { identity, payload } = result;

  console.log("Verified user:", identity.sub);
  console.log("Tenant:", identity.tenantId);
  console.log("Roles:", identity.roles);
  console.log("Scopes:", identity.scopes);
}
```

## API

### createIdentifiablVerifier(config)

```typescript
import { createIdentifiablVerifier } from "@gatewaystack/identifiabl-core";

const verify = createIdentifiablVerifier(config);
const result = await verify(token);
```

### IdentifiablCoreConfig

```typescript
interface IdentifiablCoreConfig {
  issuer: string;        // Expected issuer (e.g. Auth0 domain)
  audience: string;      // Expected audience / API identifier
  jwksUri?: string;      // Optional override; defaults to `${issuer}/.well-known/jwks.json`
  source?: string;       // Optional identity source label (e.g. "auth0", "stytch", "cognito")

  tenantClaim?: string;  // Claim name for tenant / org id
  roleClaim?: string;    // Claim name for roles array
  scopeClaim?: string;   // Claim name for space-separated scopes string
  planClaim?: string;    // Claim name for plan / subscription tier
}
```

#### issuer

Used both to:

- Build a default JWKS URL (`${issuer}/.well-known/jwks.json` after trimming trailing `/`)
- Validate the `iss` claim. Trailing slashes are tolerated (e.g. `https://foo/` equals `https://foo`).

#### audience

Passed directly to `jwtVerify` to enforce the `aud` claim.

#### jwksUri (optional)

Override if your JWKS lives somewhere else.

#### Claim mapping fields

Let you adapt to different identity providers without changing code:

- `tenantClaim` → mapped to `identity.tenantId`
- `roleClaim` → mapped to `identity.roles: string[]`
- `scopeClaim` → split on spaces into `identity.scopes: string[]`
- `planClaim` → mapped to `identity.plan`

### VerifyResult

```typescript
type VerifyResult =
  | {
      ok: true;
      identity: GatewayIdentity;
      payload: JWTPayload;
    }
  | {
      ok: false;
      error: string;
      detail?: string;
    };
```

#### On success

`identity` is a normalized view of the user:

- `sub`: subject (required)
- `issuer`: normalized issuer (no trailing `/`)
- `email`, `name` (if present)
- `tenantId`, `roles`, `scopes`, `plan` (based on your config)
- `source`: identity provider label (defaults to "auth0")
- `raw`: the full decoded JWT payload

#### On failure

- `error` is a short code (currently `invalid_token`)
- `detail` is the underlying error message from jose when available

## Example: Firebase Callable Function

```typescript
import * as functions from "firebase-functions/v2/https";
import { createIdentifiablVerifier } from "@gatewaystack/identifiabl-core";

const verify = createIdentifiablVerifier({
  issuer: "https://dev-xxxxx.us.auth0.com/",
  audience: "https://inner.app/api",
  tenantClaim: "https://inner.app/tenant_id"
});

export const myProtectedFunction = functions.onCall(async (req) => {
  const token = req.rawRequest.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token) {
    throw new functions.HttpsError("unauthenticated", "Missing bearer token");
  }

  const result = await verify(token);
  if (!result.ok) {
    throw new functions.HttpsError("unauthenticated", "Invalid or expired token");
  }

  const { identity } = result;
  // Use identity.sub / identity.tenantId / etc.
  return { ok: true, user: identity.sub, tenantId: identity.tenantId };
});
```

## what identifiabl replaces under the hood
You **do not** need to write any of the code in this section if you're using
`@gatewaystack/identifiabl-core`. This is an example of the kind of hand-rolled
JWT/JWKS + identity plumbing that `createIdentifiablVerifier()` is designed to replace.

**1. `verifyToken` — verify oidc / apps sdk identity tokens**  
validates rs256 jwts, audiences, issuers, expirations, and nonce.

a minimal typescript implementation:
```ts
// auth/verifyToken.ts
import { createRemoteJWKSet, jwtVerify, JWTPayload } from 'jose';

const ISSUER = process.env.AUTH_ISSUER!;
const AUDIENCE = process.env.AUTH_AUDIENCE!;
const JWKS_URI = process.env.AUTH_JWKS_URI!;

const jwks = createRemoteJWKSet(new URL(JWKS_URI));

export type VerifiedIdentity = {
  user_id: string;
  org_id?: string;
  tenant?: string;
  roles: string[];
  scopes: string[];
  raw: JWTPayload;
};

export async function verifyToken(authorizationHeader: string | undefined): Promise<VerifiedIdentity> {
  if (!authorizationHeader?.startsWith('Bearer ')) {
    throw new Error('missing or invalid bearer token');
  }

  const token = authorizationHeader.slice('Bearer '.length).trim();

  const { payload } = await jwtVerify(token, jwks, {
    issuer: ISSUER,
    audience: AUDIENCE,
  });

  return extractIdentity(payload);
}

function extractIdentity(payload: JWTPayload): VerifiedIdentity {
  const scopes =
    typeof payload.scope === 'string'
      ? payload.scope.split(' ').filter(Boolean)
      : Array.isArray(payload.scope)
      ? payload.scope.map(String)
      : [];

  return {
    user_id: String(payload.sub ?? ''),
    org_id: (payload['org_id'] as string) ?? undefined,
    tenant: (payload['tenant'] as string) ?? undefined,
    roles: (payload['roles'] as string[]) ?? [],
    scopes,
    raw: payload,
  };
}
```

**2. `extractIdentity` — normalize user/org/tenant metadata**  
implemented inside `verifyToken` above, it returns a canonical structure:
```ts
{ user_id, org_id, tenant, roles, scopes }
```

**3. `attachIdentity` — bind identity to model request metadata**  
injects identity into headers or context fields for downstream modules.
```ts
// middleware/attachIdentity.ts
import type { Request, Response, NextFunction } from 'express';
import { verifyToken, VerifiedIdentity } from '../auth/verifyToken';

declare module 'express-serve-static-core' {
  interface Request {
    identity?: VerifiedIdentity;
  }
}

export async function attachIdentity(req: Request, res: Response, next: NextFunction) {
  try {
    const authHeader = req.headers['authorization'] as string | undefined;

    const identity = await verifyToken(authHeader);

    // attach to request for downstream handlers / modules
    req.identity = identity;

    // inject normalized identity headers for downstream services / proxies
    req.headers['x-user-id'] = identity.user_id;
    if (identity.org_id) req.headers['x-org-id'] = identity.org_id;
    if (identity.tenant) req.headers['x-tenant'] = identity.tenant;
    req.headers['x-user-scopes'] = identity.scopes.join(' ');

    return next();
  } catch (err) {
    return res.status(401).json({
      error: 'unauthorized',
      reason: (err as Error).message ?? 'token validation failed',
    });
  }
}
```

then wire it up in your gateway server:
```ts
import express from 'express';
import { attachIdentity } from './middleware/attachIdentity';

const app = express();

app.use(attachIdentity);

// all downstream routes now see req.identity and identity headers
```

**4. `assertIdentity` — enforce presence of user identity**  
guarantees that no anonymous or shared-key requests pass through.
```ts
// middleware/assertIdentity.ts
import type { Request, Response, NextFunction } from 'express';

export function assertIdentity(req: Request, res: Response, next: NextFunction) {
  if (!req.identity) {
    return res.status(401).json({ error: 'unauthorized', reason: 'missing user identity' });
  }
  return next();
}
```

**5. `logIdentity` — produce identity-level audit events**  
emits structured logs for compliance, analytics, and debugging.
```ts
// inside your request pipeline
logger.info('identity_event', {
  user_id: req.identity?.user_id,
  org_id: req.identity?.org_id,
  scopes: req.identity?.scopes,
  path: req.path,
  action: 'model_request',
});
```

## Implementation Notes

Uses `jose` under the hood:

- `createRemoteJWKSet` to fetch and cache keys
- `jwtVerify` with `algorithms: ["RS256"]`
- `clockTolerance: "60s"` to allow for small clock skew

Currently focused on RS256 JWTs; other algorithms are intentionally not allowed.

## Related

- High-level identity gateway for Apps SDK / MCP backends:  
  [`identifiabl` on npm](https://www.npmjs.com/package/identifiabl) / [identifiabl.com](https://identifiabl.com)
- GatewayStack (user-scoped trust & governance gateway):  
  https://github.com/davidcrowe/gatewaystack
