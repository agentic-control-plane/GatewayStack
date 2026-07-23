# @gatewaystack/identifiabl

**Trust & Identity Binding** — Cryptographically verify user identity on every AI request.

## What It Does

`identifiabl` is the **foundational layer** of the GatewayStack control plane. It verifies RS256 JWTs, enforces issuer/audience requirements, and establishes a canonical user identity (`req.user`) that downstream layers use for authorization, routing, rate limiting, and audit.

**Without identifiabl:** AI requests use shared API keys with no user attribution. You can't answer "who did what?" or enforce per-user policies.

**With identifiabl:** Every request is cryptographically bound to a verified user, enabling user-scoped governance across your entire AI stack.

## Key Features

- ✅ **RS256 JWT Verification** via JWKS (supports key rotation)
- ✅ **Issuer & Audience Pinning** (prevents token substitution attacks)
- ✅ **Standard Claims Validation** (`exp`, `nbf`, `iat`, `sub`)
- ✅ **Canonical Identity Normalization** (`req.user` for downstream layers)
- ✅ **Zero Dependencies on User Code** (works with any OAuth 2.1 provider)

## Installation

```bash
npm install @gatewaystack/identifiabl
```

## Quick Start

### Basic Usage

```typescript
import express from 'express';
import { identifiabl } from '@gatewaystack/identifiabl';

const app = express();

// Add identity verification to all routes
app.use(identifiabl({
  issuer: 'https://your-tenant.auth0.com/',
  audience: 'https://gateway.local/api',
  jwksUri: 'https://your-tenant.auth0.com/.well-known/jwks.json'
}));

// Now all requests have req.user with verified identity
app.get('/api/data', (req, res) => {
  const userId = req.user.sub; // Verified user ID
  const userEmail = req.user.email; // Optional claim
  
  // Use userId to filter data per-user
  const data = getUserData(userId);
  res.json(data);
});
```

### With Protected Routes

```typescript
// Public routes (no auth required)
app.get('/health', (req, res) => res.json({ ok: true }));

// Protected routes (auth required)
app.use('/protected', identifiabl({
  issuer: process.env.OAUTH_ISSUER,
  audience: process.env.OAUTH_AUDIENCE,
  jwksUri: process.env.OAUTH_JWKS_URI
}));

app.get('/protected/data', (req, res) => {
  // req.user is guaranteed to exist here
  res.json({ user: req.user.sub });
});
```

## Configuration

### Required Options

| Option | Type | Description | Example |
|--------|------|-------------|---------|
| `issuer` | `string` | OAuth issuer (must match token `iss`) | `https://tenant.auth0.com/` |
| `audience` | `string` | API identifier (must match token `aud`) | `https://gateway.local/api` |

### Optional Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `jwksUri` | `string` | `${issuer}/.well-known/jwks.json` | JWKS endpoint (auto-derived from issuer) |
| `enforceAlg` | `string` | `'RS256'` | Require specific JWT algorithm |
| `jwksCacheMs` | `number` | `3600000` (1h) | How long to cache JWKS keys |
| `jwksTimeout` | `number` | `5000` (5s) | JWKS fetch timeout |
| `clockTolerance` | `number` | `30` (seconds) | Allow clock skew for exp/nbf |

## How It Works

### 1. Extract Token

Reads `Authorization: Bearer <token>` header and extracts the JWT.

```typescript
// Request with token
GET /api/data
Authorization: Bearer eyJhbGciOiJSUzI1NiIs...
```

### 2. Fetch & Cache JWKS

Fetches public signing keys from your IdP's JWKS endpoint and caches them for subsequent requests.

```typescript
// Cached for jwksCacheMs (default 1 hour)
const jwks = await fetch('https://tenant.auth0.com/.well-known/jwks.json');
```

### 3. Verify Signature

Uses `jose` library to cryptographically verify the JWT signature against the public key.

```typescript
import { jwtVerify } from 'jose';

const { payload } = await jwtVerify(token, jwks, {
  issuer: config.issuer,
  audience: config.audience,
  algorithms: [config.enforceAlg]
});
```

### 4. Validate Claims

Checks standard JWT claims automatically:

- ✅ `iss` (issuer) matches configured issuer
- ✅ `aud` (audience) matches configured audience
- ✅ `exp` (expiration) is in the future
- ✅ `nbf` (not before) is in the past
- ✅ `alg` (algorithm) is RS256 (or configured value)

### 5. Attach Canonical Identity

Creates `req.user` with verified claims for downstream layers:

```typescript
req.user = {
  sub: payload.sub,           // Verified user ID
  email: payload.email,       // Optional claims
  scope: payload.scope,       // Granted scopes
  org_id: payload.org_id,     // Tenant/org ID (if present)
  // ... any other claims from token
};
```

## Identity Properties

After identifiabl runs, `req.user` contains:

| Property | Description | Example |
|----------|-------------|---------|
| `sub` | **Unique user identifier** (primary key for user) | `auth0\|507f1f77bcf86cd799439011` |
| `email` | User email (if in token) | `alice@example.com` |
| `scope` | Space-separated OAuth scopes | `tool:read tool:write` |
| `org_id` | Organization/tenant ID (if multi-tenant) | `org_abc123` |
| `exp` | Token expiration timestamp | `1735776000` |

**Note:** The gateway uses `sub` as the canonical user identifier for all downstream operations (authorization, rate limiting, audit trails).

## Security Considerations

### Algorithm Enforcement

identifiabl **only accepts RS256** by default. This prevents:

- ❌ `alg: none` attacks (unsigned tokens)
- ❌ `alg: HS256` attacks (symmetric key confusion)
- ❌ Token substitution from other issuers

```typescript
// Strict algorithm enforcement
enforceAlg: 'RS256'  // Default (recommended)
```

### Audience Pinning

The `audience` parameter prevents tokens issued for one API from being used on another:

```typescript
// Token for API A won't work on API B
audience: 'https://api-a.example.com'  // API A
audience: 'https://api-b.example.com'  // API B
```

### Clock Tolerance

Allows small time differences between client/server clocks:

```typescript
clockTolerance: 30  // Allow 30 seconds of clock skew
```

### Token Lifetime

identifiabl respects token expiration (`exp`) automatically. For security:

- ✅ Issue **short-lived tokens** (15 min - 1 hour)
- ✅ Use **refresh tokens** for long-lived sessions
- ✅ Revoke tokens via your IdP when needed

## Error Handling

identifiabl returns **401 Unauthorized** for auth failures:

```typescript
// No token provided
401 Unauthorized
WWW-Authenticate: Bearer realm="gateway", error="missing_token"

// Token signature invalid
401 Unauthorized
WWW-Authenticate: Bearer realm="gateway", error="invalid_signature"

// Token expired
401 Unauthorized
WWW-Authenticate: Bearer realm="gateway", error="token_expired"

// Wrong audience
401 Unauthorized
WWW-Authenticate: Bearer realm="gateway", error="invalid_audience"
```

**Client should:** Refresh token or re-authenticate with IdP.

## Integration with Other Layers

identifiabl provides the foundation for all other GatewayStack layers:

### validatabl (Authorization)

Uses `req.user.scope` to enforce per-tool/model access:

```typescript
// identifiabl provides verified scopes
req.user.scope = 'tool:read tool:write';

// validatabl enforces scope requirements
requireScope('tool:write');
```

### limitabl (Rate Limiting)

Uses `req.user.sub` (and optionally `org_id`) to apply per-user/tenant limits:

```typescript
// Rate limit by verified user
const key = req.user.sub;
const allowed = checkRateLimit(key);
```

### proxyabl (Routing)

Injects `req.user` identity into downstream service headers:

```typescript
// Inject verified user ID for per-user data filtering
headers['X-User-Id'] = req.user.sub;
headers['X-User-Email'] = req.user.email;
```

### explicabl (Audit)

Logs verified identity with every action:

```typescript
log({
  event: 'tool_call',
  user_id: req.user.sub,
  org_id: req.user.org_id,
  // ... audit trail
});
```

## Supported Identity Providers

identifiabl works with any OAuth 2.1 / OIDC provider that issues RS256 JWTs:

| Provider | Status | Notes |
|----------|--------|-------|
| **Auth0** | ✅ Fully tested | Reference implementation |
| **Okta** | ✅ Compatible | Standard RS256 setup |
| **Entra ID** (Azure AD) | ✅ Compatible | Use v2.0 endpoint |
| **Keycloak** | ✅ Compatible | Self-hosted option |
| **Google OAuth** | ✅ Compatible | Standard setup |
| **Custom** | ✅ Any RS256 provider | Must meet requirements below |

### Provider Requirements

Your IdP must provide:

1. **RS256 JWT signing** (asymmetric keys)
2. **Public JWKS endpoint** (for key discovery)
3. **Standard claims** (`iss`, `aud`, `sub`, `exp`, `nbf`)
4. **HTTPS everywhere** (no HTTP endpoints)

## Testing

### Unit Tests

```bash
npm test
```

### Manual Testing

```bash
# Get a test token from your IdP
TOKEN="eyJhbGciOiJSUzI1NiIs..."

# Test protected endpoint
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/protected/ping

# Expected: 200 OK with user info
```

### Testing Without IdP (Demo Mode)

Use the included demo issuer for local development:

```bash
# Start demo issuer (mints RS256 tokens)
npm run -w demos/mcp-server dev

# Mint test token
curl -X POST http://localhost:5051/mint \
  -H 'content-type: application/json' \
  -d '{"scope":"tool:read tool:write","sub":"test-user"}'

# Configure gateway for demo mode
DEMO_MODE=true
OAUTH_ISSUER_DEMO=http://localhost:5051/
OAUTH_AUDIENCE_DEMO=https://gateway.local/api
OAUTH_JWKS_URI_DEMO=http://localhost:5051/.well-known/jwks.json
```

## Troubleshooting

### "Invalid signature" errors

**Cause:** Token not signed by expected issuer, or JWKS can't be fetched.

**Fix:**
1. Verify `OAUTH_ISSUER` matches token `iss` claim exactly (including trailing slash)
2. Check JWKS endpoint is reachable: `curl $OAUTH_JWKS_URI`
3. Verify token is RS256: decode at jwt.io and check `alg` header

### "Invalid audience" errors

**Cause:** Token `aud` doesn't match `OAUTH_AUDIENCE`.

**Fix:**
1. Check token audience: decode at jwt.io
2. Ensure Auth0 API identifier matches `OAUTH_AUDIENCE`
3. Verify API is included in token request (e.g., ChatGPT Post-Login Action)

### "Token expired" errors

**Cause:** Token `exp` claim is in the past.

**Fix:**
1. Get a fresh token from your IdP
2. Check clock sync between client/server
3. Increase `clockTolerance` if clocks are slightly off

### JWKS fetch failures

**Cause:** Can't reach IdP's JWKS endpoint.

**Fix:**
1. Check network connectivity: `curl $OAUTH_JWKS_URI`
2. Verify TLS certificates are valid
3. Check firewall rules allow HTTPS egress
4. Increase `jwksTimeout` if network is slow

## Performance

identifiabl is optimized for production:

- ⚡ **JWKS caching** (default 1 hour) — reduces IdP load
- ⚡ **Async verification** (non-blocking)
- ⚡ **Minimal overhead** (~2-5ms per request after cache warm)

### Benchmarks

| Operation | Latency | Notes |
|-----------|---------|-------|
| Cold start (JWKS fetch) | ~100-200ms | First request only |
| Cached verification | ~2-5ms | Typical case |
| Token decode | <1ms | JWT parsing |

## Advanced Usage

### Custom Claims Extraction

```typescript
app.use(identifiabl({
  issuer: process.env.OAUTH_ISSUER,
  audience: process.env.OAUTH_AUDIENCE,
  jwksUri: process.env.OAUTH_JWKS_URI,
  // Custom claim mapping
  extractClaims: (payload) => ({
    sub: payload.sub,
    email: payload.email,
    roles: payload['https://app.example.com/roles'], // Custom namespace
    tenant_id: payload.org_id || payload['https://app.example.com/tenant']
  })
}));
```

### Multi-Tenant Isolation

```typescript
// Enforce tenant ID in token
app.use(identifiabl({
  issuer: process.env.OAUTH_ISSUER,
  audience: process.env.OAUTH_AUDIENCE,
  jwksUri: process.env.OAUTH_JWKS_URI,
  requireClaims: ['org_id'] // Reject tokens without org_id
}));

app.get('/api/data', (req, res) => {
  const tenantId = req.user.org_id; // Guaranteed to exist
  const data = getTenantData(tenantId);
  res.json(data);
});
```

## Related Packages

- **@gatewaystack/validatabl** — Scope-based authorization (uses `req.user.scope`)
- **@gatewaystack/limitabl** — Rate limiting (uses `req.user.sub`)
- **@gatewaystack/proxyabl** — Identity injection (uses `req.user.*`)
- **@gatewaystack/explicabl** — Audit logging (uses `req.user.*`)

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

MIT — See [LICENSE](../../LICENSE)