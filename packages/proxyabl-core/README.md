# @gatewaystack/proxyabl-core

Framework-agnostic proxy forwarding, SSRF protection, auth mode routing, and provider registry for AI gateways.

`@gatewaystack/proxyabl-core` is the low-level engine behind [@gatewaystack/proxyabl](https://www.npmjs.com/package/@gatewaystack/proxyabl). Use it directly when you need proxy capabilities without Express, or in serverless / edge environments.

## Installation

```bash
npm install @gatewaystack/proxyabl-core
```

## Features

- **Auth mode routing** — resolve credentials for 5 auth modes (API key, forward bearer, service OAuth, user OAuth, none)
- **SSRF protection** — host allowlist, private IP blocking (IPv4 + IPv6), protocol enforcement
- **HTTP proxy execution** — forward requests with timeout, redirect blocking, response size capping, and header sanitization
- **Provider registry** — multi-provider configuration with default fallback
- **JWT verification** — RS256 access token validation via JWKS
- **Tool scope enforcement** — scope-to-tool mapping and assertion

## Quick Start

### Proxy a request to an upstream API

```ts
import { resolveAuth, executeProxyRequest } from "@gatewaystack/proxyabl-core";

const auth = resolveAuth(
  { mode: "api_key", apiKeyHeader: "X-API-Key", apiKeyValue: "sk-..." },
  {}
);

const response = await executeProxyRequest({
  baseUrl: "https://api.openai.com",
  path: "/v1/chat/completions",
  method: "POST",
  body: { model: "gpt-4", messages: [{ role: "user", content: "Hello" }] },
  auth,
  allowedHosts: ["api.openai.com"],
  timeoutMs: 30_000,
});

console.log(response.status, response.body);
```

### Forward the user's Bearer token

```ts
const auth = resolveAuth(
  { mode: "forward_bearer" },
  { bearerToken: req.headers.authorization?.replace("Bearer ", "") }
);
```

### Use a provider registry

```ts
import { resolveProvider, resolveAuth, executeProxyRequest } from "@gatewaystack/proxyabl-core";

const registry = {
  providers: {
    openai: {
      key: "openai",
      baseUrl: "https://api.openai.com",
      auth: { mode: "api_key" as const, apiKeyHeader: "Authorization", apiKeyValue: "Bearer sk-..." },
      allowedHosts: ["api.openai.com"],
    },
    anthropic: {
      key: "anthropic",
      baseUrl: "https://api.anthropic.com",
      auth: { mode: "api_key" as const, apiKeyHeader: "x-api-key", apiKeyValue: "sk-ant-..." },
      allowedHosts: ["api.anthropic.com"],
    },
  },
  defaultProvider: "openai",
};

const provider = resolveProvider(registry, "anthropic");
const auth = resolveAuth(provider.auth, {});
```

## API

### Auth Modes

```ts
resolveAuth(config: AuthModeConfig, context: AuthContext): ResolvedAuth
```

| Mode | Description | Required context |
|------|-------------|-----------------|
| `api_key` | Static API key in a custom header | `apiKeyHeader` + `apiKeyValue` in config |
| `forward_bearer` | Forward the incoming request's Bearer token | `bearerToken` in context |
| `service_oauth` | Use a pre-loaded M2M/service token | `serviceToken` in context |
| `user_oauth` | Use a pre-loaded user OAuth token | `userToken` in context |
| `none` | No authentication | (none) |

### SSRF Protection

> **Scope.** `assertUrlSafe` / `executeProxyRequest` are the primitive for proxying **arbitrary, caller-influenced URLs** — call them directly from your handler. The Express router in [`@gatewaystack/proxyabl`](https://www.npmjs.com/package/@gatewaystack/proxyabl) is a different thing: it forwards to an operator-**configured** backend and does not route through this engine (a configured backend may legitimately be internal, which private-IP blocking would reject). Importing the router does not give you this SSRF check automatically.

```ts
assertUrlSafe(opts: UrlSafetyOptions): Promise<void>
```

> **Breaking change in 0.1.0:** `assertUrlSafe` is now async and takes a single options object. The function performs a DNS lookup when the hostname is not an IP literal, so it cannot be synchronous.

Throws if the URL fails any check:
- Protocol must be HTTPS (unless `allowHttp: true`)
- Hostname must be in `allowedHosts` (case-insensitive exact match)
- IP literals (IPv4 or IPv6) are rejected if they fall in private ranges (10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 0/8, ::1, fc00::/7, fe80::/10)
- IPv4-mapped IPv6 (`::ffff:127.0.0.1` and its compressed hex form) is unpacked and checked as IPv4 — an attacker cannot reach loopback by wrapping it in IPv6 syntax
- **Hostnames are resolved via DNS and every returned A/AAAA is checked against private ranges.** This closes the DNS-rebinding bypass where an allowlisted name resolves to a private IP at fetch time

```ts
interface UrlSafetyOptions {
  url: URL;
  allowedHosts: string[];
  allowHttp?: boolean;       // default false
  allowPrivateIps?: boolean; // default false — set only for trusted internal callers
  resolve?: (host: string) => Promise<Array<{ address: string; family: number }>>; // test seam
}
```

```ts
sanitizeHeaderValue(value: string): string
```

Strips CRLF characters to prevent header injection.

**Known limitation:** there is a small TOCTOU window between `dns.lookup()` and the actual TCP connect in `fetch()`. A response with a very short TTL could flip public→private between those two steps. Closing this fully requires pinning the socket to the validated IP via a custom HTTP agent; tracked as a follow-up.

### HTTP Execution

```ts
executeProxyRequest(config: ProxyRequestConfig): Promise<ProxyResponse>
```

- Builds URL from `baseUrl` + `path`
- Runs SSRF check via `assertUrlSafe()`
- Injects auth headers from `ResolvedAuth`
- Filters hop-by-hop headers (host, connection, etc.)
- Uses `AbortController` for timeout (default 10s, max 120s)
- Blocks redirects (`redirect: "manual"`)
- Caps response size (default 512KB, max 5MB)
- Parses JSON responses automatically

### Provider Registry

```ts
resolveProvider(registry: ProviderRegistry, providerKey?: string): ProviderConfig
```

Returns the named provider or the default. Throws with available providers listed if not found.

### JWT Verification

```ts
verifyAccessToken(config: ProxyablConfig, token: string): Promise<VerifiedAccessToken>
assertToolScopes(config: ProxyablConfig, toolName: string, userScopes: string[]): void
```

## Related Packages

- [@gatewaystack/proxyabl](https://www.npmjs.com/package/@gatewaystack/proxyabl) — Express middleware wrapper
- [@gatewaystack/identifiabl-core](https://www.npmjs.com/package/@gatewaystack/identifiabl-core) — JWT identity verification
- [@gatewaystack/validatabl-core](https://www.npmjs.com/package/@gatewaystack/validatabl-core) — Policy enforcement

## License

MIT
