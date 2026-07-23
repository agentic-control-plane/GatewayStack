# Package Breakdown

GatewayStack ships as composable npm packages. Each governance layer has a `-core` package (framework-agnostic, pure functions) and an Express middleware wrapper.

## identifiabl

`@gatewaystack/identifiabl-core` / `@gatewaystack/identifiabl`

**Trust & Identity Binding.** Verifies RS256 JWTs via JWKS, enforces issuer/audience, maps claims into a canonical `GatewayIdentity`. Supports multi-audience verification and configurable claim extraction (tenant, roles, scopes, plan).

## transformabl

`@gatewaystack/transformabl-core` / `@gatewaystack/transformabl`

**Content Safety & Transformation.** Regex-based PII detection (email, phone, SSN, credit card, IP, DOB), three redaction modes (mask, remove, placeholder), safety classification (prompt injection, jailbreak, code injection), regulatory flagging (GDPR, PCI, COPPA, HIPAA), and risk scoring. Runs *before* authorization so policies can reference content risk.

## validatabl

`@gatewaystack/validatabl-core` / `@gatewaystack/validatabl`

**Authorization & Policy Enforcement.** Deny-by-default policy engine with priority-ordered rules and condition operators (equals, contains, in, matches, exists). Scope/role/permission checking, input schema validation, and a unified `decision()` entry point. Express middleware includes `requireScope()` and `requirePermissions()` guards.

## limitabl

`@gatewaystack/limitabl-core` / `@gatewaystack/limitabl`

**Spend Controls & Resource Governance.** Sliding-window rate limiter per user/org/IP, per-user budget tracking with pre-flight estimation, and agent guard (tool call limits, workflow cost caps, duration caps). Two-phase middleware model: pre-flight check, then post-execution recording.

## proxyabl

`@gatewaystack/proxyabl-core` / `@gatewaystack/proxyabl`

**Execution Control & Identity-Aware Routing.** Five auth modes (API key, forward bearer, service OAuth, user OAuth, none) and a multi-provider registry.

**`proxyabl-core` — SSRF-safe fetch primitive.** `assertUrlSafe` / `executeProxyRequest` provide host-allowlisting, DNS-resolving private-IP blocking (IPv4 + IPv6, incl. IPv4-mapped IPv6), protocol enforcement, redirect blocking (`redirect: "manual"`), and timeout/response-size caps. Use these directly when you proxy **arbitrary, caller-influenced URLs** — that is the case SSRF protection is for.

**`proxyabl` — Express gateway router.** Forwards to an operator-**configured** backend (`functionsBase` / proxy target). The caller controls the tool name / path, not the host: the router sanitizes the tool name, enforces a path allowlist, and pins the resolved URL's host + protocol to the configured backend. It is a pass-through proxy and **does not currently route through `proxyabl-core`'s `assertUrlSafe` engine** — the two have different threat models (a configured backend may legitimately be an internal address, which the private-IP-blocking engine would reject). The Express middleware also serves PRM/OIDC metadata, enforces scope-to-tool mappings, and injects verified identity into downstream headers.

> Converging these — one canonical `proxyabl-core` engine consumed by both the OSS router and the production gateway (which forked an equivalent) — is tracked in the proxyabl convergence work. Until then, treat `assertUrlSafe` / `executeProxyRequest` as an available primitive, not something the bundled router runs for you.

## explicabl

`@gatewaystack/explicabl`

**Runtime Audit & Conformance.** One structured JSON event per request with HTTP metadata, identity context, and timing. Health endpoints, Auth0 webhook integration, pluggable logger.

## request-context

`@gatewaystack/request-context`

**Request-Scoped Context.** AsyncLocalStorage-based context propagation. Seeds `GatewayContext` per request; all layers read/write their fields without parameter threading.

## compat

`@gatewaystack/compat`

**Interop & Parity Harness.** Legacy/test router that mirrors the original `/echo` shape for regression testing.
