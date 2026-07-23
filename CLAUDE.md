# gatewaystack

Open-source monorepo for GatewayStack's npm packages. User-scoped AI governance primitives.

## packages

| Package | Type | Description |
|---------|------|-------------|
| request-context | core | AsyncLocalStorage-based request context propagation |
| identifiabl-core | core | RS256 JWT verification and identity mapping |
| identifiabl | middleware | Express middleware for OIDC identity |
| validatabl-core | core | Deny-by-default policy engine, scope/role checking |
| validatabl | middleware | Express middleware for policy enforcement |
| limitabl-core | core | Rate limits, budget tracking, agent guard |
| limitabl | middleware | Express middleware for rate limiting |
| transformabl-core | core | PII detection, redaction, content classification |
| transformabl | middleware | Express middleware for content transformation |
| proxyabl-core | core | Auth modes, SSRF protection, HTTP proxy, provider registry |
| proxyabl | middleware | Express middleware for identity-aware routing |
| explicabl | middleware | HTTP audit logging, Auth0 webhook, health endpoints |

**Pattern:** `*-core` packages are framework-agnostic (pure functions, no Express). Middleware packages wrap core logic for Express.

## build

```bash
# single package
cd packages/<name> && npm run build

# all packages (dependency order)
# Tier 0 (no @gatewaystack deps): request-context, identifiabl-core, validatabl-core, limitabl-core, transformabl-core, proxyabl-core
# Tier 1 (depends on Tier 0): identifiabl, explicabl, validatabl, limitabl, transformabl, proxyabl
```

## publish

```bash
npm login
# then publish in dependency order with --access public --otp=<code>
```

## conventions

- ES modules throughout (`.js` extensions in imports, even for `.ts` files)
- TypeScript strict mode
- MIT license on all packages
- `@gatewaystack/` npm scope

---

## git workflow

### branches
- `main` — stable, publishable code. Only merge via PR or after local verification.
- `dev/<feature>` — feature branches for multi-step work (e.g. `dev/proxyabl-proxy-features`)
- `fix/<description>` — bugfix branches (e.g. `fix/transformabl-regex`)
- `release/<version>` — pre-publish prep if needed

### commit practices
- **Commit early and often** — small, logical commits, not giant batches
- **Commit after each meaningful unit of work**: one new file, one bug fix, one config change
- **Never bundle unrelated changes** in a single commit
- **Write descriptive commit messages** — explain the "why", not just the "what"
- **No Co-Authored-By: Claude** — never include Claude attribution in commits
- **No --amend** on pushed commits

### typical workflow
```
git checkout -b dev/<feature>
# work, commit incrementally
git push -u origin dev/<feature>
# when ready: merge to main (or PR)
```

---

## testing

### philosophy
- Every `-core` package should have unit tests for its public API
- Middleware packages should have integration tests with supertest
- Test before publish, always

### structure
Each package should have:
```
packages/<name>/
  src/           # source
  tests/         # test files
  package.json   # test script: "test": "vitest run"
```

### what to test
- **Core packages**: pure function input/output, error cases, edge cases
- **Middleware**: request/response behavior, error handling, header injection
- **Before publishing**: `npm run build && npm test` must pass

### test stack
- vitest (preferred) or jest
- supertest for Express middleware integration tests

### current status
Every `-core` package and the middleware wrappers have vitest suites under
`packages/<name>/__tests__/` (note: `__tests__/`, not `tests/`). `npm test` at
the repo root runs the whole suite; `npm run build` must pass first (the tests
import built workspace packages). Security-critical coverage is real:
proxyabl-core SSRF, transformabl-core PII regex + redaction, validatabl-core
policy enforcement, identifiabl-core JWT verification, limitabl-core
rate/budget/agent-guard.
