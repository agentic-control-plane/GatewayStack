/**
 * GatewayStack — 30-second quickstart.
 *
 * Three real governance decisions, running entirely on your machine. No IdP, no
 * backend, no config. Run it:
 *
 *   npm install && npm start
 *
 * Everything here is pure library code from the `-core` packages — the same
 * logic the Express middleware wraps. If you can see these decisions happen,
 * you can drop them into your own gateway.
 */

import { applyPolicies, type PolicySet } from "@gatewaystack/validatabl-core";
import { transformContent } from "@gatewaystack/transformabl-core";
import { LimitablEngine } from "@gatewaystack/limitabl-core";

const ALLOW = "\x1b[32m✅ ALLOW\x1b[0m";
const DENY = "\x1b[31m🛑 DENY \x1b[0m";
const h = (s: string) => console.log(`\n\x1b[1m${s}\x1b[0m`);

// ─────────────────────────────────────────────────────────────────────────
// 1. Deny-by-default policy — a tool call is refused unless a rule allows it.
// ─────────────────────────────────────────────────────────────────────────
h("1 · Deny-by-default policy (validatabl)");

const policy: PolicySet = {
  defaultEffect: "deny", // nothing is allowed unless a rule says so
  rules: [
    {
      id: "allow-reads",
      effect: "allow",
      conditions: [{ field: "tool", operator: "in", value: ["read_file", "list_files"] }],
    },
  ],
};

for (const tool of ["read_file", "delete_database"]) {
  const d = applyPolicies(policy, { identity: { sub: "agent-1" }, tool });
  console.log(`  ${d.allowed ? ALLOW : DENY}  ${tool.padEnd(16)} → ${d.reason}`);
}

// ─────────────────────────────────────────────────────────────────────────
// 2. PII redaction — sensitive values are stripped before they leave.
// ─────────────────────────────────────────────────────────────────────────
h("2 · PII redaction (transformabl)");

const raw = "Email me at john@acme.com or call about SSN 123-45-6789.";
const result = transformContent(raw, { redaction: { mode: "placeholder" } });

console.log(`  in : ${raw}`);
console.log(`  out: ${result.content}`);
console.log(`  detected: ${result.piiMatches.map((m) => m.type).join(", ") || "none"}`);

// ─────────────────────────────────────────────────────────────────────────
// 3. Rate limit — the 4th call in the window is refused.
// ─────────────────────────────────────────────────────────────────────────
h("3 · Rate limit + budget guard (limitabl)");

const engine = new LimitablEngine({ rateLimit: { windowMs: 60_000, maxRequests: 3 } });
const key = { sub: "agent-1" };

for (let i = 1; i <= 5; i++) {
  const r = engine.preflight(key);
  console.log(`  call ${i}: ${r.allowed ? ALLOW : DENY}  ${r.allowed ? "" : "→ " + r.reason}`);
}

h("Next → wire these as Express middleware: see ../../README.md#full-stack-example");
console.log();
