// Enforcement-core hardening (#41) — validatabl-core.

import { describe, it, expect } from "vitest";
import { decision } from "../src/decision.js";
import { hasScope } from "../src/scopes.js";
import { applyPolicies, validatePolicySet } from "../src/policy.js";
import type { PolicySet } from "../src/types.js";

describe("decision: schema is enforced even when input is absent", () => {
  const opts = {
    inputSchema: {
      type: "object" as const,
      required: ["x"],
      properties: { x: { type: "string" as const } },
    },
  };

  it("DENIES when a schema is configured but input is undefined (was fail-open)", () => {
    const d = decision({ identity: {} }, opts);
    expect(d.allowed).toBe(false);
    expect(d.checks.schema?.valid).toBe(false);
  });

  it("still allows a valid input", () => {
    const d = decision({ identity: {}, input: { x: "ok" } }, opts);
    expect(d.allowed).toBe(true);
  });
});

describe("hasScope: exact token match, never a regex", () => {
  it('does not treat "." as "any char" (tool.write must not match toolXwrite)', () => {
    expect(hasScope({ scope: "toolXwrite" }, "tool.write")).toBe(false);
  });

  it("matches an exact scope token", () => {
    expect(hasScope({ scope: "read tool.write admin" }, "tool.write")).toBe(true);
  });

  it("does not throw on regex-metacharacter scope strings", () => {
    expect(() => hasScope({ scope: "read" }, "a(b")).not.toThrow();
    expect(hasScope({ scope: "read" }, "a(b")).toBe(false);
  });
});

describe("policy: empty-conditions rules are rejected (no accidental allow-all)", () => {
  const blanketAllow: PolicySet = {
    rules: [{ id: "oops", effect: "allow", conditions: [] }],
  };

  it("applyPolicies throws rather than matching every request", () => {
    expect(() => applyPolicies(blanketAllow, { identity: {}, tool: "anything" })).toThrow(
      /at least one condition/
    );
  });

  it("validatePolicySet throws at load time", () => {
    expect(() => validatePolicySet(blanketAllow)).toThrow(/oops/);
  });
});

describe("policy: matches is anchored by default", () => {
  const set = (value: string): PolicySet => ({
    rules: [{ id: "r", effect: "allow", conditions: [{ field: "tool", operator: "matches", value }] }],
    defaultEffect: "deny",
  });

  it('a bare pattern no longer substring-matches ("search" must not allow "unsafe-search-exec")', () => {
    const r = applyPolicies(set("search"), { identity: {}, tool: "unsafe-search-exec" });
    expect(r.allowed).toBe(false);
  });

  it("a bare pattern still matches the exact value", () => {
    const r = applyPolicies(set("search"), { identity: {}, tool: "search" });
    expect(r.allowed).toBe(true);
  });

  it("an author-anchored prefix pattern is honored (^gpt-4 matches gpt-4-turbo)", () => {
    expect(applyPolicies(set("^gpt-4"), { identity: {}, model: "x", tool: "gpt-4-turbo" }).allowed).toBe(true);
    expect(applyPolicies(set("^gpt-4"), { identity: {}, tool: "claude-3" }).allowed).toBe(false);
  });
});

describe("policy: in does not coerce non-string fields", () => {
  const set: PolicySet = {
    rules: [{ id: "r", effect: "allow", conditions: [{ field: "sub", operator: "in", value: ["a", "b"] }] }],
    defaultEffect: "deny",
  };

  it("matches a string field that is a member", () => {
    expect(applyPolicies(set, { identity: { sub: "a" } }).allowed).toBe(true);
  });

  it("does not match a non-member", () => {
    expect(applyPolicies(set, { identity: { sub: "c" } }).allowed).toBe(false);
  });

  it("an array field cannot stringify past the allow-list", () => {
    const arraySet: PolicySet = {
      rules: [{ id: "r", effect: "allow", conditions: [{ field: "roles", operator: "in", value: ["admin,user"] }] }],
      defaultEffect: "deny",
    };
    // identity.roles = ["admin","user"] would String()-coerce to "admin,user"
    // under the old code and wrongly match. Strict typing rejects it.
    expect(applyPolicies(arraySet, { identity: { roles: ["admin", "user"] } }).allowed).toBe(false);
  });
});
