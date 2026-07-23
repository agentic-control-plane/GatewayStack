// packages/validatabl-core/src/policy.ts
//
// applyPolicies: evaluate a policy set against a request.
// Deny-by-default. Rules evaluated in priority order (lowest number first).

import type {
  PolicyRule,
  PolicyCondition,
  PolicyDecision,
  PolicySet,
  PolicyRequest,
} from "./types.js";
import { getScopeStringFromClaims } from "./scopes.js";

/**
 * Evaluate a policy set against a request.
 *
 * Rules are sorted by priority (ascending). The first matching rule wins.
 * If no rule matches, the default effect is applied (deny by default).
 *
 * FUTURE WORK:
 * - YAML policy file loading (currently JSON only)
 * - Compiled evaluation trees for high-throughput scenarios
 * - Caching of decisions per (user, model, tool, scope) tuple with configurable TTL
 * - Modification actions (strip fields, downgrade model, reduce token limits)
 *   beyond simple allow/deny
 */
/**
 * Reject structurally-unsafe rules. A rule with no conditions matches EVERY
 * request (`[].every()` is vacuously true) — an `allow` rule with empty
 * conditions is a blanket allow-all that silently defeats deny-by-default.
 * Throws on the first offending rule so a misconfigured policy set fails loudly
 * at load rather than quietly widening. Call this once when policies are
 * loaded; applyPolicies also calls it defensively.
 */
export function validatePolicySet(policySet: PolicySet): void {
  for (const rule of policySet.rules) {
    if (!Array.isArray(rule.conditions) || rule.conditions.length === 0) {
      throw new Error(
        `Invalid policy rule "${rule.id ?? "<no id>"}": a rule must have at ` +
          `least one condition (an empty condition list matches every request). ` +
          `Use an explicit catch-all condition or set defaultEffect instead.`
      );
    }
  }
}

export function applyPolicies(
  policySet: PolicySet,
  request: PolicyRequest
): PolicyDecision {
  validatePolicySet(policySet);

  const sorted = [...policySet.rules].sort(
    (a, b) => (a.priority ?? 100) - (b.priority ?? 100)
  );

  for (const rule of sorted) {
    if (matchesAllConditions(rule.conditions, request)) {
      return {
        allowed: rule.effect === "allow",
        matchedRule: rule,
        reason: rule.reason ?? `Matched rule: ${rule.id} (${rule.effect})`,
        evaluatedCount: sorted.indexOf(rule) + 1,
      };
    }
  }

  const defaultEffect = policySet.defaultEffect ?? "deny";
  return {
    allowed: defaultEffect === "allow",
    matchedRule: undefined,
    reason: `No rules matched; default: ${defaultEffect}`,
    evaluatedCount: sorted.length,
  };
}

function matchesAllConditions(
  conditions: PolicyCondition[],
  request: PolicyRequest
): boolean {
  return conditions.every((c) => matchesCondition(c, request));
}

function matchesCondition(
  condition: PolicyCondition,
  request: PolicyRequest
): boolean {
  const fieldValue = resolveField(condition.field, request);

  switch (condition.operator) {
    case "equals":
      return fieldValue === condition.value;

    case "contains": {
      // fieldValue is a space-delimited string or array; check if it contains the target
      if (typeof fieldValue === "string") {
        return fieldValue.split(" ").includes(String(condition.value));
      }
      if (Array.isArray(fieldValue)) {
        return fieldValue.includes(condition.value);
      }
      return false;
    }

    case "in": {
      // value is an array; check if fieldValue is one of its members.
      // Strict: no String() coercion. Coercing let an array field stringify to
      // "a,b" and an object to "[object Object]", so unrelated values slipped
      // past an `in` allow-list. Only a string field can be a member; anything
      // else does not match.
      if (!Array.isArray(condition.value)) return false;
      if (typeof fieldValue !== "string") return false;
      return condition.value.includes(fieldValue);
    }

    case "matches": {
      // value is a regex pattern. Anchor by default: a bare pattern like
      // "search" used to substring-match, so it silently allowed
      // "unsafe-search-exec" — an unanchored match widens every policy. A bare
      // pattern is now wrapped in ^(?:…)$ (exact whole-string match). An author
      // who wrote their own anchor ("^gpt-4" for a prefix/family match) has
      // expressed intent, so we honor it verbatim rather than double-anchor.
      if (typeof fieldValue !== "string" || typeof condition.value !== "string") {
        return false;
      }
      const raw = condition.value;
      const authored = raw.startsWith("^") || raw.endsWith("$");
      const source = authored ? raw : `^(?:${raw})$`;
      try {
        return new RegExp(source).test(fieldValue);
      } catch {
        return false;
      }
    }

    case "exists":
      return condition.value
        ? fieldValue !== undefined && fieldValue !== null
        : fieldValue === undefined || fieldValue === null;

    default:
      return false;
  }
}

/**
 * Resolve a field name to a value from the request context.
 * Supports dotted paths like "identity.org_id".
 */
function resolveField(field: string, request: PolicyRequest): unknown {
  // Shorthand fields
  switch (field) {
    case "scope":
      return getScopeStringFromClaims(request.identity);
    case "permission":
    case "permissions":
      return request.identity.permissions ?? [];
    case "role":
    case "roles":
      return request.identity.roles ?? [];
    case "org_id":
      return request.identity.org_id;
    case "sub":
      return request.identity.sub;
    case "tool":
      return request.tool;
    case "model":
      return request.model;
  }

  // Dotted path traversal
  const parts = field.split(".");
  let current: unknown = request;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    if (typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}
