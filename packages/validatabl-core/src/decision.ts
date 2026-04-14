// packages/validatabl-core/src/decision.ts
//
// decision: the unified entry point that orchestrates all validation checks.

import type {
  PolicySet,
  PolicyRequest,
  PolicyDecision,
  PermissionCheckResult,
  SchemaValidationResult,
} from "./types.js";
import { checkPermissions } from "./permissions.js";
import { applyPolicies } from "./policy.js";
import { checkSchema, type SimpleSchema } from "./schema.js";

/** Full validation result combining all checks. */
export interface ValidationDecision {
  /** Whether the request should proceed. */
  allowed: boolean;
  /** Summary reason for the decision. */
  reason: string;
  /** Individual check results. */
  checks: {
    permissions?: PermissionCheckResult;
    policy?: PolicyDecision;
    schema?: SchemaValidationResult;
  };
}

/** Options for the decision function. */
export interface DecisionOptions {
  /** Required permissions (all must be present). */
  requiredPermissions?: string[];
  /** Policy set to evaluate. */
  policies?: PolicySet;
  /** Schema to validate the input against. */
  inputSchema?: SimpleSchema;
}

/**
 * Unified entry point for validatabl.
 *
 * Runs all configured checks in order:
 * 1. Permission check (are the required scopes/permissions present?)
 * 2. Policy evaluation (does a policy rule allow or deny this request?)
 * 3. Schema validation (does the input match the expected shape?)
 *
 * Returns denied on the first failure. All checks are optional —
 * if no checks are configured, the request is allowed.
 *
 * SECURITY: this primitive is intentionally neutral — empty options
 * returns `allowed: true` so it composes cleanly with callers that
 * apply their own defaults. That means `decision(req, {})` is NOT
 * deny-by-default. Wrapping layers that expose this to user-facing
 * enforcement (e.g. the `validatabl()` Express middleware) must
 * reject empty configs themselves; that middleware does so at mount
 * time. Integrators calling this function directly are responsible
 * for the same check.
 *
 * FUTURE WORK:
 * - checkSafety integration (depends on transformabl classification output)
 *   When transformabl adds safety labels to the request context, validatabl
 *   will be able to enforce policies based on content risk level.
 */
export function decision(
  request: PolicyRequest,
  options: DecisionOptions
): ValidationDecision {
  const checks: ValidationDecision["checks"] = {};

  // 1. Permission check
  if (options.requiredPermissions && options.requiredPermissions.length > 0) {
    const permResult = checkPermissions(
      request.identity,
      options.requiredPermissions
    );
    checks.permissions = permResult;
    if (!permResult.allowed) {
      return {
        allowed: false,
        reason: permResult.reason,
        checks,
      };
    }
  }

  // 2. Policy evaluation
  if (options.policies) {
    const policyResult = applyPolicies(options.policies, request);
    checks.policy = policyResult;
    if (!policyResult.allowed) {
      return {
        allowed: false,
        reason: policyResult.reason,
        checks,
      };
    }
  }

  // 3. Schema validation
  if (options.inputSchema && request.input !== undefined) {
    const schemaResult = checkSchema(request.input, options.inputSchema);
    checks.schema = schemaResult;
    if (!schemaResult.valid) {
      return {
        allowed: false,
        reason: `Schema validation failed: ${schemaResult.errors.join("; ")}`,
        checks,
      };
    }
  }

  return {
    allowed: true,
    reason: "All checks passed",
    checks,
  };
}
