// packages/validatabl/src/middleware.ts
//
// Full validatabl middleware: runs the unified decision() function
// against every request. Configurable per-route or globally.

import type { RequestHandler } from "express";
import { decision, type DecisionOptions, type PolicyRequest } from "@gatewaystack/validatabl-core";

export interface ValidatablMiddlewareConfig extends DecisionOptions {
  /**
   * Extract the tool name from the request.
   * Default: reads from req.body?.name or req.params?.tool.
   */
  extractTool?: (req: any) => string | undefined;
  /**
   * Extract the model name from the request.
   * Default: reads from req.body?.model.
   */
  extractModel?: (req: any) => string | undefined;
  /**
   * Extract the input payload for schema validation.
   * Default: reads from req.body?.arguments or req.body.
   */
  extractInput?: (req: any) => unknown;
}

/**
 * Express middleware that runs the full validatabl decision engine.
 *
 * Reads identity from req.user (populated by identifiabl).
 * Returns 403 with decision details on denial.
 *
 * SECURITY: refuses to start if no checks are configured. The underlying
 * `decision()` primitive returns `allow` when given empty options (it is
 * a neutral building block), but mounting *this middleware* with no
 * checks would silently allow all requests — the opposite of the
 * "deny-by-default" guarantee this package advertises. Configure at
 * least one of `requiredPermissions`, `policies`, or `inputSchema`.
 */
export function validatabl(config: ValidatablMiddlewareConfig): RequestHandler {
  const hasPerms =
    Array.isArray(config.requiredPermissions) &&
    config.requiredPermissions.length > 0;
  const hasPolicies =
    !!config.policies?.rules && config.policies.rules.length > 0;
  const hasSchema = config.inputSchema !== undefined;

  if (!hasPerms && !hasPolicies && !hasSchema) {
    throw new Error(
      "[validatabl] refusing to mount with no checks configured. " +
        "Provide at least one of: requiredPermissions (non-empty), " +
        "policies (with rules), or inputSchema. Mounting empty would " +
        "allow every request through."
    );
  }

  return (req: any, res, next) => {
    const identity = {
      sub: req.user?.sub,
      scope: req.user?.scope,
      scopes: req.user?.scopes,
      permissions: req.user?.permissions,
      roles: req.user?.roles,
      org_id: req.user?.org_id,
    };

    const tool = config.extractTool
      ? config.extractTool(req)
      : req.body?.name ?? req.params?.tool;

    const model = config.extractModel
      ? config.extractModel(req)
      : req.body?.model;

    const input = config.extractInput
      ? config.extractInput(req)
      : req.body?.arguments ?? req.body;

    const request: PolicyRequest = { identity, tool, model, input };

    const result = decision(request, config);

    if (!result.allowed) {
      return res.status(403).json({
        error: "policy_denied",
        message: result.reason,
        checks: result.checks,
      });
    }

    // Attach decision to request for downstream use (e.g., logging)
    req.validatablDecision = result;
    return next();
  };
}
