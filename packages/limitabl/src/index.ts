// packages/limitabl/src/index.ts
//
// Express middleware for the limitabl governance layer.
// Two-phase model: pre-flight middleware + post-execution recorder.

import type { RequestHandler } from "express";
import type { Request } from "express";
import {
  LimitablEngine,
  type LimitablCoreConfig,
  type LimitKey,
  type UsageRecord,
} from "@gatewaystack/limitabl-core";

export type { LimitablCoreConfig, LimitKey, UsageRecord };

export interface LimitablConfig extends LimitablCoreConfig {
  /**
   * Extract the workflow ID from the request (for agent guard).
   * Default: reads from req.header("x-workflow-id").
   */
  extractWorkflowId?: (req: any) => string | undefined;
}

// Singleton engine per config (middleware is typically created once at startup)
let _engine: LimitablEngine | null = null;

function getEngine(config: LimitablCoreConfig): LimitablEngine {
  if (!_engine) {
    _engine = new LimitablEngine(config);
  }
  return _engine;
}

function keyFromReq(req: Request): LimitKey {
  const user = (req as any).user;

  // IMPORTANT: rely on Express's `req.ip`, which is safe ONLY when the
  // application has configured `app.set('trust proxy', N)` correctly for
  // its deployment (N = number of trusted proxies in front of the server).
  //
  // We deliberately do NOT read `X-Forwarded-For` directly: any client can
  // forge that header, and taking the leftmost entry — as earlier versions
  // of this middleware did — lets an attacker rotate the rate-limit key
  // per request (bypass), forge a victim's IP (targeted DoS), or inflate
  // the in-memory key map (memory growth).
  //
  // Operators behind a load balancer must set `trust proxy`; direct-exposed
  // servers should leave it at its default of false. See:
  //   https://expressjs.com/en/guide/behind-proxies.html
  const ip = (req.ip as string) ?? "unknown";

  return {
    sub: user?.sub,
    orgId: user?.org_id,
    ip,
    tenantId: (req as any).tenantId,
  };
}

/**
 * Phase 1: Pre-flight middleware.
 * Checks rate limits, budgets, and agent guard before the request proceeds.
 *
 * Attach to routes AFTER identifiabl (needs req.user).
 */
export function limitabl(config: LimitablConfig): RequestHandler {
  const engine = getEngine(config);

  return (req: any, res, next) => {
    const key = keyFromReq(req);
    const workflowId = config.extractWorkflowId
      ? config.extractWorkflowId(req)
      : req.header?.("x-workflow-id") ?? undefined;

    const result = engine.preflight(key, { workflowId });

    if (!result.allowed) {
      const status = result.rateLimit ? 429 : 403;
      const headers: Record<string, string> = {};
      if (result.rateLimit?.retryAfterSec) {
        headers["Retry-After"] = String(result.rateLimit.retryAfterSec);
      }
      res.set(headers);
      return res.status(status).json({
        error: "limit_exceeded",
        message: result.reason,
        rateLimit: result.rateLimit,
        budget: result.budget,
        agentGuard: result.agentGuard,
      });
    }

    // Attach rate limit headers
    if (result.rateLimit) {
      res.set("X-RateLimit-Remaining", String(result.rateLimit.remaining));
      res.set("X-RateLimit-Reset", String(result.rateLimit.resetAt));
    }

    // Attach engine + key for post-execution recording
    req._limitablEngine = engine;
    req._limitablKey = key;
    req._limitablWorkflowId = workflowId;

    return next();
  };
}

/**
 * Phase 2: Record usage after execution.
 * Call this in your tool handler or response middleware.
 */
export function recordUsage(req: any, usage: Omit<UsageRecord, "timestamp">): void {
  const engine: LimitablEngine | undefined = req._limitablEngine;
  const key: LimitKey | undefined = req._limitablKey;
  const workflowId: string | undefined = req._limitablWorkflowId;

  if (!engine || !key) return;

  engine.recordUsage({
    key,
    workflowId,
    usage: { ...usage, timestamp: Date.now() },
  });
}

// Re-export core for direct access
export {
  LimitablEngine,
  InMemoryRateLimiter,
  InMemoryBudgetTracker,
  AgentGuard,
} from "@gatewaystack/limitabl-core";
