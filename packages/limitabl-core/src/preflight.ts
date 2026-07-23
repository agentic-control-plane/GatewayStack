// packages/limitabl-core/src/preflight.ts
//
// Combined pre-flight check: runs rate limit + budget + agent guard
// and returns a single decision.

import type {
  LimitKey,
  RateLimitConfig,
  BudgetConfig,
  AgentGuardConfig,
  PreflightResult,
  UsageRecord,
  PostExecutionInput,
} from "./types.js";
import { InMemoryRateLimiter } from "./rateLimiter.js";
import { InMemoryBudgetTracker } from "./budgetTracker.js";
import { AgentGuard } from "./agentGuard.js";

export interface LimitablCoreConfig {
  rateLimit?: RateLimitConfig;
  budget?: BudgetConfig;
  agentGuard?: AgentGuardConfig;
}

/**
 * Orchestrates all limitabl checks.
 *
 * Phase 1 (pre-flight): call preflight() before executing a request.
 * Phase 2 (post-execution): call recordUsage() after execution completes.
 */
export class LimitablEngine {
  private rateLimiter?: InMemoryRateLimiter;
  private budgetTracker?: InMemoryBudgetTracker;
  private agentGuard?: AgentGuard;

  constructor(config: LimitablCoreConfig) {
    if (config.rateLimit) {
      this.rateLimiter = new InMemoryRateLimiter(config.rateLimit);
    }
    if (config.budget) {
      this.budgetTracker = new InMemoryBudgetTracker(config.budget);
    }
    if (config.agentGuard) {
      this.agentGuard = new AgentGuard(config.agentGuard);
    }
  }

  /**
   * Phase 1: Pre-flight check.
   * Returns whether the request should proceed.
   */
  preflight(key: LimitKey, opts?: { workflowId?: string; estimatedCost?: number }): PreflightResult {
    // Rate limit check
    if (this.rateLimiter) {
      const rl = this.rateLimiter.check(key);
      if (!rl.allowed) {
        return {
          allowed: false,
          reason: `Rate limited. Retry after ${rl.retryAfterSec}s`,
          rateLimit: rl,
        };
      }
    }

    // Budget check
    if (this.budgetTracker) {
      const budget = this.budgetTracker.check(key, opts?.estimatedCost);
      if (!budget.allowed) {
        return {
          allowed: false,
          reason: budget.reason,
          budget,
        };
      }
    }

    // Agent guard check.
    //
    // If the operator configured an agent guard, it must run. The old code
    // only ran it when a workflowId was supplied, so a client could opt out of
    // runaway protection entirely by simply omitting the id — deny instead when
    // the guard is configured but no key resolves.
    if (this.agentGuard) {
      if (!opts?.workflowId) {
        return {
          allowed: false,
          reason:
            "Agent guard is enabled but no workflow key resolved for this " +
            "request; refusing rather than running unguarded.",
        };
      }
      const guard = this.agentGuard.check(opts.workflowId);
      if (!guard.allowed) {
        return {
          allowed: false,
          reason: guard.reason,
          agentGuard: guard,
        };
      }
    }

    return { allowed: true, reason: "All checks passed" };
  }

  /**
   * Phase 2: Record usage after execution.
   * Updates budget tracker and agent guard counters.
   */
  recordUsage(input: PostExecutionInput): void {
    if (this.budgetTracker) {
      this.budgetTracker.record(input.key, input.usage);
    }
    if (this.agentGuard && input.workflowId) {
      this.agentGuard.recordToolCall(input.workflowId, input.usage.cost);
    }
  }

  /** Clean up (stop timers). */
  destroy(): void {
    this.rateLimiter?.destroy();
    this.budgetTracker?.destroy();
  }
}
