// packages/limitabl-core/src/budgetTracker.ts
//
// Per-user and per-org budget tracking with spend caps.
// In-memory implementation.
//
// FUTURE WORK:
// - Persistent storage adapter (Firestore, Redis, DynamoDB)
// - Budget alerting (webhook when 80%, 90%, 100% thresholds hit)
// - Per-model budget tracking (e.g., limit GPT-4 spend separately)
// - Budget rollover (carry unused budget to next period)
// - Budget delegation (org admin allocates budget to users)

import type {
  LimitKey,
  BudgetConfig,
  BudgetCheckResult,
  UsageRecord,
} from "./types.js";
import { resolveKey } from "./rateLimiter.js";
import { sanitizeCost } from "./sanitize.js";

interface BudgetEntry {
  records: UsageRecord[];
}

export class InMemoryBudgetTracker {
  private budgets = new Map<string, BudgetEntry>();
  private config: BudgetConfig;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(config: BudgetConfig) {
    this.config = config;
    this.cleanupInterval = setInterval(
      () => this.cleanup(),
      config.periodMs / 10
    );
    if (this.cleanupInterval.unref) this.cleanupInterval.unref();
  }

  /** Check if a request is within budget (pre-flight). */
  check(key: LimitKey, estimatedCost?: number): BudgetCheckResult {
    const k = resolveKey(key);
    const currentSpend = this.getCurrentSpend(k);
    const sanitizedEstimate = sanitizeCost(estimatedCost, "budgetTracker.check");
    const effectiveSpend = currentSpend + sanitizedEstimate;

    if (effectiveSpend > this.config.maxSpend) {
      return {
        allowed: false,
        currentSpend,
        maxSpend: this.config.maxSpend,
        percentUsed: Math.round((currentSpend / this.config.maxSpend) * 100),
        reason: `Budget exceeded: ${currentSpend} / ${this.config.maxSpend} (estimated +${estimatedCost ?? 0})`,
      };
    }

    return {
      allowed: true,
      currentSpend,
      maxSpend: this.config.maxSpend,
      percentUsed: Math.round((currentSpend / this.config.maxSpend) * 100),
      reason: "Within budget",
    };
  }

  /** Record usage after execution (post-execution / Phase 2). */
  record(key: LimitKey, usage: UsageRecord): void {
    const k = resolveKey(key);
    let entry = this.budgets.get(k);
    if (!entry) {
      entry = { records: [] };
      this.budgets.set(k, entry);
    }
    const safeCost = sanitizeCost(usage.cost, "budgetTracker.record");
    entry.records.push(safeCost === usage.cost ? usage : { ...usage, cost: safeCost });
  }

  /** Get current spend in the budget period. */
  getCurrentSpend(keyStr: string): number {
    const entry = this.budgets.get(keyStr);
    if (!entry) return 0;

    const periodStart = Date.now() - this.config.periodMs;
    return entry.records
      .filter((r) => r.timestamp > periodStart)
      .reduce((sum, r) => sum + r.cost, 0);
  }

  /** Get usage summary for a key. */
  getUsageSummary(key: LimitKey): {
    totalSpend: number;
    totalTokens: number;
    requestCount: number;
  } {
    const k = resolveKey(key);
    const entry = this.budgets.get(k);
    if (!entry) return { totalSpend: 0, totalTokens: 0, requestCount: 0 };

    const periodStart = Date.now() - this.config.periodMs;
    const inPeriod = entry.records.filter((r) => r.timestamp > periodStart);

    return {
      totalSpend: inPeriod.reduce((s, r) => s + r.cost, 0),
      totalTokens: inPeriod.reduce((s, r) => s + (r.tokens ?? 0), 0),
      requestCount: inPeriod.length,
    };
  }

  private cleanup() {
    const cutoff = Date.now() - this.config.periodMs;
    for (const [key, entry] of this.budgets) {
      entry.records = entry.records.filter((r) => r.timestamp > cutoff);
      if (entry.records.length === 0) this.budgets.delete(key);
    }
  }

  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}
