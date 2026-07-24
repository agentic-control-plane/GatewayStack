// packages/limitabl-core/src/agentGuard.ts
//
// Prevents agentic runaway: tool call limits, workflow cost caps, duration caps.
//
// FUTURE WORK:
// - Recursion depth detection (detect A→B→A→B loops)
// - Duplicate tool call detection with configurable thresholds
// - Per-tool call limits (e.g., max 5 calls to expensive-tool per workflow)
// - Circuit breaker pattern (stop all tool calls after N consecutive failures)

import type { AgentGuardConfig, AgentGuardResult } from "./types.js";
import { sanitizeCost } from "./sanitize.js";

const DEFAULT_MAX_TOOL_CALLS = 50;
const DEFAULT_MAX_WORKFLOW_COST = 1000; // $10 in cents
const DEFAULT_MAX_DURATION_MS = 300_000; // 5 minutes

interface WorkflowState {
  startedAt: number;
  toolCallCount: number;
  totalCost: number;
}

export class AgentGuard {
  private workflows = new Map<string, WorkflowState>();
  private config: Required<AgentGuardConfig>;
  private lastSweepAt = Date.now();

  constructor(config: AgentGuardConfig = {}) {
    this.config = {
      maxToolCalls: config.maxToolCalls ?? DEFAULT_MAX_TOOL_CALLS,
      maxWorkflowCost: config.maxWorkflowCost ?? DEFAULT_MAX_WORKFLOW_COST,
      maxDurationMs: config.maxDurationMs ?? DEFAULT_MAX_DURATION_MS,
    };
  }

  /**
   * Evict workflow state older than maxDurationMs. Such workflows are already
   * denied by the duration check, so their state is pure dead weight — without
   * this, a client rotating workflow ids grows the Map without bound (a memory
   * DoS). Runs lazily (at most once per maxDurationMs) off the normal call
   * path, so there is no timer to leak or to keep the process alive.
   */
  private sweepExpired(now: number): void {
    if (now - this.lastSweepAt < this.config.maxDurationMs) return;
    this.lastSweepAt = now;
    for (const [id, state] of this.workflows) {
      if (now - state.startedAt > this.config.maxDurationMs) {
        this.workflows.delete(id);
      }
    }
  }

  /** Number of workflows currently tracked (exposed for tests/observability). */
  get size(): number {
    return this.workflows.size;
  }

  /**
   * Check if a tool call is allowed within the workflow constraints.
   * Call this BEFORE executing each tool call.
   */
  check(workflowId: string): AgentGuardResult {
    const state = this.getOrCreate(workflowId);
    const now = Date.now();
    const durationMs = now - state.startedAt;

    // Check duration
    if (durationMs > this.config.maxDurationMs) {
      return {
        allowed: false,
        reason: `Workflow exceeded max duration: ${durationMs}ms > ${this.config.maxDurationMs}ms`,
        toolCallCount: state.toolCallCount,
        workflowCost: state.totalCost,
        durationMs,
      };
    }

    // Check tool call count
    if (state.toolCallCount >= this.config.maxToolCalls) {
      return {
        allowed: false,
        reason: `Workflow exceeded max tool calls: ${state.toolCallCount} >= ${this.config.maxToolCalls}`,
        toolCallCount: state.toolCallCount,
        workflowCost: state.totalCost,
        durationMs,
      };
    }

    // Check cost
    if (state.totalCost >= this.config.maxWorkflowCost) {
      return {
        allowed: false,
        reason: `Workflow exceeded max cost: ${state.totalCost} >= ${this.config.maxWorkflowCost}`,
        toolCallCount: state.toolCallCount,
        workflowCost: state.totalCost,
        durationMs,
      };
    }

    return {
      allowed: true,
      reason: "Within workflow limits",
      toolCallCount: state.toolCallCount,
      workflowCost: state.totalCost,
      durationMs,
    };
  }

  /** Record a tool call after execution (updates counters). */
  recordToolCall(workflowId: string, cost: number = 0): void {
    const state = this.getOrCreate(workflowId);
    state.toolCallCount++;
    state.totalCost += sanitizeCost(cost, "agentGuard.recordToolCall");
  }

  /** End a workflow (clean up state). */
  endWorkflow(workflowId: string): void {
    this.workflows.delete(workflowId);
  }

  private getOrCreate(workflowId: string): WorkflowState {
    this.sweepExpired(Date.now());
    let state = this.workflows.get(workflowId);
    if (!state) {
      state = { startedAt: Date.now(), toolCallCount: 0, totalCost: 0 };
      this.workflows.set(workflowId, state);
    }
    return state;
  }
}
