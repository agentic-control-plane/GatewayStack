// Enforcement-core hardening (#41) — limitabl-core agent guard.

import { describe, it, expect, vi, afterEach } from "vitest";
import { LimitablEngine } from "../src/preflight.js";
import { AgentGuard } from "../src/agentGuard.js";

afterEach(() => vi.useRealTimers());

describe("LimitablEngine: a configured agent guard cannot be opted out of", () => {
  it("DENIES when the guard is configured but no workflow key resolves", () => {
    const engine = new LimitablEngine({ agentGuard: { maxToolCalls: 5 } });
    const r = engine.preflight({ sub: "u" }); // no workflowId
    expect(r.allowed).toBe(false);
    expect(r.reason).toMatch(/no workflow key/i);
  });

  it("runs the guard normally when a workflow key is present", () => {
    const engine = new LimitablEngine({ agentGuard: { maxToolCalls: 5 } });
    const r = engine.preflight({ sub: "u" }, { workflowId: "wf-1" });
    expect(r.allowed).toBe(true);
  });

  it("does not deny for a missing workflow key when no guard is configured", () => {
    const engine = new LimitablEngine({ rateLimit: { windowMs: 1000, maxRequests: 100 } });
    const r = engine.preflight({ sub: "u" });
    expect(r.allowed).toBe(true);
  });
});

describe("AgentGuard: workflow state is bounded (TTL sweep)", () => {
  it("evicts workflows older than maxDurationMs so the map does not grow unbounded", () => {
    vi.useFakeTimers();
    const guard = new AgentGuard({ maxDurationMs: 1000 });

    // Seed 5 distinct workflows (simulating id rotation).
    for (let i = 0; i < 5; i++) guard.recordToolCall(`wf-${i}`);
    expect(guard.size).toBe(5);

    // Advance past the TTL, then touch the guard again — the sweep runs and
    // the expired rotated ids are evicted (only the fresh one remains).
    vi.advanceTimersByTime(1500);
    guard.recordToolCall("wf-fresh");
    expect(guard.size).toBe(1);
  });
});
