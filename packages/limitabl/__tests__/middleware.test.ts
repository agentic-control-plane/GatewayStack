// Enforcement-core hardening (#41) — limitabl facade.
//
// The module-level singleton engine meant a second limitabl() mount silently
// reused the first mount's engine and config. These assert each mount now owns
// its own engine and enforces its own limits.

import { describe, it, expect } from "vitest";
import express from "express";
import request from "supertest";
import { limitabl } from "../src/index.js";

function appWith(maxRequests: number) {
  const app = express();
  app.use(limitabl({ rateLimit: { windowMs: 60_000, maxRequests } }));
  app.get("/", (_req, res) => res.json({ ok: true }));
  return app;
}

async function countAllowedBeforeLimit(app: express.Express, attempts: number): Promise<number> {
  let allowed = 0;
  for (let i = 0; i < attempts; i++) {
    const res = await request(app).get("/");
    if (res.status === 200) allowed++;
    else break;
  }
  return allowed;
}

describe("limitabl: two mounts enforce their own limits (no shared singleton)", () => {
  it("a strict mount limits sooner than a lax mount created afterward", async () => {
    const strict = appWith(2);
    const lax = appWith(5); // created AFTER strict — must NOT reuse strict's engine/config

    expect(await countAllowedBeforeLimit(strict, 10)).toBe(2);
    expect(await countAllowedBeforeLimit(lax, 10)).toBe(5);
  });

  it("returns 429 with a Retry-After header once the limit is hit", async () => {
    const app = appWith(1);
    expect((await request(app).get("/")).status).toBe(200);
    const limited = await request(app).get("/");
    expect(limited.status).toBe(429);
    expect(limited.headers["retry-after"]).toBeDefined();
  });
});
