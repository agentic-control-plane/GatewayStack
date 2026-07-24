// Enforcement-core hardening (#41) — explicabl.
//
// - audit events must carry identity from the GatewayContext (ALS), which the
//   old code never read (it looked at res.locals.gatewayContext, unset).
// - aborted requests (connection close, no `finish`) must still emit exactly
//   one audit event.
// - the /webhooks/auth0 mount must call the handler FACTORY (the old code
//   mounted the factory itself, so requests hung forever).

import { describe, it, expect, vi } from "vitest";
import { EventEmitter } from "node:events";
import express from "express";
import request from "supertest";
import { runWithGatewayContext } from "@gatewaystack/request-context";
import { explicablLoggingMiddleware, explicablRouter } from "../src/index.ts";
import type { ExplicablEvent } from "../src/index.ts";

// Minimal req/res doubles so we can drive `finish` / `close` directly.
function fakeReqRes() {
  const req: any = { method: "GET", path: "/x", headers: {} };
  const res: any = new EventEmitter();
  res.locals = {};
  res.statusCode = 200;
  return { req, res };
}

describe("explicablLoggingMiddleware: identity comes from the GatewayContext", () => {
  it("reads identity from the ALS context, not res.locals", async () => {
    const logger = vi.fn();
    const { req, res } = fakeReqRes();

    runWithGatewayContext({ identity: { sub: "auth0|abc", source: "auth0" } }, () => {
      explicablLoggingMiddleware(logger)(req, res, () => {});
    });
    res.emit("finish");

    expect(logger).toHaveBeenCalledTimes(1);
    const event = logger.mock.calls[0][0] as ExplicablEvent;
    expect((event.context as any)?.identity?.sub).toBe("auth0|abc");
  });
});

describe("explicablLoggingMiddleware: aborted requests still audit, exactly once", () => {
  it("emits one event on `close` when the request was aborted (no finish)", () => {
    const logger = vi.fn();
    const { req, res } = fakeReqRes();
    explicablLoggingMiddleware(logger)(req, res, () => {});

    res.emit("close"); // client aborted; `finish` never fired
    expect(logger).toHaveBeenCalledTimes(1);
  });

  it("emits exactly one event when both finish and close fire", () => {
    const logger = vi.fn();
    const { req, res } = fakeReqRes();
    explicablLoggingMiddleware(logger)(req, res, () => {});

    res.emit("finish");
    res.emit("close");
    expect(logger).toHaveBeenCalledTimes(1);
  });
});

describe("explicablRouter: /webhooks/auth0 is wired (does not hang)", () => {
  it("responds to the webhook route instead of mounting the factory", async () => {
    const app = express();
    app.use(express.json());
    app.use(explicablRouter(process.env));

    // Without LOG_WEBHOOK_SECRET the handler refuses (503/401) — the point is
    // that it RESPONDS at all. The old code mounted the factory as middleware,
    // so this request never got a response.
    const res = await request(app).post("/webhooks/auth0").send({}).timeout(3000);
    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.status).toBeLessThan(600);
  });
});
