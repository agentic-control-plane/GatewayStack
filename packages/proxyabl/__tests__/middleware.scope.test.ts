import { describe, it, expect } from "vitest";
import type { Request, Response } from "express";
import type { ProxyablConfig } from "@gatewaystack/proxyabl-core";
import { runWithGatewayContext } from "@gatewaystack/request-context";
import { createProxyablMiddleware } from "../src/middleware.js";

/**
 * Regression tests for the trailing-slash scope-bypass.
 *
 * The middleware derives the tool name from the request path and enforces the
 * scopes configured for that tool. A caller WITHOUT the required scope must be
 * rejected regardless of trailing/duplicate slashes in the path — previously a
 * trailing slash yielded an empty final segment and skipped the check.
 */

const config: ProxyablConfig = {
  toolScopes: { deploy: ["deploy:write"] },
} as ProxyablConfig;

function mockReqRes(path: string) {
  const req = { path, header: () => "Bearer x" } as unknown as Request;
  let statusCode = 0;
  let body: any = undefined;
  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(payload: any) {
      body = payload;
      return this;
    },
  } as unknown as Response;
  return { req, res, get: () => ({ statusCode, body }) };
}

/** Run the middleware inside a gateway context carrying the given scopes. */
async function invoke(path: string, scopes: string[]) {
  const mw = createProxyablMiddleware(config);
  const { req, res, get } = mockReqRes(path);
  let nextCalled = false;
  await runWithGatewayContext(
    { identity: { sub: "user-1", issuer: "https://idp.example", scopes } as any },
    async () => {
      await mw(req, res, () => {
        nextCalled = true;
      });
    },
  );
  return { nextCalled, ...get() };
}

describe("proxyabl middleware — tool scope enforcement", () => {
  it("allows a caller that holds the required scope", async () => {
    const r = await invoke("/proxy/deploy", ["deploy:write"]);
    expect(r.nextCalled).toBe(true);
  });

  it("rejects a caller lacking the required scope", async () => {
    const r = await invoke("/proxy/deploy", []);
    expect(r.nextCalled).toBe(false);
    expect(r.statusCode).toBe(403);
  });

  it("still enforces scopes when the path has a trailing slash", async () => {
    const r = await invoke("/proxy/deploy/", []);
    expect(r.nextCalled).toBe(false);
    expect(r.statusCode).toBe(403);
  });

  it("still enforces scopes when the path has duplicate slashes", async () => {
    const r = await invoke("/proxy//deploy//", []);
    expect(r.nextCalled).toBe(false);
    expect(r.statusCode).toBe(403);
  });
});
