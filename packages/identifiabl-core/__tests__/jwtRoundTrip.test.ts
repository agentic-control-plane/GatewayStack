// Enforcement-core hardening (#41) — identifiabl-core JWT verification.
//
// Real-crypto round-trips against a live local JWKS: a validly-signed token
// passes; alg:none, expired, missing-exp, and wrong-audience tokens are all
// rejected. Also asserts the factory refuses an empty issuer/audience.

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "http";
import type { AddressInfo } from "net";
import { generateKeyPair, exportJWK, SignJWT, type KeyLike } from "jose";
import { createIdentifiablVerifier } from "../src/index.js";

const ISSUER = "https://test.auth0.com/";
const AUDIENCE = "https://api.test.com";
const KID = "test-key-1";

let server: http.Server;
let jwksUri: string;
let privateKey: KeyLike;

function b64url(o: unknown): string {
  return Buffer.from(JSON.stringify(o)).toString("base64url");
}

beforeAll(async () => {
  const { publicKey, privateKey: priv } = await generateKeyPair("RS256");
  privateKey = priv;
  const jwk = await exportJWK(publicKey);
  jwk.kid = KID;
  jwk.alg = "RS256";
  jwk.use = "sig";
  const body = JSON.stringify({ keys: [jwk] });

  server = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(body);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  jwksUri = `http://127.0.0.1:${port}/jwks.json`;
});

afterAll(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

const verifier = () => createIdentifiablVerifier({ issuer: ISSUER, audience: AUDIENCE, jwksUri });

async function sign(claims: Record<string, unknown>, opts?: { exp?: string | number | null }): Promise<string> {
  let jwt = new SignJWT({ ...claims })
    .setProtectedHeader({ alg: "RS256", kid: KID })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setSubject("auth0|user")
    .setIssuedAt();
  if (opts?.exp !== null) jwt = jwt.setExpirationTime(opts?.exp ?? "1h");
  return jwt.sign(privateKey);
}

describe("createIdentifiablVerifier: accepts a valid token", () => {
  it("verifies a correctly-signed, unexpired token", async () => {
    const token = await sign({});
    const r = await verifier()(token);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.identity.sub).toBe("auth0|user");
  });
});

describe("createIdentifiablVerifier: rejects bad tokens", () => {
  it("rejects an unsigned alg:none token", async () => {
    const forged = `${b64url({ alg: "none", typ: "JWT" })}.${b64url({
      sub: "auth0|user",
      iss: ISSUER,
      aud: AUDIENCE,
      exp: Math.floor(Date.now() / 1000) + 3600,
    })}.`;
    const r = await verifier()(forged);
    expect(r.ok).toBe(false);
  });

  it("rejects an expired token", async () => {
    const token = await sign({}, { exp: Math.floor(Date.now() / 1000) - 3600 });
    const r = await verifier()(token);
    expect(r.ok).toBe(false);
  });

  it("rejects a token with no exp claim (would otherwise never expire)", async () => {
    const token = await sign({}, { exp: null });
    const r = await verifier()(token);
    expect(r.ok).toBe(false);
  });

  it("rejects a token minted for a different audience", async () => {
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", kid: KID })
      .setIssuer(ISSUER)
      .setAudience("https://some-other-api.example.com")
      .setSubject("auth0|user")
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(privateKey);
    const r = await verifier()(token);
    expect(r.ok).toBe(false);
  });
});

describe("createIdentifiablVerifier: rejects a misconfigured factory", () => {
  it("throws on an empty issuer", () => {
    expect(() => createIdentifiablVerifier({ issuer: "", audience: AUDIENCE, jwksUri })).toThrow(/issuer/i);
  });

  it("throws on an empty audience", () => {
    expect(() => createIdentifiablVerifier({ issuer: ISSUER, audience: "", jwksUri })).toThrow(/audience/i);
  });
});
