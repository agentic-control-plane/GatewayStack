import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
} from "jose";

// import type {
//   GatewayIdentity,
//   IdentitySource,
// } from "@gatewaystack/request-context";

// remove this:
// import type { GatewayIdentity, IdentitySource } from "@gatewaystack/request-context";

export type IdentitySource =
  | "auth0"
  | "stytch"
  | "cognito"
  | "custom"
  | string;

export interface GatewayIdentity {
  sub: string;
  issuer: string;
  tenantId?: string;
  email?: string;
  name?: string;
  roles?: string[];
  scopes?: string[];
  plan?: string;
  source: IdentitySource;
  raw: Record<string, unknown>;
}

export interface IdentifiablCoreConfig {
  issuer: string;
  audience: string | string[];
  jwksUri?: string;
  source?: IdentitySource;
  tenantClaim?: string;
  roleClaim?: string;
  scopeClaim?: string;
  planClaim?: string;
}

export interface VerifySuccess {
  ok: true;
  identity: GatewayIdentity;
  payload: JWTPayload;
}

export interface VerifyFailure {
  ok: false;
  error: string;
  detail?: string;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

// /**
//  * Escape a string for safe use inside a RegExp literal.
//  */
// function escapeForRegex(input: string): string {
//   return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
// }

// /**
//  * Build a pattern that matches the issuer with or without a trailing slash.
//  */
// function buildIssuerPattern(issuer: string): RegExp {
//   const issuerNoSlash = issuer.replace(/\/+$/, "");
//   return new RegExp(`^${escapeForRegex(issuerNoSlash)}\\/?$`);
// }



function mapPayloadToGatewayIdentity(
  payload: JWTPayload,
  config: IdentifiablCoreConfig,
  normalizedIssuer: string
): GatewayIdentity {
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  if (!sub) {
    throw new Error('missing "sub" claim in token');
  }

  const email =
    typeof payload.email === "string" ? (payload.email as string) : undefined;
  const name =
    typeof payload.name === "string" ? (payload.name as string) : undefined;

  let tenantId: string | undefined;
  if (config.tenantClaim) {
    const rawTenant = payload[config.tenantClaim];
    if (typeof rawTenant === "string") {
      tenantId = rawTenant;
    }
  }

  let roles: string[] | undefined;
  if (config.roleClaim) {
    const rawRoles = payload[config.roleClaim];
    if (Array.isArray(rawRoles)) {
      roles = rawRoles.filter((r): r is string => typeof r === "string");
    }
  }

  let scopes: string[] | undefined;
  if (config.scopeClaim) {
    const rawScope = payload[config.scopeClaim];
    if (typeof rawScope === "string") {
      scopes = rawScope.split(" ").filter(Boolean);
    }
  }

  let plan: string | undefined;
  if (config.planClaim) {
    const rawPlan = payload[config.planClaim];
    if (typeof rawPlan === "string") {
      plan = rawPlan;
    }
  }

  return {
    sub,
    issuer: normalizedIssuer,
    tenantId,
    email,
    name,
    roles,
    scopes,
    plan,
    source: config.source ?? "auth0",
    raw: payload as Record<string, unknown>,
  };
}

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === "/") {
    end--;
  }
  return value.slice(0, end);
}

/**
 * Factory that returns a token verifier you can use in any environment.
 */
export function createIdentifiablVerifier(
  config: IdentifiablCoreConfig
): (token: string) => Promise<VerifyResult> {
  const issuerNoSlash = trimTrailingSlashes(config.issuer);
  const audience = config.audience;

  // Reject a misconfigured verifier at construction rather than minting one
  // that silently accepts tokens. An empty issuer makes the post-verify issuer
  // check pass for `iss: ""`; an empty/absent audience disables audience
  // binding in jose, so a token minted for any audience would verify.
  if (!issuerNoSlash) {
    throw new Error("identifiabl: config.issuer is required and must be non-empty");
  }
  const audienceEmpty =
    audience === undefined ||
    audience === null ||
    (typeof audience === "string" && audience.trim() === "") ||
    (Array.isArray(audience) && audience.filter((a) => String(a).trim()).length === 0);
  if (audienceEmpty) {
    throw new Error("identifiabl: config.audience is required and must be non-empty");
  }

  const jwksUri =
    config.jwksUri || `${issuerNoSlash}/.well-known/jwks.json`;

  const JWKS = createRemoteJWKSet(new URL(jwksUri));

  return async (token: string): Promise<VerifyResult> => {
    try {
      const { payload } = await jwtVerify(token, JWKS, {
        audience,
        algorithms: ["RS256"],
        clockTolerance: "60s",
        // Require an expiry. Without this, jose accepts a token that simply
        // omits `exp` — a token that never expires. `exp` is then enforced by
        // jose's own clock check (with the tolerance above).
        requiredClaims: ["exp"],
      });

      const iss = String(payload.iss || "");
      const issNoSlash = trimTrailingSlashes(iss);
      if (issNoSlash !== issuerNoSlash) {
        return {
          ok: false,
          error: "invalid_token",
          detail: `unexpected "iss" claim value: ${iss}`,
        };
      }

      const identity = mapPayloadToGatewayIdentity(
        payload,
        config,
        issuerNoSlash
      );

      return {
        ok: true,
        identity,
        payload,
      };
    } catch (e: any) {
      return {
        ok: false,
        error: "invalid_token",
        detail: e?.message,
      };
    }
  };
}