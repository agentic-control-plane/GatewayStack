// packages/validatabl-core/src/scopes.ts

export interface ScopeClaims {
  scope?: string | string[];
  scopes?: string[]; // some IdPs put scopes here instead
}

/**
 * Normalize scopes from various JWT claim shapes into a single space-delimited string.
 */
export function getScopeStringFromClaims(claims: ScopeClaims): string {
  if (typeof claims.scope === "string") {
    return claims.scope;
  }
  if (Array.isArray(claims.scope)) {
    return claims.scope.join(" ");
  }
  if (Array.isArray(claims.scopes)) {
    return claims.scopes.join(" ");
  }
  return "";
}

/**
 * Check whether a given scope is present in the user's scopes.
 *
 * Membership is an exact, whitespace-delimited token match — never a regex.
 * Building a `RegExp` from the caller's scope string (the old implementation)
 * meant a required scope containing regex metacharacters either widened the
 * check (`tool.write` matched `toolXwrite` because `.` is "any char") or threw
 * on an unbalanced metachar and 500'd the request.
 */
export function hasScope(claims: ScopeClaims, scope: string): boolean {
  if (!scope) return false;
  return getScopeStringFromClaims(claims).split(/\s+/).includes(scope);
}
