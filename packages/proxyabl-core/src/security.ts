// packages/proxyabl-core/src/security.ts
//
// SSRF protection and header sanitization for proxy forwarding.
//
// The v0.1 rewrite makes `assertUrlSafe` async and adds DNS-level checking:
// an attacker-controlled hostname that appears on the allowlist but resolves
// to a private IP (classic DNS-rebinding-adjacent SSRF) is now rejected
// after resolution. Earlier versions of this file checked the hostname
// string only and deferred to the caller's socket-level resolution — which
// is the same hostname-level check an attacker defeats.
//
// Residual risk: there is a small TOCTOU window between `dns.lookup()` here
// and the actual TCP connect in `fetch()`. A DNS response with a very short
// TTL could flip from public to private between those two steps. Closing
// that gap requires pinning the socket to the validated IP via a custom
// HTTP agent; tracked as a follow-up.

import * as dns from "node:dns/promises";
import { isIP as netIsIP } from "node:net";

/** Resolve all A/AAAA records for a hostname. Thin wrapper around dns.lookup
 *  so the return type is always an array (the bare `lookup(host)` overload
 *  returns a single record). */
async function defaultResolve(
  host: string
): Promise<Array<{ address: string; family: number }>> {
  return dns.lookup(host, { all: true });
}

export interface UrlSafetyOptions {
  url: URL;
  allowedHosts: string[];
  /** Allow plain HTTP in addition to HTTPS. Default: false. */
  allowHttp?: boolean;
  /** Skip private-IP checks. Only enable for trusted internal callers. Default: false. */
  allowPrivateIps?: boolean;
  /**
   * Injection seam for testing. Defaults to node:dns/promises `lookup`.
   * Resolves all A/AAAA records for a hostname.
   */
  resolve?: (host: string) => Promise<Array<{ address: string; family: number }>>;
}

function normalizeHost(h: string): string {
  let s = h.trim().toLowerCase();
  // URL.hostname preserves square brackets for IPv6 literals ("[::1]").
  // Strip them so downstream comparisons and net.isIP() work.
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  return s;
}

export function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map((x) => Number(x));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;

  const [a, b] = parts;

  if (a === 0) return true; // 0.0.0.0/8 — "this network"
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // 127.0.0.0/8 — loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 — link-local + cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16

  return false;
}

export function isPrivateIpv6(ip: string): boolean {
  const s = ip.toLowerCase();

  if (s === "::1") return true; // loopback
  if (s.startsWith("fc") || s.startsWith("fd")) return true; // fc00::/7 unique local
  // fe80::/10 link-local — covers 3rd-hex-digit 8,9,a,b
  if (
    s.startsWith("fe8") ||
    s.startsWith("fe9") ||
    s.startsWith("fea") ||
    s.startsWith("feb")
  ) {
    return true;
  }

  return false;
}

/**
 * If `ipv6` is an IPv4-mapped IPv6 address (::ffff:a.b.c.d), return the
 * embedded IPv4. These addresses route as their IPv4 equivalent, so an
 * attacker could use `::ffff:127.0.0.1` to reach localhost while bypassing
 * a check that looks at IPv6 privacy ranges only.
 */
export function extractIpv4MappedIpv6(ipv6: string): string | null {
  // Dotted form: ::ffff:127.0.0.1
  const dotted = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ipv6);
  if (dotted) return dotted[1];

  // Canonical compressed hex form (what Node's URL parser produces for
  // IPv4-mapped addresses): ::ffff:HHHH:HHHH — two 16-bit groups encoding
  // the embedded IPv4.
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ipv6);
  if (hex) {
    const high = parseInt(hex[1], 16);
    const low = parseInt(hex[2], 16);
    if (
      Number.isInteger(high) && high >= 0 && high <= 0xffff &&
      Number.isInteger(low) && low >= 0 && low <= 0xffff
    ) {
      return [
        (high >> 8) & 0xff,
        high & 0xff,
        (low >> 8) & 0xff,
        low & 0xff,
      ].join(".");
    }
  }

  return null;
}

function assertIpNotPrivate(addr: string, family: number, context: string): void {
  if (family === 4 && isPrivateIpv4(addr)) {
    throw new Error(`Blocked private IPv4 ${context}: ${addr}`);
  }
  if (family === 6) {
    const mapped = extractIpv4MappedIpv6(addr);
    if (mapped && isPrivateIpv4(mapped)) {
      throw new Error(`Blocked IPv4-mapped IPv6 private ${context}: ${addr}`);
    }
    if (isPrivateIpv6(addr)) {
      throw new Error(`Blocked private IPv6 ${context}: ${addr}`);
    }
  }
}

/**
 * Assert that a URL is safe to fetch from the gateway.
 *
 * Validates, in order:
 *   1. Protocol (https; http only when allowHttp=true).
 *   2. Hostname against `allowedHosts` (case-insensitive exact match).
 *   3. If the hostname is an IP literal, its privacy class (unless
 *      `allowPrivateIps` is true). Covers IPv4-mapped IPv6.
 *   4. If the hostname is a name, resolves all A/AAAA records via DNS and
 *      rejects if any resolved address is private. This is the DNS
 *      rebinding / hostname-hiding defense.
 *
 * Throws an `Error` with a short reason on any violation. Error messages
 * do not echo the target URL's path or query string.
 */
export async function assertUrlSafe(opts: UrlSafetyOptions): Promise<void> {
  const {
    url,
    allowedHosts,
    allowHttp = false,
    allowPrivateIps = false,
    resolve = defaultResolve,
  } = opts;

  const proto = url.protocol.toLowerCase();
  if (proto !== "https:" && !(allowHttp && proto === "http:")) {
    throw new Error(`Blocked protocol: ${url.protocol}`);
  }

  const host = normalizeHost(url.hostname);
  const allowed = allowedHosts.map(normalizeHost);
  if (!allowed.includes(host)) {
    throw new Error(`Blocked host: ${host} (not in allowedHosts)`);
  }

  if (allowPrivateIps) return;

  const ipType = netIsIP(host);
  if (ipType !== 0) {
    assertIpNotPrivate(host, ipType, "host");
    return;
  }

  // Hostname — resolve and validate every address.
  const addrs = await resolve(host);
  for (const a of addrs) {
    assertIpNotPrivate(a.address, a.family, `resolved address for ${host}`);
  }
}

/** Sanitize a header value to prevent CRLF injection. */
export function sanitizeHeaderValue(v: string): string {
  return v.replace(/[\r\n]+/g, " ").trim();
}
