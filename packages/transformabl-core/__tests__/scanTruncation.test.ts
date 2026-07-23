// PII-scan truncation loudness (M2 / #40).
//
// detectPii caps scanning at MAX_PII_SCAN_LENGTH (512 KB). Before this fix the
// cap was silent, so PII past it flowed through unredacted AND unlogged —
// a fail-open that wasn't loud. detectPiiDetailed / TransformResult now carry a
// `scanTruncated` flag so a consumer can tell "scanned clean" from "not fully
// scanned."

import { describe, it, expect } from "vitest";
import {
  detectPii,
  detectPiiDetailed,
  MAX_PII_SCAN_LENGTH,
} from "../src/detect.js";
import { transformContent } from "../src/transform.js";

describe("scan-cap truncation is reported (not silent)", () => {
  it("does not flag truncation for normal-sized input", () => {
    const r = detectPiiDetailed("contact john@example.com please");
    expect(r.scanTruncated).toBe(false);
    expect(r.totalLength).toBe("contact john@example.com please".length);
    expect(r.scannedLength).toBe(r.totalLength);
    expect(r.matches.some((m) => m.type === "email")).toBe(true);
  });

  it("flags truncation and does NOT scan PII past the cap", () => {
    const filler = "a".repeat(MAX_PII_SCAN_LENGTH + 100);
    const input = `${filler} leak@example.com`;
    const r = detectPiiDetailed(input);

    expect(r.scanTruncated).toBe(true);
    expect(r.scannedLength).toBe(MAX_PII_SCAN_LENGTH);
    expect(r.totalLength).toBe(input.length);
    // The email is beyond the cap, so it is (knowingly) not found — the flag
    // is what makes that honest rather than a silent miss.
    expect(r.matches.some((m) => m.type === "email")).toBe(false);
  });

  it("still finds PII that falls before the cap in an over-cap input", () => {
    const input = `early@example.com ${"a".repeat(MAX_PII_SCAN_LENGTH)} late@example.com`;
    const r = detectPiiDetailed(input);
    expect(r.scanTruncated).toBe(true);
    const emails = r.matches.filter((m) => m.type === "email");
    expect(emails).toHaveLength(1);
    expect(emails[0].value).toBe("early@example.com");
  });

  it("transformContent surfaces scanTruncated on the result", () => {
    const small = transformContent("john@example.com");
    expect(small.scanTruncated).toBe(false);

    const big = transformContent("a".repeat(MAX_PII_SCAN_LENGTH + 1));
    expect(big.scanTruncated).toBe(true);
  });

  it("detectPii (array wrapper) stays behaviourally identical to detectPiiDetailed().matches", () => {
    const input = "ssn 123-45-6789 and mail a@b.co";
    expect(detectPii(input)).toEqual(detectPiiDetailed(input).matches);
  });
});
