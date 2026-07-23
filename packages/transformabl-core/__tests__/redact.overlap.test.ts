// Overlapping-match redaction (H4 / #40).
//
// Detection routinely emits overlapping spans — e.g. `us_bank_number`
// (`\d{8,17}`) covers the same digit run as `npi` / `us_drivers_license`. The
// old descending-start substitution let an inner match's replacement shift the
// text so an outer match's stale `end` sliced the wrong point, leaving trailing
// PII digits behind in placeholder/remove modes. These lock in the
// merge-into-maximal-intervals fix.

import { describe, it, expect } from "vitest";
import { redactPii } from "../src/redact.js";
import type { PiiMatch } from "../src/types.js";

describe("redactPii — overlapping matches merge into maximal intervals", () => {
  // A partial overlap that, under the old code, left the digits "23" behind:
  // the inner npi span (higher start) was substituted first, shifting the text
  // so the outer us_bank_number span's stale `end` sliced past its real end.
  const text = "id 1234567890123 end MORE";
  const overlapping: PiiMatch[] = [
    { type: "us_bank_number", value: "1234567890123", start: 3, end: 16 }, // outer
    { type: "npi", value: "234", start: 4, end: 7 }, // inner, higher start
  ];

  it("placeholder mode: the outer span is replaced once and no digits survive", () => {
    const result = redactPii(text, overlapping, { mode: "placeholder" });
    expect(result).toBe("id [US_BANK_NUMBER] end MORE");
    expect(result).not.toMatch(/\d/);
  });

  it("remove mode: the outer span is removed cleanly and no digits survive", () => {
    const result = redactPii(text, overlapping, { mode: "remove" });
    expect(result).toBe("id  end MORE");
    expect(result).not.toMatch(/\d/);
  });

  it("acceptance (#40): output contains no substring of any original match value", () => {
    for (const mode of ["placeholder", "remove"] as const) {
      const result = redactPii(text, overlapping, { mode });
      for (const m of overlapping) {
        expect(result).not.toContain(m.value);
      }
      expect(result).not.toMatch(/\d/);
    }
  });

  it("labels the merged span by its widest contributing type", () => {
    const result = redactPii(text, overlapping, { mode: "placeholder" });
    expect(result).toContain("[US_BANK_NUMBER]");
    expect(result).not.toContain("[NPI]");
  });

  it("identical spans (same start and end) collapse to one replacement", () => {
    // us_bank_number and us_drivers_license both match an 8-digit run.
    const t = "acct 12345678 ok";
    const same: PiiMatch[] = [
      { type: "us_bank_number", value: "12345678", start: 5, end: 13 },
      { type: "us_drivers_license", value: "12345678", start: 5, end: 13 },
    ];
    const result = redactPii(t, same, { mode: "placeholder" });
    expect(result).toBe("acct [US_BANK_NUMBER] ok");
    expect(result).not.toMatch(/\d/);
  });

  it("respects `types`: only the requested type's span is redacted", () => {
    // Only redact npi. Its [4,7] span ("234") is replaced; the surrounding
    // bank digits are the caller's explicit choice to keep, and the merge must
    // not sweep the excluded us_bank_number span in.
    const result = redactPii(text, overlapping, { mode: "placeholder", types: ["npi"] });
    expect(result).toBe("id 1[NPI]567890123 end MORE");
  });

  it("mask mode masks the whole merged span (keeps only edge chars)", () => {
    const result = redactPii(text, overlapping, { mode: "mask" });
    // Full 13-char span masked keeping 2 at each edge: "12" + 9*'*' + "23".
    expect(result).toBe("id 12*********23 end MORE");
  });

  it("non-overlapping matches are unaffected by the merge", () => {
    const t = "mail x@y.com then 123-45-6789 z";
    const matches: PiiMatch[] = [
      { type: "email", value: "x@y.com", start: 5, end: 12 },
      { type: "ssn", value: "123-45-6789", start: 18, end: 29 },
    ];
    const result = redactPii(t, matches, { mode: "placeholder" });
    expect(result).toBe("mail [EMAIL] then [SSN] z");
  });
});
