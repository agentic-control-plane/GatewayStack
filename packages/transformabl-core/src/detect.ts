// packages/transformabl-core/src/detect.ts
//
// Regex-based PII detection. Recognizer set tracks Microsoft Presidio's
// default recognizer list (US-focused) plus healthcare-specific additions
// that are standard under HIPAA but not covered by Presidio's core list.
//
// FUTURE WORK:
// - ML-based NER detection (plug in spaCy, Presidio, or cloud NER APIs)
// - Address detection (street addresses, zip codes)
// - Name detection (requires NER - too many false positives with regex)
// - Country-specific identifiers (UK NHS, AU ABN, IN PAN, etc.)

import type { PiiType, PiiMatch } from "./types.js";
import { stripInvisible } from "./normalize.js";

interface PiiPattern {
  type: PiiType;
  pattern: RegExp;
}

/**
 * Built-in PII detection patterns.
 * Each pattern uses the global flag for multi-match detection.
 */
const BUILTIN_PATTERNS: PiiPattern[] = [
  {
    type: "email",
    // Quantifiers are bounded to RFC 5321 limits (local ≤64, domain ≤255,
    // TLD ≤24). The previous unbounded `+…+` form around a single mandatory
    // `@` was quadratic (O(n²)) — a long alphanumeric run with no `@` made
    // the engine scan-to-end-then-backtrack from every start position, so a
    // ~1 MB string of `a`s could block the event loop for minutes (ReDoS).
    // Bounding the work per start position makes it effectively linear.
    pattern: /[a-zA-Z0-9._%+-]{1,64}@[a-zA-Z0-9.-]{1,255}\.[a-zA-Z]{2,24}/g,
  },
  {
    type: "phone",
    // US 10-digit formats AND international E.164 (+<country><7-14 digits>).
    pattern:
      /(?:\+1[-.\s]?)\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\(?\d{3}\)?[-.\s]\d{3}[-.\s]?\d{4}\b|\+(?!1[-.\s]?\d)\d{1,3}[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}\b/g,
  },
  {
    type: "ssn",
    // US Social Security Numbers: xxx-xx-xxxx
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: "us_itin",
    // US Individual Taxpayer Identification Number: 9XX-(7X|8X)-XXXX where
    // the middle group starts with 7, 8, or 9. Must be checked BEFORE the
    // generic SSN pattern since ITIN overlaps structurally with SSN — ITIN
    // is more specific, so order matters when dedup'ing overlapping hits.
    pattern: /\b9\d{2}-[78]\d-\d{4}\b/g,
  },
  {
    type: "credit_card",
    // Major card formats: Visa (13-19), MC (16), Amex (15), Discover (16), Diners (14)
    // Matches 13-19 digit sequences with optional separators (space or dash)
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2})|3(?:0[0-5]|[68]\d)\d)[-\s]?\d{4,6}[-\s]?\d{4,5}(?:[-\s]?\d{1,4})?\b/g,
  },
  {
    type: "us_bank_number",
    // US bank account numbers: 8-17 digits. Loose by design — banks don't
    // publish a format. Tightened with word boundaries + minimum length to
    // avoid matching short IDs. Will false-positive on other long digit
    // strings; acceptable for a governance layer that prefers over-
    // redaction on financial context.
    pattern: /\b\d{8,17}\b/g,
  },
  {
    type: "us_passport",
    // US passport: 9 digits (older) or 1 letter + 8 digits (newer).
    pattern: /\b(?:[A-Z]\d{8}|\d{9})\b/g,
  },
  {
    type: "us_drivers_license",
    // US driver's license formats are state-specific. Approximation:
    // 1 letter + 7-8 digits, or 7-9 all-digit sequences with "DL:" prefix.
    // False-positive rate is non-trivial; callers can disable this type.
    pattern: /\b(?:DL[:\s]?)?(?:[A-Z]\d{7,8}|\d{7,9})\b/g,
  },
  {
    type: "iban",
    // ISO 13616 IBAN: 2 letters (country) + 2 check digits + 11-30 alphanum.
    // Optional spaces every 4 chars are stripped by normalize.ts before scan.
    pattern: /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g,
  },
  {
    type: "ip_address",
    // IPv4 OR IPv6 (full + compressed forms). Three alternatives:
    //   (1) IPv4 dotted-quad
    //   (2) IPv6 full form — 8 hex groups separated by `:`
    //   (3) IPv6 compressed — contains `::`, with hex groups on either side
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?<![\w:])(?:[0-9a-fA-F]{1,4}:){1,7}:(?:[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4})*)?(?![\w:])/g,
  },
  {
    type: "date_of_birth",
    // Common date formats that might be DOBs: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD
    pattern: /\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{4}|\d{4}-\d{2}-\d{2})\b/g,
  },
  {
    type: "icd_10",
    // ICD-10-CM diagnosis codes: 1 letter + 2 digits + optional ".Xn" (up
    // to 4 decimals). E.g. F32.9, E11.65, Z00. HIPAA PHI.
    pattern: /\b[A-TV-Z][0-9][0-9AB](?:\.[0-9A-Z]{1,4})?\b/g,
  },
  {
    type: "icd_9",
    // ICD-9-CM: 3 digits + optional decimal + up to 2 digits, OR V/E codes.
    // Legacy system but still present in historical records.
    pattern: /\b(?:[VE]\d{2}(?:\.\d{1,2})?|\d{3}(?:\.\d{1,2})?)\b/g,
  },
  {
    type: "npi",
    // National Provider Identifier: 10 digits starting with 1 or 2.
    // Mod-10 Luhn checksum validation is done post-match by checksum logic;
    // regex just grabs candidates.
    pattern: /\b[12]\d{9}\b/g,
  },
  {
    type: "crypto_wallet",
    // Bitcoin (P2PKH/P2SH base58 and bech32) + Ethereum (0x + 40 hex).
    pattern:
      /\b(?:bc1[a-z0-9]{25,39}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b/g,
  },
];

/**
 * Defense-in-depth against pathological inputs: cap the length we scan.
 * Even with bounded patterns, running every pattern over an unbounded body
 * is a DoS lever (this is an agent/LLM gateway — large tool-call payloads
 * are normal). PII beyond this cap is not scanned; callers handling very
 * large bodies should chunk. 512 KB comfortably covers real tool I/O.
 */
export const MAX_PII_SCAN_LENGTH = 512 * 1024;

/** Result of a PII scan, including whether the scan cap truncated the input. */
export interface DetectionResult {
  /** All matches found, in original-text coordinates, sorted by start. */
  matches: PiiMatch[];
  /**
   * True when the (invisible-stripped) input was longer than
   * {@link MAX_PII_SCAN_LENGTH} and PII past the cap was NOT scanned. When
   * true, absence of matches beyond the cap is not evidence of absence — the
   * caller must treat this as a loud fail-open signal, not silently pass the
   * unscanned tail through as clean.
   */
  scanTruncated: boolean;
  /** Number of characters actually scanned. */
  scannedLength: number;
  /** Full length of the invisible-stripped input. */
  totalLength: number;
}

/**
 * Detect PII in text content.
 * Returns all matches with their positions.
 *
 * Back-compatible thin wrapper over {@link detectPiiDetailed}. Callers that
 * need to know whether the scan cap truncated the input (M2 / #40) should use
 * {@link detectPiiDetailed} and inspect `scanTruncated`.
 */
export function detectPii(
  text: string,
  customPatterns?: Array<{ type: string; pattern: RegExp }>
): PiiMatch[] {
  return detectPiiDetailed(text, customPatterns).matches;
}

/**
 * Detect PII and report scan-cap truncation.
 * Returns matches plus a `scanTruncated` flag so a truncated scan is never a
 * silent fail-open.
 */
export function detectPiiDetailed(
  text: string,
  customPatterns?: Array<{ type: string; pattern: RegExp }>
): DetectionResult {
  // Strip zero-width / invisible characters before scanning so an attacker
  // cannot defeat the regex by inserting them inside PII values (e.g.
  // `john\u200B@example.com`). Matches found in the stripped form are
  // reported in ORIGINAL-text coordinates so redaction covers the whole
  // obfuscated span — including the invisible chars themselves.
  const { text: scanText, map } = stripInvisible(text);

  const scanTruncated = scanText.length > MAX_PII_SCAN_LENGTH;
  const boundedScanText = scanTruncated
    ? scanText.slice(0, MAX_PII_SCAN_LENGTH)
    : scanText;

  const matches: PiiMatch[] = [];
  const allPatterns: Array<{ type: string; pattern: RegExp }> = [
    ...BUILTIN_PATTERNS,
    ...(customPatterns ?? []),
  ];

  for (const { type, pattern } of allPatterns) {
    // Reset lastIndex for global regex reuse
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(boundedScanText)) !== null) {
      const s = match.index;
      const e = match.index + match[0].length;

      // Remap to original-text offsets. If no stripping happened, map is
      // null and offsets are identical to scanText offsets.
      const originalStart = map ? map[s] : s;
      const originalEnd = map
        ? e > s
          ? map[e - 1] + 1
          : originalStart
        : e;

      matches.push({
        type: type as PiiType,
        // Use the original substring so that redaction modes (mask/
        // remove/placeholder) operate on what was actually in the text.
        value: map ? text.slice(originalStart, originalEnd) : match[0],
        start: originalStart,
        end: originalEnd,
      });
    }
  }

  // Sort by position
  matches.sort((a, b) => a.start - b.start);

  return {
    matches,
    scanTruncated,
    scannedLength: boundedScanText.length,
    totalLength: scanText.length,
  };
}
