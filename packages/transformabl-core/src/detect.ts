// packages/transformabl-core/src/detect.ts
//
// Regex-based PII detection.
//
// FUTURE WORK:
// - ML-based NER detection (plug in spaCy, Presidio, or cloud NER APIs)
// - Address detection (street addresses, zip codes)
// - Name detection (requires NER - too many false positives with regex)
// - International phone number formats
// - Passport numbers, driver's license numbers

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
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  },
  {
    type: "phone",
    // US phone numbers (10+ digits): (xxx) xxx-xxxx, xxx-xxx-xxxx, +1xxxxxxxxxx
    // Requires area code (3 digits) + 7-digit number to avoid matching short numbers
    pattern: /(?:\+1[-.\s]?)\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b|\b\(?\d{3}\)?[-.\s]\d{3}[-.\s]?\d{4}\b/g,
  },
  {
    type: "ssn",
    // US Social Security Numbers: xxx-xx-xxxx
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
  {
    type: "credit_card",
    // Major card formats: Visa (13-19), MC (16), Amex (15), Discover (16), Diners (14)
    // Matches 13-19 digit sequences with optional separators (space or dash)
    pattern: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2})|3(?:0[0-5]|[68]\d)\d)[-\s]?\d{4,6}[-\s]?\d{4,5}(?:[-\s]?\d{1,4})?\b/g,
  },
  {
    type: "ip_address",
    // IPv4 addresses
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
  },
  {
    type: "date_of_birth",
    // Common date formats that might be DOBs: MM/DD/YYYY, DD-MM-YYYY, YYYY-MM-DD
    pattern: /\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{4}|\d{4}-\d{2}-\d{2})\b/g,
  },
];

/**
 * Detect PII in text content.
 * Returns all matches with their positions.
 */
export function detectPii(
  text: string,
  customPatterns?: Array<{ type: string; pattern: RegExp }>
): PiiMatch[] {
  // Strip zero-width / invisible characters before scanning so an attacker
  // cannot defeat the regex by inserting them inside PII values (e.g.
  // `john\u200B@example.com`). Matches found in the stripped form are
  // reported in ORIGINAL-text coordinates so redaction covers the whole
  // obfuscated span — including the invisible chars themselves.
  const { text: scanText, map } = stripInvisible(text);

  const matches: PiiMatch[] = [];
  const allPatterns: Array<{ type: string; pattern: RegExp }> = [
    ...BUILTIN_PATTERNS,
    ...(customPatterns ?? []),
  ];

  for (const { type, pattern } of allPatterns) {
    // Reset lastIndex for global regex reuse
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(scanText)) !== null) {
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
  return matches;
}
