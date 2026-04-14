// packages/transformabl-core/src/normalize.ts
//
// Text normalization helpers for detection. Currently handles zero-width
// character stripping; future revisions may add NFKC normalization and
// homoglyph folding.
//
// Why: an attacker can interleave zero-width characters inside PII values
// (e.g. `john\u200B@example.com`) to defeat regex detection, while most
// downstream consumers (LLMs, email parsers, databases) ignore those
// characters and see the unobfuscated form. Stripping before detection
// closes this bypass class.

/**
 * Result of stripping invisible characters from an input string.
 *
 * `map[i]` holds the index in the ORIGINAL text of the i-th character in
 * `text`. This lets callers report match positions back in original-text
 * coordinates so that downstream tools (e.g. redaction) operate on the
 * original string correctly, including any interleaved invisible chars.
 *
 * If `map` is `null`, no stripping happened and `text` is reference-equal
 * to the input.
 */
export interface StrippedText {
  text: string;
  map: number[] | null;
}

// Zero-width / invisible formatting characters:
//   U+200B ZERO WIDTH SPACE
//   U+200C ZERO WIDTH NON-JOINER
//   U+200D ZERO WIDTH JOINER
//   U+2060 WORD JOINER
//   U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)
const INVISIBLE_CHAR_RE = /[\u200B-\u200D\u2060\uFEFF]/;

// Defensive upper bound on the normalization pass. Callers should enforce
// their own payload-size limits upstream; this cap exists so an oversized
// input cannot itself turn the O(n) character walk into a DoS vector.
// PII detection still runs on the full original input — the oversized-
// input path just skips ZW-normalization rather than iterating.
const MAX_NORMALIZE_LENGTH = 1_000_000;

export function stripInvisible(input: string): StrippedText {
  if (input.length > MAX_NORMALIZE_LENGTH) {
    return { text: input, map: null };
  }
  if (!INVISIBLE_CHAR_RE.test(input)) {
    return { text: input, map: null };
  }
  const limit = Math.min(input.length, MAX_NORMALIZE_LENGTH);
  const chars: string[] = [];
  const map: number[] = [];
  for (let i = 0; i < limit; i++) {
    const code = input.charCodeAt(i);
    if (
      (code >= 0x200b && code <= 0x200d) ||
      code === 0x2060 ||
      code === 0xfeff
    ) {
      continue;
    }
    chars.push(input.charAt(i));
    map.push(i);
  }
  return { text: chars.join(""), map };
}
