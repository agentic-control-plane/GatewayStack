// packages/transformabl-core/src/redact.ts
//
// PII redaction: mask, remove, or replace detected PII.

import type { PiiMatch, PiiType, RedactionConfig, RedactionMode } from "./types.js";

/** A maximal interval formed by merging overlapping matches. */
interface MergedSpan {
  start: number;
  end: number;
  /** Type of the widest contributing match — used for the placeholder label. */
  repType: PiiType;
  repWidth: number;
}

/**
 * Redact PII matches from text.
 *
 * Modes:
 * - "mask": Replace middle characters with mask char (e.g., "jo**@example.com")
 * - "remove": Remove the PII entirely
 * - "placeholder": Replace with type label (e.g., "[EMAIL]")
 *
 * Overlapping matches are merged into maximal intervals before substitution.
 * Detection routinely produces overlaps — e.g. `us_bank_number` (`\d{8,17}`)
 * spans the same digit run as `npi` / `us_drivers_license`. Substituting them
 * independently (the old descending-start loop) let an inner match's
 * replacement shift the text so an outer match's now-stale `end` sliced the
 * wrong point, leaving trailing PII digits behind in placeholder/remove modes
 * (H4). Merging first guarantees the spans handed to substitution are
 * disjoint, so no substitution can invalidate another's offsets.
 */
export function redactPii(
  text: string,
  matches: PiiMatch[],
  config?: RedactionConfig
): string {
  if (matches.length === 0) return text;

  const mode: RedactionMode = config?.mode ?? "mask";
  const maskChar = config?.maskChar ?? "*";
  const maskKeep = config?.maskKeep ?? 2;
  const typesToRedact = config?.types
    ? new Set(config.types)
    : null; // null = redact all

  // Only redact matches the caller asked for. Filtering BEFORE the merge is
  // what keeps an excluded type from being swept into a redacted span just
  // because it overlapped an included one. Drop zero-width/inverted spans too.
  const selected = matches.filter(
    (m) => (!typesToRedact || typesToRedact.has(m.type)) && m.end > m.start
  );
  if (selected.length === 0) return text;

  // Merge overlapping spans into maximal intervals. Sort ascending by start
  // (then end) and extend the current interval whenever the next match starts
  // before the current one ends. Touching spans (start === prev end) stay
  // separate — they are already disjoint and safe to substitute independently.
  const asc = [...selected].sort((a, b) => a.start - b.start || a.end - b.end);
  const merged: MergedSpan[] = [];
  for (const m of asc) {
    const width = m.end - m.start;
    const last = merged[merged.length - 1];
    if (last && m.start < last.end) {
      if (m.end > last.end) last.end = m.end;
      if (width > last.repWidth) {
        last.repType = m.type;
        last.repWidth = width;
      }
    } else {
      merged.push({ start: m.start, end: m.end, repType: m.type, repWidth: width });
    }
  }

  // Substitute right-to-left so earlier offsets stay valid. Spans are disjoint,
  // so the substring being replaced is exactly the original PII span — no other
  // span's coordinates can have shifted underneath it.
  let result = text;
  for (let i = merged.length - 1; i >= 0; i--) {
    const span = merged[i];
    const original = text.slice(span.start, span.end);

    let replacement: string;
    switch (mode) {
      case "mask":
        replacement = maskValue(original, maskChar, maskKeep);
        break;
      case "remove":
        replacement = "";
        break;
      case "placeholder":
        replacement = config?.placeholder
          ? config.placeholder.replace("{TYPE}", span.repType.toUpperCase())
          : `[${span.repType.toUpperCase()}]`;
        break;
    }

    result = result.slice(0, span.start) + replacement + result.slice(span.end);
  }

  return result;
}

function maskValue(value: string, maskChar: string, keep: number): string {
  if (value.length <= keep * 2) {
    return maskChar.repeat(value.length);
  }
  const start = value.slice(0, keep);
  const end = value.slice(-keep);
  const middle = maskChar.repeat(value.length - keep * 2);
  return start + middle + end;
}
