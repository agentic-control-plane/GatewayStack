// packages/limitabl-core/src/sanitize.ts
//
// Numeric input sanitization for budget / cost values.
//
// Caps the economic security boundary: negative, NaN, or ±Infinity values
// passed to cost tracking would otherwise let a caller (or an upstream the
// caller trusts) bypass or break budget enforcement:
//   - negative cost subtracts from the running sum → budget refund bypass
//   - NaN cost poisons the sum (NaN > maxSpend === false) → cap becomes no-op
//   - Infinity cost pins the sum at Infinity → targeted DoS of one victim
//
// We clamp rather than throw so a buggy caller does not crash the request
// path in production; the clamp is logged so the bug still surfaces.

export function sanitizeCost(
  value: number | undefined,
  context: string
): number {
  if (value === undefined) return 0;
  if (!Number.isFinite(value)) {
    console.warn(
      `[limitabl-core] non-finite cost (${String(value)}) in ${context}; clamped to 0`
    );
    return 0;
  }
  if (value < 0) {
    console.warn(
      `[limitabl-core] negative cost (${value}) in ${context}; clamped to 0`
    );
    return 0;
  }
  return value;
}
