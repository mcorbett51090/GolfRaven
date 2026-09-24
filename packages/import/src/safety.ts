/**
 * Shared safety limits applied by every parser (build plan §7.3 lane 2
 * "Safety"). Parsing is pure and untrusted-input-facing — a file picked
 * from the device's file system or share sheet — so these are enforced
 * uniformly rather than left to each format.
 */

/** Input size cap. A file over this is refused outright before any
 * parsing work happens. */
export const MAX_INPUT_BYTES = 20 * 1024 * 1024; // 20 MB

/** Fix count cap. A file with more raw fixes than this is truncated (kept
 * first, dropped rest, sorted afterwards) with a warning — downsampling
 * for matching is `@golfraven/matching`'s `simplifyToMaxPoints`, not this
 * package's job; this cap exists only to bound memory/CPU on a hostile or
 * absurd input. */
export const MAX_FIXES = 200_000;

export function checkInputSize(byteLength: number): string | undefined {
  if (byteLength > MAX_INPUT_BYTES) {
    return `input is ${byteLength} bytes, over the ${MAX_INPUT_BYTES}-byte cap`;
  }
  return undefined;
}

/** True for a finite, in-range latitude. */
export function isValidLat(lat: number): boolean {
  return Number.isFinite(lat) && lat >= -90 && lat <= 90;
}

/** True for a finite, in-range longitude. */
export function isValidLon(lon: number): boolean {
  return Number.isFinite(lon) && lon >= -180 && lon <= 180;
}

/** True for a finite epoch-millisecond timestamp. Doesn't bound the range
 * (a device clock can be wrong; matching decides what to do with that) —
 * only rejects `NaN`/`Infinity`, which a JSON or XML round trip can
 * produce from a malformed source. */
export function isValidTimestamp(ts: number): boolean {
  return Number.isFinite(ts);
}

export interface FixLike {
  lat: number;
  lon: number;
  timestamp: number;
}

/**
 * Applies the fix-count cap and sorts ascending by timestamp. Invalid
 * (non-finite or out-of-range) fixes must already have been dropped by
 * the caller — this only caps count and orders what's left, and reports
 * what it did via the returned warnings.
 */
export function capAndSortFixes<T extends FixLike>(fixes: T[]): { fixes: T[]; warnings: string[] } {
  const warnings: string[] = [];
  let capped = fixes;
  if (fixes.length > MAX_FIXES) {
    capped = fixes.slice(0, MAX_FIXES);
    warnings.push(
      `fix count ${fixes.length} exceeded the ${MAX_FIXES} cap; truncated to the first ${MAX_FIXES} — downsampling for matching is left to the matcher`,
    );
  }
  const sorted = capped
    .map((item, index) => ({ item, index }))
    .sort((a, b) => a.item.timestamp - b.item.timestamp || a.index - b.index)
    .map((entry) => entry.item);
  return { fixes: sorted, warnings };
}
