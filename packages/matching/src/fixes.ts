/**
 * Fix validation and ordering (build plan gate fixes: "sort the fixes
 * stably by timestamp before doing anything" / "throw a RangeError on
 * non-finite lat, lon or timestamp").
 */
import type { RouteFix } from "./types.js";

/** Throws `RangeError` if any fix has a non-finite `point.lat`,
 * `point.lon`, or `timestamp` — matching arrives from an untrusted
 * boundary (device outbox JSON, server replay of stored evidence, build
 * plan §3.1 row D / §3.3), so a `NaN`/`Infinity` (or, after a JSON round
 * trip, `null` in place of a `NaN`) must fail loudly rather than silently
 * poison a ratio or a duration computation. */
export function validateFixesOrThrow(fixes: readonly RouteFix[]): void {
  for (let i = 0; i < fixes.length; i++) {
    const f = fixes[i]!;
    if (
      !Number.isFinite(f.point?.lat) ||
      !Number.isFinite(f.point?.lon) ||
      !Number.isFinite(f.timestamp)
    ) {
      throw new RangeError(
        `matchRoute: fix at index ${i} has a non-finite lat, lon, or timestamp`,
      );
    }
  }
}

interface HasTimestamp {
  timestamp: number;
}

/** Stably sorts `items` ascending by `timestamp`. `Array.prototype.sort`
 * has been spec-guaranteed stable since ES2019 and both V8 and Hermes
 * implement it, but this decorates with the original index as an explicit
 * tiebreaker anyway (build plan gate fix: determinism) so stability never
 * depends on engine compliance — two fixes sharing one timestamp always
 * keep their original relative order, on every engine, forever. */
export function stableSortByTimestamp<T extends HasTimestamp>(items: readonly T[]): T[] {
  return items
    .map((item, index) => ({ item, index }))
    .sort((a, b) => a.item.timestamp - b.item.timestamp || a.index - b.index)
    .map((entry) => entry.item);
}
