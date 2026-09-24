import { roundTo } from "./geo.js";
import type { RouteFix } from "./types.js";

/** Elapsed time between the earliest and latest fix, in hours. Assumes
 * `fixes` is already sorted ascending by `timestamp` (build plan gate fix:
 * sort fixes stably before doing anything — see `route-match.ts`), but
 * falls back to min/max regardless, so a caller that passes an unsorted
 * array still gets a sane duration rather than a wrong (or negative) one.
 * Returns 0 for zero or one fix. */
export function computeDurationHours(fixes: readonly RouteFix[]): number {
  if (fixes.length < 2) return 0;
  let min = Infinity;
  let max = -Infinity;
  for (const f of fixes) {
    if (f.timestamp < min) min = f.timestamp;
    if (f.timestamp > max) max = f.timestamp;
  }
  return roundTo((max - min) / 3_600_000, 9);
}

/** The build plan §7.4 step 4 duration acceptance window: 1.5–6 h for an
 * 18-hole (or unspecified-hole-count) course, ≥ 0.75 h with no stated
 * upper bound for a 9-hole course. `holes` defaults to 18 when omitted
 * (see `CandidateCourse.holes` doc comment). Rounds both sides of the
 * comparison to the same fixed precision as `computeDurationHours`
 * (build plan gate fix: determinism at exact thresholds). */
export function isWithinDurationWindow(durationHours: number, holes: number | undefined): boolean {
  const hours = roundTo(durationHours, 9);
  if ((holes ?? 18) === 9) {
    return hours >= roundTo(0.75, 9);
  }
  return hours >= roundTo(1.5, 9) && hours <= roundTo(6, 9);
}
