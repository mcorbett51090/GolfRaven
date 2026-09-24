import type { RouteFix } from "./types.js";

/** Elapsed time between the earliest and latest fix, in hours. Does not
 * assume `fixes` is chronologically sorted (uses min/max, not first/last),
 * so an out-of-order outbox batch still produces a sane duration. Returns
 * 0 for zero or one fix. */
export function computeDurationHours(fixes: readonly RouteFix[]): number {
  if (fixes.length < 2) return 0;
  let min = Infinity;
  let max = -Infinity;
  for (const f of fixes) {
    if (f.timestamp < min) min = f.timestamp;
    if (f.timestamp > max) max = f.timestamp;
  }
  return (max - min) / 3_600_000;
}

/** The build plan §7.4 step 4 duration acceptance window: 1.5–6 h for an
 * 18-hole (or unspecified-hole-count) course, ≥ 0.75 h with no stated
 * upper bound for a 9-hole course. `holes` defaults to 18 when omitted
 * (see `CandidateCourse.holes` doc comment). */
export function isWithinDurationWindow(durationHours: number, holes: number | undefined): boolean {
  if ((holes ?? 18) === 9) {
    return durationHours >= 0.75;
  }
  return durationHours >= 1.5 && durationHours <= 6;
}
