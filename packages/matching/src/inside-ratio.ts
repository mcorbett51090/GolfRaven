import { roundTo } from "./geo.js";
import { isInsidePreparedWithBuffer, type PreparedPolygonGeometry } from "./polygon.js";
import type { LatLng } from "./types.js";

export interface TimestampedPoint {
  point: LatLng;
  timestamp: number;
}

/**
 * The cap on any single inter-fix interval's contribution to the
 * time-weighted computations below, in seconds (matcher parameter — see
 * `version.ts` and `README.md`). Without a cap, two widely-spaced fixes
 * that both happen to be inside the polygon can dominate the ratio
 * through the sheer size of the gap between them: e.g. one inside fix,
 * then a 3-hour gap, then one more inside fix would (uncapped) count that
 * whole 3 hours as "inside" time, even though nothing was actually
 * observed during it. Any interval longer than this is only counted up
 * to the cap; the remainder is simply left out of both the inside and the
 * overall total (see `computeObservedCoverage`) — it is unobserved, not
 * "outside".
 */
export const MAX_GAP_SECONDS = 300;
const MAX_GAP_MS = MAX_GAP_SECONDS * 1000;

/** Below this fraction of the route's wall-clock duration actually being
 * covered by fixes (after gap-capping), a route can never be `matched` —
 * only `typeahead` (matcher parameter — see `version.ts` and
 * `README.md`). This blocks exactly the shape above: a route reduced to
 * a couple of isolated "inside" pings hours apart is mostly unobserved,
 * however clean its (geometry-only) ratio looks over what little was
 * actually seen. */
export const MIN_OBSERVED_COVERAGE = 0.5;

function cappedGapsMs(sortedFixes: readonly { timestamp: number }[]): number[] {
  const n = sortedFixes.length;
  const gaps = new Array<number>(Math.max(0, n - 1));
  for (let i = 0; i < n - 1; i++) {
    const gap = sortedFixes[i + 1]!.timestamp - sortedFixes[i]!.timestamp;
    gaps[i] = Math.min(Math.max(gap, 0), MAX_GAP_MS);
  }
  return gaps;
}

/**
 * The fraction of the route's total wall-clock span (`last.timestamp -
 * first.timestamp`) that was actually observed, after capping each
 * inter-fix interval at `MAX_GAP_SECONDS`. Geometry-independent — this
 * depends only on the fixes' timestamps, so it is computed once per
 * `matchRoute` call and reused for every candidate (build plan gate fix:
 * cap the gaps in the time-weighting).
 *
 * A route with zero or one fix, or where every fix shares one timestamp,
 * has zero wall-clock span to miss anything from, so it is defined as
 * fully observed (`1`) rather than dividing by zero.
 */
export function computeObservedCoverage(sortedFixes: readonly { timestamp: number }[]): number {
  const n = sortedFixes.length;
  if (n < 2) return 1;
  const rawDuration = sortedFixes[n - 1]!.timestamp - sortedFixes[0]!.timestamp;
  if (rawDuration <= 0) return 1;
  const observedMs = cappedGapsMs(sortedFixes).reduce((sum, g) => sum + g, 0);
  return roundTo(observedMs / rawDuration, 9);
}

/**
 * Time-weighted fraction of `sortedFixes`' *observed* duration spent
 * inside `prepared` (+ `bufferMeters`) — build plan gate fix 1: computed
 * on the raw, already-time-sorted fixes, never on a post-simplification
 * vertex count.
 *
 * Each fix is weighted by half of each of its adjacent time intervals (a
 * standard trapezoidal time-weighting), with every individual interval
 * first capped at `MAX_GAP_SECONDS` (gate fix: cap the gaps): an interior
 * fix's weight is `(cappedGapBefore + cappedGapAfter) / 2`, an endpoint's
 * weight is half its one adjacent capped gap. Summed across all fixes
 * this equals the *observed* duration (the sum of the capped gaps, which
 * is what `computeObservedCoverage` reports as a fraction of the route's
 * real wall-clock span) — not the raw duration, and not a point fraction.
 * This makes the ratio robust to both sampling-density bias (a long
 * straight stretch and a short winding stretch each count for exactly the
 * wall-clock time they actually took) and to gap exploitation (a huge gap
 * between two isolated "inside" fixes no longer buys that pair an
 * outsized share of the ratio — its contribution is capped, and the
 * uncapped remainder shows up instead as reduced `observedCoverage`).
 *
 * Requires `sortedFixes` to already be sorted ascending by `timestamp`
 * (`matchRoute` sorts once, up front, and reuses the sorted array
 * everywhere — see `route-match.ts`).
 */
export function computeTimeWeightedInsideRatio(
  sortedFixes: readonly TimestampedPoint[],
  prepared: PreparedPolygonGeometry,
  bufferMeters: number,
): number {
  const n = sortedFixes.length;
  if (n === 0) return 0;

  const rawDuration = n >= 2 ? sortedFixes[n - 1]!.timestamp - sortedFixes[0]!.timestamp : 0;

  if (rawDuration <= 0) {
    // n === 1, or every fix shares one timestamp: no gap is even
    // possible, so there is nothing to cap or to miss. Fall back to a
    // plain per-fix average rather than dividing by zero, so a
    // same-instant burst still scores sensibly (rounded the same as the
    // normal path, for the same determinism reasons — see `version.ts`).
    let insideCount = 0;
    for (const f of sortedFixes) {
      if (isInsidePreparedWithBuffer(f.point, prepared, bufferMeters)) insideCount += 1;
    }
    return roundTo(insideCount / n, 9);
  }

  const gaps = cappedGapsMs(sortedFixes);
  let totalWeight = 0;
  let insideWeight = 0;
  for (let i = 0; i < n; i++) {
    const prevCapped = i > 0 ? gaps[i - 1]! : undefined;
    const nextCapped = i < n - 1 ? gaps[i]! : undefined;
    const weight =
      prevCapped !== undefined && nextCapped !== undefined
        ? (prevCapped + nextCapped) / 2
        : (prevCapped ?? nextCapped ?? 0) / 2;
    totalWeight += weight;
    if (isInsidePreparedWithBuffer(sortedFixes[i]!.point, prepared, bufferMeters)) {
      insideWeight += weight;
    }
  }

  // totalWeight > 0 whenever rawDuration > 0: the capped gaps sum to
  // rawDuration exactly when nothing needed capping, and capping can only
  // shrink individual positive gaps toward (never past) zero, so at least
  // one of them — and therefore the sum — stays positive.
  return roundTo(insideWeight / totalWeight, 9);
}
