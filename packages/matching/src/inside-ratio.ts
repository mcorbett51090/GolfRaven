import { roundTo } from "./geo.js";
import { isInsidePreparedWithBuffer, type PreparedPolygonGeometry } from "./polygon.js";
import type { LatLng } from "./types.js";

export interface TimestampedPoint {
  point: LatLng;
  timestamp: number;
}

/**
 * Time-weighted fraction of `sortedFixes`' total duration spent inside
 * `prepared` (+ `bufferMeters`) — build plan gate fix 1: computed on the
 * raw, already-time-sorted fixes, never on a post-simplification vertex
 * count.
 *
 * Each fix is weighted by half of each of its adjacent time intervals (a
 * standard trapezoidal time-weighting): an interior fix's weight is
 * `(gapBefore + gapAfter) / 2`, an endpoint's weight is half its one
 * adjacent gap. Summed across all fixes this equals the route's total
 * duration exactly, so the result is a genuine time fraction, not a point
 * fraction. This makes the ratio robust to sampling-density bias — a long
 * straight stretch and a short winding stretch each count for exactly the
 * wall-clock time they actually took, regardless of how many fixes were
 * recorded during each (unlike counting vertices after Douglas-Peucker
 * simplification, which disproportionately keeps points along a winding
 * path and collapses a straight one to its two endpoints).
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
  if (n === 1) {
    return isInsidePreparedWithBuffer(sortedFixes[0]!.point, prepared, bufferMeters) ? 1 : 0;
  }

  let totalWeight = 0;
  let insideWeight = 0;
  for (let i = 0; i < n; i++) {
    const prevGap = i > 0 ? sortedFixes[i]!.timestamp - sortedFixes[i - 1]!.timestamp : undefined;
    const nextGap = i < n - 1 ? sortedFixes[i + 1]!.timestamp - sortedFixes[i]!.timestamp : undefined;
    const weight =
      prevGap !== undefined && nextGap !== undefined
        ? (prevGap + nextGap) / 2
        : (prevGap ?? nextGap ?? 0) / 2;
    totalWeight += weight;
    if (isInsidePreparedWithBuffer(sortedFixes[i]!.point, prepared, bufferMeters)) {
      insideWeight += weight;
    }
  }

  if (totalWeight <= 0) {
    // Every fix shares one timestamp (or the route is otherwise
    // degenerate): fall back to a plain per-fix average rather than
    // dividing by zero, so a same-instant burst still scores sensibly.
    let insideCount = 0;
    for (const f of sortedFixes) {
      if (isInsidePreparedWithBuffer(f.point, prepared, bufferMeters)) insideCount += 1;
    }
    return insideCount / n;
  }

  return roundTo(insideWeight / totalWeight, 9);
}
