/**
 * Deterministic route simplification (build plan §7.4 step 1: "Simplify
 * the route to at most 500 points. Use Douglas-Peucker or similar, and
 * make it deterministic.") — used only to shrink the transmitted summary
 * / geometry, never to compute `insideRatio` (build plan gate fix 1; see
 * `inside-ratio.ts`).
 *
 * **Algorithm.** Classic Douglas-Peucker takes a distance tolerance
 * (epsilon), not a target point count, so the original implementation
 * binary-searched epsilon — running a full DP pass on every iteration
 * (~40 full passes for one simplification). That is correct but wasteful.
 * This version instead runs the recursive subdivision **once**, and
 * records each point's "importance": the perpendicular deviation value at
 * which that point would first be kept if DP were run with a
 * progressively smaller epsilon. Picking the top `maxPoints` points by
 * that importance (breaking ties by original index, for determinism) is
 * then a single sort — no repeated re-simplification. This is the same
 * "hierarchical Douglas-Peucker" idea used by tools like Mapshaper's
 * "weighted" simplification, applied here purely to satisfy a point-count
 * cap rather than a semantic epsilon.
 *
 * The subdivision itself uses an explicit stack over index ranges (no
 * recursion, no `Array.slice` copies at each level) — build plan gate fix
 * (performance): this avoids both the O(n log n) allocation churn of
 * slicing at every level AND any risk of a native stack overflow on a
 * pathological, very long or spiral-shaped route.
 */
import {
  distancePointToSegment,
  makeProjector,
  type Projector,
  type XY,
} from "./geo.js";
import type { LatLng } from "./types.js";

function boundingDiagonalMeters(xy: readonly XY[]): number {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const { x, y } of xy) {
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  }
  return Math.hypot(maxX - minX, maxY - minY);
}

/** Computes each point's DP "importance" (see module doc comment) over
 * pre-projected coordinates `xy`, via an explicit index-range stack. The
 * first and last points always get `Infinity` (always kept). */
function computeImportances(xy: readonly XY[]): Float64Array {
  const n = xy.length;
  const importance = new Float64Array(n);
  if (n === 0) return importance;
  importance[0] = Infinity;
  importance[n - 1] = Infinity;
  if (n < 3) return importance;

  const stack: number[] = [0, n - 1];
  while (stack.length > 0) {
    const endIdx = stack.pop()!;
    const startIdx = stack.pop()!;
    if (endIdx - startIdx < 2) continue;
    const a = xy[startIdx]!;
    const b = xy[endIdx]!;
    let maxDist = -1;
    let splitIdx = -1;
    for (let i = startIdx + 1; i < endIdx; i++) {
      const d = distancePointToSegment(xy[i]!, a, b);
      if (d > maxDist) {
        maxDist = d;
        splitIdx = i;
      }
    }
    if (splitIdx === -1) continue;
    importance[splitIdx] = maxDist;
    stack.push(startIdx, splitIdx, splitIdx, endIdx);
  }
  return importance;
}

/** Simplifies `points` to at most `maxPoints` points (minimum 2: start and
 * end are always kept), preserving the original points when the route is
 * already short enough. Deterministic: no randomness, ties in importance
 * broken by original index. */
export function simplifyToMaxPoints(
  points: readonly LatLng[],
  maxPoints: number,
): LatLng[] {
  const cap = Math.max(2, Math.floor(maxPoints));
  const n = points.length;
  if (n <= cap) return points.slice();

  const proj: Projector = makeProjector(points[0]!);
  const xy = points.map((p) => proj.toXY(p));

  if (boundingDiagonalMeters(xy) === 0) {
    // Degenerate: every point is (numerically) the same location.
    return [points[0]!, points[n - 1]!];
  }

  const importance = computeImportances(xy);
  const indices = Array.from({ length: n }, (_, i) => i);
  indices.sort((a, b) => {
    const diff = importance[b]! - importance[a]!;
    return diff !== 0 ? diff : a - b;
  });
  const kept = indices.slice(0, cap).sort((a, b) => a - b);
  return kept.map((i) => points[i]!);
}
