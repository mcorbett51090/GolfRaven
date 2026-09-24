/**
 * Deterministic route simplification (build plan §7.4 step 1: "Simplify
 * the route to at most 500 points. Use Douglas-Peucker or similar, and
 * make it deterministic.").
 *
 * Classic Douglas-Peucker takes a distance tolerance (epsilon), not a
 * target point count, so `simplifyToMaxPoints` binary-searches epsilon
 * over a fixed number of iterations until the simplified result is at or
 * under the cap. The search is over plain floating-point arithmetic with
 * no randomness and a fixed iteration count, so the same input always
 * produces the same output.
 */
import { makeProjector, type Projector } from "./geo.js";
import type { LatLng } from "./types.js";

function perpendicularDistanceMeters(
  point: LatLng,
  lineStart: LatLng,
  lineEnd: LatLng,
  proj: Projector,
): number {
  const p = proj.toXY(point);
  const a = proj.toXY(lineStart);
  const b = proj.toXY(lineEnd);
  const abx = b.x - a.x;
  const aby = b.y - a.y;
  if (abx === 0 && aby === 0) {
    return Math.hypot(p.x - a.x, p.y - a.y);
  }
  const numerator = Math.abs(aby * p.x - abx * p.y + b.x * a.y - b.y * a.x);
  const denominator = Math.hypot(abx, aby);
  return numerator / denominator;
}

function douglasPeucker(points: readonly LatLng[], epsilonMeters: number, proj: Projector): LatLng[] {
  if (points.length < 3) return points.slice();
  let maxDist = 0;
  let splitIndex = 0;
  const first = points[0]!;
  const last = points[points.length - 1]!;
  for (let i = 1; i < points.length - 1; i++) {
    const d = perpendicularDistanceMeters(points[i]!, first, last, proj);
    if (d > maxDist) {
      maxDist = d;
      splitIndex = i;
    }
  }
  if (maxDist > epsilonMeters) {
    const left = douglasPeucker(points.slice(0, splitIndex + 1), epsilonMeters, proj);
    const right = douglasPeucker(points.slice(splitIndex), epsilonMeters, proj);
    return left.slice(0, -1).concat(right);
  }
  return [first, last];
}

function boundingDiagonalMeters(points: readonly LatLng[], proj: Projector): number {
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  for (const p of points) {
    const { x, y } = proj.toXY(p);
    if (x < minX) minX = x;
    if (x > maxX) maxX = x;
    if (y < minY) minY = y;
    if (y > maxY) maxY = y;
  }
  return Math.hypot(maxX - minX, maxY - minY);
}

/** Simplifies `points` to at most `maxPoints` points (minimum 2: start and
 * end are always kept), preserving the original points when the route is
 * already short enough. Deterministic: fixed iteration count, no
 * randomness. */
export function simplifyToMaxPoints(points: readonly LatLng[], maxPoints: number): LatLng[] {
  const cap = Math.max(2, Math.floor(maxPoints));
  if (points.length <= cap) return points.slice();

  const proj = makeProjector(points[0]!);
  const diagonal = boundingDiagonalMeters(points, proj);
  if (diagonal === 0) {
    // Degenerate: every point is (numerically) the same location.
    return [points[0]!, points[points.length - 1]!];
  }

  let lowEpsilon = 0;
  let highEpsilon = diagonal;
  let best = douglasPeucker(points, highEpsilon, proj);

  for (let iteration = 0; iteration < 40; iteration++) {
    const midEpsilon = (lowEpsilon + highEpsilon) / 2;
    const candidate = douglasPeucker(points, midEpsilon, proj);
    if (candidate.length <= cap) {
      best = candidate;
      highEpsilon = midEpsilon;
    } else {
      lowEpsilon = midEpsilon;
    }
  }

  return best;
}
