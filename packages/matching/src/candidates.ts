import { distanceToPolygonMeters, haversineMeters } from "./geo.js";
import type { CandidateCourse, LatLng } from "./types.js";

/** Distance in meters from the nearest of `points` to `candidate`'s
 * geometry (0 if any point is inside it). A candidate with neither a
 * polygon nor a radius-fallback circle can never be matched geometrically
 * and is reported as infinitely far away, so it never enters the
 * candidate set. */
export function minDistanceMetersToGeometry(
  points: readonly LatLng[],
  candidate: CandidateCourse,
): number {
  if (points.length === 0) return Infinity;
  if (candidate.polygon && candidate.polygon.length >= 3) {
    let min = Infinity;
    for (const p of points) {
      const d = distanceToPolygonMeters(p, candidate.polygon);
      if (d < min) min = d;
      if (min === 0) break;
    }
    return min;
  }
  if (candidate.radiusFallback) {
    const { center, radiusMeters } = candidate.radiusFallback;
    let min = Infinity;
    for (const p of points) {
      const d = Math.max(0, haversineMeters(p, center) - radiusMeters);
      if (d < min) min = d;
      if (min === 0) break;
    }
    return min;
  }
  return Infinity;
}

/** Candidates within `radiusMeters` of any point on the (simplified)
 * route — build plan §7.4 step 2: "Collect candidates within 3 km:
 * verified courses plus unverified directory polygons". Unverified stubs
 * are included exactly like any other candidate: this function does not
 * look at `verificationTier` at all. */
export function candidatesWithinRadius(
  points: readonly LatLng[],
  candidates: readonly CandidateCourse[],
  radiusMeters: number,
): CandidateCourse[] {
  return candidates.filter((c) => minDistanceMetersToGeometry(points, c) <= radiusMeters);
}
