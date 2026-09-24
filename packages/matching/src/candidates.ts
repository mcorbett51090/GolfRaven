import { haversineMeters } from "./geo.js";
import { isWithinDistanceOfPrepared, preparePolygonGeometry } from "./polygon.js";
import type { CandidateCourse, LatLng } from "./types.js";

/** True if any of `points` is within `radiusMeters` of `candidate`'s
 * geometry (0 m = inside it). Prepares the candidate's polygon geometry
 * once (projected + bbox) and reuses it across every point, bbox-
 * prefiltered, instead of re-deriving a projector per point (build plan
 * gate fix: project each polygon once per match). Breaks out on the
 * first point found within range. A candidate with neither a polygon nor
 * a radius-fallback circle can never be matched geometrically and is
 * never "within range". */
export function isCandidateWithinRadius(
  points: readonly LatLng[],
  candidate: CandidateCourse,
  radiusMeters: number,
): boolean {
  if (points.length === 0) return false;
  if (candidate.polygon) {
    const prepared = preparePolygonGeometry(candidate.polygon);
    if (!prepared) return false;
    for (const p of points) {
      if (isWithinDistanceOfPrepared(p, prepared, radiusMeters)) return true;
    }
    return false;
  }
  if (candidate.radiusFallback) {
    const { center, radiusMeters: circleRadius } = candidate.radiusFallback;
    for (const p of points) {
      if (haversineMeters(p, center) - circleRadius <= radiusMeters) return true;
    }
    return false;
  }
  return false;
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
  return candidates.filter((c) => isCandidateWithinRadius(points, c, radiusMeters));
}
