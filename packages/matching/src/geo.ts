/**
 * Geodesic-correct-enough geometry helpers.
 *
 * Distances use the haversine formula (great-circle, spherical-Earth).
 * Polygon math (point-in-polygon, buffer distance, simplification) needs a
 * planar coordinate system, so points are projected into a **local
 * equirectangular ("plate carrée") plane** centered on the geometry being
 * tested, using the standard `cos(lat0)` longitude-scaling correction:
 *
 *   x = (lon - lon0) * cos(lat0) * R * (π / 180)
 *   y = (lat - lat0) * R * (π / 180)
 *
 * **Error bound (corrected — the previous version of this comment
 * overstated the projection's accuracy by treating the error as a
 * second-order (extent/R)² quantity; it is first order in latitude
 * offset).** Holding longitude fixed and varying only latitude by Δlat
 * from the origin, the equirectangular y-coordinate is exact for the
 * meridional arc length in the small-angle limit, but the `cos(lat0)`
 * longitude scale factor is evaluated at the *origin's* latitude, not at
 * the point's own latitude — so the x-coordinate's error grows
 * approximately linearly with Δlat (via `cos(lat0) - cos(lat0 + Δlat) ≈
 * Δlat · sin(lat0)`), not quadratically. Concretely, projecting a point
 * 3 km due north of a 49°N origin (Δlat ≈ 3000/R ≈ 0.027°) introduces an
 * east-west scale error of about `3000 · tan(49°) · (3000/R) ≈ 1.6 m` at
 * the far edge of that span — first order in the offset, not the
 * sub-millimeter figure a naive (extent/R)² estimate would suggest. That
 * ~1.6 m is still well under the 30 m / 50 m buffers this package applies
 * (roughly 5%), but it is not negligible in the way the old comment
 * claimed, and it grows with `|Δlat|` and with `tan(latitude)`, so it is
 * measurably worse near the poles. Every projection in this package is
 * re-centered locally (per course, or per route in `simplify.ts`), which
 * keeps `Δlat` bounded to a few km and keeps this error a small fraction
 * of the buffers — but it is a real, first-order effect, not a rounding
 * artifact.
 */
import type { LatLng } from "./types.js";

const EARTH_RADIUS_METERS = 6_371_000;

function toRadians(degrees: number): number {
  return (degrees * Math.PI) / 180;
}

/** Great-circle distance between two points, in meters. */
export function haversineMeters(a: LatLng, b: LatLng): number {
  const dLat = toRadians(b.lat - a.lat);
  const dLon = toRadians(b.lon - a.lon);
  const lat1 = toRadians(a.lat);
  const lat2 = toRadians(b.lat);
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_METERS * Math.asin(Math.min(1, Math.sqrt(h)));
}

export interface XY {
  x: number;
  y: number;
}

export interface Projector {
  toXY(point: LatLng): XY;
}

/** Builds a local equirectangular projector centered at `origin`. See the
 * module doc comment for the error bound. */
export function makeProjector(origin: LatLng): Projector {
  const lat0 = toRadians(origin.lat);
  const metersPerDegreeLat = EARTH_RADIUS_METERS * (Math.PI / 180);
  const metersPerDegreeLon =
    EARTH_RADIUS_METERS * (Math.PI / 180) * Math.cos(lat0);
  return {
    toXY(point: LatLng): XY {
      return {
        x: (point.lon - origin.lon) * metersPerDegreeLon,
        y: (point.lat - origin.lat) * metersPerDegreeLat,
      };
    },
  };
}

export function centroid(points: readonly LatLng[]): LatLng {
  let lat = 0;
  let lon = 0;
  for (const p of points) {
    lat += p.lat;
    lon += p.lon;
  }
  return { lat: lat / points.length, lon: lon / points.length };
}

/**
 * Rounds `value` to `decimals` decimal places. Used wherever a boundary
 * comparison (an acceptance threshold, a buffer, a tie gap) decides the
 * matcher's outcome, so that a sub-ULP difference in trigonometric
 * function results between JS engines (see `version.ts`) can never flip a
 * decision that both engines "morally" agree on (build plan gate fix:
 * determinism).
 */
export function roundTo(value: number, decimals: number): number {
  if (!Number.isFinite(value)) return value;
  const factor = 10 ** decimals;
  return Math.round(value * factor) / factor;
}

/** Ray-casting point-in-polygon test on projected (planar) coordinates.
 * The ring is treated as closed regardless of whether the first and last
 * points repeat. */
export function pointInPolygonXY(point: XY, ring: readonly XY[]): boolean {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const a = ring[i]!;
    const b = ring[j]!;
    const intersects =
      a.y > point.y !== b.y > point.y &&
      point.x < ((b.x - a.x) * (point.y - a.y)) / (b.y - a.y) + a.x;
    if (intersects) inside = !inside;
  }
  return inside;
}

export function distancePointToSegment(point: XY, a: XY, b: XY): number {
  const abx = b.x - a.x;
  const aby = b.y - a.y;
  const lengthSquared = abx * abx + aby * aby;
  if (lengthSquared === 0) {
    return Math.hypot(point.x - a.x, point.y - a.y);
  }
  let t = ((point.x - a.x) * abx + (point.y - a.y) * aby) / lengthSquared;
  t = Math.max(0, Math.min(1, t));
  const projX = a.x + t * abx;
  const projY = a.y + t * aby;
  return Math.hypot(point.x - projX, point.y - projY);
}

/** Distance in meters from `point` to the nearest edge of `ring` — always
 * the boundary distance, regardless of whether `point` is inside or
 * outside the ring. (Contrast with `distanceToPolygonMeters`, which
 * returns 0 for an inside point.) Used for hole rings, where "inside the
 * hole ring" does not mean "distance 0" the way it does for an outer
 * ring. */
export function distanceToRingBoundaryXY(
  point: XY,
  ring: readonly XY[],
): number {
  let min = Infinity;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const d = distancePointToSegment(point, ring[j]!, ring[i]!);
    if (d < min) min = d;
  }
  return min;
}

/** Distance in meters from `point` to `polygon`: 0 if the point is inside,
 * otherwise the distance to the nearest edge. Requires at least 3
 * vertices. This is the single-ring primitive (no hole awareness — for a
 * candidate's full polygon-with-holes/multipolygon geometry, see
 * `polygon.ts`). */
export function distanceToPolygonMeters(
  point: LatLng,
  polygon: readonly LatLng[],
): number {
  if (polygon.length < 3) return Infinity;
  const origin = centroid(polygon);
  const proj = makeProjector(origin);
  const ring = polygon.map((p) => proj.toXY(p));
  const pt = proj.toXY(point);
  if (pointInPolygonXY(pt, ring)) return 0;
  return distanceToRingBoundaryXY(pt, ring);
}

/** True if `point` is inside `polygon`, or within `bufferMeters` of its
 * boundary (build plan §7.4 step 3 / §4.5 co-signal definition: "inside
 * the facility's polygon + 50 m", "inside polygon + 30 m buffer"). Single
 * ring, no hole awareness — see `polygon.ts` for the full-geometry
 * version used by route/check-in matching. */
export function isInsidePolygonWithBuffer(
  point: LatLng,
  polygon: readonly LatLng[],
  bufferMeters: number,
): boolean {
  return (
    roundTo(distanceToPolygonMeters(point, polygon), 2) <=
    roundTo(Math.max(0, bufferMeters), 2)
  );
}

/** Fraction of `points` that fall inside `polygon` (+ `bufferMeters`),
 * counted **per vertex** (not time-weighted). This is the original, naive
 * ratio — kept for callers that genuinely want a plain vertex count (e.g.
 * a quick density check), and deliberately NOT used by `matchRoute` for
 * its `insideRatio` any more: a per-vertex ratio computed after route
 * simplification is biased by which segments Douglas-Peucker happened to
 * compress (a long straight stretch collapses to ~2 points regardless of
 * its real duration, a winding stretch of the same duration keeps many).
 * `matchRoute` uses `computeTimeWeightedInsideRatio` (`polygon.ts`)
 * instead, on the raw, time-sorted fixes. Returns 0 for an empty point
 * list. */
export function computeInsideRatio(
  points: readonly LatLng[],
  polygon: readonly LatLng[],
  bufferMeters: number,
): number {
  if (points.length === 0) return 0;
  let inside = 0;
  for (const p of points) {
    if (isInsidePolygonWithBuffer(p, polygon, bufferMeters)) inside += 1;
  }
  return inside / points.length;
}
