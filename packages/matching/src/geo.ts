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
 * **Error bound.** This projection's distortion grows with distance from
 * the origin and is a *relative* error on the order of (extent / R)²,
 * where `extent` is the geometry's span and R is Earth's radius
 * (≈ 6,371,000 m). A golf course's polygon spans at most a few hundred
 * meters to ~2 km; even generously bounding `extent` at 3 km (the
 * candidate-search radius, the largest span anything here is projected
 * over) gives (3,000 / 6,371,000)² ≈ 2.2e-7, i.e. sub-millimeter absolute
 * distortion over a 3 km span. That is many orders of magnitude below the
 * 30 m / 50 m buffers this package applies, so it is negligible for every
 * use in this package. (It would NOT be negligible projected over
 * hundreds of kilometers — this package never does that; every projection
 * here is re-centered locally per course or per route.)
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
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
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
  const metersPerDegreeLon = EARTH_RADIUS_METERS * (Math.PI / 180) * Math.cos(lat0);
  return {
    toXY(point: LatLng): XY {
      return {
        x: (point.lon - origin.lon) * metersPerDegreeLon,
        y: (point.lat - origin.lat) * metersPerDegreeLat,
      };
    },
  };
}

function centroid(points: readonly LatLng[]): LatLng {
  let lat = 0;
  let lon = 0;
  for (const p of points) {
    lat += p.lat;
    lon += p.lon;
  }
  return { lat: lat / points.length, lon: lon / points.length };
}

/** Ray-casting point-in-polygon test on projected (planar) coordinates.
 * The ring is treated as closed regardless of whether the first and last
 * points repeat. */
function pointInPolygonXY(point: XY, ring: readonly XY[]): boolean {
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

function distancePointToSegment(point: XY, a: XY, b: XY): number {
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

function distanceToPolygonBoundaryXY(point: XY, ring: readonly XY[]): number {
  let min = Infinity;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const d = distancePointToSegment(point, ring[j]!, ring[i]!);
    if (d < min) min = d;
  }
  return min;
}

/** Distance in meters from `point` to `polygon`: 0 if the point is inside,
 * otherwise the distance to the nearest edge. Requires at least 3
 * vertices. */
export function distanceToPolygonMeters(point: LatLng, polygon: readonly LatLng[]): number {
  if (polygon.length < 3) return Infinity;
  const origin = centroid(polygon);
  const proj = makeProjector(origin);
  const ring = polygon.map((p) => proj.toXY(p));
  const pt = proj.toXY(point);
  if (pointInPolygonXY(pt, ring)) return 0;
  return distanceToPolygonBoundaryXY(pt, ring);
}

/** True if `point` is inside `polygon`, or within `bufferMeters` of its
 * boundary (build plan §7.4 step 3 / §4.5 co-signal definition: "inside
 * the facility's polygon + 50 m", "inside polygon + 30 m buffer"). */
export function isInsidePolygonWithBuffer(
  point: LatLng,
  polygon: readonly LatLng[],
  bufferMeters: number,
): boolean {
  return distanceToPolygonMeters(point, polygon) <= Math.max(0, bufferMeters);
}

/** Fraction of `points` that fall inside `polygon` (+ `bufferMeters`).
 * Returns 0 for an empty point list. */
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

/** Fraction of `points` within `circle` (no buffer — see build plan §4.2:
 * a radius-fallback match is decided by start/end containment, not by a
 * ratio; this is informational only, reported in `MatchedCourse.insideRatio`
 * for a radius-kind match). */
export function computeInsideRatioForCircle(
  points: readonly LatLng[],
  center: LatLng,
  radiusMeters: number,
): number {
  if (points.length === 0) return 0;
  let inside = 0;
  for (const p of points) {
    if (haversineMeters(p, center) <= radiusMeters) inside += 1;
  }
  return inside / points.length;
}
