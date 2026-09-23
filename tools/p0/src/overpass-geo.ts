/**
 * Pure geometry helpers for `x5-overpass`'s match rule (`docs/p0/X5.md`
 * "Match rule", pre-registered before any query is run — implemented
 * literally, not reinterpreted).
 */

export interface LatLon {
  lat: number;
  lon: number;
}

const EARTH_RADIUS_METERS = 6371000;

/** Great-circle distance in meters (haversine). */
export function haversineMeters(a: LatLon, b: LatLon): number {
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLon = toRad(b.lon - a.lon);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);
  const h =
    Math.sin(dLat / 2) ** 2 + Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLon / 2) ** 2;
  return 2 * EARTH_RADIUS_METERS * Math.asin(Math.min(1, Math.sqrt(h)));
}

/** Standard ray-casting point-in-polygon test. `ring` is treated as a
 * closed polygon (first/last point need not be identical). */
export function pointInPolygon(point: LatLon, ring: LatLon[]): boolean {
  let inside = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const pi = ring[i];
    const pj = ring[j];
    if (!pi || !pj) continue;
    const xi = pi.lon;
    const yi = pi.lat;
    const xj = pj.lon;
    const yj = pj.lat;
    const intersects =
      yi > point.lat !== yj > point.lat &&
      point.lon < ((xj - xi) * (point.lat - yi)) / (yj - yi) + xi;
    if (intersects) inside = !inside;
  }
  return inside;
}

/** Bounding box (south, west, north, east) around a center point, sized by
 * a radius in meters. This is only a *query-fetch* window — how wide a net
 * to cast for Overpass candidates — not itself a pass/fail parameter; the
 * pre-registered pass/fail parameter is the match rule applied to whatever
 * candidates come back (containment, or 500 m name-match). Default radius
 * is documented in `x5-overpass.ts` / README, not X5.md, since X5.md does
 * not pre-register a fetch-window size (only the 500 m name-match radius,
 * which is applied separately in `matchCourse`). */
export function boundingBox(
  center: LatLon,
  radiusMeters: number,
): { south: number; west: number; north: number; east: number } {
  const latDelta = radiusMeters / 111320;
  const lonDelta = radiusMeters / (111320 * Math.cos((center.lat * Math.PI) / 180));
  return {
    south: center.lat - latDelta,
    west: center.lon - lonDelta,
    north: center.lat + latDelta,
    east: center.lon + lonDelta,
  };
}

/** Centroid of a ring, used only as a representative point for the
 * name-match 500 m distance test when a candidate has no single point
 * (e.g. for comparing a way's approximate location to a course's
 * approximate location). Plain arithmetic mean — adequate for a
 * roughly-convex golf-course polygon at the 500 m scale this is used at. */
export function ringCentroid(ring: LatLon[]): LatLon {
  const sum = ring.reduce((acc, p) => ({ lat: acc.lat + p.lat, lon: acc.lon + p.lon }), {
    lat: 0,
    lon: 0,
  });
  return { lat: sum.lat / ring.length, lon: sum.lon / ring.length };
}
