/**
 * Geo helpers used by `verify-catalog`'s `tz` and geometry-diff gates
 * (§4.1 "Facility time zone (G-P0-11)"; §10 P1 AT(1) "centroid moved > 150
 * m"). No network fetch — everything here is arithmetic over lat/lng plus
 * the pinned `tz-lookup` package's bundled boundary data and the vendored
 * tzdb backward-links table (`tzdb-backward-links.json`).
 */
import tzlookup from "tz-lookup";
import tzdbBackward from "./tzdb-backward-links.json" with { type: "json" };

const EARTH_RADIUS_METERS = 6_371_000;

function toRadians(degrees: number): number {
  return (degrees * Math.PI) / 180;
}

/** Great-circle distance in meters (haversine formula). Used for the
 * re-seed spatial-match rule (§4.2 "within 150 m") and the geometry-diff
 * coordinate-move gate (§10 P1 AT(1) "centroid moved > 150 m"). */
export function haversineDistanceMeters(
  a: { lat: number; lng: number },
  b: { lat: number; lng: number },
): number {
  const dLat = toRadians(b.lat - a.lat);
  const dLng = toRadians(b.lng - a.lng);
  const lat1 = toRadians(a.lat);
  const lat2 = toRadians(b.lat);
  const sinDLat = Math.sin(dLat / 2);
  const sinDLng = Math.sin(dLng / 2);
  const h =
    sinDLat * sinDLat + Math.cos(lat1) * Math.cos(lat2) * sinDLng * sinDLng;
  const c = 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
  return EARTH_RADIUS_METERS * c;
}

/** Offsets a coordinate by `meters` due north/south/east/west. Local
 * equirectangular approximation (fine at the 5 km scale this is used at —
 * see `tzLikelyContainsCoordinates`'s border-tolerance doc). */
function offsetCoordinate(
  coord: { lat: number; lng: number },
  bearing: "N" | "S" | "E" | "W",
  meters: number,
): { lat: number; lng: number } {
  const metersPerDegreeLat = (Math.PI / 180) * EARTH_RADIUS_METERS;
  const metersPerDegreeLng = metersPerDegreeLat * Math.cos(toRadians(coord.lat));
  switch (bearing) {
    case "N":
      return { lat: coord.lat + meters / metersPerDegreeLat, lng: coord.lng };
    case "S":
      return { lat: coord.lat - meters / metersPerDegreeLat, lng: coord.lng };
    case "E":
      return { lat: coord.lat, lng: coord.lng + meters / metersPerDegreeLng };
    case "W":
      return { lat: coord.lat, lng: coord.lng - meters / metersPerDegreeLng };
  }
}

/**
 * Canonicalizes an IANA zone name through the vendored tzdb backward-links
 * table (`tzdb-backward-links.json` — its own `tzdbVersion` field records
 * the pinned tzdb release, exported here as `TZDB_BACKWARD_LINKS_VERSION`).
 * A name not in the table (already canonical, or simply unknown) is
 * returned unchanged. Follows at most a few hops with cycle protection,
 * though the real backward file is a flat alias -> canonical map (single
 * hop) as of this pin.
 */
const BACKWARD_LINKS: Record<string, string> = tzdbBackward.links;
export const TZDB_BACKWARD_LINKS_VERSION: string = tzdbBackward.tzdbVersion;

export function canonicalizeTimeZone(tz: string): string {
  let current = tz;
  const seen = new Set<string>();
  for (;;) {
    const next = BACKWARD_LINKS[current];
    if (next === undefined || seen.has(current)) break; // defensive: the real table has no cycles
    seen.add(current);
    current = next;
  }
  return current;
}

/**
 * The "wrong-zone" half of the `tz` gate (§4.1: *"The check uses a pinned
 * time-zone boundary dataset `[unverified — training knowledge; library
 * choice in P1]`."*). A real, pinned, offline boundary lookup — see
 * `tz-lookup`'s license/vintage/size writeup, unchanged from round 1.
 *
 * **Round 2 additions (gate review):**
 *
 * 1. **Link-table canonicalization, both sides.** `tz-lookup`'s bundled
 *    data (vintage "6 Jan 2019") still returns pre-2022-merge Canadian zone
 *    names for some coordinates (e.g. Thunder Bay -> `America/Thunder_Bay`,
 *    not the now-canonical `America/Toronto`), and a facility may
 *    legitimately declare a legacy alias (`America/Indianapolis` rather
 *    than `America/Indiana/Indianapolis`). Comparing raw strings made both
 *    of those fail incorrectly. Both `tz-lookup`'s answer and the
 *    facility's declared `tz` are now canonicalized through
 *    `canonicalizeTimeZone` before comparing.
 * 2. **Border tolerance (~5 km).** `tz-lookup`'s simplified polygons can
 *    misattribute a point within a few km of a real zone boundary to the
 *    wrong neighbour entirely (not a linkable alias — a genuinely
 *    different zone, e.g. Rainy River, ON reads as `America/Chicago`
 *    instead of `America/Winnipeg`). Rather than trying to detect
 *    "near a boundary" directly (this package has no polygon data, only
 *    point lookups), this looks up 4 more points 5 km due
 *    north/south/east/west of the declared coordinate and accepts the
 *    declared `tz` if ANY of the 5 lookups (center + 4 offsets),
 *    canonicalized, matches it. This can only make the check MORE
 *    permissive near a boundary — it never accepts a zone that isn't
 *    within 5 km of the declared point under this package's own lookup.
 */
const BORDER_TOLERANCE_METERS = 5_000;

export function tzLikelyContainsCoordinates(
  tz: string,
  coord: { lat: number; lng: number },
): boolean {
  const declaredCanonical = canonicalizeTimeZone(tz);
  const points = [
    coord,
    offsetCoordinate(coord, "N", BORDER_TOLERANCE_METERS),
    offsetCoordinate(coord, "S", BORDER_TOLERANCE_METERS),
    offsetCoordinate(coord, "E", BORDER_TOLERANCE_METERS),
    offsetCoordinate(coord, "W", BORDER_TOLERANCE_METERS),
  ];
  return points.some(
    (p) => canonicalizeTimeZone(tzlookup(p.lat, p.lng)) === declaredCanonical,
  );
}
