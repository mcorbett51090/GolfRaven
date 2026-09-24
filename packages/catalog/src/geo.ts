/**
 * Geo helpers used by `verify-catalog`'s `tz` and geometry-diff gates
 * (§4.1 "Facility time zone (G-P0-11)"; §10 P1 AT(1) "centroid moved > 150
 * m"). No network fetch — everything here is arithmetic over lat/lng plus
 * the pinned `tz-lookup` package's bundled boundary data.
 */
import tzlookup from "tz-lookup";

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

/**
 * The "wrong-zone" half of the `tz` gate (§4.1: *"The check uses a pinned
 * time-zone boundary dataset `[unverified — training knowledge; library
 * choice in P1]`."*). **Gate-review correction (post-e9b3ab0): this is now
 * a real, pinned, offline boundary lookup**, not a longitude heuristic —
 * the earlier ±3 h offset approximation is retired; the exact fixtures it
 * couldn't discriminate (Knoxville/Chicago vs New_York, Phoenix/Denver,
 * Kenora/Toronto vs Winnipeg, Indianapolis) all resolve correctly under
 * this package.
 *
 * **Library choice, pinned exactly.** [`tz-lookup@6.1.25`](https://www.npmjs.com/package/tz-lookup)
 * (npm, resolved and installed this session — network was reachable).
 * - **License:** CC0-1.0 (public domain dedication) — no attribution
 *   obligation, compatible with anything.
 * - **Data vintage:** the package's own README states its bundled
 *   boundary data, sourced from Evan Siroky's `timezone-boundary-builder`,
 *   *"was last updated on 6 Jan 2019"* — stated here rather than assumed,
 *   since the plan explicitly asked the vintage be named. This is a known
 *   staleness: a handful of real-world zone-boundary or naming changes
 *   since 2019 (rare, and none in the pilot slate's TN/VI/RTJ regions)
 *   would not be reflected. Acceptable for P1a's purpose (catching an
 *   unambiguously wrong zone, not adjudicating a meters-from-the-border
 *   dispute); flagged here so a future re-pin is a deliberate decision,
 *   not a silent gap.
 * - **Size:** ~152 KB unpacked (`tz.js` is ~73 KB), zero runtime
 *   dependencies — small enough to vendor into every environment that
 *   imports `@golfraven/catalog` without materially changing its footprint.
 * - **Mechanism:** synchronous `tzlookup(lat, lng) -> IANA zone name`,
 *   using simplified/compressed boundary polygons (its own README: "the
 *   timezones returned ... are approximate ... expect errors near timezone
 *   borders far away from populated areas" — acceptable for the same
 *   reason as the data-vintage note above).
 *
 * This function compares `tz-lookup`'s own answer for the coordinate
 * against the facility's declared `tz`, by exact string equality — two
 * IANA names can denote the same underlying rules (e.g. historical
 * aliases), but P1a does not attempt alias resolution; an exact match is
 * the literal, unambiguous reading of "does this tz contain this
 * coordinate".
 */
export function tzLikelyContainsCoordinates(
  tz: string,
  coord: { lat: number; lng: number },
): boolean {
  return tzlookup(coord.lat, coord.lng) === tz;
}
