/**
 * Geo helpers used by `verify-catalog`'s `tz` and geometry-diff gates
 * (§4.1 "Facility time zone (G-P0-11)"; §10 P1 AT(1) "centroid moved > 150
 * m"). No network fetch — everything here is arithmetic over lat/lng plus
 * the runtime's own ICU tz database.
 */

const EARTH_RADIUS_METERS = 6_371_000;

function toRadians(degrees: number): number {
  return (degrees * Math.PI) / 180;
}

/** Great-circle distance in meters (haversine formula). Used for the
 * re-seed spatial-match rule (§4.2 "within 150 m") and the geometry-diff
 * centroid-move gate (§10 P1 AT(1) "centroid moved > 150 m"). */
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
 * The plan flags the "wrong-zone" half of the `tz` gate as resting on a
 * library choice it defers: *"The check uses a pinned time-zone boundary
 * dataset `[unverified — training knowledge; library choice in P1]`."*
 * P1a has no network fetch and ships no such dataset, so this is a
 * longitude-based heuristic, not the real boundary check: it compares the
 * zone's actual UTC offset (read from the runtime's own ICU data, at a
 * fixed non-DST reference instant) against the offset a coordinate's
 * longitude alone would suggest (`round(lng / 15)`), and flags a mismatch
 * only past a wide tolerance. This catches an unambiguously wrong zone
 * (Illinois coordinates tagged `Asia/Tokyo`) but not a genuine boundary
 * error (a few km on the wrong side of a real zone line) — see the P1a
 * report for why the real dataset is out of scope here.
 */
const TZ_OFFSET_TOLERANCE_HOURS = 3;
/** A fixed, non-DST reference instant (January, UTC) so the heuristic does
 * not depend on when `verify-catalog` happens to run. */
const TZ_OFFSET_REFERENCE_INSTANT = new Date("2026-01-15T12:00:00Z");

function actualUtcOffsetHours(tz: string): number {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: tz,
    timeZoneName: "shortOffset",
    hour: "numeric",
  }).formatToParts(TZ_OFFSET_REFERENCE_INSTANT);
  const name = parts.find((p) => p.type === "timeZoneName")?.value;
  if (!name) {
    throw new Error(`could not read a UTC offset for time zone "${tz}"`);
  }
  if (name === "GMT") return 0;
  const match = /^GMT([+-]\d+)(?::(\d+))?$/.exec(name);
  if (!match) {
    throw new Error(
      `unexpected offset format "${name}" for time zone "${tz}"`,
    );
  }
  const hours = Number(match[1]);
  const minutes = match[2] ? Number(match[2]) / 60 : 0;
  return hours >= 0 ? hours + minutes : hours - minutes;
}

function longitudeSuggestedOffsetHours(lng: number): number {
  return Math.round(lng / 15);
}

/** `true` when `tz`'s actual UTC offset is within tolerance of what the
 * coordinate's longitude alone suggests. See the module doc above for what
 * this heuristic does and does not catch. Throws if `tz` is not a real IANA
 * zone name — callers are expected to have already validated that with
 * `IanaTimeZoneSchema`. */
export function tzLikelyContainsCoordinates(
  tz: string,
  coord: { lat: number; lng: number },
): boolean {
  const actual = actualUtcOffsetHours(tz);
  const suggested = longitudeSuggestedOffsetHours(coord.lng);
  return Math.abs(actual - suggested) <= TZ_OFFSET_TOLERANCE_HOURS;
}
