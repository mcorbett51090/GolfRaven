/**
 * Foreground check-in matching (build plan §7.4 step 5): "one fix with
 * accuracy ≤ 50 m, inside the polygon + 50 m; the `simulated` flag must be
 * read, and a simulated fix is rejected; attestation is out of scope, but
 * accept an opaque assertion field and pass it through."
 *
 * **Fails closed** (build plan gate fix): this function is a boundary
 * that receives untrusted data (a device outbox payload, or a server
 * replay of stored JSON — build plan §3.1 row D, §3.3), where
 * `CheckInFix`'s declared types are not runtime guarantees. Every check
 * below is a strict, explicit validation, not a type-trusting shortcut —
 * anything that doesn't unambiguously satisfy the rule is rejected, never
 * silently coerced or defaulted into acceptance.
 */
import { haversineMeters, roundTo } from "./geo.js";
import { isInsidePreparedWithBuffer, preparePolygonGeometry } from "./polygon.js";
import type { CandidateCourse, CheckInFix, CheckInResult } from "./types.js";

const CHECKIN_ACCURACY_MAX_METERS = 50;
const CHECKIN_BUFFER_METERS = 50;

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** Matches a single foreground check-in fix against one candidate course.
 * The caller picks which candidate to check against (typically the one
 * the player is looking at in the app); this function does not search —
 * use `matchRoute`'s candidate search for that. */
export function matchCheckIn(fix: CheckInFix, candidate: CandidateCourse): CheckInResult {
  // Fails closed on malformed coordinates before anything else — an
  // invalid point can't be meaningfully tested against any geometry.
  if (
    !isFiniteNumber(fix.point?.lat) ||
    !isFiniteNumber(fix.point?.lon) ||
    !isFiniteNumber(fix.timestamp)
  ) {
    return { accepted: false, reason: "invalid_fix" };
  }

  // `simulated` must be the literal boolean `false`. `undefined`, `null`,
  // a truthy value, or anything else fails closed as "treat as
  // simulated" — the build plan requires the flag to be read and a
  // simulated fix rejected; it never says an *absent* flag is safe to
  // wave through.
  if (fix.simulated !== false) {
    return { accepted: false, reason: "simulated" };
  }

  // Accuracy must be a finite, non-negative number at or under 50 m.
  // `NaN` (including a `NaN` that round-tripped through JSON as `null`),
  // `Infinity`, and a negative value are all rejected — none of them
  // satisfy "accuracy ≤ 50 m".
  if (
    !isFiniteNumber(fix.accuracyMeters) ||
    fix.accuracyMeters < 0 ||
    roundTo(fix.accuracyMeters, 2) > roundTo(CHECKIN_ACCURACY_MAX_METERS, 2)
  ) {
    return { accepted: false, reason: "inaccurate" };
  }

  let inside: boolean;
  let geometryKind: "polygon" | "radius";
  if (candidate.polygon) {
    const prepared = preparePolygonGeometry(candidate.polygon);
    if (!prepared) return { accepted: false, reason: "no_geometry" };
    geometryKind = "polygon";
    inside = isInsidePreparedWithBuffer(fix.point, prepared, CHECKIN_BUFFER_METERS);
  } else if (candidate.radiusFallback) {
    geometryKind = "radius";
    const { center, radiusMeters } = candidate.radiusFallback;
    inside =
      roundTo(haversineMeters(fix.point, center), 2) <= roundTo(radiusMeters + CHECKIN_BUFFER_METERS, 2);
  } else {
    return { accepted: false, reason: "no_geometry" };
  }

  if (!inside) {
    return { accepted: false, reason: "outside_polygon" };
  }

  return {
    accepted: true,
    courseId: candidate.id,
    facilityId: candidate.facilityId,
    verificationTier: candidate.verificationTier,
    geometryKind,
    point: fix.point,
    accuracyMeters: fix.accuracyMeters,
    timestamp: fix.timestamp,
    ...(fix.attestationAssertion !== undefined
      ? { attestationAssertion: fix.attestationAssertion }
      : {}),
  };
}
