/**
 * Foreground check-in matching (build plan §7.4 step 5): "one fix with
 * accuracy ≤ 50 m, inside the polygon + 50 m; the `simulated` flag must be
 * read, and a simulated fix is rejected; attestation is out of scope, but
 * accept an opaque assertion field and pass it through."
 */
import { haversineMeters, isInsidePolygonWithBuffer } from "./geo.js";
import type { CandidateCourse, CheckInFix, CheckInResult } from "./types.js";

const CHECKIN_ACCURACY_MAX_METERS = 50;
const CHECKIN_BUFFER_METERS = 50;

/** Matches a single foreground check-in fix against one candidate course.
 * The caller picks which candidate to check against (typically the one
 * the player is looking at in the app); this function does not search —
 * use `matchRoute`'s candidate search for that. */
export function matchCheckIn(fix: CheckInFix, candidate: CandidateCourse): CheckInResult {
  if (fix.simulated) {
    return { accepted: false, reason: "simulated" };
  }
  if (fix.accuracyMeters > CHECKIN_ACCURACY_MAX_METERS) {
    return { accepted: false, reason: "inaccurate" };
  }

  let inside: boolean;
  let geometryKind: "polygon" | "radius";
  if (candidate.polygon && candidate.polygon.length >= 3) {
    geometryKind = "polygon";
    inside = isInsidePolygonWithBuffer(fix.point, candidate.polygon, CHECKIN_BUFFER_METERS);
  } else if (candidate.radiusFallback) {
    geometryKind = "radius";
    const { center, radiusMeters } = candidate.radiusFallback;
    inside = haversineMeters(fix.point, center) <= radiusMeters + CHECKIN_BUFFER_METERS;
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
