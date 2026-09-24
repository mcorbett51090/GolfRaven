/**
 * `@golfraven/matching` — on-device course matching (build plan §3.1 row
 * D, §7.4): simplify a route, collect nearby candidates (including
 * unverified stubs), compute `insideRatio` (or the radius-fallback
 * containment test), apply the acceptance / ask_user / typeahead rules,
 * and match a single foreground check-in fix. Pure TypeScript, no
 * dependencies: the same code runs on device, in tests, and in server
 * replay for disputes.
 *
 * Deliberately does **not** import `@golfraven/catalog` (its schema is
 * being revised in a parallel workstream) — see `types.ts` for the
 * minimal `CandidateCourse` shape this package defines instead, and the
 * handback report for how to adapt catalog rows into it.
 *
 * Deciding rewards (`packages/rules` `scorePlay`) is out of scope — this
 * package only produces the `MatchSummary`-shaped output build plan §4.5
 * says the scorer consumes.
 */

export { MATCHER_VERSION } from "./version.js";

export {
  haversineMeters,
  makeProjector,
  distanceToPolygonMeters,
  isInsidePolygonWithBuffer,
  computeInsideRatio,
  computeInsideRatioForCircle,
} from "./geo.js";
export type { XY, Projector } from "./geo.js";

export { simplifyToMaxPoints } from "./simplify.js";

export { computeDurationHours, isWithinDurationWindow } from "./duration.js";

export { candidatesWithinRadius, minDistanceMetersToGeometry } from "./candidates.js";

export { matchRoute, resolveAskUser } from "./route-match.js";

export { matchCheckIn } from "./checkin.js";

export type {
  LatLng,
  RadiusFallbackCircle,
  VerificationTier,
  CandidateCourse,
  RouteFix,
  GeometryKind,
  CourseDisambiguatedBy,
  MatchSummaryFields,
  MatchedCourse,
  TiedCandidateSummary,
  AskUserReason,
  MatchOutcome,
  MatchRouteInput,
  FacilityDatePick,
  CheckInFix,
  CheckInResult,
} from "./types.js";
