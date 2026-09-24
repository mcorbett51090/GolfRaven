/**
 * `@golfraven/matching` — on-device course matching (build plan §3.1 row
 * D, §7.4): simplify a route, collect nearby candidates (including
 * unverified stubs), compute a time-weighted `insideRatio` (or the
 * radius-fallback containment test), apply the acceptance / ask_user /
 * typeahead rules, and match a single foreground check-in fix. Pure
 * TypeScript, no dependencies: the same code runs on device, in tests,
 * and in server replay for disputes.
 *
 * Deliberately does **not** import `@golfraven/catalog` (its schema is
 * being revised in a parallel workstream) — see `types.ts` for the
 * minimal `CandidateCourse` shape this package defines instead, and
 * `README.md` for the ambiguity list resolved while doing that
 * adaptation.
 *
 * Deciding rewards (`packages/rules` `scorePlay`) is out of scope — this
 * package only produces the `MatchSummary`-shaped output build plan §4.5
 * says the scorer consumes.
 */

export { MATCHER_VERSION } from "./version.js";

export {
  haversineMeters,
  makeProjector,
  centroid,
  roundTo,
  distanceToPolygonMeters,
  isInsidePolygonWithBuffer,
  computeInsideRatio,
} from "./geo.js";
export type { XY, Projector } from "./geo.js";

export {
  normalizePolygon,
  preparePolygonGeometry,
  isInsidePreparedWithBuffer,
  isWithinDistanceOfPrepared,
  distanceToPreparedMeters,
} from "./polygon.js";
export type { PreparedPolygonGeometry } from "./polygon.js";

export {
  computeTimeWeightedInsideRatio,
  computeObservedCoverage,
  MAX_GAP_SECONDS,
  MIN_OBSERVED_COVERAGE,
} from "./inside-ratio.js";

export { simplifyToMaxPoints } from "./simplify.js";

export { computeDurationHours, isWithinDurationWindow } from "./duration.js";

export { validateFixesOrThrow, stableSortByTimestamp } from "./fixes.js";

export { candidatesWithinRadius, isCandidateWithinRadius } from "./candidates.js";

export { matchRoute, resolveAskUser } from "./route-match.js";

export { matchCheckIn } from "./checkin.js";

export type {
  LatLng,
  Ring,
  PolygonWithHoles,
  MultiPolygon,
  PolygonInput,
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
