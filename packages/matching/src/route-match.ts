/**
 * Route matching (build plan §7.4 steps 1–4): simplify the route, collect
 * nearby candidates, score each against its geometry, and apply the
 * acceptance / ask_user / typeahead rules.
 */
import { candidatesWithinRadius } from "./candidates.js";
import { computeDurationHours, isWithinDurationWindow } from "./duration.js";
import { computeInsideRatio, computeInsideRatioForCircle, haversineMeters } from "./geo.js";
import { simplifyToMaxPoints } from "./simplify.js";
import type {
  AskUserReason,
  CandidateCourse,
  FacilityDatePick,
  GeometryKind,
  LatLng,
  MatchOutcome,
  MatchRouteInput,
  MatchSummaryFields,
  TiedCandidateSummary,
  VerificationTier,
} from "./types.js";
import { MATCHER_VERSION } from "./version.js";

const DEFAULT_CANDIDATE_RADIUS_METERS = 3000;
const DEFAULT_INSIDE_RATIO_BUFFER_METERS = 30;
const DEFAULT_MAX_SIMPLIFIED_POINTS = 500;
const DEFAULT_TIE_THRESHOLD = 0.15;
const DEFAULT_ACCEPT_INSIDE_RATIO = 0.6;

interface ScoredCandidate {
  candidate: CandidateCourse;
  geometryKind: GeometryKind;
  /** The `insideRatio` value reported in output. For a radius match this
   * is informational only (see `computeInsideRatioForCircle`'s doc
   * comment). */
  insideRatio: number;
  /** The value compared for acceptance and for the 0.15 tie threshold.
   * For a polygon match this equals `insideRatio`. For a radius match it
   * is a boolean-derived 1 (qualifies) or 0 (doesn't) — build plan §4.2:
   * a radius match is decided by start/end containment, "not by
   * insideRatio", so it has no continuous score to compare. Two
   * qualifying radius candidates therefore always tie (score 1 vs 1),
   * which is exactly the outcome build plan §7.4 step 4 wants for
   * "identical radius circles at a 36-hole site" — and, as a side effect,
   * for any two genuinely distinct radius-fallback courses whose circles
   * both happen to contain the route's start and end (see the handback
   * report's ambiguity list). */
  matchScore: number;
  qualifiesGeometrically: boolean;
}

function scoreCandidate(
  candidate: CandidateCourse,
  points: readonly LatLng[],
  start: LatLng,
  end: LatLng,
  bufferMeters: number,
  acceptInsideRatio: number,
): ScoredCandidate | undefined {
  if (candidate.polygon && candidate.polygon.length >= 3) {
    const insideRatio = computeInsideRatio(points, candidate.polygon, bufferMeters);
    return {
      candidate,
      geometryKind: "polygon",
      insideRatio,
      matchScore: insideRatio,
      qualifiesGeometrically: insideRatio >= acceptInsideRatio,
    };
  }
  if (candidate.radiusFallback) {
    const { center, radiusMeters } = candidate.radiusFallback;
    const startInside = haversineMeters(start, center) <= radiusMeters;
    const endInside = haversineMeters(end, center) <= radiusMeters;
    const qualifies = startInside && endInside;
    return {
      candidate,
      geometryKind: "radius",
      insideRatio: computeInsideRatioForCircle(points, center, radiusMeters),
      matchScore: qualifies ? 1 : 0,
      qualifiesGeometrically: qualifies,
    };
  }
  return undefined;
}

function toTiedSummary(s: ScoredCandidate): TiedCandidateSummary {
  return {
    courseId: s.candidate.id,
    facilityId: s.candidate.facilityId,
    verificationTier: s.candidate.verificationTier,
    geometryKind: s.geometryKind,
    insideRatio: s.insideRatio,
    sharedGeometry: s.candidate.sharedGeometry === true,
  };
}

/**
 * Matches a played route against nearby candidate courses (build plan
 * §7.4 steps 1–4). Pure function, no I/O (build plan §3.1 row D): the
 * same code runs on device, in tests, and in server replay.
 */
export function matchRoute(input: MatchRouteInput): MatchOutcome {
  const {
    fixes,
    candidates,
    catalogVersion,
    sourceBundle,
    candidateRadiusMeters = DEFAULT_CANDIDATE_RADIUS_METERS,
    insideRatioBufferMeters = DEFAULT_INSIDE_RATIO_BUFFER_METERS,
    maxSimplifiedPoints = DEFAULT_MAX_SIMPLIFIED_POINTS,
    tieThreshold = DEFAULT_TIE_THRESHOLD,
    acceptInsideRatio = DEFAULT_ACCEPT_INSIDE_RATIO,
  } = input;

  if (fixes.length === 0) {
    throw new RangeError("matchRoute requires at least one fix");
  }

  const rawPoints = fixes.map((f) => f.point);
  const simplifiedPoints = simplifyToMaxPoints(rawPoints, maxSimplifiedPoints);
  const start = rawPoints[0]!;
  const end = rawPoints[rawPoints.length - 1]!;
  const durationHours = computeDurationHours(fixes);
  const anySimulated = fixes.some((f) => f.simulated === true);

  const summary: MatchSummaryFields = {
    matcherVersion: MATCHER_VERSION,
    ...(catalogVersion !== undefined ? { catalogVersion } : {}),
    ...(sourceBundle !== undefined ? { sourceBundle } : {}),
    simulated: anySimulated,
    pointCount: simplifiedPoints.length,
    rawPointCount: rawPoints.length,
    start,
    end,
    durationHours,
  };

  const nearby = candidatesWithinRadius(simplifiedPoints, candidates, candidateRadiusMeters);

  const scored = nearby
    .map((c) => scoreCandidate(c, simplifiedPoints, start, end, insideRatioBufferMeters, acceptInsideRatio))
    .filter((s): s is ScoredCandidate => s !== undefined);

  const qualifying = scored.filter(
    (s) => s.qualifiesGeometrically && isWithinDurationWindow(durationHours, s.candidate.holes),
  );

  if (qualifying.length === 0) {
    return { kind: "typeahead", summary };
  }

  qualifying.sort((a, b) => b.matchScore - a.matchScore);
  const top = qualifying[0]!;
  const tied = qualifying.filter((s) => top.matchScore - s.matchScore <= tieThreshold);

  if (tied.length > 1) {
    const sameFacility = tied.every((s) => s.candidate.facilityId === top.candidate.facilityId);
    const anySharedGeometry = tied.some((s) => s.candidate.sharedGeometry === true);
    const reason: AskUserReason = sameFacility && anySharedGeometry ? "shared_geometry" : "close_scores";
    return {
      kind: "ask_user",
      reason,
      tied: tied.map(toTiedSummary),
      summary,
    };
  }

  return {
    kind: "matched",
    course: {
      courseId: top.candidate.id,
      facilityId: top.candidate.facilityId,
      verificationTier: top.candidate.verificationTier as VerificationTier,
      geometryKind: top.geometryKind,
      insideRatio: top.insideRatio,
      courseDisambiguatedBy: "geometry",
    },
    summary,
  };
}

/**
 * Resolves an `ask_user` outcome once the player has picked a course
 * (build plan §4.3 `course_disambiguated_by = 'user'`) and applies the
 * one-pick-per-facility-per-date guard: "one pick per facility per date …
 * a second, different pick on the same date replaces the first (audited)"
 * (build plan §4.3). Applied uniformly to every `ask_user` resolution,
 * not only the `shared_geometry` reason — see the handback report's
 * ambiguity list for why.
 *
 * Pure function: `priorPicks` is read-only input and the (possibly
 * updated) list is returned for the caller to persist. This package does
 * no I/O.
 */
export function resolveAskUser(
  pick: TiedCandidateSummary,
  localDate: string,
  priorPicks: readonly FacilityDatePick[],
): {
  course: {
    courseId: string;
    facilityId: string;
    verificationTier: VerificationTier;
    geometryKind: GeometryKind;
    insideRatio: number;
    courseDisambiguatedBy: "user";
  };
  updatedPicks: FacilityDatePick[];
  replacedCourseId: string | undefined;
} {
  const existingIndex = priorPicks.findIndex(
    (p) => p.facilityId === pick.facilityId && p.localDate === localDate,
  );
  const replaced = existingIndex >= 0 ? priorPicks[existingIndex] : undefined;
  const nextPick: FacilityDatePick = {
    facilityId: pick.facilityId,
    localDate,
    courseId: pick.courseId,
  };
  const updatedPicks = priorPicks.slice();
  if (existingIndex >= 0) {
    updatedPicks[existingIndex] = nextPick;
  } else {
    updatedPicks.push(nextPick);
  }
  return {
    course: {
      courseId: pick.courseId,
      facilityId: pick.facilityId,
      verificationTier: pick.verificationTier,
      geometryKind: pick.geometryKind,
      insideRatio: pick.insideRatio,
      courseDisambiguatedBy: "user",
    },
    updatedPicks,
    replacedCourseId: replaced && replaced.courseId !== pick.courseId ? replaced.courseId : undefined,
  };
}
