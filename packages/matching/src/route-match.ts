/**
 * Route matching (build plan §7.4 steps 1–4): simplify the route (for the
 * transmitted summary only), collect nearby candidates, score each
 * against its geometry, and apply the acceptance / ask_user / typeahead
 * rules.
 */
import { candidatesWithinRadius } from "./candidates.js";
import { computeDurationHours, isWithinDurationWindow } from "./duration.js";
import { validateFixesOrThrow, stableSortByTimestamp } from "./fixes.js";
import { haversineMeters, roundTo } from "./geo.js";
import {
  computeObservedCoverage,
  computeTimeWeightedInsideRatio,
  MIN_OBSERVED_COVERAGE,
} from "./inside-ratio.js";
import { preparePolygonGeometry } from "./polygon.js";
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
  /** `null` for a radius candidate — see `MatchedCourse.insideRatio`'s
   * doc comment: a radius match is never ranked on the polygon's
   * insideRatio scale (build plan gate fix 2). */
  insideRatio: number | null;
  radiusStartEndInside: boolean;
  /** The value compared for ranking and for the tie threshold. Only ever
   * compared *within* one geometry tier (see `matchRoute`): polygon
   * candidates are scored by `insideRatio`, and are ranked strictly ahead
   * of every radius candidate regardless of any radius candidate's own
   * `score`, which exists only so multiple qualifying radius candidates
   * can be gap-compared against each other. */
  score: number;
  qualifiesGeometrically: boolean;
  qualifies: boolean;
}

function scoreCandidate(
  candidate: CandidateCourse,
  sortedTimestampedPoints: readonly { point: LatLng; timestamp: number }[],
  start: LatLng,
  end: LatLng,
  bufferMeters: number,
  acceptInsideRatio: number,
  durationHours: number,
  observedCoverage: number,
  minObservedCoverage: number,
): ScoredCandidate | undefined {
  if (candidate.polygon) {
    const prepared = preparePolygonGeometry(candidate.polygon);
    if (!prepared) return undefined;
    const insideRatio = computeTimeWeightedInsideRatio(sortedTimestampedPoints, prepared, bufferMeters);
    const qualifiesRatio = roundTo(insideRatio, 9) >= roundTo(acceptInsideRatio, 9);
    const qualifiesCoverage = roundTo(observedCoverage, 9) >= roundTo(minObservedCoverage, 9);
    const qualifiesGeometrically = qualifiesRatio && qualifiesCoverage;
    const qualifiesDuration = isWithinDurationWindow(durationHours, candidate.holes);
    return {
      candidate,
      geometryKind: "polygon",
      insideRatio,
      radiusStartEndInside: false,
      score: insideRatio,
      qualifiesGeometrically,
      qualifies: qualifiesGeometrically && qualifiesDuration,
    };
  }
  if (candidate.radiusFallback) {
    const { center, radiusMeters } = candidate.radiusFallback;
    const startInside = roundTo(haversineMeters(start, center), 2) <= roundTo(radiusMeters, 2);
    const endInside = roundTo(haversineMeters(end, center), 2) <= roundTo(radiusMeters, 2);
    const qualifiesGeometrically = startInside && endInside;
    const qualifiesDuration = isWithinDurationWindow(durationHours, candidate.holes);
    return {
      candidate,
      geometryKind: "radius",
      insideRatio: null,
      radiusStartEndInside: qualifiesGeometrically,
      score: qualifiesGeometrically ? 1 : 0,
      qualifiesGeometrically,
      qualifies: qualifiesGeometrically && qualifiesDuration,
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
    ...(s.geometryKind === "radius" ? { radiusStartEndInside: true as const } : {}),
    sharedGeometry: s.candidate.sharedGeometry === true,
  };
}

/** Ordinal (not locale-aware) string comparison, so candidate ordering
 * never depends on ICU/locale differences between JS engines (build plan
 * gate fix: determinism). */
function compareIds(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

function byScoreThenId(a: ScoredCandidate, b: ScoredCandidate): number {
  const scoreDiff = roundTo(b.score, 9) - roundTo(a.score, 9);
  if (scoreDiff !== 0) return scoreDiff;
  return compareIds(a.candidate.id, b.candidate.id);
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
  validateFixesOrThrow(fixes);

  const sortedFixes = stableSortByTimestamp(fixes);
  const rawPoints = sortedFixes.map((f) => f.point);
  const simplifiedPoints = simplifyToMaxPoints(rawPoints, maxSimplifiedPoints);
  const start = rawPoints[0]!;
  const end = rawPoints[rawPoints.length - 1]!;
  const startedAt = sortedFixes[0]!.timestamp;
  const endedAt = sortedFixes[sortedFixes.length - 1]!.timestamp;
  const durationHours = computeDurationHours(sortedFixes);
  const anySimulated = sortedFixes.some((f) => f.simulated === true);
  const observedCoverage = computeObservedCoverage(sortedFixes);

  const summary: MatchSummaryFields = {
    matcherVersion: MATCHER_VERSION,
    ...(catalogVersion !== undefined ? { catalogVersion } : {}),
    ...(sourceBundle !== undefined ? { sourceBundle } : {}),
    simulated: anySimulated,
    pointCount: simplifiedPoints.length,
    rawPointCount: rawPoints.length,
    start,
    end,
    startedAt,
    endedAt,
    durationHours,
    observedCoverage,
  };

  const nearby = candidatesWithinRadius(simplifiedPoints, candidates, candidateRadiusMeters);

  const scored = nearby
    .map((c) =>
      scoreCandidate(
        c,
        sortedFixes,
        start,
        end,
        insideRatioBufferMeters,
        acceptInsideRatio,
        durationHours,
        observedCoverage,
        MIN_OBSERVED_COVERAGE,
      ),
    )
    .filter((s): s is ScoredCandidate => s !== undefined);

  // Gate fix 2: a qualifying polygon candidate always outranks every
  // radius candidate. Radius candidates are only even considered when no
  // polygon candidate qualifies — never compared on the same numeric
  // scale.
  const qualifyingPolygon = scored.filter((s) => s.geometryKind === "polygon" && s.qualifies);
  const qualifyingRadius = scored.filter((s) => s.geometryKind === "radius" && s.qualifies);
  const activeTier = qualifyingPolygon.length > 0 ? qualifyingPolygon : qualifyingRadius;

  if (activeTier.length === 0) {
    return {
      kind: "typeahead",
      nearbyCandidateIds: nearby.map((c) => c.id).sort(compareIds),
      summary,
    };
  }

  const ranked = activeTier.slice().sort(byScoreThenId);
  const top = ranked[0]!;
  let tied = ranked.filter((s) => roundTo(top.score - s.score, 9) <= roundTo(tieThreshold, 9));

  // Should-fix 4: if the sole surviving candidate is itself flagged
  // `sharedGeometry`, geometry alone cannot vouch for it even though no
  // sibling is present in this call (e.g. a sibling was filtered out by
  // the duration window) — route to ask_user rather than auto-accepting.
  const soloShared = tied.length === 1 && tied[0]!.candidate.sharedGeometry === true;

  if (tied.length > 1 || soloShared) {
    const sameFacility = tied.every((s) => s.candidate.facilityId === tied[0]!.candidate.facilityId);
    const anySharedGeometry = tied.some((s) => s.candidate.sharedGeometry === true);
    const reason: AskUserReason = sameFacility && anySharedGeometry ? "shared_geometry" : "close_scores";
    return {
      kind: "ask_user",
      reason,
      tied: tied.map(toTiedSummary),
      summary,
    };
  }

  const winner = tied[0]!;
  return {
    kind: "matched",
    course: {
      courseId: winner.candidate.id,
      facilityId: winner.candidate.facilityId,
      verificationTier: winner.candidate.verificationTier as VerificationTier,
      geometryKind: winner.geometryKind,
      insideRatio: winner.insideRatio,
      ...(winner.geometryKind === "radius" ? { radiusStartEndInside: true as const } : {}),
      courseDisambiguatedBy: "geometry",
      holes: winner.candidate.holes ?? 18,
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
 * not only the `shared_geometry` reason — see `README.md`'s ambiguity
 * list for why.
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
    insideRatio: number | null;
    radiusStartEndInside?: true;
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
      ...(pick.geometryKind === "radius" ? { radiusStartEndInside: true as const } : {}),
      courseDisambiguatedBy: "user",
    },
    updatedPicks,
    replacedCourseId: replaced && replaced.courseId !== pick.courseId ? replaced.courseId : undefined,
  };
}
