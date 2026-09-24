/**
 * `@golfraven/matching` input/output types.
 *
 * This package must not import `@golfraven/catalog` (that schema is being
 * revised in a parallel workstream), so it defines its own minimal
 * candidate-course shape instead of importing `Course`/`Facility` from the
 * catalog. Whoever wires this package up (the app, the server replay path)
 * is responsible for projecting catalog rows into `CandidateCourse` before
 * calling in. Keep this interface narrow — it is meant to be trivially
 * adaptable once the catalog schema settles (build plan §3.1 row D).
 */

/** A geodetic point. Longitude/latitude order follows GeoJSON convention
 * (`lon`, `lat`) is deliberately NOT used here — fields are named to avoid
 * that ambiguity entirely. */
export interface LatLng {
  lat: number;
  lon: number;
}

/** A radius-fallback circle for a `listed-verified` course with no polygon
 * (build plan §4.2). Every course at a multi-course site shares the same
 * circle, because `Course` has no coordinate of its own (§4.2) — which is
 * why `sharedGeometry` (below) applies to a radius circle exactly the same
 * way it applies to a shared polygon. */
export interface RadiusFallbackCircle {
  center: LatLng;
  radiusMeters: number;
}

export type VerificationTier = "unverified" | "listed-verified" | "play-verified";

/**
 * The minimal candidate-course shape this package needs (design
 * constraint: id, verification tier, polygon-or-radius-circle, facility
 * id, whether the geometry is shared).
 *
 * Exactly one of `polygon` / `radiusFallback` should be set:
 *  - `polygon` set → geometry-kind `'polygon'`, matched with `insideRatio`
 *    (build plan §7.4 step 3, §4.5 co-signal definition: "the facility
 *    must be `play-verified`; a radius-fallback circle never qualifies").
 *  - `radiusFallback` set, `polygon` absent → geometry-kind `'radius'`,
 *    matched by start/end containment only (§4.2 "Routes against a
 *    circle").
 * A candidate with neither is dropped from the candidate search (it
 * cannot be matched geometrically at all).
 *
 * `holes` is an addition beyond the design constraint's literal field
 * list — see the package README / handback report, "ambiguity 1": the
 * acceptance duration window in build plan §7.4 step 4 depends on whether
 * the candidate is a 9-hole course, so the matcher needs *some* signal
 * for that. It is optional and defaults to 18 holes (the 1.5–6 h window)
 * when omitted.
 */
export interface CandidateCourse {
  /** The course's own `crs_` id — including an unverified stub's id (build
   * plan §7.4 step 2: "A match to an unverified polygon returns the
   * stub's own `crs_` id"). */
  id: string;
  /** The `fac_` id of the facility this course belongs to (build plan
   * §4.3: membership and the one-pick-per-facility-per-date guard are
   * keyed on this). */
  facilityId: string;
  verificationTier: VerificationTier;
  /** Outer ring of the course polygon, lat/lng. Does not need to be
   * explicitly closed (first point repeated as the last) — the ring is
   * treated as closed regardless. Absent when the course relies on the
   * radius fallback. */
  polygon?: LatLng[];
  /** Present when there is no polygon (build plan §4.2 radius fallback).
   * Mutually exclusive with `polygon` in practice; if both are set,
   * `polygon` takes precedence (a play-verified course always prefers its
   * real geometry). */
  radiusFallback?: RadiusFallbackCircle;
  /**
   * True when this course's geometry — its polygon (a facility polygon
   * with `sharedWithFacility`, build plan §4.2) or its radius-fallback
   * circle (identical for every course at the site, §4.2/§4.3) — cannot
   * by itself tell this course apart from a sibling course at the same
   * facility. Geometry alone can never resolve a match among candidates
   * flagged this way; the matcher routes those to `ask_user`
   * (build plan §4.3, §7.4 step 4).
   */
  sharedGeometry?: boolean;
  /** Hole count, when known. Defaults to 18 (see the doc comment above).
   * Only 9 is treated specially (the shorter acceptance window); every
   * other value (18, 27-composite unions, etc.) uses the 1.5–6 h window. */
  holes?: number;
}

/** A single recorded GPS fix along a played route. */
export interface RouteFix {
  point: LatLng;
  /** Epoch milliseconds. */
  timestamp: number;
  /** iOS `isSimulatedBySoftware` / Android mock-location flag. Defaults to
   * `false` when omitted — callers that can't determine this should say
   * so explicitly rather than relying on the default, because §4.5 caps a
   * simulated fix's evidence weight and a foreground check-in rejects it
   * outright (build plan §7.4 step 5). */
  simulated?: boolean;
  /** Horizontal accuracy in meters, when known. */
  accuracyMeters?: number;
}

export type GeometryKind = "polygon" | "radius";

/** Who/what decided which course, of possibly several at one facility,
 * was played (build plan §4.3). This package only ever produces
 * `'geometry'` (its own decision) or routes to `ask_user`, whose
 * resolution via `resolveAskUser` produces `'user'`. `'staff'` is a
 * partner-portal decision made entirely outside this package's boundary
 * (build plan §3.1 rows D/H) and never appears in its output — it is
 * listed here only so downstream code can share one type across all three
 * sources. */
export type CourseDisambiguatedBy = "geometry" | "staff" | "user";

/** Fields that accompany every `matchRoute` outcome, matched to build plan
 * §3.3's `MatchSummary`: "course id, insideRatio, start/end, point count,
 * simulated flag, source bundle, `matcherVersion`, `catalogVersion`." The
 * course id and insideRatio live on the per-candidate result instead
 * (there may be zero, one, or several courses in play), everything else
 * is here. */
export interface MatchSummaryFields {
  matcherVersion: number;
  /** Passed through verbatim from the input; matching neither reads nor
   * validates it (build plan §3.3 data flow 2). */
  catalogVersion?: string;
  /** `HKSource.bundleIdentifier` / Health Connect `dataOrigin`, passed
   * through verbatim for the scorer's allow-list check and weighting
   * (build plan §7.3 lane 5, §4.5 `health_route` row). Matching performs
   * no allow-listing itself. */
  sourceBundle?: string;
  /** True if *any* fix in the route was flagged simulated. */
  simulated: boolean;
  /** Point count after simplification (build plan §7.4 step 1). */
  pointCount: number;
  /** Point count before simplification, for observability. */
  rawPointCount: number;
  start: LatLng;
  end: LatLng;
  durationHours: number;
}

export interface MatchedCourse {
  courseId: string;
  facilityId: string;
  verificationTier: VerificationTier;
  geometryKind: GeometryKind;
  /** Fraction of the (simplified) route inside the polygon + 30 m buffer
   * (build plan §7.4 step 3). For a `'radius'` match this is informational
   * only — acceptance for a radius match is decided by start/end
   * containment, not by this ratio (build plan §4.2 "Routes against a
   * circle"). */
  insideRatio: number;
  courseDisambiguatedBy: "geometry";
}

export interface TiedCandidateSummary {
  courseId: string;
  facilityId: string;
  verificationTier: VerificationTier;
  geometryKind: GeometryKind;
  insideRatio: number;
  sharedGeometry: boolean;
}

export type AskUserReason = "close_scores" | "shared_geometry";

export type MatchOutcome =
  | { kind: "matched"; course: MatchedCourse; summary: MatchSummaryFields }
  | {
      kind: "ask_user";
      reason: AskUserReason;
      tied: TiedCandidateSummary[];
      summary: MatchSummaryFields;
    }
  | { kind: "typeahead"; summary: MatchSummaryFields };

export interface MatchRouteInput {
  fixes: RouteFix[];
  /** Includes verified courses and unverified directory stubs alike
   * (build plan §7.4 step 2). */
  candidates: CandidateCourse[];
  catalogVersion?: string;
  sourceBundle?: string;
  /** Candidate search radius in meters (build plan §7.4 step 2: 3 km). */
  candidateRadiusMeters?: number;
  /** `insideRatio` buffer in meters (build plan §7.4 step 3: 30 m). */
  insideRatioBufferMeters?: number;
  /** Route simplification cap (build plan §7.4 step 1: 500). */
  maxSimplifiedPoints?: number;
  /** Score-gap tie threshold (build plan §7.4 step 4: 0.15). */
  tieThreshold?: number;
  /** `insideRatio` acceptance threshold (build plan §7.4 step 4: 0.6). */
  acceptInsideRatio?: number;
}

/** One prior user pick, for the §4.3 one-pick-per-facility-per-date guard.
 * Storage is the caller's job (this package does no I/O); this type is
 * just the shape the guard reads and writes. */
export interface FacilityDatePick {
  facilityId: string;
  /** Facility-local calendar date, `YYYY-MM-DD` (build plan §4.1 `tz`). */
  localDate: string;
  courseId: string;
}

/** A single fix used for the foreground check-in match (build plan §7.4
 * step 5). */
export interface CheckInFix {
  point: LatLng;
  accuracyMeters: number;
  simulated: boolean;
  timestamp: number;
  /** Opaque device-attestation assertion bound to the payload. Attestation
   * verification is out of scope for this package (build plan §7.4 step
   * 5) — it is only accepted and passed through untouched. */
  attestationAssertion?: string;
}

export type CheckInResult =
  | {
      accepted: true;
      courseId: string;
      facilityId: string;
      verificationTier: VerificationTier;
      geometryKind: GeometryKind;
      point: LatLng;
      accuracyMeters: number;
      timestamp: number;
      attestationAssertion?: string;
    }
  | { accepted: false; reason: "simulated" | "inaccurate" | "outside_polygon" | "no_geometry" };
