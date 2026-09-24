/**
 * `@golfraven/matching` input/output types.
 *
 * This package must not import `@golfraven/catalog` (that schema is being
 * revised in a parallel workstream), so it defines its own minimal
 * candidate-course shape instead of importing `Course`/`Facility` from the
 * catalog. Whoever wires this package up (the app, the server replay path)
 * is responsible for projecting catalog rows into `CandidateCourse` before
 * calling in. Keep this interface narrow — it is meant to be trivially
 * adaptable once the catalog schema settles (build plan §3.1 row D). See
 * `README.md` for the full ambiguity list this package resolved while
 * doing that adaptation.
 */

/** A geodetic point. Longitude/latitude order follows GeoJSON convention
 * (`lon`, `lat`) is deliberately NOT used here — fields are named to avoid
 * that ambiguity entirely. */
export interface LatLng {
  lat: number;
  lon: number;
}

/** A closed ring of points (outer boundary or a hole), lat/lng. Does not
 * need to be explicitly closed (first point repeated as the last) — every
 * ring is treated as closed regardless. */
export type Ring = LatLng[];

/** One polygon: an outer boundary ring followed by zero or more hole
 * rings. A point inside a hole is outside the polygon (build plan gate
 * fix: "Points inside holes are outside"). `rings[0]` is always the outer
 * ring. */
export type PolygonWithHoles = Ring[];

/** Several disjoint (or non-overlapping) polygons that together make up
 * one course's playable area — e.g. two separate landmasses of the same
 * course around a water hazard, or a composite course's several
 * non-adjacent nines. */
export type MultiPolygon = PolygonWithHoles[];

/**
 * What `CandidateCourse.polygon` accepts, in increasing generality:
 *  - `LatLng[]` — a single outer ring, no holes (the original, still-
 *    supported shape).
 *  - `Ring[]` — one polygon's outer ring plus its holes.
 *  - `MultiPolygon` — several such polygons.
 * `normalizePolygon` (in `polygon.ts`) turns any of these into the
 * canonical `MultiPolygon` form by inspecting nesting depth at runtime;
 * see that function's doc comment for exactly how the three shapes are
 * told apart.
 */
export type PolygonInput = LatLng[] | Ring[] | MultiPolygon;

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
 *  - `polygon` set → geometry-kind `'polygon'`, matched with a time-
 *    weighted `insideRatio` (build plan §7.4 step 3, §4.5 co-signal
 *    definition: "the facility must be `play-verified`; a radius-fallback
 *    circle never qualifies").
 *  - `radiusFallback` set, `polygon` absent → geometry-kind `'radius'`,
 *    matched by start/end containment only (§4.2 "Routes against a
 *    circle") — never ranked on the `insideRatio` scale (README
 *    ambiguity: radius vs. polygon ranking).
 * A candidate with neither is dropped from the candidate search (it
 * cannot be matched geometrically at all).
 *
 * `holes` is an addition beyond the design constraint's literal field
 * list — see `README.md` "ambiguity 1": the acceptance duration window
 * in build plan §7.4 step 4 depends on whether the candidate is a 9-hole
 * course, so the matcher needs *some* signal for that. It is optional and
 * defaults to 18 holes (the 1.5–6 h window) when omitted.
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
  /** Absent when the course relies on the radius fallback. */
  polygon?: PolygonInput;
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
   * flagged this way, so the matcher routes to `ask_user` whenever the
   * top candidate carries this flag — even when it is the only candidate
   * left standing, e.g. because a sibling was filtered out by the
   * duration window (build plan §4.3, §7.4 step 4).
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
  /** Point count after simplification (build plan §7.4 step 1). Used only
   * for the transmitted summary/geometry — `insideRatio` is computed from
   * the raw, unsimplified, time-sorted fixes (gate fix 1). */
  pointCount: number;
  /** Point count before simplification, for observability. */
  rawPointCount: number;
  start: LatLng;
  end: LatLng;
  /** Epoch milliseconds of the earliest and latest fix, after sorting. */
  startedAt: number;
  endedAt: number;
  durationHours: number;
  /** Fraction of the route's wall-clock span actually covered by fixes,
   * after capping each inter-fix gap at `MAX_GAP_SECONDS` (build plan gate
   * fix: cap the gaps in the time-weighting — see `inside-ratio.ts`).
   * Below `MIN_OBSERVED_COVERAGE`, a route can never be `matched` via a
   * polygon candidate, however high its geometry-only ratio looks over
   * what little was actually observed. */
  observedCoverage: number;
}

export interface MatchedCourse {
  courseId: string;
  facilityId: string;
  verificationTier: VerificationTier;
  geometryKind: GeometryKind;
  /**
   * Time-weighted fraction of the route's *duration* spent inside the
   * polygon + 30 m buffer (build plan §7.4 step 3; gate fix 1) — computed
   * from the raw, time-sorted fixes, never from post-simplification
   * vertex counts.
   *
   * `null` for a `'radius'` match: a radius match is decided by start/end
   * containment only, never by a ratio (build plan §4.2 "Routes against a
   * circle"), and is never ranked against a polygon candidate's
   * `insideRatio` scale (gate fix 2) — the §4.5 scorer's 0.6/0.8 bands
   * must never see a radius-derived number here. See
   * `radiusStartEndInside` instead.
   */
  insideRatio: number | null;
  /** Present (and `true`) only for a `'radius'` match: both the route's
   * start and end fell inside the circle. */
  radiusStartEndInside?: true;
  courseDisambiguatedBy: "geometry";
  /** The candidate's hole count, defaulted to 18 when the candidate didn't
   * state one (see `CandidateCourse.holes`). */
  holes: number;
}

export interface TiedCandidateSummary {
  courseId: string;
  facilityId: string;
  verificationTier: VerificationTier;
  geometryKind: GeometryKind;
  /** Same nullability rule as `MatchedCourse.insideRatio` — see there. */
  insideRatio: number | null;
  radiusStartEndInside?: true;
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
  | {
      kind: "typeahead";
      /** Candidate ids that were within the search radius but didn't
       * geometrically-and-durationally qualify, sorted ascending — a seed
       * list for a typeahead search UI (gate fix, output contract). */
      nearbyCandidateIds: string[];
      summary: MatchSummaryFields;
    };

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
  /** Route simplification cap (build plan §7.4 step 1: 500) — applied only
   * to the transmitted summary, never to the `insideRatio` computation
   * (gate fix 1). */
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
 * step 5).
 *
 * The declared types below (`number`, `boolean`) are the honest contract
 * for a well-behaved caller, but this struct also arrives over
 * `POST /v1/evidence` and from server replay of stored JSON (build plan
 * §3.1 row D, §3.3) — an untrusted boundary where TypeScript's types are
 * erased and a hostile or buggy client can send anything, including
 * `null`, `NaN` (which round-trips through `JSON.stringify` as `null`),
 * or an omitted field. `matchCheckIn` validates every field at runtime
 * regardless of what the type declares, and fails closed on anything that
 * doesn't strictly conform (gate fix: "Check-in fails closed"). */
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
  | {
      accepted: false;
      reason: "simulated" | "inaccurate" | "outside_polygon" | "no_geometry" | "invalid_fix";
    };
