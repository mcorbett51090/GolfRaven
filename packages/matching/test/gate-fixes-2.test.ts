/**
 * Round 3 of the Opus gate: cap the gaps in the time-weighting (blocking),
 * plus pinning tests for the should-fix findings from round 2's re-review.
 * Fixture names/shapes mirror /tmp/mprobe/probe3.mjs where applicable.
 */
import { describe, expect, it } from "vitest";
import {
  computeTimeWeightedInsideRatio,
  matchCheckIn,
  matchRoute,
  preparePolygonGeometry,
  type CandidateCourse,
} from "../src/index.js";
import {
  fixesAlong,
  loopInsideRectangle,
  ORIGIN,
  offset,
  rectangle,
} from "./helpers.js";

const HOUR = 3_600_000;
const MIN = 60_000;
const T0 = 0;

describe("blocking: cap the gaps in the time-weighting", () => {
  const A: CandidateCourse = {
    id: "crs_A",
    facilityId: "fac_A",
    verificationTier: "play-verified",
    polygon: rectangle(ORIGIN, 400, 400),
  };

  it("fixture G1: 1,800 fixes at 1 Hz 2 km off-course, then one fix inside, a 3 h gap, then one more inside — must NOT match", () => {
    const fixes: { point: { lat: number; lon: number }; timestamp: number }[] =
      [];
    for (let i = 0; i < 1800; i++) {
      fixes.push({
        point: offset(ORIGIN, 2000 + (i % 30), 0),
        timestamp: i * 1000,
      });
    }
    fixes.push({ point: ORIGIN, timestamp: 1800 * 1000 });
    fixes.push({
      point: offset(ORIGIN, 10, 10),
      timestamp: 1800 * 1000 + 3 * HOUR,
    });

    const outcome = matchRoute({ fixes, candidates: [A] });
    expect(outcome.kind).toBe("typeahead");
    expect(outcome.summary.observedCoverage).toBeLessThan(0.5);
  });

  it("a legitimate round with a 4-minute GPS dropout inside the course still matches", () => {
    // A normal 18-hole loop, but with a 4-minute (240 s) gap spliced in
    // partway through — under the 300 s cap, so it costs nothing.
    const loop = loopInsideRectangle(ORIGIN, 400, 400, 20, 60);
    const durationMs = 4 * HOUR;
    const fixes = fixesAlong(loop, T0, T0 + durationMs);
    const splitAt = 30;
    const gapMs = 4 * MIN;
    const before = fixes.slice(0, splitAt);
    const after = fixes
      .slice(splitAt)
      .map((f) => ({ ...f, timestamp: f.timestamp + gapMs }));
    const withDropout = [...before, ...after];

    const outcome = matchRoute({ fixes: withDropout, candidates: [A] });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.insideRatio).toBeGreaterThanOrEqual(0.6);
    }
    expect(outcome.summary.observedCoverage).toBeGreaterThan(0.9);
  });

  it("reports observedCoverage on every outcome, including a clean, fully-observed route", () => {
    const loop = loopInsideRectangle(ORIGIN, 400, 400, 20, 60);
    const outcome = matchRoute({
      fixes: fixesAlong(loop, T0, T0 + 4 * HOUR),
      candidates: [A],
    });
    expect(outcome.summary.observedCoverage).toBeCloseTo(1, 6);
  });
});

describe("should-fix 1 (pinning): time-weighting vs. per-point ratio disagree", () => {
  it("fails if time-weighting is removed: the time-weighted and per-point ratios land on opposite sides of 0.6", () => {
    const A: CandidateCourse = {
      id: "crs_uneven",
      facilityId: "fac_uneven",
      verificationTier: "play-verified",
      polygon: rectangle(ORIGIN, 400, 400),
    };
    // 20 inside points, each 300 s (exactly MAX_GAP_SECONDS — so nothing
    // is lost to the cap) apart, followed by 200 outside points packed
    // 1 s apart. Per-point ratio: 20/220 ≈ 0.091 (well below 0.6). Every
    // gap stays at-or-under the cap, so observedCoverage ≈ 1 and nothing
    // is lost — but the 20 widely (yet cap-safe) spaced inside points
    // hold almost all of the route's actual TIME (≈ 95 of ≈ 98 minutes),
    // while the 200 densely-packed outside points barely register any
    // time at all — so the time-weighted ratio comes out **above** 0.6.
    const insideCluster = Array.from({ length: 20 }, () => ORIGIN); // deep inside
    const outsideCluster = Array.from({ length: 200 }, (_, i) =>
      offset(ORIGIN, 1000 + i, 0),
    ); // deep outside
    const points = [...insideCluster, ...outsideCluster];
    const GAP = 300_000; // exactly MAX_GAP_SECONDS, in ms — no cap loss
    const fixes = [
      ...insideCluster.map((point, i) => ({ point, timestamp: i * GAP })),
      ...outsideCluster.map((point, i) => ({
        point,
        timestamp: (insideCluster.length - 1) * GAP + 1000 + i * 1000,
      })),
    ];

    // Per-point ratio (naive vertex count): well below 0.6.
    const perPointRatio = insideCluster.length / points.length;
    expect(perPointRatio).toBeLessThan(0.3);

    const outcome = matchRoute({ fixes, candidates: [A] });
    expect(outcome.summary.observedCoverage).toBeGreaterThan(0.95); // nothing lost to the cap
    // Time-weighted: the sparse-but-cap-safe inside points hold almost
    // all the actual wall-clock time — so the time-weighted ratio sits
    // comfortably above 0.6, and the route matches, even though the
    // naive per-point count would not have qualified.
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.insideRatio).toBeGreaterThanOrEqual(0.6);
    }
  });
});

describe("should-fix 2 (pinning): check-in fail-closed edges", () => {
  const polygonCourse: CandidateCourse = {
    id: "crs_checkin_polygon",
    facilityId: "fac_checkin",
    verificationTier: "play-verified",
    polygon: rectangle(ORIGIN, 400, 300),
  };
  const radiusCourse: CandidateCourse = {
    id: "crs_checkin_radius",
    facilityId: "fac_checkin_radius",
    verificationTier: "listed-verified",
    radiusFallback: { center: ORIGIN, radiusMeters: 400 },
  };

  it("rejects a fix with `simulated` omitted entirely — fails if the check becomes `=== true`", () => {
    const fix = {
      point: ORIGIN,
      accuracyMeters: 10,
      timestamp: 1000,
    } as unknown as Parameters<typeof matchCheckIn>[0];
    expect(matchCheckIn(fix, polygonCourse)).toEqual({
      accepted: false,
      reason: "simulated",
    });
  });

  it("rejects a fix with `simulated: null` — fails if the check becomes `=== true`", () => {
    const fix = {
      point: ORIGIN,
      accuracyMeters: 10,
      simulated: null,
      timestamp: 1000,
    } as unknown as Parameters<typeof matchCheckIn>[0];
    expect(matchCheckIn(fix, polygonCourse)).toEqual({
      accepted: false,
      reason: "simulated",
    });
  });

  it("rejects a negative accuracy", () => {
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: -5, simulated: false, timestamp: 1000 },
      polygonCourse,
    );
    expect(result).toEqual({ accepted: false, reason: "inaccurate" });
  });

  it("radius + 40 m is accepted, radius + 60 m is rejected — fails if the 50 m buffer is removed", () => {
    const at40 = offset(ORIGIN, 440, 0); // radius 400 + 40 m
    const at60 = offset(ORIGIN, 460, 0); // radius 400 + 60 m
    const accepted = matchCheckIn(
      { point: at40, accuracyMeters: 5, simulated: false, timestamp: 1000 },
      radiusCourse,
    );
    const rejected = matchCheckIn(
      { point: at60, accuracyMeters: 5, simulated: false, timestamp: 1000 },
      radiusCourse,
    );
    expect(accepted.accepted).toBe(true);
    expect(rejected).toEqual({ accepted: false, reason: "outside_polygon" });
  });
});

describe("should-fix 3 (pinning): 3 km candidate search radius", () => {
  it("a candidate 2 km away is nearby; one 4 km away is not — fails if the radius is changed to 100 m", () => {
    const near: CandidateCourse = {
      id: "crs_near_2km",
      facilityId: "fac_near",
      verificationTier: "play-verified",
      polygon: rectangle(offset(ORIGIN, 2000, 0), 100, 100),
    };
    const far: CandidateCourse = {
      id: "crs_far_4km",
      facilityId: "fac_far",
      verificationTier: "play-verified",
      polygon: rectangle(offset(ORIGIN, 4000, 0), 100, 100),
    };
    // A short route that itself never leaves the very center — the only
    // thing under test is which candidates the 3 km search picks up, so
    // nothing here qualifies as a match; we only read `nearbyCandidateIds`.
    const points = loopInsideRectangle(ORIGIN, 40, 40, 5, 12);
    const outcome = matchRoute({
      fixes: fixesAlong(points, T0, T0 + 1 * MIN), // too short to qualify anything on duration
      candidates: [near, far],
    });
    expect(outcome.kind).toBe("typeahead");
    if (outcome.kind === "typeahead") {
      expect(outcome.nearbyCandidateIds).toEqual(["crs_near_2km"]);
    }
  });
});

describe("nit: the all-equal-timestamps fallback ratio is rounded too", () => {
  it("rounds a repeating-fraction ratio (1/3) to 9 decimal places, same as the normal path", () => {
    const prepared = preparePolygonGeometry(rectangle(ORIGIN, 400, 400));
    expect(prepared).toBeDefined();
    if (!prepared) return;
    // 3 fixes, all at the same instant: 1 inside, 2 outside → exactly
    // 1/3, a repeating decimal that would show raw float noise
    // (0.3333333333333333) if the fallback branch didn't round it.
    const fixes = [
      { point: ORIGIN, timestamp: 0 },
      { point: offset(ORIGIN, 1000, 0), timestamp: 0 },
      { point: offset(ORIGIN, 1000, 0), timestamp: 0 },
    ];
    const ratio = computeTimeWeightedInsideRatio(fixes, prepared, 30);
    expect(ratio).toBe(Math.round((1 / 3) * 1e9) / 1e9);
    expect(String(ratio).replace(/^0\./, "").length).toBeLessThanOrEqual(9);
  });
});

describe("should-fix 4 (pinning): sameFacility gates the shared_geometry reason", () => {
  it("a close-scores tie across two DIFFERENT facilities stays close_scores even when one candidate is sharedGeometry — fails if sameFacility is dropped", () => {
    // Two overlapping polygons at different facilities; one is flagged
    // sharedGeometry (as if it were a facility polygon shared with a
    // sibling course elsewhere), but that sibling isn't in play here —
    // the tie is with an unrelated facility's course, so geometry alone
    // still (weakly) distinguishes them and this must never be reported
    // as the §4.3 shared-polygon case.
    const overlapCenter = offset(ORIGIN, -100, 0);
    const A: CandidateCourse = {
      id: "crs_diff_facility_a",
      facilityId: "fac_1",
      verificationTier: "play-verified",
      sharedGeometry: true,
      polygon: rectangle(offset(ORIGIN, -200, 0), 300, 300), // covers x ∈ [-350, -50]
    };
    const B: CandidateCourse = {
      id: "crs_diff_facility_b",
      facilityId: "fac_2",
      verificationTier: "play-verified",
      polygon: rectangle(offset(ORIGIN, 0, 0), 300, 300), // covers x ∈ [-150, 150]
    };
    // Confined to the overlap band x ∈ [-150, -50], inside both.
    const points = loopInsideRectangle(overlapCenter, 60, 200, 5, 40);
    const outcome = matchRoute({
      fixes: fixesAlong(points, T0, T0 + 4 * HOUR),
      candidates: [A, B],
    });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.reason).toBe("close_scores");
      expect(outcome.tied.map((t) => t.courseId).sort()).toEqual([
        "crs_diff_facility_a",
        "crs_diff_facility_b",
      ]);
    }
  });
});
