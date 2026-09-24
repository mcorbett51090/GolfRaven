/**
 * Build plan §7.4 step 6: every golden fixture listed there, built as
 * synthetic geometry. Where a fixture's expected outcome depends on the
 * scorer (`packages/rules` `scorePlay`, out of this package's scope),
 * each test asserts only the matcher's own output and says in a comment
 * which §4.5 scorer fixture completes it.
 */
import { describe, expect, it } from "vitest";
import {
  matchCheckIn,
  matchRoute,
  resolveAskUser,
  type CandidateCourse,
} from "../src/index.js";
import { fixesAlong, loopInsideRectangle, ORIGIN, offset, rectangle } from "./helpers.js";

const HOUR = 3_600_000;
const T0 = Date.parse("2026-06-01T08:00:00Z");

describe("golden fixture: adjacent courses", () => {
  it("matches the course the route actually stayed in, ignoring its neighbor 300 m away", () => {
    const centerA = offset(ORIGIN, -300, 0);
    const centerB = offset(ORIGIN, 300, 0);
    const candidates: CandidateCourse[] = [
      { id: "crs_adjacent_a", facilityId: "fac_adjacent_a", verificationTier: "play-verified", polygon: rectangle(centerA, 300, 300) },
      { id: "crs_adjacent_b", facilityId: "fac_adjacent_b", verificationTier: "play-verified", polygon: rectangle(centerB, 300, 300) },
    ];
    const points = loopInsideRectangle(centerA, 300, 300, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.courseId).toBe("crs_adjacent_a");
      expect(outcome.course.courseDisambiguatedBy).toBe("geometry");
      expect(outcome.course.geometryKind).toBe("polygon");
    }
  });
});

describe("golden fixture: 36-hole facility", () => {
  const centerFront = offset(ORIGIN, -200, 0);
  const centerBack = offset(ORIGIN, 0, 0);
  const candidates: CandidateCourse[] = [
    { id: "crs_36_front", facilityId: "fac_36", verificationTier: "play-verified", polygon: rectangle(centerFront, 300, 300) },
    { id: "crs_36_back", facilityId: "fac_36", verificationTier: "play-verified", polygon: rectangle(centerBack, 300, 300) },
  ];

  it("matches cleanly when the round stayed in one course's footprint", () => {
    const points = loopInsideRectangle(centerFront, 300, 300, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") expect(outcome.course.courseId).toBe("crs_36_front");
  });

  it("asks the user when the round sat in the overlap between two real (non-shared) polygons", () => {
    // The two rings overlap in x ∈ [-50, 50]; a loop confined to that band
    // scores near-1.0 insideRatio against BOTH — a genuine near-tie, not a
    // `sharedGeometry`-flagged candidate.
    const overlapCenter = offset(ORIGIN, -50, 0);
    const points = loopInsideRectangle(overlapCenter, 80, 200, 10, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.reason).toBe("close_scores");
      expect(outcome.tied.map((t) => t.courseId).sort()).toEqual(["crs_36_back", "crs_36_front"]);
      expect(outcome.tied.every((t) => t.sharedGeometry === false)).toBe(true);
    }
  });
});

describe("golden fixture: shared clubhouse", () => {
  it("still disambiguates by polygon even though two facilities' rounds start/end at the same clubhouse point", () => {
    const clubhouse = ORIGIN;
    const centerEast = offset(clubhouse, 500, 0);
    const centerWest = offset(clubhouse, -500, 0);
    const candidates: CandidateCourse[] = [
      { id: "crs_clubhouse_east", facilityId: "fac_east", verificationTier: "play-verified", polygon: rectangle(centerEast, 400, 400) },
      { id: "crs_clubhouse_west", facilityId: "fac_west", verificationTier: "play-verified", polygon: rectangle(centerWest, 400, 400) },
    ];
    // Starts and ends at the shared clubhouse; the round itself is played
    // entirely on the east course.
    const loop = loopInsideRectangle(centerEast, 400, 400, 20, 30);
    const points = [clubhouse, ...loop, clubhouse];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") expect(outcome.course.courseId).toBe("crs_clubhouse_east");
  });
});

describe("golden fixture: 27-hole composite", () => {
  it("prefers the composite's union polygon over either constituent nine", () => {
    const centerRed = offset(ORIGIN, -300, 0);
    const centerWhite = offset(ORIGIN, 0, 0);
    const centerBlue = offset(ORIGIN, 300, 0);
    const centerComposite = offset(ORIGIN, -150, 0);
    const candidates: CandidateCourse[] = [
      { id: "crs_red", facilityId: "fac_27", verificationTier: "play-verified", holes: 9, polygon: rectangle(centerRed, 300, 600) },
      { id: "crs_white", facilityId: "fac_27", verificationTier: "play-verified", holes: 9, polygon: rectangle(centerWhite, 300, 600) },
      { id: "crs_blue", facilityId: "fac_27", verificationTier: "play-verified", holes: 9, polygon: rectangle(centerBlue, 300, 600) },
      { id: "crs_red_white", facilityId: "fac_27", verificationTier: "play-verified", holes: 18, polygon: rectangle(centerComposite, 600, 600) },
    ];
    // A perimeter loop of the red+white union: ~half the points sit only
    // in red or only in white (below the 0.6 acceptance threshold for
    // each), while every point sits inside the composite's own polygon.
    const points = loopInsideRectangle(centerComposite, 600, 600, 20, 60);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 3.5 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.courseId).toBe("crs_red_white");
      expect(outcome.course.insideRatio).toBeGreaterThan(0.9);
    }
    // Roster aggregation — that a play on the composite also satisfies
    // crs_red and crs_white as roster members, but counts once in
    // uniqueCourses (build plan §4.3) — is `packages/rules`' job, not
    // this package's.
  });
});

describe("golden fixture: shared polygon on a course-unit trail (user pick)", () => {
  const facilityId = "fac_shared";
  const sharedPolygon = rectangle(ORIGIN, 400, 400);
  const candidates: CandidateCourse[] = [
    { id: "crs_shared_x", facilityId, verificationTier: "play-verified", sharedGeometry: true, polygon: sharedPolygon },
    { id: "crs_shared_y", facilityId, verificationTier: "play-verified", sharedGeometry: true, polygon: sharedPolygon },
  ];

  it("routes to ask_user with reason shared_geometry, never picking one on its own", () => {
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.reason).toBe("shared_geometry");
      expect(outcome.tied.map((t) => t.courseId).sort()).toEqual(["crs_shared_x", "crs_shared_y"]);
      expect(outcome.tied.every((t) => t.sharedGeometry)).toBe(true);
    }
    // Completed by the §4.5 golden fixture #16 (build plan line 1079):
    // "36-hole site, shared polygon, dwell, course-unit trail, user
    // pick" → score_badge 0.50, score_monetary 0.00, presence_signal
    // true, money: no.
  });

  it("resolveAskUser records the user pick, and a later different pick on the same date replaces it (audited)", () => {
    const tied = [
      { courseId: "crs_shared_x", facilityId, verificationTier: "play-verified" as const, geometryKind: "polygon" as const, insideRatio: 0.95, sharedGeometry: true },
      { courseId: "crs_shared_y", facilityId, verificationTier: "play-verified" as const, geometryKind: "polygon" as const, insideRatio: 0.93, sharedGeometry: true },
    ];
    const first = resolveAskUser(tied[0]!, "2026-06-01", []);
    expect(first.course).toMatchObject({ courseId: "crs_shared_x", courseDisambiguatedBy: "user" });
    expect(first.replacedCourseId).toBeUndefined();
    expect(first.updatedPicks).toEqual([{ facilityId, localDate: "2026-06-01", courseId: "crs_shared_x" }]);

    const second = resolveAskUser(tied[1]!, "2026-06-01", first.updatedPicks);
    expect(second.course.courseId).toBe("crs_shared_y");
    expect(second.replacedCourseId).toBe("crs_shared_x");
    expect(second.updatedPicks).toEqual([{ facilityId, localDate: "2026-06-01", courseId: "crs_shared_y" }]);

    const same = resolveAskUser(tied[1]!, "2026-06-01", second.updatedPicks);
    expect(same.replacedCourseId).toBeUndefined();
    expect(same.updatedPicks).toEqual(second.updatedPicks);

    const otherDate = resolveAskUser(tied[0]!, "2026-06-02", second.updatedPicks);
    expect(otherDate.replacedCourseId).toBeUndefined();
    expect(otherDate.updatedPicks).toHaveLength(2);
  });
});

describe("golden fixture: identical radius circles at a 36-hole site", () => {
  it("has the same outcome as the shared-polygon case: ask_user, reason shared_geometry", () => {
    const facilityId = "fac_radius_36";
    const circle = { center: ORIGIN, radiusMeters: 500 };
    const candidates: CandidateCourse[] = [
      { id: "crs_radius_r1", facilityId, verificationTier: "listed-verified", sharedGeometry: true, radiusFallback: circle },
      { id: "crs_radius_r2", facilityId, verificationTier: "listed-verified", sharedGeometry: true, radiusFallback: circle },
    ];
    const points = [offset(ORIGIN, 50, 0), offset(ORIGIN, 0, 100), offset(ORIGIN, -50, 0)];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.reason).toBe("shared_geometry");
      expect(outcome.tied.every((t) => t.geometryKind === "radius")).toBe(true);
    }
  });
});

describe("golden fixture: radius fallback, route leaves the circle mid-round but starts and ends inside", () => {
  it("matches by start/end containment alone, not by insideRatio", () => {
    const candidates: CandidateCourse[] = [
      {
        id: "crs_radius_leaves",
        facilityId: "fac_radius_leaves",
        verificationTier: "listed-verified",
        radiusFallback: { center: ORIGIN, radiusMeters: 400 },
      },
    ];
    const points = [
      offset(ORIGIN, 50, 0), // start: inside
      offset(ORIGIN, 600, 0), // mid-round: outside
      offset(ORIGIN, 800, 200), // mid-round: outside
      offset(ORIGIN, -100, 0), // end: inside
    ];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.courseId).toBe("crs_radius_leaves");
      expect(outcome.course.geometryKind).toBe("radius");
      // Informational only — acceptance did not depend on this being ≥ 0.6.
      expect(outcome.course.insideRatio).toBeLessThan(0.6);
    }
  });
});

describe("golden fixture: Health routes of 1.6 h and 5.5 h", () => {
  const candidates: CandidateCourse[] = [
    { id: "crs_health_window", facilityId: "fac_health", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 400, 400) },
  ];
  const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 30);

  it.each([1.6, 5.5])("matches at %s h, inside the 1.5–6 h acceptance window", (hours) => {
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + hours * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    // The health_route weight (0.60 at insideRatio ≥ 0.8, else 0.40) is
    // assigned by packages/rules using this same window (build plan
    // §4.5, G2-07) — not asserted here.
  });

  it.each([1.4, 6.2])("does not match at %s h, outside the window (typeahead)", (hours) => {
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + hours * HOUR), candidates });
    expect(outcome.kind).toBe("typeahead");
  });
});

describe("golden fixture: 9-hole loops, including a 55-minute 9-hole dwell", () => {
  const candidate: CandidateCourse = {
    id: "crs_nine",
    facilityId: "fac_nine",
    verificationTier: "play-verified",
    holes: 9,
    polygon: rectangle(ORIGIN, 200, 200),
  };
  const points = loopInsideRectangle(ORIGIN, 200, 200, 20, 24);

  it("matches a 55-minute 9-hole round (above the 0.75 h floor)", () => {
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 55 * 60_000), candidates: [candidate] });
    expect(outcome.kind).toBe("matched");
  });

  it("does not match a 40-minute 9-hole round (below the 0.75 h floor)", () => {
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 40 * 60_000), candidates: [candidate] });
    expect(outcome.kind).toBe("typeahead");
  });

  it("accepts the two check-in fixes 55 minutes apart that a dwell would be built from", () => {
    const checkIn = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 15, simulated: false, timestamp: T0 },
      candidate,
    );
    const checkOut = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 15, simulated: false, timestamp: T0 + 55 * 60_000 },
      candidate,
    );
    expect(checkIn.accepted).toBe(true);
    expect(checkOut.accepted).toBe(true);
    // Combining these two `foreground_checkin` matches into a
    // `foreground_dwell` (and applying FM-18's ≥ 50 min-for-9-holes /
    // ≥ 90 min-for-18-holes threshold) is packages/rules' job — build
    // plan §4.5 `foreground_dwell` row.
  });
});

describe("golden fixture: GPS drift", () => {
  const candidates: CandidateCourse[] = [
    { id: "crs_drift", facilityId: "fac_drift", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 300, 300) },
  ];

  it("still matches when a minority of fixes drift outside the buffer", () => {
    const clean = loopInsideRectangle(ORIGIN, 300, 300, 20, 40);
    const drifted = clean.map((p, i) => (i % 5 === 0 ? offset(p, 60, 0) : p)); // 20% pushed ~60 m off
    const outcome = matchRoute({ fixes: fixesAlong(drifted, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.insideRatio).toBeGreaterThanOrEqual(0.6);
      expect(outcome.course.insideRatio).toBeLessThan(1);
    }
  });

  it("falls back to typeahead when drift is severe enough to drop insideRatio below 0.6", () => {
    const clean = loopInsideRectangle(ORIGIN, 300, 300, 20, 40);
    const heavilyDrifted = clean.map((p, i) => (i % 2 === 0 ? offset(p, 80, 0) : p)); // 50% pushed off
    const outcome = matchRoute({ fixes: fixesAlong(heavilyDrifted, T0, T0 + 4 * HOUR), candidates });
    expect(outcome.kind).toBe("typeahead");
  });
});

describe("golden fixture: a spoofed straight line", () => {
  it("matches like any other qualifying route — matching performs no spoof/velocity detection", () => {
    const candidates: CandidateCourse[] = [
      { id: "crs_spoofed", facilityId: "fac_spoofed", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 300, 300) },
    ];
    // An unnaturally straight diagonal corner-to-corner "flight" through
    // the polygon, evenly spaced, built directly in local meters.
    const line = Array.from({ length: 20 }, (_, i) => {
      const t = i / 19;
      return offset(ORIGIN, -140 + t * 280, -140 + t * 280);
    });
    const outcome = matchRoute({ fixes: fixesAlong(line, T0, T0 + 3 * HOUR), candidates });
    expect(outcome.kind).toBe("matched");
    // Implied-velocity / straight-line fraud heuristics (build plan
    // §4.5: "Implied velocity above 200 km/h … sets status = disputed")
    // are the rules/server's job, evaluated once this evidence reaches
    // `POST /v1/evidence` (§3.3 data flow 2) — never this package's.
  });
});

describe("golden fixture: a Connect IQ fix trace", () => {
  it("matches from a sparse, low-metadata fix sequence (no accuracy, no simulated flag)", () => {
    const candidates: CandidateCourse[] = [
      { id: "crs_ciq", facilityId: "fac_ciq", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 300, 300) },
    ];
    const points = loopInsideRectangle(ORIGIN, 300, 300, 30, 8); // sparse: 8 points
    const fixes = fixesAlong(points, T0, T0 + 3 * HOUR).map((f) => ({ point: f.point, timestamp: f.timestamp }));
    const outcome = matchRoute({ fixes, candidates });
    expect(outcome.kind).toBe("matched");
    // The connect_iq class weight (0.50 recorder / 0.30 one-tap
    // check-in) is assigned by packages/rules (build plan §4.5) — this
    // package only supplies the geometry match.
  });
});

describe("golden fixture: an unlisted Health source", () => {
  it("passes the source bundle through verbatim; matching does no allow-listing", () => {
    const candidates: CandidateCourse[] = [
      { id: "crs_unlisted", facilityId: "fac_unlisted", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 400, 400) },
    ];
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 30);
    const outcome = matchRoute({
      fixes: fixesAlong(points, T0, T0 + 4 * HOUR),
      candidates,
      sourceBundle: "com.unknown.unlisted-golf-app",
    });
    expect(outcome.kind).toBe("matched");
    expect(outcome.summary.sourceBundle).toBe("com.unknown.unlisted-golf-app");
    // The allow-list check, and the 0.10 weight for an unlisted source
    // (ruling SP1-2 lane 5; build plan §4.5 `health_route` row), are
    // applied by packages/rules from this same passed-through field.
  });
});
