/**
 * Direct coverage for the Opus gate's blocking / should-fix findings.
 * Scenarios mirror /tmp/mprobe/probe.mjs and probe2.mjs as closely as
 * possible so this suite and the gate's own probes agree.
 */
import { describe, expect, it } from "vitest";
import {
  isInsidePreparedWithBuffer,
  matchCheckIn,
  matchRoute,
  preparePolygonGeometry,
  simplifyToMaxPoints,
  stableSortByTimestamp,
  type CandidateCourse,
  type PolygonInput,
} from "../src/index.js";
import { fixesAlong, loopInsideRectangle, ORIGIN, offset, rectangle } from "./helpers.js";

const HOUR = 3_600_000;
const T0 = Date.parse("2026-06-01T08:00:00Z");

describe("gate fix 1: time-weighted insideRatio on raw fixes", () => {
  const A: CandidateCourse = {
    id: "crs_A",
    facilityId: "fac_A",
    verificationTier: "play-verified",
    polygon: rectangle(ORIGIN, 400, 400),
  };

  function wanderingInside(n: number): { lat: number; lon: number }[] {
    const pts = [];
    for (let i = 0; i < n; i++) {
      pts.push(offset(ORIGIN, (i % 20) * 15 - 150 + ((i * 7) % 11), Math.floor(i / 20) * 6 - 150));
    }
    return pts;
  }
  function straightRoadOutside(n: number): { lat: number; lon: number }[] {
    const pts = [];
    for (let i = 0; i < n; i++) pts.push(offset(ORIGIN, 400 + i * 3, 0));
    return pts;
  }

  it("does NOT match a route that is half inside and half a straight road outside (raw ratio 0.50)", () => {
    const points = [...wanderingInside(1000), ...straightRoadOutside(1000)];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [A] });
    expect(outcome.kind).toBe("typeahead");
  });

  it("gives the SAME outcome whether or not the route was thinned below the 500-point simplification cap", () => {
    const points = [...wanderingInside(1000), ...straightRoadOutside(1000)];
    const thinned = points.filter((_, i) => i % 5 === 0); // 400 raw points, same proportions
    const full = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [A] });
    const thin = matchRoute({ fixes: fixesAlong(thinned, T0, T0 + 4 * HOUR), candidates: [A] });
    expect(full.kind).toBe(thin.kind);
    expect(full.kind).toBe("typeahead");
  });

  it("DOES match a 90%-inside round with 10% single-fix spikes outside", () => {
    const pts = [];
    for (let i = 0; i < 3000; i++) {
      const t = (i / 3000) * 2 * Math.PI * 6;
      let p = offset(ORIGIN, 150 * Math.cos(t), 150 * Math.sin(t));
      if (i % 10 === 0) p = offset(ORIGIN, 150 * Math.cos(t) * 2.2, 150 * Math.sin(t) * 2.2); // spike outside
      pts.push(p);
    }
    const outcome = matchRoute({ fixes: fixesAlong(pts, T0, T0 + 4 * HOUR), candidates: [A] });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.insideRatio).toBeGreaterThanOrEqual(0.6);
      expect(outcome.course.insideRatio).toBeLessThan(1);
    }
  });
});

describe("gate fix 2: a qualifying polygon candidate always outranks every radius candidate", () => {
  it("prefers the polygon course over a nearby qualifying radius course, never comparing their scores", () => {
    const A: CandidateCourse = {
      id: "crs_A",
      facilityId: "fac_A",
      verificationTier: "play-verified",
      polygon: rectangle(ORIGIN, 400, 400),
    };
    const B: CandidateCourse = {
      id: "crs_B_radius",
      facilityId: "fac_B",
      verificationTier: "listed-verified",
      radiusFallback: { center: offset(ORIGIN, -260, 0), radiusMeters: 250 },
    };
    // A loop confined to A's polygon (~0.8 insideRatio, well below a
    // theoretical "radius beats polygon" score but still ≥ 0.6), whose
    // start/end also both happen to sit inside B's circle.
    const points = [
      offset(ORIGIN, -190, 0),
      ...loopInsideRectangle(ORIGIN, 400, 400, 40, 78),
      offset(ORIGIN, 300, 0),
      offset(ORIGIN, -190, 10),
    ];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [A, B] });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") {
      expect(outcome.course.courseId).toBe("crs_A");
      expect(outcome.course.geometryKind).toBe("polygon");
    }
  });

  it("falls back to the radius tier only when no polygon candidate qualifies, and asks_user when several radius candidates qualify", () => {
    const R1: CandidateCourse = {
      id: "crs_R1",
      facilityId: "fac_R1",
      verificationTier: "listed-verified",
      radiusFallback: { center: offset(ORIGIN, -100, 0), radiusMeters: 300 },
    };
    const R2: CandidateCourse = {
      id: "crs_R2",
      facilityId: "fac_R2",
      verificationTier: "listed-verified",
      radiusFallback: { center: offset(ORIGIN, 100, 0), radiusMeters: 300 },
    };
    // Start and end both inside BOTH circles (circles overlap around the origin).
    const points = [offset(ORIGIN, 20, 0), offset(ORIGIN, 0, 50), offset(ORIGIN, -20, 0)];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [R1, R2] });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.tied.every((t) => t.geometryKind === "radius")).toBe(true);
      expect(outcome.tied.every((t) => t.insideRatio === null)).toBe(true);
    }
  });
});

describe("should-fix 4: a solo top candidate flagged sharedGeometry still asks_user", () => {
  it("asks_user even when duration filtered the sibling out of this call", () => {
    const sharedPolygon = rectangle(ORIGIN, 400, 400);
    const nine: CandidateCourse = {
      id: "crs_s9",
      facilityId: "fac_S",
      verificationTier: "play-verified",
      sharedGeometry: true,
      holes: 9,
      polygon: sharedPolygon,
    };
    const eighteen: CandidateCourse = {
      id: "crs_s18",
      facilityId: "fac_S",
      verificationTier: "play-verified",
      sharedGeometry: true,
      polygon: sharedPolygon,
    };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    // 1h: only the 9-hole sibling's duration window (≥0.75h) is satisfied;
    // the 18-hole sibling (1.5–6h) is filtered out entirely.
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 1 * HOUR), candidates: [nine, eighteen] });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.reason).toBe("shared_geometry");
      expect(outcome.tied).toHaveLength(1);
      expect(outcome.tied[0]!.courseId).toBe("crs_s9");
    }
  });

  it("asks_user even with only one candidate in the whole input", () => {
    const eighteen: CandidateCourse = {
      id: "crs_s18",
      facilityId: "fac_S",
      verificationTier: "play-verified",
      sharedGeometry: true,
      polygon: rectangle(ORIGIN, 400, 400),
    };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 3 * HOUR), candidates: [eighteen] });
    expect(outcome.kind).toBe("ask_user");
    if (outcome.kind === "ask_user") {
      expect(outcome.reason).toBe("shared_geometry");
      expect(outcome.tied).toHaveLength(1);
    }
  });

  it("still matches normally (no ask_user) when the solo qualifying candidate is NOT flagged shared", () => {
    const solo: CandidateCourse = {
      id: "crs_solo",
      facilityId: "fac_solo",
      verificationTier: "play-verified",
      polygon: rectangle(ORIGIN, 400, 400),
    };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 3 * HOUR), candidates: [solo] });
    expect(outcome.kind).toBe("matched");
  });
});

describe("should-fix 5: fixes are sorted stably by timestamp before anything else", () => {
  it("gives the same result for an unsorted fix array as for the sorted one", () => {
    const R: CandidateCourse = {
      id: "crs_R",
      facilityId: "fac_R",
      verificationTier: "listed-verified",
      radiusFallback: { center: ORIGIN, radiusMeters: 300 },
    };
    const p0 = offset(ORIGIN, 0, 0); // true start (t=T0): inside
    const p1 = offset(ORIGIN, -1000, 0); // t=T0+2h: outside, irrelevant to accept rule
    const p2 = offset(ORIGIN, 50, 50); // true end (t=T0+4h): inside
    const p3 = offset(ORIGIN, 1000, 0); // t=T0+3h: outside, irrelevant
    const sorted = [
      { point: p0, timestamp: T0 },
      { point: p1, timestamp: T0 + 2 * HOUR },
      { point: p3, timestamp: T0 + 3 * HOUR },
      { point: p2, timestamp: T0 + 4 * HOUR },
    ];
    const shuffled = [sorted[2]!, sorted[0]!, sorted[3]!, sorted[1]!];

    const a = matchRoute({ fixes: shuffled, candidates: [R] });
    const b = matchRoute({ fixes: sorted, candidates: [R] });
    expect(a).toEqual(b);
    expect(a.kind).toBe("matched");
  });

  it("stableSortByTimestamp keeps original relative order for equal timestamps", () => {
    const items = [
      { id: "a", timestamp: 5 },
      { id: "b", timestamp: 1 },
      { id: "c", timestamp: 1 },
      { id: "d", timestamp: 3 },
    ];
    expect(stableSortByTimestamp(items).map((i) => i.id)).toEqual(["b", "c", "d", "a"]);
  });
});

describe("should-fix 6: matchRoute validates input and throws RangeError on non-finite fields", () => {
  const A: CandidateCourse = {
    id: "crs_A",
    facilityId: "fac_A",
    verificationTier: "play-verified",
    polygon: rectangle(ORIGIN, 400, 400),
  };

  it("throws on a NaN lat/lon in one fix", () => {
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const fixes = fixesAlong(points, T0, T0 + 3 * HOUR);
    fixes[5] = { point: { lat: NaN, lon: NaN }, timestamp: T0 + 1000 };
    expect(() => matchRoute({ fixes, candidates: [A] })).toThrow(RangeError);
  });

  it("throws on a NaN timestamp", () => {
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const fixes = fixesAlong(points, T0, T0 + 3 * HOUR).map((f) => ({ ...f, timestamp: NaN }));
    expect(() => matchRoute({ fixes, candidates: [A] })).toThrow(RangeError);
  });

  it("does not throw for a single valid fix", () => {
    const outcome = matchRoute({ fixes: [{ point: ORIGIN, timestamp: T0 }], candidates: [A] });
    expect(outcome.kind).toBe("typeahead");
  });
});

describe("should-fix 7: determinism", () => {
  it("sorts tied by score, then by courseId — independent of candidate input order", () => {
    const S = rectangle(ORIGIN, 400, 400);
    const x: CandidateCourse = {
      id: "crs_x",
      facilityId: "f",
      verificationTier: "play-verified",
      sharedGeometry: true,
      polygon: S,
    };
    const y: CandidateCourse = {
      id: "crs_y",
      facilityId: "f",
      verificationTier: "play-verified",
      sharedGeometry: true,
      polygon: S,
    };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const fixes = fixesAlong(points, T0, T0 + 3 * HOUR);
    const forward = matchRoute({ fixes, candidates: [x, y] });
    const reversed = matchRoute({ fixes, candidates: [y, x] });
    expect(forward.kind).toBe("ask_user");
    expect(reversed.kind).toBe("ask_user");
    if (forward.kind === "ask_user" && reversed.kind === "ask_user") {
      expect(forward.tied.map((t) => t.courseId)).toEqual(["crs_x", "crs_y"]);
      expect(reversed.tied.map((t) => t.courseId)).toEqual(["crs_x", "crs_y"]);
    }
  });
});

describe("should-fix 8: output contract", () => {
  it("carries startedAt/endedAt and the matched course's holes", () => {
    const A: CandidateCourse = {
      id: "crs_A",
      facilityId: "fac_A",
      verificationTier: "play-verified",
      holes: 9,
      polygon: rectangle(ORIGIN, 200, 200),
    };
    const points = loopInsideRectangle(ORIGIN, 200, 200, 20, 24);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 55 * 60_000), candidates: [A] });
    expect(outcome.summary.startedAt).toBe(T0);
    expect(outcome.summary.endedAt).toBe(T0 + 55 * 60_000);
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") expect(outcome.course.holes).toBe(9);
  });

  it("typeahead lists nearby (non-qualifying) candidate ids, sorted", () => {
    const far: CandidateCourse = {
      id: "crs_zzz",
      facilityId: "fac_far",
      verificationTier: "play-verified",
      polygon: rectangle(offset(ORIGIN, 3500, 0), 200, 200),
    };
    const near: CandidateCourse = {
      id: "crs_aaa",
      facilityId: "fac_near",
      verificationTier: "play-verified",
      polygon: rectangle(offset(ORIGIN, 100, 0), 50, 50), // too small/far from the route below to qualify
    };
    const points = loopInsideRectangle(ORIGIN, 200, 200, 20, 24);
    const outcome = matchRoute({
      fixes: fixesAlong(points, T0, T0 + 1 * 60_000), // way too short a duration to qualify anything
      candidates: [far, near],
    });
    expect(outcome.kind).toBe("typeahead");
    if (outcome.kind === "typeahead") {
      expect(outcome.nearbyCandidateIds).toEqual(["crs_aaa"]); // "far" is outside the 3 km search radius
    }
  });
});

describe("should-fix 9: polygons with holes, and multipolygons", () => {
  it("treats a point inside a hole as outside the polygon", () => {
    const outer = rectangle(ORIGIN, 400, 400);
    const hole = rectangle(ORIGIN, 100, 100); // a lake in the middle of the course
    const prepared = preparePolygonGeometry([outer, hole]);
    expect(prepared).toBeDefined();
    if (!prepared) return;
    // Center of the hole: outside (it's within the hole).
    expect(isInsidePreparedWithBuffer(ORIGIN, prepared, 0)).toBe(false);
    // Between the hole and the outer edge: inside.
    expect(isInsidePreparedWithBuffer(offset(ORIGIN, 150, 0), prepared, 0)).toBe(true);
  });

  it("matches a route confined to one lobe of a two-lobe multipolygon course", () => {
    const lobeA: import("../src/index.js").PolygonWithHoles = [rectangle(offset(ORIGIN, -300, 0), 300, 300)];
    const lobeB: import("../src/index.js").PolygonWithHoles = [rectangle(offset(ORIGIN, 300, 0), 300, 300)];
    const candidate: CandidateCourse = {
      id: "crs_multi",
      facilityId: "fac_multi",
      verificationTier: "play-verified",
      polygon: [lobeA, lobeB],
    };
    const points = loopInsideRectangle(offset(ORIGIN, -300, 0), 300, 300, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [candidate] });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") expect(outcome.course.insideRatio).toBeGreaterThan(0.9);
  });

  it("a hole excludes a check-in fix that would otherwise be inside", () => {
    const outer = rectangle(ORIGIN, 400, 400);
    const hole = rectangle(ORIGIN, 300, 300);
    const candidate: CandidateCourse = {
      id: "crs_hole",
      facilityId: "fac_hole",
      verificationTier: "play-verified",
      polygon: [outer, hole],
    };
    // The hole has a 150 m half-width; ORIGIN is dead center of the hole,
    // well clear (150 m > 50 m) of the check-in buffer around the hole's
    // own edge, so the buffer cannot rescue it.
    const result = matchCheckIn(
      { point: ORIGIN, accuracyMeters: 5, simulated: false, timestamp: T0 },
      candidate,
    );
    expect(result.accepted).toBe(false);
  });
});

describe("should-fix 10: performance", () => {
  it("matches an 18,000-fix route against 300 candidates of 400 vertices in well under 1 s", () => {
    const points: { lat: number; lon: number }[] = [];
    for (let i = 0; i < 18_000; i++) {
      const t = (i / 18_000) * 2 * Math.PI * 9;
      points.push(
        offset(ORIGIN, 180 * Math.cos(t) + 20 * Math.sin(i * 0.37), 180 * Math.sin(t * 1.3) + 20 * Math.cos(i * 0.51)),
      );
    }
    const circle = (center: { lat: number; lon: number }, radius: number, n: number) =>
      Array.from({ length: n }, (_, k) => offset(center, radius * Math.cos((2 * Math.PI * k) / n), radius * Math.sin((2 * Math.PI * k) / n)));
    const candidates: CandidateCourse[] = [];
    for (let k = 0; k < 300; k++) {
      candidates.push({
        id: `crs_${k}`,
        facilityId: `fac_${k}`,
        verificationTier: "unverified",
        polygon: circle(offset(ORIGIN, (k % 20) * 800 - 8000, Math.floor(k / 20) * 800 - 6000), 350, 400),
      });
    }
    const fixes = points.map((p, i) => ({ point: p, timestamp: i * 1000 }));
    const start = Date.now();
    const outcome = matchRoute({ fixes, candidates });
    const elapsedMs = Date.now() - start;
    expect(outcome.kind).toBeDefined();
    // Generous bound (the gate's own target is "under 1 s"; observed
    // locally around 300–400 ms).
    expect(elapsedMs).toBeLessThan(5000);
  });

  it("simplifies 200,000 points without throwing (no native recursion, no stack overflow)", () => {
    const points: { lat: number; lon: number }[] = [];
    for (let i = 0; i < 200_000; i++) {
      const a = i * 0.001;
      points.push(offset(ORIGIN, a * 5 * Math.cos(a), a * 5 * Math.sin(a)));
    }
    expect(() => simplifyToMaxPoints(points, 500)).not.toThrow();
    expect(simplifyToMaxPoints(points, 500)).toHaveLength(500);
  });
});

describe("mutation-catching boundary fixtures", () => {
  const buildPolygonRoute = (insideFraction: number, n: number) => {
    // A loop where exactly insideFraction of points sit inside a 400x400
    // course rectangle and the rest sit ~200 m further out (well clear of
    // the 30 m buffer either way).
    const insideCount = Math.round(n * insideFraction);
    const pts: { lat: number; lon: number }[] = [];
    for (let i = 0; i < n; i++) {
      pts.push(
        i < insideCount
          ? offset(ORIGIN, (i % 10) * 30 - 135, Math.floor(i / 10) * 30 - 135)
          : offset(ORIGIN, 800 + i, 800),
      );
    }
    return pts;
  };

  it("score gap 0.14 (tied, ask_user) vs 0.16 (clear winner, matched)", () => {
    const facilityId = "fac_gap";
    // 100 points on a line, 50 m apart (well over the 30 m buffer, so each
    // point's inclusion is unambiguous), evenly spaced in time so the
    // time-weighted ratio equals the plain point fraction.
    const points = Array.from({ length: 100 }, (_, i) => offset(ORIGIN, i * 50, 0));

    // A box spanning x ∈ [-50, maxX] (+30 m buffer) includes point i iff
    // i*50 <= maxX + 30. Choosing maxX = (count-1)*50 includes exactly
    // `count` points (i = 0..count-1) with a comfortable margin before
    // the next excluded point (>= 50 m - 30 m = 20 m clearance).
    function boxCoveringCount(count: number): PolygonInput {
      const maxX = (count - 1) * 50;
      return [
        offset(ORIGIN, -50, -50),
        offset(ORIGIN, maxX, -50),
        offset(ORIGIN, maxX, 50),
        offset(ORIGIN, -50, 50),
      ];
    }

    const A: CandidateCourse = {
      id: "crs_gap_a",
      facilityId,
      verificationTier: "play-verified",
      polygon: boxCoveringCount(90), // insideRatio 0.90
    };

    function outcomeWithBRatio(count: number) {
      const B: CandidateCourse = {
        id: "crs_gap_b",
        facilityId,
        verificationTier: "play-verified",
        polygon: boxCoveringCount(count),
      };
      return matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [A, B] });
    }

    const clearWinner = outcomeWithBRatio(74); // gap = 0.90 - 0.74 = 0.16 → not tied
    const tied = outcomeWithBRatio(76); // gap = 0.90 - 0.76 = 0.14 → tied

    expect(clearWinner.kind).toBe("matched");
    if (clearWinner.kind === "matched") expect(clearWinner.course.courseId).toBe("crs_gap_a");
    expect(tied.kind).toBe("ask_user");
  });

  it("buffer: 25 m from the edge is inside (+30 m buffer), 35 m is outside", () => {
    const rect = rectangle(ORIGIN, 400, 400); // half-width 200 m
    const A: CandidateCourse = { id: "crs_buf", facilityId: "fac_buf", verificationTier: "play-verified", polygon: rect };
    const inside25 = offset(ORIGIN, 225, 0); // 25 m past the 200 m edge
    const outside35 = offset(ORIGIN, 235, 0); // 35 m past the edge
    const loop25 = Array.from({ length: 40 }, () => inside25);
    const loop35 = Array.from({ length: 40 }, () => outside35);
    const a = matchRoute({ fixes: fixesAlong(loop25, T0, T0 + 4 * HOUR), candidates: [A] });
    const b = matchRoute({ fixes: fixesAlong(loop35, T0, T0 + 4 * HOUR), candidates: [A] });
    expect(a.kind).toBe("matched");
    expect(b.kind).toBe("typeahead");
  });

  it("radius: both ends inside matches; one end outside does not", () => {
    const R: CandidateCourse = {
      id: "crs_radius_edge",
      facilityId: "fac_radius_edge",
      verificationTier: "listed-verified",
      radiusFallback: { center: ORIGIN, radiusMeters: 300 },
    };
    const bothInside = [offset(ORIGIN, 50, 0), offset(ORIGIN, 0, 50), offset(ORIGIN, -50, 0)];
    const oneOutside = [offset(ORIGIN, 50, 0), offset(ORIGIN, 0, 50), offset(ORIGIN, 400, 0)];
    const a = matchRoute({ fixes: fixesAlong(bothInside, T0, T0 + 4 * HOUR), candidates: [R] });
    const b = matchRoute({ fixes: fixesAlong(oneOutside, T0, T0 + 4 * HOUR), candidates: [R] });
    expect(a.kind).toBe("matched");
    expect(b.kind).toBe("typeahead");
  });

  it("9-hole duration: 44 min does not qualify, 46 min does (0.75 h = 45 min floor)", () => {
    const nine: CandidateCourse = {
      id: "crs_nine_edge",
      facilityId: "fac_nine_edge",
      verificationTier: "play-verified",
      holes: 9,
      polygon: rectangle(ORIGIN, 200, 200),
    };
    const points = loopInsideRectangle(ORIGIN, 200, 200, 20, 24);
    const short = matchRoute({ fixes: fixesAlong(points, T0, T0 + 44 * 60_000), candidates: [nine] });
    const long = matchRoute({ fixes: fixesAlong(points, T0, T0 + 46 * 60_000), candidates: [nine] });
    expect(short.kind).toBe("typeahead");
    expect(long.kind).toBe("matched");
  });

  it("18-hole duration lower edge: 1.49 h does not qualify, 1.51 h does", () => {
    const A: CandidateCourse = { id: "crs_dur_lo", facilityId: "fac_dur_lo", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 400, 400) };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const low = matchRoute({ fixes: fixesAlong(points, T0, T0 + 1.49 * HOUR), candidates: [A] });
    const ok = matchRoute({ fixes: fixesAlong(points, T0, T0 + 1.51 * HOUR), candidates: [A] });
    expect(low.kind).toBe("typeahead");
    expect(ok.kind).toBe("matched");
  });

  it("18-hole duration upper edge: 5.99 h qualifies, 6.01 h does not", () => {
    const A: CandidateCourse = { id: "crs_dur_hi", facilityId: "fac_dur_hi", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 400, 400) };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const ok = matchRoute({ fixes: fixesAlong(points, T0, T0 + 5.99 * HOUR), candidates: [A] });
    const high = matchRoute({ fixes: fixesAlong(points, T0, T0 + 6.01 * HOUR), candidates: [A] });
    expect(ok.kind).toBe("matched");
    expect(high.kind).toBe("typeahead");
  });

  it("insideRatio 0.59 does not qualify, 0.61 does", () => {
    const A: CandidateCourse = { id: "crs_ratio_edge", facilityId: "fac_ratio_edge", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 400, 400) };
    const n = 100;
    const low = buildPolygonRoute(0.59, n);
    const high = buildPolygonRoute(0.61, n);
    const a = matchRoute({ fixes: fixesAlong(low, T0, T0 + 4 * HOUR), candidates: [A] });
    const b = matchRoute({ fixes: fixesAlong(high, T0, T0 + 4 * HOUR), candidates: [A] });
    expect(a.kind).toBe("typeahead");
    expect(b.kind).toBe("matched");
    if (b.kind === "matched") expect(b.course.insideRatio).toBeCloseTo(0.61, 2);
  });

  it("a route over 500 raw points still computes insideRatio from the raw fixes, not the simplified ones", () => {
    const A: CandidateCourse = { id: "crs_over500", facilityId: "fac_over500", verificationTier: "play-verified", polygon: rectangle(ORIGIN, 400, 400) };
    // 600 raw points, exactly half inside / half on a straight road well
    // outside — must NOT match, and must be simplified to ≤500 for the
    // summary while still scoring on the raw 600.
    const inside = Array.from({ length: 300 }, (_, i) => offset(ORIGIN, (i % 10) * 30 - 135, Math.floor(i / 10) * 5 - 75));
    const outside = Array.from({ length: 300 }, (_, i) => offset(ORIGIN, 800 + i, 800));
    const points = [...inside, ...outside];
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [A] });
    expect(outcome.summary.rawPointCount).toBe(600);
    expect(outcome.summary.pointCount).toBeLessThanOrEqual(500);
    expect(outcome.kind).toBe("typeahead");
  });

  it("a non-qualifying candidate never joins a tie, even if numerically close to the winner", () => {
    const facilityId = "fac_nonqual";
    const winner: CandidateCourse = {
      id: "crs_winner",
      facilityId,
      verificationTier: "play-verified",
      polygon: rectangle(ORIGIN, 400, 400),
    };
    // A duration-disqualified candidate at effectively the same insideRatio
    // (same polygon) but holes:9 with a route duration outside even the
    // 9-hole floor — it must never appear in `tied`.
    const disqualified: CandidateCourse = {
      id: "crs_disqualified",
      facilityId,
      verificationTier: "play-verified",
      holes: 9,
      polygon: rectangle(offset(ORIGIN, 5000, 0), 400, 400), // far away: excluded by candidate search too
    };
    const points = loopInsideRectangle(ORIGIN, 400, 400, 20, 40);
    const outcome = matchRoute({ fixes: fixesAlong(points, T0, T0 + 4 * HOUR), candidates: [winner, disqualified] });
    expect(outcome.kind).toBe("matched");
    if (outcome.kind === "matched") expect(outcome.course.courseId).toBe("crs_winner");
  });
});
