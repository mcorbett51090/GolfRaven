import { describe, expect, it, vi, afterEach } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  buildNOsmQuery,
  buildCourseCoverageQuery,
  parseNOsm,
  splitCoverageResponse,
  matchCourse,
  buildDenominatorEntries,
  computeCoverage,
  courseKey,
  assertNoOverpassRemark,
  runCoverage,
  type OverpassResponse,
  type OverpassGeometryElement,
  type PilotCandidateCourse,
  type CourseCoverageEntry,
} from "../src/x5-overpass.js";
import { boundingBox, haversineMeters, pointInPolygon } from "../src/overpass-geo.js";

const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-x5-test-"));

describe("x5-overpass: query builders match docs/p0/X5.md verbatim", () => {
  it("buildNOsmQuery reproduces the exact X5.md §1 query", () => {
    const q = buildNOsmQuery();
    expect(q).toContain('area["ISO3166-1"="US"][admin_level=2]->.us;');
    expect(q).toContain('area["ISO3166-1"="CA"][admin_level=2]->.ca;');
    expect(q).toContain('way["leisure"="golf_course"](area.us);');
    expect(q).toContain('relation["leisure"="golf_course"](area.ca);');
    expect(q).toContain("out count;");
    expect(q).toContain("[out:json][timeout:180];");
  });

  it("buildCourseCoverageQuery templates the X5.md §2 bbox query shape", () => {
    const q = buildCourseCoverageQuery({ lat: 36.0, lon: -87.0 }, 2000);
    expect(q).toContain('way["leisure"="golf_course"](');
    expect(q).toContain('relation["leisure"="golf_course"](');
    expect(q).toContain("out geom;");
    expect(q).toContain('way["golf"="hole"](');
    expect(q).toContain("out count;");
    expect(q).toContain("[out:json][timeout:60];");
  });
});

describe("x5-overpass: N_osm parsing", () => {
  it("parses the count element's total", () => {
    const response: OverpassResponse = {
      elements: [{ type: "count", id: 0, tags: { total: "16234", nodes: "0", ways: "16000", relations: "234" } }],
    };
    expect(parseNOsm(response)).toBe(16234);
  });

  it("throws when there is no count element", () => {
    const response: OverpassResponse = { elements: [] };
    expect(() => parseNOsm(response)).toThrow(/count/);
  });

  it("gate finding B-4: throws on an Overpass remark (runtime error), never silently returns", () => {
    const response: OverpassResponse = { elements: [], remark: "runtime error: query timed out" };
    expect(() => parseNOsm(response)).toThrow(/remark/);
  });
});

describe("x5-overpass: assertNoOverpassRemark / run integrity (decision 0001 Addendum F)", () => {
  it("does not throw when there is no remark", () => {
    expect(() => assertNoOverpassRemark({ elements: [] }, "ctx")).not.toThrow();
  });

  it("throws, naming the context, when a remark is present", () => {
    expect(() => assertNoOverpassRemark({ elements: [], remark: "timeout" }, "course X")).toThrow(/course X/);
  });

  it("splitCoverageResponse throws on a remark instead of returning an empty/unmatched result", () => {
    const response = { elements: [], remark: "runtime error: query timed out" } as unknown as OverpassResponse;
    expect(() => splitCoverageResponse(response, "course X")).toThrow(/remark/);
  });

  it("splitCoverageResponse throws on an unparseable response (no elements array)", () => {
    const response = { foo: "bar" } as unknown as OverpassResponse;
    expect(() => splitCoverageResponse(response, "course X")).toThrow(/unparseable/);
  });
});

describe("x5-overpass: match rule (decision 0001 Addendum F, literal)", () => {
  // A simple square polygon "containing" (36.00, -87.00).
  const containingWay: OverpassGeometryElement = {
    type: "way",
    id: 1,
    tags: { name: "Pilot Ridge Golf Course", leisure: "golf_course" },
    geometry: [
      { lat: 35.99, lon: -87.01 },
      { lat: 35.99, lon: -86.99 },
      { lat: 36.01, lon: -86.99 },
      { lat: 36.01, lon: -87.01 },
    ],
  };
  const neighborWay: OverpassGeometryElement = {
    type: "way",
    id: 2,
    tags: { name: "Neighbor Course", leisure: "golf_course" },
    geometry: [
      { lat: 37.99, lon: -88.01 },
      { lat: 37.99, lon: -87.99 },
      { lat: 38.01, lon: -87.99 },
      { lat: 38.01, lon: -88.01 },
    ],
  };

  it("point-containment: matches when the known point is inside a candidate polygon", () => {
    const course: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: 36.0,
      lon: -87.0,
      trail: "TN",
      unit: "course",
      knownPoint: { lat: 36.0, lon: -87.0 },
    };
    expect(matchCourse(course, [neighborWay, containingWay])).toBe("point");
  });

  it("point-containment: does NOT match a bbox neighbor whose polygon doesn't contain the point", () => {
    const course: PilotCandidateCourse = {
      name: "Some Course",
      lat: 36.0,
      lon: -87.0,
      trail: "TN",
      unit: "course",
      knownPoint: { lat: 36.0, lon: -87.0 },
    };
    // Only the neighbor's (non-containing) polygon is returned.
    expect(matchCourse(course, [neighborWay])).toBeNull();
  });

  it("point-containment does NOT fall back to name-match when a known point is given but doesn't match", () => {
    const course: PilotCandidateCourse = {
      name: "Neighbor Course", // name matches neighborWay...
      lat: 38.0,
      lon: -88.0,
      trail: "TN",
      unit: "course",
      knownPoint: { lat: 36.0, lon: -87.0 }, // ...but the point is nowhere near it
    };
    expect(matchCourse(course, [neighborWay])).toBeNull();
  });

  it("name-match: a point INSIDE a same-named polygon matches (distance 0 — gate finding B-2)", () => {
    const course: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: 36.0,
      lon: -87.0, // inside containingWay
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(course, [containingWay])).toBe("name");
  });

  it("BOUNDARY: name-match distance is to the POLYGON EDGE, not a centroid — 499m outside passes, 501m fails", () => {
    // containingWay's north edge is at lat 36.01.
    const northEdgeLat = 36.01;
    const justInside: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: northEdgeLat + 499 / 111320, // ~499m north of the edge itself
      lon: -87.0,
      trail: "TN",
      unit: "course",
    };
    const justOutside: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: northEdgeLat + 501 / 111320, // ~501m north of the edge itself
      lon: -87.0,
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(justInside, [containingWay])).toBe("name");
    expect(matchCourse(justOutside, [containingWay])).toBeNull();
  });

  it("name-match requires the name to match, not just proximity", () => {
    const course: PilotCandidateCourse = {
      name: "Totally Different Name",
      lat: 36.0,
      lon: -87.0,
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(course, [containingWay])).toBeNull();
  });

  it("name-match is case-insensitive (Addendum F normalisation)", () => {
    const course: PilotCandidateCourse = {
      name: "pilot ridge golf course",
      lat: 36.0,
      lon: -87.0,
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(course, [containingWay])).toBe("name");
  });

  it("does not count 'any polygon returned by the bbox' — only a genuinely matching one", () => {
    const course: PilotCandidateCourse = {
      name: "Not In This List",
      lat: 36.0,
      lon: -87.0,
      trail: "TN",
      unit: "course",
    };
    // Both a containing-but-wrong-name way and a correctly-named-but-far way
    // are present; neither should match.
    expect(matchCourse(course, [containingWay, neighborWay])).toBeNull();
  });
});

describe("x5-overpass: name normalisation (decision 0001 Addendum F, gate finding B-3 — literal, no abbreviation list)", () => {
  function namedWay(name: string): OverpassGeometryElement {
    return {
      type: "way",
      id: 99,
      tags: { name, leisure: "golf_course" },
      geometry: [
        { lat: 35.99, lon: -87.01 },
        { lat: 35.99, lon: -86.99 },
        { lat: 36.01, lon: -86.99 },
        { lat: 36.01, lon: -87.01 },
      ],
    };
  }
  function courseNamed(name: string): PilotCandidateCourse {
    return { name, lat: 36.0, lon: -87.0, trail: "TN", unit: "course" };
  }

  it("trailing whitespace and case differences are normalised away", () => {
    expect(matchCourse(courseNamed("Pilot Ridge Golf Course"), [namedWay("  pilot ridge golf course  ")])).toBe(
      "name",
    );
  });

  it("typographic apostrophes are unified by NFKD + non-letter/digit stripping", () => {
    expect(matchCourse(courseNamed("Hammock's Dunes"), [namedWay("Hammock’s Dunes")])).toBe("name");
  });

  it("NBSP and doubled internal whitespace collapse to a single space", () => {
    expect(matchCourse(courseNamed("Pilot Ridge Golf Course"), [namedWay("Pilot Ridge  Golf   Course")])).toBe(
      "name",
    );
  });

  it("diacritics are stripped via NFKD (Café Course == Cafe Course)", () => {
    expect(matchCourse(courseNamed("Cafe Course"), [namedWay("Café Course")])).toBe("name");
  });

  it('"St." and "Saint" do NOT match — no abbreviation list, per Addendum F literally', () => {
    expect(matchCourse(courseNamed("St. Andrews Golf Course"), [namedWay("Saint Andrews Golf Course")])).toBeNull();
  });

  it('"Golf Club" and "Golf Course" do NOT match — no generic-suffix unification', () => {
    expect(matchCourse(courseNamed("Pilot Ridge Golf Club"), [namedWay("Pilot Ridge Golf Course")])).toBeNull();
  });

  it("whole-word containment: the course name as a whole-word sequence inside a longer OSM name matches", () => {
    // "the OSM name equals the course name, or contains it as a whole-word sequence"
    expect(
      matchCourse(courseNamed("Grand National"), [namedWay("Robert Trent Jones Golf Trail at Grand National")]),
    ).toBe("name");
  });

  it("whole-word containment does NOT match a mere substring across word boundaries", () => {
    expect(matchCourse(courseNamed("Grand"), [namedWay("Grandview Golf Course")])).toBeNull();
  });

  it("an empty/whitespace-only course name never matches", () => {
    expect(matchCourse(courseNamed("   "), [namedWay("Anything Golf Course")])).toBeNull();
  });
});

describe("x5-overpass: relation (multipolygon) outer-ring assembly — gate finding B-1", () => {
  // A rectangle split into two OPEN "outer"-role way segments that must be
  // joined end-to-end (Overpass out geom shape: a relation's geometry is
  // under members[], never a top-level `geometry`).
  const A = { lat: 36.0, lon: -87.01 };
  const B = { lat: 36.0, lon: -86.99 };
  const C = { lat: 36.02, lon: -86.99 };
  const D = { lat: 36.02, lon: -87.01 };
  const splitRingRelation: OverpassGeometryElement = {
    type: "relation",
    id: 500,
    tags: { name: "Split Ring Course", leisure: "golf_course" },
    members: [
      { type: "way", ref: 1, role: "outer", geometry: [A, B, C] },
      { type: "way", ref: 2, role: "outer", geometry: [C, D, A] },
    ],
  };
  const insidePoint = { lat: 36.01, lon: -87.0 };

  it("a relation has NO top-level geometry (confirms the shape this fixture and the fix target)", () => {
    expect((splitRingRelation as unknown as { geometry?: unknown }).geometry).toBeUndefined();
  });

  it("point-containment matches against a relation's assembled outer ring (split across 2 members)", () => {
    const course: PilotCandidateCourse = {
      name: "Anything",
      lat: insidePoint.lat,
      lon: insidePoint.lon,
      trail: "TN",
      unit: "course",
      knownPoint: insidePoint,
    };
    expect(matchCourse(course, [splitRingRelation])).toBe("point");
  });

  it("name-match against a relation gets distance 0 for a point inside its assembled outer ring", () => {
    const course: PilotCandidateCourse = {
      name: "Split Ring Course",
      lat: insidePoint.lat,
      lon: insidePoint.lon,
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(course, [splitRingRelation])).toBe("name");
  });

  it("a relation with only NODE members (no way geometry) has no rings and never matches", () => {
    const nodeOnlyRelation: OverpassGeometryElement = {
      type: "relation",
      id: 501,
      tags: { name: "No Geometry Course", leisure: "golf_course" },
      members: [{ type: "node", ref: 9, role: "outer" }],
    };
    const course: PilotCandidateCourse = {
      name: "No Geometry Course",
      lat: 36.01,
      lon: -87.0,
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(course, [nodeOnlyRelation])).toBeNull();
  });
});

describe("x5-overpass: splitCoverageResponse separates geometry from the golf=hole count", () => {
  it("splits way/relation elements from the count element", () => {
    const response: OverpassResponse = {
      elements: [
        { type: "way", id: 1, tags: { leisure: "golf_course" }, geometry: [] },
        { type: "count", id: 0, tags: { total: "9" } },
      ],
    };
    const { matchingElements, golfHoleWaysInBbox } = splitCoverageResponse(response, "test");
    expect(matchingElements).toHaveLength(1);
    expect(golfHoleWaysInBbox).toBe(9);
  });
});

describe("x5-overpass: unit + facility-sharing rules (docs/p0/X5.md 'Unit', literal)", () => {
  function coverageEntry(
    name: string,
    trail: string,
    unit: PilotCandidateCourse["unit"],
    matched: boolean,
    facilityId?: string,
    id?: string,
  ): CourseCoverageEntry {
    const course: PilotCandidateCourse = {
      name,
      lat: 0,
      lon: 0,
      trail,
      unit,
      ...(facilityId ? { facilityId } : {}),
      ...(id ? { id } : {}),
    };
    return { course, matchedVia: matched ? "point" : null, golfHoleWaysInBbox: 0 };
  }

  it("'course' unit: one denominator entry per course, even when several share a facility polygon", () => {
    // RTJ-style: 3 courses at 1 site, all matched via the same shared facility polygon.
    const entries = [
      coverageEntry("RTJ Course A", "RTJ", "course", true),
      coverageEntry("RTJ Course B", "RTJ", "course", true),
      coverageEntry("RTJ Course C", "RTJ", "course", true),
    ];
    const denom = buildDenominatorEntries(entries, []);
    expect(denom).toHaveLength(3); // one data point per course, not one per facility
    expect(denom.every((e) => e.matched)).toBe(true);
  });

  it("'facility' unit: groups courses sharing a facilityId into one denominator entry", () => {
    const entries = [
      coverageEntry("Facility Course A", "VI", "facility", true, "fac-1"),
      coverageEntry("Facility Course B", "VI", "facility", false, "fac-1"),
    ];
    const warnings: string[] = [];
    const denom = buildDenominatorEntries(entries, warnings);
    expect(denom).toHaveLength(1);
    expect(denom[0]?.matched).toBe(true); // any course at the facility matching is enough
    expect(denom[0]?.courseNames).toEqual(["Facility Course A", "Facility Course B"]);
  });

  it("'hole' unit is one denominator entry per course (decision 0001 Addendum E)", () => {
    const entries = [coverageEntry("Hole Unit Course", "OK", "hole", true)];
    const warnings: string[] = [];
    const denom = buildDenominatorEntries(entries, warnings);
    expect(denom).toHaveLength(1);
    // Addendum E pins hole-unit as one entry per course, so no "unspecified rule" warning is emitted.
    expect(warnings.some((w) => w.includes("does not specify hole-unit"))).toBe(false);
  });

  it("gate finding B-12: two courses sharing a NAME get distinct denominator entries when each has its own id", () => {
    const entries = [
      coverageEntry("Pilot Course", "TN", "course", true, undefined, "tn-1"),
      coverageEntry("Pilot Course", "RTJ", "course", false, undefined, "rtj-9"),
    ];
    const denom = buildDenominatorEntries(entries, []);
    expect(denom.map((e) => e.key).sort()).toEqual(["rtj-9", "tn-1"]);
  });

  it("courseKey falls back to name when no id is given", () => {
    const course: PilotCandidateCourse = { name: "No Id Course", lat: 0, lon: 0, trail: "TN", unit: "course" };
    expect(courseKey(course)).toBe("No Id Course");
  });
});

describe("x5-overpass: coverage calculation and the 60% bar (literal)", () => {
  it("BOUNDARY: exactly 60% is a pass", () => {
    const entries = [
      { key: "a", trail: "T", matched: true, courseNames: ["a"] },
      { key: "b", trail: "T", matched: true, courseNames: ["b"] },
      { key: "c", trail: "T", matched: true, courseNames: ["c"] },
      { key: "d", trail: "T", matched: false, courseNames: ["d"] },
      { key: "e", trail: "T", matched: false, courseNames: ["e"] },
    ];
    const summary = computeCoverage(entries);
    expect(summary.combined.pct).toBe(60);
    expect(summary.overallVerdict).toBe("pass");
  });

  it("BOUNDARY: just under 60% is a kill", () => {
    const entries = [
      { key: "a", trail: "T", matched: true, courseNames: ["a"] },
      { key: "b", trail: "T", matched: true, courseNames: ["b"] },
      { key: "c", trail: "T", matched: false, courseNames: ["c"] },
      { key: "d", trail: "T", matched: false, courseNames: ["d"] },
      { key: "e", trail: "T", matched: false, courseNames: ["e"] },
    ];
    const summary = computeCoverage(entries);
    expect(summary.combined.pct).toBeCloseTo(40, 5);
    expect(summary.overallVerdict).toBe("kill");
  });

  it("computes per-trail coverage alongside combined", () => {
    const entries = [
      { key: "a", trail: "TN", matched: true, courseNames: ["a"] },
      { key: "b", trail: "TN", matched: false, courseNames: ["b"] },
      { key: "c", trail: "VI", matched: true, courseNames: ["c"] },
      { key: "d", trail: "VI", matched: true, courseNames: ["d"] },
    ];
    const summary = computeCoverage(entries);
    expect(summary.perTrail.TN).toEqual({ matchedCount: 1, total: 2, pct: 50 });
    expect(summary.perTrail.VI).toEqual({ matchedCount: 2, total: 2, pct: 100 });
    expect(summary.combined).toEqual({ matchedCount: 3, total: 4, pct: 75 });
  });
});

describe("x5-overpass: geometry helpers", () => {
  it("pointInPolygon: inside and outside a simple square", () => {
    const square = [
      { lat: 0, lon: 0 },
      { lat: 0, lon: 1 },
      { lat: 1, lon: 1 },
      { lat: 1, lon: 0 },
    ];
    expect(pointInPolygon({ lat: 0.5, lon: 0.5 }, square)).toBe(true);
    expect(pointInPolygon({ lat: 2, lon: 2 }, square)).toBe(false);
  });

  it("haversineMeters: distance between two nearby points is roughly correct", () => {
    // 1 degree of latitude is ~111.32km
    const d = haversineMeters({ lat: 0, lon: 0 }, { lat: 1, lon: 0 });
    expect(d).toBeGreaterThan(110_000);
    expect(d).toBeLessThan(112_000);
  });

  it("boundingBox produces a box centered on the input point", () => {
    const bbox = boundingBox({ lat: 36, lon: -87 }, 1000);
    expect(bbox.south).toBeLessThan(36);
    expect(bbox.north).toBeGreaterThan(36);
    expect(bbox.west).toBeLessThan(-87);
    expect(bbox.east).toBeGreaterThan(-87);
  });
});

describe("x5-overpass: run integrity at the CLI level (decision 0001 Addendum F)", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("refuses (throws) on an empty course list, never a vacuous 0/0", async () => {
    const coursesPath = path.join(OUT_DIR, "empty-courses.json");
    writeFileSync(coursesPath, "[]\n", "utf8");
    await expect(
      runCoverage({ courses: coursesPath, out: path.join(OUT_DIR, "empty-result") }),
    ).rejects.toThrow(/empty course list/);
  });

  it("refuses (throws) when --responses is missing a course's response, rather than treating it as unmatched", async () => {
    const coursesPath = path.join(OUT_DIR, "missing-response-courses.json");
    writeFileSync(
      coursesPath,
      JSON.stringify([{ name: "Ghost Course", lat: 36.0, lon: -87.0, trail: "TN", unit: "course" }]),
      "utf8",
    );
    const responsesPath = path.join(OUT_DIR, "missing-response-responses.json");
    writeFileSync(responsesPath, "{}\n", "utf8");
    await expect(
      runCoverage({
        courses: coursesPath,
        responses: responsesPath,
        out: path.join(OUT_DIR, "missing-response-result"),
      }),
    ).rejects.toThrow(/No saved Overpass response/);
  });

  it("gate finding B-5: a LIVE run (no --responses) saves every raw response alongside the result", async () => {
    const coursesPath = path.join(OUT_DIR, "live-courses.json");
    writeFileSync(
      coursesPath,
      JSON.stringify([{ name: "Live Course", lat: 36.0, lon: -87.0, trail: "TN", unit: "course" }]),
      "utf8",
    );
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          elements: [
            { type: "count", id: 0, tags: { total: "0" } },
          ],
        }),
        { status: 200 },
      ),
    );
    vi.stubGlobal("fetch", fetchMock);

    const outPrefix = path.join(OUT_DIR, "live-result");
    await runCoverage({ courses: coursesPath, out: outPrefix });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const saved = JSON.parse(readFileSync(`${outPrefix}-responses.json`, "utf8")) as Record<
      string,
      { query: string; fetchedAt: string; response: unknown }
    >;
    expect(Object.keys(saved)).toEqual(["Live Course"]);
    expect(saved["Live Course"]?.query).toContain("out geom;");
    expect(typeof saved["Live Course"]?.fetchedAt).toBe("string");
  });

  it("gate finding B-11: the bbox is centered on knownPoint when present, not the approximate lat/lon", async () => {
    const coursesPath = path.join(OUT_DIR, "known-point-courses.json");
    writeFileSync(
      coursesPath,
      JSON.stringify([
        {
          name: "Known Point Course",
          lat: 0,
          lon: 0, // far from knownPoint — would produce a very different bbox
          trail: "TN",
          unit: "course",
          knownPoint: { lat: 36.0, lon: -87.0 },
        },
      ]),
      "utf8",
    );
    let capturedBody = "";
    const fetchMock = vi.fn(async (_url: unknown, init: { body: string }) => {
      capturedBody = init.body;
      return new Response(JSON.stringify({ elements: [{ type: "count", id: 0, tags: { total: "0" } }] }), {
        status: 200,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    await runCoverage({ courses: coursesPath, out: path.join(OUT_DIR, "known-point-result") });
    const decoded = decodeURIComponent(capturedBody.replace(/^data=/, ""));
    // The bbox should be built around (36, -87), not (0, 0).
    expect(decoded).toMatch(/3[0-9]\.\d+,-8[0-9]\.\d+,3[0-9]\.\d+,-8[0-9]\.\d+/);
  });
});
