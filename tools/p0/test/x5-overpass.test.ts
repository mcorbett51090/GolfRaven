import { describe, expect, it } from "vitest";
import {
  buildNOsmQuery,
  buildCourseCoverageQuery,
  parseNOsm,
  splitCoverageResponse,
  matchCourse,
  buildDenominatorEntries,
  computeCoverage,
  type OverpassResponse,
  type OverpassGeometryElement,
  type PilotCandidateCourse,
  type CourseCoverageEntry,
} from "../src/x5-overpass.js";
import { boundingBox, haversineMeters, pointInPolygon } from "../src/overpass-geo.js";

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
});

describe("x5-overpass: match rule (docs/p0/X5.md, literal)", () => {
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

  it("name-match fallback: matches within the 500m radius when no known point is given", () => {
    const course: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: 36.0,
      lon: -87.0, // very close to containingWay's centroid
      trail: "TN",
      unit: "course",
    };
    expect(matchCourse(course, [containingWay])).toBe("name");
  });

  it("BOUNDARY: name-match fails just outside 500m, passes just inside", () => {
    // containingWay's centroid is at lat 36.00, lon -87.00 (average of the 4 corners).
    const centroid = { lat: 36.0, lon: -87.0 };
    // ~499m north
    const justInside: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: centroid.lat + 499 / 111320,
      lon: centroid.lon,
      trail: "TN",
      unit: "course",
    };
    // ~501m north
    const justOutside: PilotCandidateCourse = {
      name: "Pilot Ridge Golf Course",
      lat: centroid.lat + 501 / 111320,
      lon: centroid.lon,
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

  it("name-match is case-insensitive", () => {
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

describe("x5-overpass: splitCoverageResponse separates geometry from the golf=hole count", () => {
  it("splits way/relation elements from the count element", () => {
    const response: OverpassResponse = {
      elements: [
        { type: "way", id: 1, tags: { leisure: "golf_course" }, geometry: [] },
        { type: "count", id: 0, tags: { total: "9" } },
      ],
    };
    const { matchingElements, golfHoleWaysInBbox } = splitCoverageResponse(response);
    expect(matchingElements).toHaveLength(1);
    expect(golfHoleWaysInBbox).toBe(9);
  });
});

describe("x5-overpass: unit + facility-sharing rules (docs/p0/X5.md 'Unit', literal)", () => {
  function coverageEntry(name: string, trail: string, unit: PilotCandidateCourse["unit"], matched: boolean, facilityId?: string): CourseCoverageEntry {
    const course: PilotCandidateCourse = { name, lat: 0, lon: 0, trail, unit, ...(facilityId ? { facilityId } : {}) };
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
