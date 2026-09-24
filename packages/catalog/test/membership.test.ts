import { describe, expect, it } from "vitest";
import { mintId } from "../src/ids.js";
import { emptyLedger, mergeIntoSurvivor } from "../src/ledger.js";
import {
  latestRosterVersion,
  primaryTrailOf,
  privateStopCount,
  rosterStops,
  trailsOfCourse,
  trailsOfFacility,
} from "../src/membership.js";
import type { Catalog } from "../src/load.js";
import type { Facility, Trail } from "../src/schema.js";

const source = { url: "https://example.com", retrieved: "2026-09-24" };

function facility(
  id: string,
  courseIds: string[],
  opts: { access?: Facility["access"] } = {},
): Facility {
  return {
    id: id as Facility["id"],
    slug: `facility-${id.slice(-6).toLowerCase()}`,
    region: "US-TN",
    tz: "America/Chicago",
    access: opts.access,
    verification: { status: "unverified" },
    seed: { origin: "osm" },
    booking: [],
    courses: courseIds.map((cid) => ({
      id: cid as Facility["courses"][number]["id"],
      slug: `course-${cid.slice(-6).toLowerCase()}`,
    })),
  } as Facility;
}

function trailWithMembers(
  id: string,
  members: Trail["rosterVersions"][number]["members"],
  version = 1,
): Trail {
  return {
    id: id as Trail["id"],
    slug: `trail-${id.slice(-6).toLowerCase()}`,
    name: `Trail ${id.slice(-4)}`,
    countries: ["US"],
    regions: ["US-TN"],
    kind: "state-agency",
    status: "active",
    operator: { name: "Op", url: "https://example.com", type: "state" },
    officialUrl: "https://example.com",
    rosterStatus: "verified",
    rosterVersions: [
      {
        version,
        effectiveFrom: "2026-01-01",
        source,
        verifiedAt: "2026-01-01",
        completionUnit: "course",
        markerUnit: "facility",
        completionRule: { kind: "all" },
        markerRule: { kind: "all" },
        members,
      },
    ],
    lastReviewed: "2026-09-24",
    sources: [source],
  } as Trail;
}

describe("latestRosterVersion", () => {
  it("returns the version with the highest `version` number", () => {
    const trail = trailWithMembers(mintId("trl"), [
      { unit: "facility", facilityId: mintId("fac") as Facility["id"] },
    ]);
    // Append a v2.
    trail.rosterVersions.push({
      ...trail.rosterVersions[0]!,
      version: 2,
    });
    expect(latestRosterVersion(trail).version).toBe(2);
  });
});

describe("trailsOfCourse / trailsOfFacility — unit-aware (§4.3)", () => {
  it("a course-unit member resolves trailsOfCourse for that exact course, and trailsOfFacility for its facility", () => {
    const facilityId = mintId("fac");
    const courseId = mintId("crs");
    const trailId = mintId("trl");
    const fac = facility(facilityId, [courseId]);
    const trail = trailWithMembers(trailId, [
      { unit: "course", courseId: courseId as Facility["courses"][number]["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [trail],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(trailsOfCourse(catalog, courseId as never).map((t) => t.id)).toEqual([trailId]);
    expect(trailsOfFacility(catalog, facilityId as never).map((t) => t.id)).toEqual([trailId]);
  });

  it("a facility-unit member (RTJ-style) covers EVERY course at that facility", () => {
    const facilityId = mintId("fac");
    const courseA = mintId("crs");
    const courseB = mintId("crs");
    const trailId = mintId("trl");
    const fac = facility(facilityId, [courseA, courseB]);
    const trail = trailWithMembers(trailId, [
      { unit: "facility", facilityId: facilityId as Facility["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [trail],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(trailsOfCourse(catalog, courseA as never).map((t) => t.id)).toEqual([trailId]);
    expect(trailsOfCourse(catalog, courseB as never).map((t) => t.id)).toEqual([trailId]);
  });

  it("an anyOf course member (a 27-hole 'stop') covers every named course", () => {
    const facilityId = mintId("fac");
    const courseA = mintId("crs");
    const courseB = mintId("crs");
    const trailId = mintId("trl");
    const fac = facility(facilityId, [courseA, courseB]);
    const trail = trailWithMembers(trailId, [
      {
        unit: "course",
        anyOf: [courseA, courseB] as Facility["courses"][number]["id"][],
      },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [trail],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(trailsOfCourse(catalog, courseB as never).map((t) => t.id)).toEqual([trailId]);
  });

  it("a course not on any roster resolves to no trails", () => {
    const facilityId = mintId("fac");
    const courseId = mintId("crs");
    const otherCourseId = mintId("crs");
    const trailId = mintId("trl");
    const fac = facility(facilityId, [courseId]);
    const trail = trailWithMembers(trailId, [
      { unit: "course", courseId: courseId as Facility["courses"][number]["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [trail],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(trailsOfCourse(catalog, otherCourseId as never)).toEqual([]);
  });

  it("resolves membership through a ledger merge (A2-04)", () => {
    const oldFacilityId = mintId("fac");
    const survivorFacilityId = mintId("fac");
    const courseId = mintId("crs");
    const trailId = mintId("trl");
    let ledger = emptyLedger();
    ledger = {
      entries: {
        ...ledger.entries,
        [oldFacilityId]: { id: oldFacilityId, kind: "fac", transitions: [] },
        [survivorFacilityId]: { id: survivorFacilityId, kind: "fac", transitions: [] },
      },
    } as unknown as typeof ledger;
    ledger = mergeIntoSurvivor(ledger, [oldFacilityId], survivorFacilityId, {
      catalogVersion: "v1",
      date: "2026-09-24",
    });
    const fac = facility(survivorFacilityId, [courseId]);
    // Roster still names the OLD (now-tombstoned) facility id.
    const trail = trailWithMembers(trailId, [
      { unit: "facility", facilityId: oldFacilityId as Facility["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [trail],
      designers: [],
      achievements: [],
      idLedger: ledger,
    };
    expect(trailsOfFacility(catalog, survivorFacilityId as never).map((t) => t.id)).toEqual([
      trailId,
    ]);
  });
});

describe("primaryTrailOf", () => {
  it("picks the trail with the fewest roster members (the tightest-knit trail)", () => {
    const facilityId = mintId("fac");
    const bigTrailId = mintId("trl");
    const smallTrailId = mintId("trl");
    const fac = facility(facilityId, [mintId("crs")]);
    const bigTrail = trailWithMembers(bigTrailId, [
      { unit: "facility", facilityId: facilityId as Facility["id"] },
      { unit: "facility", facilityId: mintId("fac") as Facility["id"] },
      { unit: "facility", facilityId: mintId("fac") as Facility["id"] },
    ]);
    const smallTrail = trailWithMembers(smallTrailId, [
      { unit: "facility", facilityId: facilityId as Facility["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [bigTrail, smallTrail],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(primaryTrailOf(catalog, facilityId as never)?.id).toBe(smallTrailId);
  });

  it("breaks a tie by trail id", () => {
    const facilityId = mintId("fac");
    const fac = facility(facilityId, [mintId("crs")]);
    const trailIds = [mintId("trl"), mintId("trl")].sort();
    const [lower, higher] = trailIds;
    const trailA = trailWithMembers(higher!, [
      { unit: "facility", facilityId: facilityId as Facility["id"] },
    ]);
    const trailB = trailWithMembers(lower!, [
      { unit: "facility", facilityId: facilityId as Facility["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [trailA, trailB],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(primaryTrailOf(catalog, facilityId as never)?.id).toBe(lower);
  });

  it("returns undefined when the facility is on no trail", () => {
    const facilityId = mintId("fac");
    const fac = facility(facilityId, [mintId("crs")]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(primaryTrailOf(catalog, facilityId as never)).toBeUndefined();
  });

  it("honours an override, but only when the facility is genuinely a member of that trail", () => {
    const facilityId = mintId("fac");
    const realTrailId = mintId("trl");
    const bogusTrailId = mintId("trl");
    const fac = facility(facilityId, [mintId("crs")]);
    const realTrail = trailWithMembers(realTrailId, [
      { unit: "facility", facilityId: facilityId as Facility["id"] },
    ]);
    const bogusTrail = trailWithMembers(bogusTrailId, [
      { unit: "facility", facilityId: mintId("fac") as Facility["id"] },
    ]);
    const catalog: Catalog = {
      regions: [],
      facilities: [fac],
      trails: [realTrail, bogusTrail],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    const overrides = new Map([[facilityId as never, bogusTrailId as never]]);
    // Override names a trail the facility isn't really on — ignored.
    expect(primaryTrailOf(catalog, facilityId as never, overrides)?.id).toBe(realTrailId);
  });
});

describe("rosterStops", () => {
  it("resolves facility- and course-unit members to their Facility/Course and sorts by stopOrder", () => {
    const facA = mintId("fac");
    const facB = mintId("fac");
    const courseB = mintId("crs");
    const trailId = mintId("trl");
    const catalog: Catalog = {
      regions: [],
      facilities: [facility(facA, [mintId("crs")]), facility(facB, [courseB])],
      trails: [
        trailWithMembers(trailId, [
          { unit: "facility", facilityId: facB as Facility["id"], stopOrder: 1 },
          { unit: "facility", facilityId: facA as Facility["id"], stopOrder: 0 },
        ]),
      ],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    const trail = catalog.trails[0]!;
    const stops = rosterStops(catalog, trail);
    expect(stops.map((s) => s.facility.id)).toEqual([facA, facB]);
  });

  it("skips a dangling member reference rather than throwing", () => {
    const trailId = mintId("trl");
    const catalog: Catalog = {
      regions: [],
      facilities: [],
      trails: [
        trailWithMembers(trailId, [
          { unit: "facility", facilityId: mintId("fac") as Facility["id"] },
        ]),
      ],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    expect(rosterStops(catalog, catalog.trails[0]!)).toEqual([]);
  });
});

describe("privateStopCount (O8)", () => {
  it("counts distinct private-access facilities among the resolved stops", () => {
    const facilityId = mintId("fac");
    const trailId = mintId("trl");
    const catalog: Catalog = {
      regions: [],
      facilities: [facility(facilityId, [mintId("crs")], { access: "private" })],
      trails: [
        trailWithMembers(trailId, [
          { unit: "facility", facilityId: facilityId as Facility["id"] },
        ]),
      ],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    const stops = rosterStops(catalog, catalog.trails[0]!);
    expect(privateStopCount(stops)).toBe(1);
  });

  it("is 0 when no resolved stop is private", () => {
    const facilityId = mintId("fac");
    const trailId = mintId("trl");
    const catalog: Catalog = {
      regions: [],
      facilities: [facility(facilityId, [mintId("crs")], { access: "public" })],
      trails: [
        trailWithMembers(trailId, [
          { unit: "facility", facilityId: facilityId as Facility["id"] },
        ]),
      ],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    };
    const stops = rosterStops(catalog, catalog.trails[0]!);
    expect(privateStopCount(stops)).toBe(0);
  });
});
