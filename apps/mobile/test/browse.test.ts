import type { Facility, Trail } from "@golfraven/catalog";
import { describe, expect, it } from "vitest";
import {
  bookingLinks,
  buildIndex,
  courseName,
  currentRoster,
  facilitiesInRegion,
  facilityName,
  isSafeHttpsUrl,
  regionSummaries,
  rosterStops,
  titleFromSlug,
  trailName,
  trailsInRegion,
} from "../src/browse";
import { buildSnapshot } from "../src/catalog/snapshot";

const SRC = { url: "https://example.com/s", retrieved: "2026-01-01" };
const fac = (id: string, slug: string, region: string, courses: { id: string; slug: string; name?: string }[], extra: Record<string, unknown> = {}): Facility =>
  ({ id, slug, region, tz: "America/Chicago", verification: { status: "unverified" }, seed: { origin: "manual" }, booking: [], courses, ...extra }) as unknown as Facility;

const F1 = fac("fac_1", "west-nashville-golf", "US-TN", [{ id: "crs_1", slug: "main" }]);
const F2 = fac("fac_2", "two-course-club", "US-TN", [{ id: "crs_2a", slug: "north", name: "North Course" }, { id: "crs_2b", slug: "south-nine" }], { name: "Two Course Club", nameFr: "Club à deux terrains" });
const F3 = fac("fac_3", "lac-beauport", "CA-QC", [{ id: "crs_3", slug: "lac" }], { name: "Lac Beauport", booking: [{ provider: "golfnow", url: "https://golfnow.example/x", source: SRC, checkedAt: "2026-01-01" }, { provider: "course-native", url: "javascript:alert(1)", source: SRC, checkedAt: "2026-01-01" }] });

const trail = (id: string, name: string, regions: string[], members: unknown[], versions = 1, extra: Record<string, unknown> = {}): Trail =>
  ({
    id,
    slug: id,
    name,
    countries: ["US"],
    regions,
    kind: "state-agency",
    status: "active",
    operator: { name: "Op", url: "https://example.com", type: "x" },
    officialUrl: "https://example.com",
    rosterStatus: "verified",
    rosterVersions: Array.from({ length: versions }, (_, i) => ({ version: i + 1, members: i + 1 === versions ? members : [{ unit: "course", courseId: "crs_old" }] })),
    lastReviewed: "2026-01-01",
    sources: [SRC],
    ...extra,
  }) as unknown as Trail;

const T1 = trail("trl_1", "Zeta Trail", ["US-TN"], [
  { unit: "course", courseId: "crs_2b", stopOrder: 2 },
  { unit: "facility", facilityId: "fac_1", stopOrder: 1 },
  { unit: "course", anyOf: ["crs_2a", "crs_2b"] },
  { unit: "hole", holeId: "hol_9", courseId: "crs_1" },
  { unit: "course", courseId: "crs_missing", stopOrder: 0 },
], 3, { nameFr: "Circuit Zêta" });
const T2 = trail("trl_2", "Alpha Trail", ["US-TN", "CA-QC"], [{ unit: "course", courseId: "crs_3" }]);

const snapshot = buildSnapshot({
  catalogVersion: "20260101-aaaaaaa",
  generatedAt: "2026-01-01T00:00:00.000Z",
  shards: [
    { path: "trails.json", text: JSON.stringify([T1, T2]) },
    { path: "facilities/us-tn.json", text: JSON.stringify([F1, F2]) },
    { path: "facilities/ca-qc.json", text: JSON.stringify([F3]) },
    { path: "osm/directory/us-tn.json", text: "{}" },
    { path: "designers.json", text: "[]" },
  ],
});
const index = buildIndex(snapshot);
const labels = { anyOf: (n: number) => `any of ${n}`, hole: (c: string) => `hole at ${c}` };

describe("snapshot + index", () => {
  it("loads trails and every facilities/<region> shard, ignoring other shards", () => {
    expect(snapshot.trails).toHaveLength(2);
    expect(snapshot.facilities.map((f) => f.id).sort()).toEqual(["fac_1", "fac_2", "fac_3"]);
    expect([...index.courses.keys()].sort()).toEqual(["crs_1", "crs_2a", "crs_2b", "crs_3"]);
    expect(index.courses.get("crs_2b")?.facility.id).toBe("fac_2");
  });

  it("a malformed shard is a parse error, never a half-loaded snapshot", () => {
    expect(() => buildSnapshot({ catalogVersion: "v", generatedAt: "t", shards: [{ path: "trails.json", text: "{}" }] })).toThrow(/not an array/);
    expect(() => buildSnapshot({ catalogVersion: "v", generatedAt: "t", shards: [{ path: "trails.json", text: '[{"id":"zzz"}]' }] })).toThrow(/not a Trail/);
    expect(() => buildSnapshot({ catalogVersion: "v", generatedAt: "t", shards: [{ path: "facilities/us-tn.json", text: '[{"id":"fac_x"}]' }] })).toThrow(/not a Facility/);
    expect(() => buildSnapshot({ catalogVersion: "v", generatedAt: "t", shards: [{ path: "trails.json", text: "{nope" }] })).toThrow();
  });
});

describe("naming and localization", () => {
  it("falls back from name to a title built from the slug (stub facilities have no name yet)", () => {
    expect(facilityName(F1, "en")).toBe("West Nashville Golf");
    expect(titleFromSlug("a--b")).toBe("A B");
  });
  it("uses the French fields in fr-CA when present, English otherwise", () => {
    expect(facilityName(F2, "fr-CA")).toBe("Club à deux terrains");
    expect(facilityName(F2, "en")).toBe("Two Course Club");
    expect(facilityName(F3, "fr-CA")).toBe("Lac Beauport");
    expect(trailName(T1, "fr-CA")).toBe("Circuit Zêta");
    expect(trailName(T2, "fr-CA")).toBe("Alpha Trail");
  });
  it("a single-course facility's course takes the facility's name; a multi-course one uses course name/slug", () => {
    expect(courseName(index.courses.get("crs_1")!, "en")).toBe("West Nashville Golf");
    expect(courseName(index.courses.get("crs_2a")!, "en")).toBe("North Course");
    expect(courseName(index.courses.get("crs_2b")!, "en")).toBe("South Nine");
  });
});

describe("roster", () => {
  it("shows the highest roster version", () => {
    expect(currentRoster(T1).version).toBe(3);
  });

  it("resolves every member kind, orders by stopOrder, keeps unresolved ids visible", () => {
    const stops = rosterStops(T1, index, "en", labels);
    expect(stops.map((s) => `${s.kind}:${s.label}`)).toEqual([
      "course:crs_missing", // stopOrder 0, not in the catalog but NOT dropped
      "facility:West Nashville Golf", // stopOrder 1
      "course:South Nine", // stopOrder 2
      "any_of:any of 2", // no stopOrder: catalog order, after the ordered ones
      "hole:hole at West Nashville Golf",
    ]);
    expect(stops).toHaveLength(T1.rosterVersions[2]!.members.length); // the stop count never shrinks
    expect(stops.find((s) => s.kind === "course" && s.label === "South Nine")).toMatchObject({ courseId: "crs_2b", facilityId: "fac_2" });
  });
});

describe("regions and lists", () => {
  it("summarises regions from facilities and trails", () => {
    expect(regionSummaries(snapshot)).toEqual([
      { region: "CA-QC", facilities: 1, trails: 1 },
      { region: "US-TN", facilities: 2, trails: 2 },
    ]);
  });
  it("filters and sorts", () => {
    expect(trailsInRegion(snapshot, null).map((t) => t.name)).toEqual(["Alpha Trail", "Zeta Trail"]);
    expect(trailsInRegion(snapshot, "CA-QC").map((t) => t.name)).toEqual(["Alpha Trail"]);
    expect(facilitiesInRegion(snapshot, "US-TN", "en").map((f) => f.id)).toEqual(["fac_2", "fac_1"]); // "Two Course Club" < "West Nashville Golf"
    expect(facilitiesInRegion(snapshot, null, "en")).toHaveLength(3);
    expect(facilitiesInRegion(snapshot, "XX", "en")).toEqual([]);
  });
});

describe("outbound links", () => {
  it("only https URLs are ever opened", () => {
    expect(isSafeHttpsUrl("https://golfnow.com/x?y=1")).toBe(true);
    for (const bad of ["http://x.com", "javascript:alert(1)", "data:text/html,x", "//x.com", "https://", "https:// space.com", "https://a.com/\u0000"]) {
      expect(isSafeHttpsUrl(bad)).toBe(false);
    }
  });
  it("drops an unsafe booking URL even if the catalog somehow carried one", () => {
    expect(bookingLinks(F3)).toEqual([{ provider: "golfnow", url: "https://golfnow.example/x" }]);
  });
});
