import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { mintId } from "../src/ids.js";
import { emptyLedger } from "../src/ledger.js";
import {
  isCatalogEmpty,
  loadCatalog,
  loadCatalogFromBundle,
  loadCatalogFromDataDir,
} from "../src/load.js";

const source = { url: "https://example.com", retrieved: "2026-09-24" };

function makeFacility(id: string, courseId: string) {
  return {
    id,
    slug: `facility-${id.slice(-6).toLowerCase()}`,
    region: "US-TN",
    tz: "America/Chicago",
    verification: { status: "unverified" },
    seed: { origin: "osm", osmRef: "way/1" },
    booking: [],
    courses: [{ id: courseId, slug: "stub-course", seed: { osmRef: "way/1" } }],
  };
}

function makeTrail(id: string, facilityId: string) {
  return {
    id,
    slug: "test-trail",
    name: "Test Trail",
    countries: ["US"],
    regions: ["US-TN"],
    kind: "state-agency",
    status: "active",
    operator: { name: "Test Operator", url: "https://example.com", type: "state" },
    officialUrl: "https://example.com",
    rosterStatus: "verified",
    rosterVersions: [
      {
        version: 1,
        effectiveFrom: "2026-01-01",
        source,
        verifiedAt: "2026-01-01",
        completionUnit: "facility",
        markerUnit: "facility",
        completionRule: { kind: "all" },
        markerRule: { kind: "all" },
        members: [{ unit: "facility", facilityId }],
      },
    ],
    lastReviewed: "2026-09-24",
    sources: [source],
  };
}

const tmpDirs: string[] = [];
afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe("loadCatalogFromBundle", () => {
  it("normalizes a minimal valid bundle, filling omitted arrays with []", () => {
    const catalog = loadCatalogFromBundle({});
    expect(catalog).toEqual({
      regions: [],
      facilities: [],
      trails: [],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    });
  });

  it("normalizes a bundle carrying real facilities and trails", () => {
    const facilityId = mintId("fac");
    const courseId = mintId("crs");
    const trailId = mintId("trl");
    const catalog = loadCatalogFromBundle({
      facilities: [makeFacility(facilityId, courseId)],
      trails: [makeTrail(trailId, facilityId)],
    });
    expect(catalog.facilities).toHaveLength(1);
    expect(catalog.trails).toHaveLength(1);
    expect(isCatalogEmpty(catalog)).toBe(false);
  });

  it("throws (Zod) on a malformed bundle rather than silently dropping data", () => {
    expect(() => loadCatalogFromBundle({ facilities: [{ not: "a facility" }] })).toThrow();
  });

  it("rejects an unrecognized top-level key (strict object)", () => {
    expect(() => loadCatalogFromBundle({ somethingElse: true })).toThrow();
  });
});

describe("loadCatalog({ bundle })", () => {
  it("dispatches to loadCatalogFromBundle", async () => {
    const catalog = await loadCatalog({ bundle: {} });
    expect(isCatalogEmpty(catalog)).toBe(true);
  });
});

describe("loadCatalogFromDataDir", () => {
  it("reads an empty-but-existing data dir as an all-empty catalog (P1a's real data/)", async () => {
    const dir = await mkdtemp(join(tmpdir(), "golfraven-catalog-"));
    tmpDirs.push(dir);
    const catalog = await loadCatalogFromDataDir(dir);
    expect(catalog).toEqual({
      regions: [],
      facilities: [],
      trails: [],
      designers: [],
      achievements: [],
      idLedger: emptyLedger(),
    });
    expect(isCatalogEmpty(catalog)).toBe(true);
  });

  it("reads a nonexistent data dir the same way (never throws ENOENT)", async () => {
    const dir = join(tmpdir(), `golfraven-catalog-missing-${Date.now()}`);
    const catalog = await loadCatalogFromDataDir(dir);
    expect(isCatalogEmpty(catalog)).toBe(true);
  });

  it("reads facilities/, trails/, designers.json, achievements/ and id-ledger.json from disk", async () => {
    const dir = await mkdtemp(join(tmpdir(), "golfraven-catalog-"));
    tmpDirs.push(dir);
    const facilityId = mintId("fac");
    const courseId = mintId("crs");
    const trailId = mintId("trl");
    const designerId = mintId("dsg");
    const achievementId = mintId("ach");

    await mkdir(join(dir, "facilities"));
    await writeFile(
      join(dir, "facilities", "one.json"),
      JSON.stringify(makeFacility(facilityId, courseId)),
    );
    await mkdir(join(dir, "trails"));
    await writeFile(
      join(dir, "trails", "one.json"),
      JSON.stringify(makeTrail(trailId, facilityId)),
    );
    await writeFile(
      join(dir, "designers.json"),
      JSON.stringify([{ id: designerId, name: "A. Designer", sources: [source] }]),
    );
    await mkdir(join(dir, "achievements"));
    await writeFile(
      join(dir, "achievements", "one.json"),
      JSON.stringify({
        id: achievementId,
        title: "First Tee",
        tier: "bronze",
        rule: { kind: "agg", name: "trailComplete", trailId },
        minConfidence: 0.5,
        scope: "verified-only",
        active: true,
      }),
    );
    await writeFile(
      join(dir, "id-ledger.json"),
      JSON.stringify({
        entries: {
          [facilityId]: { id: facilityId, kind: "fac", transitions: [] },
        },
      }),
    );

    const catalog = await loadCatalogFromDataDir(dir);
    expect(catalog.facilities.map((f) => f.id)).toEqual([facilityId]);
    expect(catalog.trails.map((t) => t.id)).toEqual([trailId]);
    expect(catalog.designers.map((d) => d.id)).toEqual([designerId]);
    expect(catalog.achievements.map((a) => a.id)).toEqual([achievementId]);
    expect(catalog.idLedger.entries[facilityId]).toBeDefined();
    expect(isCatalogEmpty(catalog)).toBe(false);
  });

  it("throws on a malformed committed file rather than skipping it silently", async () => {
    const dir = await mkdtemp(join(tmpdir(), "golfraven-catalog-"));
    tmpDirs.push(dir);
    await mkdir(join(dir, "facilities"));
    await writeFile(join(dir, "facilities", "bad.json"), JSON.stringify({ not: "valid" }));
    await expect(loadCatalogFromDataDir(dir)).rejects.toThrow();
  });
});

describe("isCatalogEmpty", () => {
  it("is true when there are achievements but no facilities/trails (this repo's real data/ today)", () => {
    const catalog = loadCatalogFromBundle({
      achievements: [
        {
          id: mintId("ach"),
          title: "First Tee",
          tier: "bronze",
          rule: { kind: "agg", name: "trailComplete", trailId: mintId("trl") },
          minConfidence: 0.5,
          scope: "verified-only",
          active: true,
        },
      ],
    });
    expect(isCatalogEmpty(catalog)).toBe(true);
  });
});
