/**
 * Shared, minimal `CatalogBundle` fixture for the emitter/signing test
 * suites (`emit-catalog.test.ts`, `sign.test.ts`). Not a `test/fixtures/*`
 * JSON file — this task's lane is `tools/catalog/test/emit*`, `sign*`,
 * `manifest*` only, and a shared object literal avoids any ambiguity about
 * whether a new `test/fixtures/*.json` file would fall inside or outside
 * that lane. Every id here is synthetic, matching the rest of this
 * package's fixtures (see `tools/catalog/README.md`'s "Fixtures" section).
 */
import { parseCatalogBundle, type CatalogBundle } from "../src/bundle.js";

const FACILITY_ID = "fac_01M39GMFJZYF7W9HXMEC5V7FJ8";
const FACILITY_ID_2 = "fac_01M39GMFJZYF7W9HXMEC5V7FJ9";
const COURSE_ID = "crs_01M39GMFJZ2P89V3ZZXPPH671T";
const COURSE_ID_2 = "crs_01M39GMFJZ2P89V3ZZXPPH671W";
const TRAIL_ID = "trl_01M39GMFJZQN74WV3R6HA63H0F";
const DESIGNER_ID = "dsg_01M39GMFJZ21RFA7G11961JMQC";

/** A bundle with two facilities in two different regions (so the emitter's
 * region-sharding has more than one shard to sort/write), a trail, a
 * designer, and OSM-joined content for one stub facility (so the ODbL
 * `osm/` shard path is exercised). Every field only carries what its
 * `verification.status: "unverified"` allows to stay minimal (content
 * fields are optional pre-`listed-verified`, §4.1). */
export function minimalBundleRaw(overrides: Record<string, unknown> = {}): unknown {
  return {
    contractVersion: 0,
    facilities: [
      {
        id: FACILITY_ID,
        slug: "test-facility-one",
        region: "US-TN",
        tz: "America/Chicago",
        verification: { status: "unverified" },
        seed: { origin: "osm", osmRef: "way/1001" },
        booking: [],
        courses: [{ id: COURSE_ID, slug: "test-course-one" }],
      },
      {
        id: FACILITY_ID_2,
        slug: "test-facility-two",
        region: "CA-QC",
        tz: "America/Toronto",
        verification: { status: "unverified" },
        seed: { origin: "manual" },
        booking: [],
        courses: [{ id: COURSE_ID_2, slug: "test-course-two" }],
      },
    ],
    trails: [
      {
        id: TRAIL_ID,
        slug: "test-trail",
        name: "Test Trail",
        countries: ["US"],
        regions: ["US-TN"],
        kind: "state-agency",
        status: "active",
        operator: { name: "Test Operator", url: "https://example.com/operator", type: "state-agency" },
        officialUrl: "https://example.com/trail",
        rosterStatus: "verified",
        rosterVersions: [
          {
            version: 1,
            effectiveFrom: "2026-01-01",
            source: { url: "https://example.com/source", retrieved: "2026-01-01" },
            verifiedAt: "2026-01-01",
            completionUnit: "course",
            markerUnit: "facility",
            completionRule: { kind: "all" },
            markerRule: { kind: "all" },
            members: [{ unit: "course", courseId: COURSE_ID }],
          },
        ],
        lastReviewed: "2026-01-01",
        sources: [{ url: "https://example.com/source", retrieved: "2026-01-01" }],
      },
    ],
    designers: [
      {
        id: DESIGNER_ID,
        name: "Test Designer",
        sources: [{ url: "https://example.com/source", retrieved: "2026-01-01" }],
      },
    ],
    idLedger: {
      entries: {
        [FACILITY_ID]: { id: FACILITY_ID, kind: "fac", slug: "test-facility-one", status: "stub", transitions: [] },
        [COURSE_ID]: {
          id: COURSE_ID,
          kind: "crs",
          status: "stub",
          facilityId: FACILITY_ID,
          transitions: [],
        },
        [FACILITY_ID_2]: {
          id: FACILITY_ID_2,
          kind: "fac",
          slug: "test-facility-two",
          status: "stub",
          transitions: [],
        },
        [COURSE_ID_2]: {
          id: COURSE_ID_2,
          kind: "crs",
          status: "stub",
          facilityId: FACILITY_ID_2,
          transitions: [],
        },
        [TRAIL_ID]: { id: TRAIL_ID, kind: "trl", slug: "test-trail", transitions: [] },
        [DESIGNER_ID]: { id: DESIGNER_ID, kind: "dsg", transitions: [] },
      },
    },
    osm: {
      "way/1001": { lat: 36.16, lng: -86.78, name: "Test Facility One (OSM)", holes: 18 },
    },
    ...overrides,
  };
}

export function minimalBundle(overrides: Record<string, unknown> = {}): CatalogBundle {
  const parsed = parseCatalogBundle(minimalBundleRaw(overrides));
  if (!parsed.ok) {
    throw new Error(
      `minimalBundle: fixture itself failed schema validation:\n${parsed.schemaIssues
        .map((i) => `  ${i.path}: ${i.message}`)
        .join("\n")}`,
    );
  }
  return parsed.bundle;
}
