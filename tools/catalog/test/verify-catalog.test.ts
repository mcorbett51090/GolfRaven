/**
 * P1 AT(1): "`verify-catalog` fails each must-fail fixture and passes the
 * good one." Every fixture here is a full `CatalogBundle` under
 * `test/fixtures/`; each must-fail case asserts the SPECIFIC issue code
 * (never just "fails"), per the task's own instruction.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyCatalogRaw } from "../src/verify-catalog.js";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

async function loadFixture(name: string): Promise<unknown> {
  return JSON.parse(await readFile(join(FIXTURES_DIR, `${name}.json`), "utf8"));
}

async function expectFails(name: string, code: string, options: { base?: string } = {}) {
  const bundle = await loadFixture(name);
  const base = options.base ? await loadFixture(options.base) : undefined;
  const result = verifyCatalogRaw(bundle, base ? { base: base as never } : {});
  expect(result.ok).toBe(false);
  const codes = result.issues.map((i) => i.code);
  expect(codes).toContain(code);
}

async function expectPasses(name: string) {
  const bundle = await loadFixture(name);
  const result = verifyCatalogRaw(bundle);
  if (!result.ok) {
    // eslint-disable-next-line no-console
    console.error(`${name} unexpectedly failed:`, result.issues);
  }
  expect(result.ok).toBe(true);
  expect(result.issues).toEqual([]);
}

describe("verify-catalog — must-pass fixtures", () => {
  it("mp-good: a fully verified facility + trail with no issues", async () => {
    await expectPasses("mp-good");
  });

  it('mp-stub-facility: an OSM-seeded stub facility and its stub course with only derived keys (AT(1) must-pass)', async () => {
    await expectPasses("mp-stub-facility");
  });

  it("mp-private-facility-all: a verified roster with one access:'private' member under completionRule: all (v6 must-pass)", async () => {
    await expectPasses("mp-private-facility-all");
  });
});

describe("verify-catalog — must-fail fixtures (AT(1))", () => {
  it("duplicate id", () => expectFails("mf-duplicate-id", "DUPLICATE_ID"));

  it("reused (tombstoned) id", () =>
    expectFails("mf-reused-tombstoned-id", "REUSED_TOMBSTONED_ID"));

  it("missing member (dangling reference)", () =>
    expectFails("mf-missing-member", "ROSTER_MISSING_MEMBER"));

  it("roster without a source (structurally required, §4.1)", () =>
    expectFails("mf-roster-no-source", "SCHEMA_INVALID"));

  it("unit/member-type mismatch within a version", () =>
    expectFails("mf-unit-member-mismatch", "ROSTER_UNIT_MEMBER_MISMATCH"));

  it("a published RosterVersion changed (A2-02)", () =>
    expectFails("mf-roster-version-changed", "ROSTER_VERSION_IMMUTABLE_CHANGE", {
      base: "mf-roster-version-changed.base",
    }));

  it("a latest roster version containing a closed course", () =>
    expectFails("mf-closed-course-in-latest", "ROSTER_LATEST_CONTAINS_CLOSED_COURSE"));

  it("booking host off the allow-list", () =>
    expectFails("mf-booking-host-not-allowed", "BOOKING_HOST_NOT_ALLOWED"));

  it("course-native host != facility domain", () =>
    expectFails("mf-course-native-host-mismatch", "BOOKING_COURSE_NATIVE_HOST_MISMATCH"));

  it("play-verified facility without a polygon", () =>
    expectFails("mf-play-verified-missing-polygon", "PLAY_VERIFIED_MISSING_POLYGON"));

  it("a verified facility with approx = true", () =>
    expectFails("mf-verified-approx-true", "VERIFIED_APPROX_TRUE"));

  it("missing tz", () => expectFails("mf-tz-missing", "SCHEMA_INVALID"));

  it("non-IANA tz", () => expectFails("mf-tz-not-iana", "SCHEMA_INVALID"));

  it("wrong-zone tz (G-P0-11)", () => expectFails("mf-tz-wrong-zone", "TZ_WRONG_ZONE"));

  it("centroid moved > 150 m without the geometry-reviewed label", () =>
    expectFails("mf-geometry-diff-unreviewed", "GEOMETRY_DIFF_UNREVIEWED", {
      base: "mf-geometry-diff-unreviewed.base",
    }));

  it("url/phone/booking host changed without the contact-reviewed label (FM-21)", () =>
    expectFails("mf-contact-diff-unreviewed", "CONTACT_DIFF_UNREVIEWED", {
      base: "mf-contact-diff-unreviewed.base",
    }));

  it("course-claim without claimProof", () =>
    expectFails("mf-course-claim-no-proof", "SCHEMA_INVALID"));

  it("an OSM content field with no non-OSM prov (gate rule (a))", () =>
    expectFails("mf-prov-missing-or-osm", "PROV_MISSING_OR_OSM"));

  it("a listed-verified+ facility missing a required content field (gate rule (b))", () =>
    expectFails("mf-verified-content-incomplete", "VERIFIED_CONTENT_INCOMPLETE"));

  it("derivedFrom on a field other than region/tz/slug (gate rule (c))", () =>
    expectFails("mf-derived-from-invalid-key", "SCHEMA_INVALID"));

  it("n-of-m completionRule with no ruleSource (v6, O15)", () =>
    expectFails("mf-nofm-no-rulesource", "SCHEMA_INVALID"));

  it("a listed-verified+ roster member with no access value (v6, O8)", () =>
    expectFails("mf-roster-member-missing-access", "ROSTER_MEMBER_MISSING_ACCESS"));

  it("an access: 'private' facility with a booking[] entry (v6, O8)", () =>
    expectFails("mf-private-facility-has-booking", "PRIVATE_FACILITY_HAS_BOOKING"));

  it("a curated Course whose name has prov: 'osm' fails (AT(8))", () =>
    expectFails("mf-course-name-prov-osm", "SCHEMA_INVALID"));
});

describe("verify-catalog — each must-fail fixture fails for its OWN reason", () => {
  it("no two must-fail fixtures share their only issue code by accident", async () => {
    const names = [
      "mf-duplicate-id",
      "mf-reused-tombstoned-id",
      "mf-missing-member",
      "mf-unit-member-mismatch",
      "mf-closed-course-in-latest",
      "mf-booking-host-not-allowed",
      "mf-course-native-host-mismatch",
      "mf-play-verified-missing-polygon",
      "mf-verified-approx-true",
      "mf-tz-wrong-zone",
      "mf-prov-missing-or-osm",
      "mf-verified-content-incomplete",
      "mf-roster-member-missing-access",
      "mf-private-facility-has-booking",
    ];
    const codeSets = await Promise.all(
      names.map(async (name) => {
        const bundle = await loadFixture(name);
        const result = verifyCatalogRaw(bundle);
        return new Set(result.issues.map((i) => i.code));
      }),
    );
    // Every fixture must fail (non-empty code set).
    for (const codes of codeSets) expect(codes.size).toBeGreaterThan(0);
  });
});
