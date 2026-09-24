/**
 * P1 AT(1): "`verify-catalog` fails each must-fail fixture and passes the
 * good one." Every fixture here is a full `CatalogBundle` under
 * `test/fixtures/`.
 *
 * **S5 (gate review, post-e9b3ab0): exact issue set, not `toContain`.**
 * Each must-fail case asserts the FULL set of `{code, path}` pairs the run
 * produces — not just "this code appears somewhere" — so a fixture that
 * starts silently emitting an extra (or one fewer) issue fails the test
 * that's supposed to catch exactly that regression.
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { verifyCatalogRaw, type CatalogIssue } from "../src/verify-catalog.js";

const FIXTURES_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");
const BOOKING_HOSTS = ["www.golfnow.com"];

async function loadFixture(name: string): Promise<unknown> {
  return JSON.parse(await readFile(join(FIXTURES_DIR, `${name}.json`), "utf8"));
}

interface ExpectedIssue {
  code: string;
  path: string;
}

function sortIssues(
  issues: { code: string; path: string }[],
): { code: string; path: string }[] {
  return [...issues]
    .map((i) => ({ code: i.code, path: i.path }))
    .sort((a, b) => (a.code + a.path).localeCompare(b.code + b.path));
}

async function expectExactFail(
  name: string,
  expected: ExpectedIssue[],
  options: {
    base?: string;
    bookingHostAllowList?: string[];
    labels?: string[];
  } = {},
) {
  const bundle = await loadFixture(name);
  const base = options.base ? await loadFixture(options.base) : undefined;
  const result = verifyCatalogRaw(bundle, {
    ...(base ? { base: base as never } : {}),
    bookingHostAllowList: options.bookingHostAllowList ?? BOOKING_HOSTS,
    labels: options.labels ?? [],
  });
  expect(result.ok).toBe(false);
  expect(sortIssues(result.issues as CatalogIssue[])).toEqual(
    sortIssues(expected),
  );
}

async function expectPasses(
  name: string,
  options: { bookingHostAllowList?: string[] } = {},
) {
  const bundle = await loadFixture(name);
  const result = verifyCatalogRaw(bundle, {
    bookingHostAllowList: options.bookingHostAllowList ?? BOOKING_HOSTS,
    labels: [],
  });
  if (!result.ok) {
    // eslint-disable-next-line no-console
    console.error(`${name} unexpectedly failed:`, result.issues);
  }
  expect(result.issues).toEqual([]);
  expect(result.ok).toBe(true);
}

describe("verify-catalog — must-pass fixtures", () => {
  it("mp-good: a fully verified facility + trail with no issues", async () => {
    await expectPasses("mp-good");
  });

  it("mp-stub-facility: an OSM-seeded stub facility and its stub course with only derived keys (AT(1) must-pass)", async () => {
    await expectPasses("mp-stub-facility", { bookingHostAllowList: [] });
  });

  it("mp-private-facility-all: a verified roster with one access:'private' member under completionRule: all (v6 must-pass)", async () => {
    await expectPasses("mp-private-facility-all", { bookingHostAllowList: [] });
  });

  it("mp-offer-terms-qc-with-fr: a QC-linked offerTerms WITH termsFr passes (S6 must-pass)", async () => {
    await expectPasses("mp-offer-terms-qc-with-fr");
  });

  it("mp-achievement-good: two AchievementDefs referencing real trail/course/designer ids (part B must-pass)", async () => {
    await expectPasses("mp-achievement-good");
  });
});

describe("verify-catalog — must-fail fixtures (AT(1), exact issue sets — S5)", () => {
  it("duplicate id", () =>
    expectExactFail("mf-duplicate-id", [
      { code: "DUPLICATE_ID", path: "facilities[0].id" },
      { code: "DUPLICATE_ID", path: "facilities[1].id" },
      { code: "DUPLICATE_ID", path: "facilities[0].courses[0].id" },
      { code: "DUPLICATE_ID", path: "facilities[1].courses[0].id" },
      { code: "CROSS_REF_SLUG_MISMATCH", path: "facilities[1].slug" },
    ]));

  it("reused (tombstoned) id", () =>
    expectExactFail("mf-reused-tombstoned-id", [
      { code: "REUSED_TOMBSTONED_ID", path: "facilities[0].id" },
    ]));

  it("missing member (dangling reference)", () =>
    expectExactFail("mf-missing-member", [
      {
        code: "ROSTER_MISSING_MEMBER",
        path: "trails[0].rosterVersions[0].members[1]",
      },
    ]));

  it("roster without a source (structurally required, §4.1)", () =>
    expectExactFail("mf-roster-no-source", [
      { code: "SCHEMA_INVALID", path: "trails[0].rosterVersions[0].source" },
    ]));

  it("unit/member-type mismatch within a version", () =>
    expectExactFail("mf-unit-member-mismatch", [
      {
        code: "ROSTER_UNIT_MEMBER_MISMATCH",
        path: "trails[0].rosterVersions[0].members[0]",
      },
    ]));

  it("a published RosterVersion changed (A2-02)", () =>
    expectExactFail(
      "mf-roster-version-changed",
      [
        {
          code: "ROSTER_VERSION_IMMUTABLE_CHANGE",
          path: "trails[0].rosterVersions[0]",
        },
      ],
      { base: "mf-roster-version-changed.base" },
    ));

  it("a latest roster version containing a closed course", () =>
    expectExactFail("mf-closed-course-in-latest", [
      {
        code: "ROSTER_LATEST_CONTAINS_CLOSED_COURSE",
        path: "trails[0].rosterVersions[0].members[0]",
      },
    ]));

  it("booking host off the allow-list", () =>
    expectExactFail(
      "mf-booking-host-not-allowed",
      [{ code: "BOOKING_HOST_NOT_ALLOWED", path: "facilities[0].booking[0]" }],
      { bookingHostAllowList: [] },
    ));

  it("course-native host != facility domain", () =>
    expectExactFail("mf-course-native-host-mismatch", [
      {
        code: "BOOKING_COURSE_NATIVE_HOST_MISMATCH",
        path: "facilities[0].booking[1]",
      },
    ]));

  it("play-verified facility without a polygon", () =>
    expectExactFail("mf-play-verified-missing-polygon", [
      { code: "PLAY_VERIFIED_MISSING_POLYGON", path: "facilities[0].courses" },
    ]));

  it("a verified facility with approx = true", () =>
    expectExactFail("mf-verified-approx-true", [
      { code: "VERIFIED_APPROX_TRUE", path: "facilities[0].approx" },
    ]));

  it("missing tz", () =>
    expectExactFail("mf-tz-missing", [
      { code: "SCHEMA_INVALID", path: "facilities[0].tz" },
    ]));

  it("non-IANA tz", () =>
    expectExactFail("mf-tz-not-iana", [
      { code: "SCHEMA_INVALID", path: "facilities[0].tz" },
    ]));

  it("wrong-zone tz (G-P0-11) — tz-lookup pinned dataset", () =>
    expectExactFail("mf-tz-wrong-zone", [
      { code: "TZ_WRONG_ZONE", path: "facilities[0].tz" },
    ]));

  it("coordinate moved > 150 m without the geometry-reviewed label", () =>
    expectExactFail(
      "mf-geometry-diff-unreviewed",
      [{ code: "GEOMETRY_DIFF_UNREVIEWED", path: "facilities[0].lat" }],
      { base: "mf-geometry-diff-unreviewed.base" },
    ));

  it("S1: a course's geometry FIELDS changed (not a coordinate move) without the label", () =>
    expectExactFail(
      "mf-geometry-field-diff-unreviewed",
      [
        {
          code: "GEOMETRY_DIFF_UNREVIEWED",
          path: "facilities[0].courses[0].geometry",
        },
      ],
      { base: "mf-geometry-field-diff-unreviewed.base" },
    ));

  it("url/phone/booking host changed without the contact-reviewed label (FM-21)", () =>
    expectExactFail(
      "mf-contact-diff-unreviewed",
      [{ code: "CONTACT_DIFF_UNREVIEWED", path: "facilities[0]" }],
      { base: "mf-contact-diff-unreviewed.base" },
    ));

  it("course-claim without claimProof", () =>
    expectExactFail("mf-course-claim-no-proof", [
      { code: "SCHEMA_INVALID", path: "facilities[0].verification.claimProof" },
    ]));

  it("an OSM content field with no non-OSM prov (gate rule (a))", () =>
    expectExactFail("mf-prov-missing-or-osm", [
      { code: "PROV_MISSING_OR_OSM", path: "facilities[0].prov.town" },
    ]));

  it("a listed-verified+ facility missing a required content field (gate rule (b))", () =>
    expectExactFail("mf-verified-content-incomplete", [
      { code: "VERIFIED_CONTENT_INCOMPLETE", path: "facilities[0].town" },
    ]));

  it("derivedFrom on a field other than region/tz/slug (gate rule (c))", () =>
    expectExactFail("mf-derived-from-invalid-key", [
      { code: "SCHEMA_INVALID", path: "facilities[0].derivedFrom" },
    ]));

  it("completionRule n-of-m with no ruleSource (v6, O15)", () =>
    expectExactFail("mf-nofm-no-rulesource", [
      {
        code: "SCHEMA_INVALID",
        path: "trails[0].rosterVersions[0].completionRule.ruleSource",
      },
    ]));

  it("S6: markerRule n-of-m with no ruleSource", () =>
    expectExactFail("mf-markerrule-nofm-no-rulesource", [
      {
        code: "SCHEMA_INVALID",
        path: "trails[0].rosterVersions[0].markerRule.ruleSource",
      },
    ]));

  it("a listed-verified+ roster member with no access value (v6, O8)", () =>
    expectExactFail("mf-roster-member-missing-access", [
      {
        code: "ROSTER_MEMBER_MISSING_ACCESS",
        path: "trails[0].rosterVersions[0].members[0]",
      },
    ]));

  it("an access: 'private' facility with a booking[] entry (v6, O8)", () =>
    expectExactFail("mf-private-facility-has-booking", [
      { code: "PRIVATE_FACILITY_HAS_BOOKING", path: "facilities[0].booking" },
    ]));

  it("a curated Course whose name has prov: 'osm' fails (AT(8))", () =>
    expectExactFail("mf-course-name-prov-osm", [
      { code: "SCHEMA_INVALID", path: "facilities[0].courses[0].prov.name" },
    ]));

  it("a curated Course whose name has NO prov at all fails (AT(8))", () =>
    expectExactFail("mf-course-name-no-prov", [
      {
        code: "PROV_MISSING_OR_OSM",
        path: "facilities[0].courses[0].prov.name",
      },
    ]));

  it("S2: facility nameFr with no prov stamp", () =>
    expectExactFail("mf-facility-namefr-no-prov", [
      { code: "PROV_MISSING_OR_OSM", path: "facilities[0].prov.nameFr" },
    ]));

  it("S3: a verified facility missing basis/verifiedAt/source (plan 677)", () =>
    expectExactFail("mf-verification-missing-fields", [
      { code: "SCHEMA_INVALID", path: "facilities[0].verification.basis" },
      { code: "SCHEMA_INVALID", path: "facilities[0].verification.verifiedAt" },
      { code: "SCHEMA_INVALID", path: "facilities[0].verification.source" },
    ]));

  it("S4: a dangling holeId", () =>
    expectExactFail("mf-dangling-hole-id", [
      {
        code: "CROSS_REF_DANGLING_HOLE_ID",
        path: "trails[0].rosterVersions[0].members[0].holeId",
      },
    ]));

  it("S4: a dangling anyOf id", () =>
    expectExactFail("mf-dangling-anyof-id", [
      {
        code: "CROSS_REF_DANGLING_ANYOF_ID",
        path: "trails[0].rosterVersions[0].members[0].anyOf[1]",
      },
    ]));

  it("S4: composite pointing at a non-existent course", () =>
    expectExactFail("mf-composite-dangling", [
      {
        code: "CROSS_REF_COMPOSITE_DANGLING",
        path: "facilities[0].courses[0].composite[1]",
      },
    ]));

  it("S4: a designer id not in designers[] (plan 611)", () =>
    expectExactFail("mf-unknown-designer", [
      {
        code: "CROSS_REF_UNKNOWN_DESIGNER",
        path: "facilities[0].courses[0].designers",
      },
    ]));

  it("S4: a catalog id missing from the ledger", () =>
    expectExactFail("mf-id-not-in-ledger", [
      { code: "CROSS_REF_ID_NOT_IN_LEDGER", path: "facilities[0].courses[0]" },
    ]));

  it("S4: a slug that differs from the ledger's", () =>
    expectExactFail("mf-slug-mismatch", [
      { code: "CROSS_REF_SLUG_MISMATCH", path: "facilities[0].slug" },
    ]));

  it("S4: a ledger key != its entry.id", () =>
    expectExactFail("mf-ledger-key-mismatch", [
      {
        code: "LEDGER_KEY_MISMATCH",
        path: "idLedger.entries.fac_01M39GMFJZ21RFA7G11961JMQA",
      },
    ]));

  it("S4: duplicate roster version numbers", () =>
    expectExactFail("mf-duplicate-roster-version", [
      {
        code: "ROSTER_DUPLICATE_VERSION_NUMBER",
        path: "trails[0].rosterVersions",
      },
    ]));

  it("S4: a published trail deleted relative to --base", () =>
    expectExactFail(
      "mf-trail-removed-vs-base",
      [{ code: "ROSTER_TRAIL_REMOVED", path: "trails" }],
      { base: "mf-trail-removed-vs-base.base" },
    ));

  it("S4: the ledger must not un-tombstone an entry vs --base", () =>
    expectExactFail(
      "mf-ledger-untombstoned",
      [
        {
          code: "LEDGER_UNTOMBSTONED",
          path: "idLedger.entries.fac_01M39GMFJZ7W1CX5QJKNS64Y7Z.tombstoned",
        },
      ],
      { base: "mf-ledger-untombstoned.base" },
    ));

  it("S4: the ledger must not remove an entry vs --base", () =>
    expectExactFail(
      "mf-ledger-entry-removed",
      [
        {
          code: "CROSS_REF_ID_NOT_IN_LEDGER",
          path: "facilities[0].courses[0]",
        },
        {
          code: "LEDGER_ENTRY_REMOVED",
          path: "idLedger.entries.crs_01M39GMFJZ2P89V3ZZXPPH671T",
        },
      ],
      { base: "mf-ledger-entry-removed.base" },
    ));

  it("S4: ledger transitions must be append-only vs --base", () =>
    expectExactFail(
      "mf-ledger-transitions-not-appendonly",
      [
        {
          code: "LEDGER_TRANSITIONS_NOT_APPEND_ONLY",
          path: "idLedger.entries.fac_01M39GMFJZYF7W9HXMEC5V7FJ8.transitions",
        },
      ],
      { base: "mf-ledger-transitions-not-appendonly.base" },
    ));

  it("S6: QC offer terms without FR", () =>
    expectExactFail("mf-offer-terms-qc-no-fr", [
      { code: "OFFER_TERMS_QC_MISSING_FR", path: "offerTerms[0].termsFr" },
    ]));

  it("S7: facility url is not https:", () =>
    expectExactFail("mf-facility-url-not-https", [
      { code: "SCHEMA_INVALID", path: "facilities[0].url" },
    ]));

  it("S7: facility url is javascript:", () =>
    expectExactFail("mf-facility-url-javascript-scheme", [
      { code: "SCHEMA_INVALID", path: "facilities[0].url" },
    ]));

  it("S7: booking url is not https:", () =>
    expectExactFail("mf-booking-url-not-https", [
      { code: "SCHEMA_INVALID", path: "facilities[0].booking[0].url" },
    ]));

  it("blocking #2: a bundle can no longer self-assert labels[]", () =>
    expectExactFail("mf-bundle-cannot-self-label", [
      { code: "SCHEMA_INVALID", path: "<root>" },
    ]));

  it("blocking #2: a bundle can no longer self-assert bookingHostAllowList", () =>
    expectExactFail("mf-bundle-cannot-self-allow-booking-host", [
      { code: "SCHEMA_INVALID", path: "<root>" },
    ]));

  // --- Round 2 (gate review) ---

  it("item 2: the ledger must not change a published slug vs --base", () =>
    expectExactFail(
      "mf-ledger-slug-changed",
      [
        {
          code: "LEDGER_SLUG_CHANGED",
          path: "idLedger.entries.fac_01M39GMFJZYF7W9HXMEC5V7FJ8.slug",
        },
      ],
      { base: "mf-ledger-slug-changed.base" },
    ));

  it("item 2: the ledger must not remove a seedRef vs --base", () =>
    expectExactFail(
      "mf-ledger-seedrefs-removed",
      [
        {
          code: "LEDGER_SEEDREFS_REMOVED",
          path: "idLedger.entries.fac_01M39GMFJZYF7W9HXMEC5V7FJ8.seedRefs",
        },
      ],
      { base: "mf-ledger-seedrefs-removed.base" },
    ));

  it("nit: a closed FACILITY in the latest roster fails, not just a closed course", () =>
    expectExactFail("mf-closed-facility-in-latest", [
      {
        code: "ROSTER_LATEST_CONTAINS_CLOSED_FACILITY",
        path: "trails[0].rosterVersions[0].members[0]",
      },
    ]));

  it("nit: composite rejects the same course listed twice", () =>
    expectExactFail("mf-composite-same-course", [
      { code: "SCHEMA_INVALID", path: "facilities[0].courses[0].composite" },
    ]));

  it("nit: region code validated against the pinned US/CA list (US-ZZ)", () =>
    expectExactFail("mf-region-not-pinned", [
      { code: "SCHEMA_INVALID", path: "facilities[0].region" },
    ]));

  it("nit: a mergedInto cycle is reported as an issue, never thrown", () =>
    expectExactFail("mf-ledger-merge-cycle", [
      { code: "REUSED_TOMBSTONED_ID", path: "facilities[0].courses[0].id" },
      {
        code: "LEDGER_MERGE_CYCLE",
        path: "idLedger.entries.crs_01M39GMFJZ2P89V3ZZXPPH671T.mergedInto",
      },
    ]));

  it("item 4: a stub with no coordinates and no OSM join fails closed (TZ_UNVERIFIABLE)", () =>
    expectExactFail("mf-tz-unverifiable", [
      { code: "TZ_UNVERIFIABLE", path: "facilities[0].tz" },
    ]));

  // --- Part B: AchievementDef / RuleExpr wiring ---

  it("part B: an achievement rule referencing an unknown trail id", () =>
    expectExactFail("mf-achievement-unknown-trail", [
      { code: "ACHIEVEMENT_RULE_UNKNOWN_TRAIL", path: "achievements[0].rule" },
    ]));

  it("part B: an achievement rule that is statically unsatisfiable (R-F4-shaped)", () =>
    expectExactFail("mf-achievement-unsatisfiable", [
      { code: "RULE_UNSATISFIABLE", path: "achievements[0].rule" },
    ]));

  it('S6: an achievement rule\'s countWhere("facility", …) referencing an unknown facility', () =>
    expectExactFail("mf-achievement-unknown-facility", [
      {
        code: "ACHIEVEMENT_RULE_UNKNOWN_FACILITY",
        path: "achievements[0].rule",
      },
    ]));

  it('S6: an achievement rule\'s countDistinct("trail", {in}) referencing an unknown trail', () =>
    expectExactFail("mf-achievement-unknown-trail-countdistinct", [
      { code: "ACHIEVEMENT_RULE_UNKNOWN_TRAIL", path: "achievements[0].rule" },
    ]));

  it("N5: completionRule n-of-m with n greater than the member count", () =>
    expectExactFail("mf-nofm-exceeds-member-count", [
      {
        code: "ROSTER_NOFM_EXCEEDS_MEMBER_COUNT",
        path: "trails[0].rosterVersions[0].completionRule.n",
      },
    ]));

  // Re-gate item 3: pins the marker n-of-m gate to markerRosterSize (distinct
  // FACILITIES), not the raw member count. Two course members share ONE
  // facility here (markerRosterSize=1, memberCount=2) with markerRule.n=2 —
  // n exceeds markerRosterSize but NOT memberCount, so a mutation that
  // compares against memberCount instead would wrongly let this pass.
  it("N-gate: markerRule n-of-m with n greater than the DISTINCT-FACILITY marker roster (but not the raw member count)", () =>
    expectExactFail("mf-nofm-exceeds-marker-roster", [
      {
        code: "ROSTER_NOFM_EXCEEDS_MEMBER_COUNT",
        path: "trails[0].rosterVersions[0].markerRule.n",
      },
    ]));
});
