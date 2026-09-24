/**
 * P1 AT(6): "the §8.2 completion fixtures pass in `packages/rules`:
 * addition, removal, closure, pre-launch history, `trackingStartsOn`, the
 * three A2-02 rule-change fixtures (`trackingStartsOn` added in V2, `n`
 * changed, unit changed), merge after publication (A2-04), marker parity
 * with both dates pinned, `n-of-m` + `markerRule`, the corroboration-
 * excluded `marker_requires_completion` case, the user-pick member, the
 * composite count, and the date-only `local_date` case" (build plan §10
 * P1). Every fixture here maps 1:1 to a row of §8.2's own golden-fixtures
 * table (plan lines 1968-1993), cited by row text in each `it`.
 *
 * The composite-count row is covered in `at3-marker-roster.test.ts`
 * (A2-18's other AT — AT(3) — names the same fixture, so it is not
 * duplicated here). O15 ("a roster version with `completionRule`/
 * `markerRule` `n-of-m` and no `ruleSource` fails `verify-catalog`") is a
 * SCHEMA-level rule (`CompletionOrMarkerRuleSchema`'s discriminated union,
 * `packages/catalog/src/schema.ts`) already covered by
 * `tools/catalog/test/verify-catalog.test.ts`'s `mf-nofm-no-rulesource` /
 * `mf-markerrule-nofm-no-rulesource` fixtures — `packages/rules` never
 * even sees a `RosterVersion` that fails to parse, so there is nothing for
 * a pure-evaluation fixture to test there.
 */
import { describe, expect, it } from "vitest";
import { mintId, type CourseId, type FacilityId, type RosterVersion, type TrailId } from "@golfraven/catalog";
import {
  applyUserPickGuard,
  evaluateVersionCompletion,
  isTrailComplete,
  markerSetComplete,
  specialMarkerEntitlement,
  trailProgress,
  type CompletionContext,
  type MarkerPurchase,
  type Play,
} from "../src/completion.js";

/* ------------------------------------------------------------------ */
/* Shared fixture builders                                             */
/* ------------------------------------------------------------------ */

function makeCourses(n: number, facilityPrefix = "shared"): {
  courseIds: CourseId[];
  courses: CompletionContext["courses"];
} {
  const facilityId = mintId("fac") as FacilityId;
  void facilityPrefix;
  const courseIds: CourseId[] = [];
  const courses: CompletionContext["courses"] = {};
  for (let i = 0; i < n; i += 1) {
    const courseId = mintId("crs", new Date(Date.now() + i)) as CourseId;
    courseIds.push(courseId);
    courses[courseId] = { id: courseId, facilityId };
  }
  return { courseIds, courses };
}

/** One course PER distinct facility — needed for every marker-roster /
 * special-marker-entitlement fixture below, since the marker roster is
 * "the set of distinct FACILITIES that host a member of V" (§4.3): a
 * fixture that wants to exercise "8 of 9 marker-roster facilities" needs
 * 9 actually-distinct facilities, not 9 courses sharing one. */
function makeCoursesOneFacilityEach(n: number): {
  courseIds: CourseId[];
  courses: CompletionContext["courses"];
} {
  const courseIds: CourseId[] = [];
  const courses: CompletionContext["courses"] = {};
  for (let i = 0; i < n; i += 1) {
    const courseId = mintId("crs", new Date(Date.now() + i)) as CourseId;
    const facilityId = mintId("fac", new Date(Date.now() + 1000 + i)) as FacilityId;
    courseIds.push(courseId);
    courses[courseId] = { id: courseId, facilityId };
  }
  return { courseIds, courses };
}

function courseVersion(
  version: number,
  courseIds: CourseId[],
  opts: Partial<RosterVersion> = {},
): RosterVersion {
  return {
    version,
    effectiveFrom: "2026-01-01",
    source: { url: "https://example.com/roster", retrieved: "2026-01-01" },
    verifiedAt: "2026-01-01",
    completionUnit: "course",
    markerUnit: "facility",
    completionRule: { kind: "all" },
    markerRule: { kind: "all" },
    members: courseIds.map((courseId) => ({ unit: "course" as const, courseId })),
    ...opts,
  };
}

function play(courseId: CourseId, localDate: string, overrides: Partial<Play> = {}): Play {
  return { courseId, localDate, scoreBadge: 1, ...overrides };
}

/* ------------------------------------------------------------------ */
/* Row: Addition mid-progress                                          */
/* ------------------------------------------------------------------ */

describe("AT(6): addition mid-progress", () => {
  it("8 of V1's 9 played before V2 (12 courses) takes effect, the 9th after -> Complete (v1); v2 shows 9/12", () => {
    const { courseIds: v1Courses, courses: coursesV1 } = makeCourses(9);
    const { courseIds: extra, courses: coursesExtra } = makeCourses(3);
    const courses = { ...coursesV1, ...coursesExtra };
    const v1 = courseVersion(1, v1Courses, { effectiveFrom: "2026-01-01" });
    const v2 = courseVersion(2, [...v1Courses, ...extra], { effectiveFrom: "2026-06-01" });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };

    const plays: Play[] = [
      ...v1Courses.slice(0, 8).map((c, i) => play(c, `2026-02-0${i + 1}`)),
      play(v1Courses[8]!, "2026-07-01"), // the 9th, after V2 exists
    ];

    const v1Result = evaluateVersionCompletion(v1, allVersions, plays, ctx);
    expect(v1Result.complete).toBe(true);
    expect(v1Result.satisfiedCount).toBe(9);

    const v2Result = evaluateVersionCompletion(v2, allVersions, plays, ctx);
    expect(v2Result.satisfiedCount).toBe(9);
    expect(v2Result.requiredCount).toBe(12);
    expect(v2Result.complete).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* Row: Removal mid-progress                                           */
/* ------------------------------------------------------------------ */

describe("AT(6): removal mid-progress", () => {
  it("V2 drops a course U played before the drop -> that play still satisfies V1; V2 does not need it", () => {
    const { courseIds, courses } = makeCourses(3);
    const [dropped, kept1, kept2] = courseIds as [CourseId, CourseId, CourseId];
    const v1 = courseVersion(1, [dropped, kept1, kept2], { effectiveFrom: "2026-01-01" });
    const v2 = courseVersion(2, [kept1, kept2], { effectiveFrom: "2026-06-01" });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [
      play(dropped, "2026-02-01"),
      play(kept1, "2026-02-02"),
      play(kept2, "2026-02-03"),
    ];

    const v1Result = evaluateVersionCompletion(v1, allVersions, plays, ctx);
    expect(v1Result.complete).toBe(true);

    const v2Result = evaluateVersionCompletion(v2, allVersions, plays, ctx);
    expect(v2Result.complete).toBe(true);
    expect(v2Result.requiredCount).toBe(2);
  });
});

/* ------------------------------------------------------------------ */
/* Row: closure                                                        */
/* ------------------------------------------------------------------ */

describe("AT(6): a member course closes", () => {
  it("dropped in V3 (Course.closed flags the open roster) -> earned completions stand; V3 is completable without it", () => {
    const { courseIds, courses } = makeCourses(2);
    const [closedCourse, otherCourse] = courseIds as [CourseId, CourseId];
    courses[closedCourse]!.closed = true;
    const v1 = courseVersion(1, [closedCourse, otherCourse], { effectiveFrom: "2026-01-01" });
    const v3 = courseVersion(3, [otherCourse], { effectiveFrom: "2026-09-01" });
    const allVersions = [v1, v3];
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(closedCourse, "2026-01-15"), play(otherCourse, "2026-01-16")];

    expect(evaluateVersionCompletion(v1, allVersions, plays, ctx).complete).toBe(true);
    expect(evaluateVersionCompletion(v3, allVersions, plays, ctx).complete).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Row: pre-launch history / trackingStartsOn                          */
/* ------------------------------------------------------------------ */

describe("AT(6): pre-launch history and trackingStartsOn", () => {
  it("V with no trackingStartsOn -> pre-launch evidenced plays satisfy members", () => {
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds, { effectiveFrom: "2027-01-01" });
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseIds[0]!, "2020-01-01")]; // long pre-launch
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });

  it("V with trackingStartsOn = 2027-01-01 -> plays before it do not count in V", () => {
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds, { trackingStartsOn: "2027-01-01" });
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseIds[0]!, "2026-12-31")];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(false);
    const laterPlays: Play[] = [play(courseIds[0]!, "2027-01-01")];
    expect(evaluateVersionCompletion(v1, [v1], laterPlays, ctx).complete).toBe(true);
  });

  it("trackingStartsOn introduced in V2; U has 8/9 pre-date plays then the 9th after -> Complete (v1); V2 counts only the post-date play", () => {
    const { courseIds, courses } = makeCourses(9);
    const v1 = courseVersion(1, courseIds, { effectiveFrom: "2026-01-01" });
    const v2 = courseVersion(2, courseIds, {
      effectiveFrom: "2026-06-01",
      trackingStartsOn: "2027-01-01",
    });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [
      ...courseIds.slice(0, 8).map((c, i) => play(c, `2026-02-0${i + 1}`)),
      play(courseIds[8]!, "2027-02-01"),
    ];
    expect(evaluateVersionCompletion(v1, allVersions, plays, ctx).complete).toBe(true);
    const v2Result = evaluateVersionCompletion(v2, allVersions, plays, ctx);
    expect(v2Result.satisfiedCount).toBe(1);
    expect(v2Result.complete).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* Row: n changed                                                       */
/* ------------------------------------------------------------------ */

describe("AT(6): n changed (A2-02)", () => {
  it("V1 10-of-12, V2 12-of-15; U has 10 of V1's 12 -> Complete (v1)", () => {
    const { courseIds, courses } = makeCourses(15);
    const v1Members = courseIds.slice(0, 12);
    const v2Members = courseIds.slice(0, 15);
    const v1 = courseVersion(1, v1Members, {
      effectiveFrom: "2026-01-01",
      completionRule: { kind: "n-of-m", n: 10, ruleSource: { url: "https://example.com/r", retrieved: "2026-01-01" } },
    });
    const v2 = courseVersion(2, v2Members, {
      effectiveFrom: "2026-06-01",
      completionRule: { kind: "n-of-m", n: 12, ruleSource: { url: "https://example.com/r", retrieved: "2026-06-01" } },
    });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    const plays: Play[] = v1Members.slice(0, 10).map((c, i) => play(c, `2026-02-${String(i + 1).padStart(2, "0")}`));

    expect(evaluateVersionCompletion(v1, allVersions, plays, ctx).complete).toBe(true);
    expect(evaluateVersionCompletion(v2, allVersions, plays, ctx).complete).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* Row: unit changed                                                    */
/* ------------------------------------------------------------------ */

describe("AT(6): unit changed (A2-02)", () => {
  it("V1 course, V2 facility; U plays a V1 course after V2's effectiveFrom -> each version evaluates under its own unit; the play still counts in V1", () => {
    const facilityId = mintId("fac") as FacilityId;
    const courseId = mintId("crs") as CourseId;
    const courses: CompletionContext["courses"] = { [courseId]: { id: courseId, facilityId } };
    const v1 = courseVersion(1, [courseId], { effectiveFrom: "2026-01-01" });
    const v2: RosterVersion = {
      version: 2,
      effectiveFrom: "2026-06-01",
      source: { url: "https://example.com/r", retrieved: "2026-06-01" },
      verifiedAt: "2026-06-01",
      completionUnit: "facility",
      markerUnit: "facility",
      completionRule: { kind: "all" },
      markerRule: { kind: "all" },
      members: [{ unit: "facility", facilityId }],
    };
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    // A play AFTER V2's effectiveFrom — re-typing is not a drop, so it
    // must still count toward V1.
    const plays: Play[] = [play(courseId, "2026-07-01")];
    expect(evaluateVersionCompletion(v1, allVersions, plays, ctx).complete).toBe(true);
    expect(evaluateVersionCompletion(v2, allVersions, plays, ctx).complete).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Row: merge after publication (A2-04)                                 */
/* ------------------------------------------------------------------ */

describe("AT(6): merge after publication (A2-04)", () => {
  it("V1 lists crs_x, later tombstoned into crs_y; U played crs_y -> crs_x is satisfied in V1", () => {
    const facilityId = mintId("fac") as FacilityId;
    const crsX = mintId("crs") as CourseId;
    const crsY = mintId("crs", new Date(Date.now() + 1)) as CourseId;
    const courses: CompletionContext["courses"] = {
      [crsX]: { id: crsX, facilityId },
      [crsY]: { id: crsY, facilityId },
    };
    const v1 = courseVersion(1, [crsX]);
    const ctx: CompletionContext = {
      courses,
      ledger: {
        entries: {
          [crsX]: { id: crsX, kind: "crs", transitions: [], tombstoned: true, mergedInto: crsY },
          [crsY]: { id: crsY, kind: "crs", transitions: [] },
        },
      },
    };
    const plays: Play[] = [play(crsY, "2026-03-01")];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Row: marker parity, n-of-m + markerRule, marker_requires_completion  */
/* ------------------------------------------------------------------ */

describe("AT(6): marker vs completion parity", () => {
  it("trackingStartsOn absent, both dates before every play/purchase -> the marker set and the badge reach the same verdict for the same member set", () => {
    const { courseIds, courses } = makeCourses(3);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = courseIds.map((c, i) => play(c, `2026-01-0${i + 1}`, { moneyQualifies: true }));
    const purchases: MarkerPurchase[] = [{ facilityId: courses[courseIds[0]!]!.facilityId, localDate: "2026-01-01" }];
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(true);
    expect(isTrailComplete([v1], plays, ctx)).toBe(true);
  });

  it("starts_on falls after one purchase -> that purchase does not count; the play still does", () => {
    const { courseIds, courses } = makeCourses(1);
    const facilityId = courses[courseIds[0]!]!.facilityId;
    const v1 = courseVersion(1, courseIds, { trackingStartsOn: "2026-06-01" });
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = [{ facilityId, localDate: "2026-01-01" }]; // before starts_on
    const plays: Play[] = [play(courseIds[0]!, "2026-07-01", { moneyQualifies: true })]; // after
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false); // purchase leg missing
    expect(entitlement.missingPurchases).toContain(facilityId);
    const badgeOnlyPlays = plays.map(({ moneyQualifies: _moneyQualifies, ...rest }) => rest);
    expect(evaluateVersionCompletion(v1, [v1], badgeOnlyPlays, ctx).complete).toBe(true);
  });

  it("n-of-m completion with markerRule: all -> badge at n; the marker set still needs every facility", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(3);
    const v1 = courseVersion(1, courseIds, {
      completionRule: { kind: "n-of-m", n: 2, ruleSource: { url: "https://example.com/r", retrieved: "2026-01-01" } },
      markerRule: { kind: "all" },
    });
    const ctx: CompletionContext = { courses };
    const plays: Play[] = courseIds.slice(0, 2).map((c, i) => play(c, `2026-01-0${i + 1}`));
    const result = evaluateVersionCompletion(v1, [v1], plays, ctx);
    expect(result.complete).toBe(true); // 2 of 3 (n-of-m)
    // markerSetComplete needs ALL facilities credited (markerRule: all) —
    // only 2 of 3 have qualifying plays.
    expect(markerSetComplete([v1], plays, ctx)).toBe(false);
  });

  it("marker_requires_completion=true, reachable only by counting purchase corroboration (A2-19) -> not complete; no entitlement", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const facilityIds = courseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    // Only purchases, no money-mode qualifying plays at all.
    const purchases: MarkerPurchase[] = facilityIds.map((f) => ({ facilityId: f, localDate: "2026-01-01" }));
    const entitlement = specialMarkerEntitlement([v1], [], purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    expect(entitlement.missingMoneyPlays.length).toBe(2);
  });
});

/* ------------------------------------------------------------------ */
/* Rows: O19 default (true) — each leg reported missing on its own      */
/* ------------------------------------------------------------------ */

describe("AT(6): O19 default (marker_requires_completion: true)", () => {
  it("a valid purchase at every marker-roster facility; money-mode plays at 8 of 9 members -> no entitlement; names the missing stop", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(9);
    const facilityIds = courseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = facilityIds.map((f) => ({ facilityId: f, localDate: "2026-01-01" }));
    const plays: Play[] = courseIds
      .slice(0, 8)
      .map((c, i) => play(c, `2026-02-0${i + 1}`, { moneyQualifies: true }));
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    expect(entitlement.missingMoneyPlays).toEqual([facilityIds[8]]);
    expect(entitlement.missingPurchases).toEqual([]);
  });

  it("money-mode plays at all 9 members; purchases at 8 of 9 facilities -> no entitlement; names the missing shop", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(9);
    const facilityIds = courseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = facilityIds
      .slice(0, 8)
      .map((f) => ({ facilityId: f, localDate: "2026-01-01" }));
    const plays: Play[] = courseIds.map((c, i) => play(c, `2026-02-0${(i % 9) + 1}`, { moneyQualifies: true }));
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    expect(entitlement.missingPurchases).toEqual([facilityIds[8]]);
    expect(entitlement.missingMoneyPlays).toEqual([]);
  });

  it("both legs complete, but one play is badge-level only -> no entitlement; the trail-completion badge is still earned", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const facilityIds = courseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = facilityIds.map((f) => ({ facilityId: f, localDate: "2026-01-01" }));
    const plays: Play[] = [
      play(courseIds[0]!, "2026-02-01", { moneyQualifies: true }),
      play(courseIds[1]!, "2026-02-02", { moneyQualifies: false, scoreBadge: 0.6 }), // badge-level only
    ];
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    // the BADGE is still earned (badge mode ignores moneyQualifies).
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });

  it("both legs complete, but one leg on V1 and the other only on V2 -> no entitlement: both legs must hold on the same V", () => {
    // V1 and V2 are given ENTIRELY DISJOINT rosters (a full member
    // replacement, not an addition) so that "leg 1 satisfied against V1's
    // roster" and "leg 2 satisfied against V2's roster" cannot spuriously
    // also satisfy the OTHER version just because the same facilities
    // happen to appear in both (which is exactly what made an overlapping-
    // roster version of this fixture accidentally satisfy V1 on both legs
    // — plays are never upper-bounded by a later version's start date
    // unless a member is actually dropped). A disjoint-roster replacement
    // still tests the real claim: purchases exist only for V1's
    // facilities (V2's own roster is entirely unpurchased) and
    // money-qualifying plays exist only for V2's facilities (V1's own
    // roster has none) — every version is missing at least one leg
    // entirely, so nothing is ever entitled.
    const { courseIds: v1CourseIds, courses: v1Courses } = makeCoursesOneFacilityEach(2);
    const { courseIds: v2CourseIds, courses: v2Courses } = makeCoursesOneFacilityEach(2);
    const courses = { ...v1Courses, ...v2Courses };
    const v1FacilityIds = v1CourseIds.map((c) => courses[c]!.facilityId);
    const v2FacilityIds = v2CourseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, v1CourseIds, { effectiveFrom: "2026-01-01" });
    const v2 = courseVersion(2, v2CourseIds, { effectiveFrom: "2026-06-01" });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    // Leg 1 (purchases): only V1's facilities.
    const purchases: MarkerPurchase[] = v1FacilityIds.map((f) => ({ facilityId: f, localDate: "2026-02-01" }));
    // Leg 2 (money-mode plays): only V2's courses.
    const plays: Play[] = v2CourseIds.map((c, i) => play(c, `2026-07-0${i + 1}`, { moneyQualifies: true }));
    const entitlement = specialMarkerEntitlement(allVersions, plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    // V1: purchase leg fully held, money leg fully missing.
    // V2: money leg fully held, purchase leg fully missing.
    expect(entitlement.missingMoneyPlays.length + entitlement.missingPurchases.length).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------ */
/* Row: O8 — a private-club member is satisfied like any other          */
/* ------------------------------------------------------------------ */

describe("AT(6): O8 — a private-club roster member", () => {
  it("a trail with one access: 'private' member; a guest play satisfies it like any other — never skipped", () => {
    // packages/rules models no `access` field at all — a member is
    // satisfied purely by a qualifying play at its physical unit,
    // regardless of the facility's access tier (which is a CATALOG
    // concern, gated at `verify-catalog`'s ROSTER_MEMBER_MISSING_ACCESS,
    // not an evaluation-time concern). This test proves the evaluator
    // does not (and structurally cannot) special-case or skip a private
    // member: it is satisfied exactly like a public one.
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    // The "guest" evidence path (course-QR scan + check-in, per §8.2) is
    // already resolved into an ordinary qualifying Play by the time it
    // reaches this package.
    const plays: Play[] = [play(courseIds[0]!, "2026-03-01")];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Row: 36-hole course-unit member, shared polygon, dwell, user pick    */
/* ------------------------------------------------------------------ */

describe("AT(6): the user-pick member (A2-01)", () => {
  it("satisfied at badge level; no money", () => {
    const { courseIds, courses } = makeCourses(2, "36hole");
    const [pickedCourse] = courseIds as [CourseId];
    const v1 = courseVersion(1, [pickedCourse]);
    const ctx: CompletionContext = { courses };
    // A user pick: score_badge capped at 0.50 (facility-level weight, per
    // A2-01), score_monetary 0 (moneyQualifies: false) — both inputs, per
    // this package's own scope (the scorer that computes them is P3).
    const plays: Play[] = [
      play(pickedCourse, "2026-04-01", {
        courseDisambiguatedBy: "user",
        scoreBadge: 0.5,
        moneyQualifies: false,
      }),
    ];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
    expect(trailProgress([v1], plays, ctx, true)).toBe(0); // no money-mode progress
  });

  it("the one-pick-per-facility-per-date guard: a second, different user pick on the same date replaces the first", () => {
    const { courseIds, courses } = makeCourses(2, "36hole-guard");
    const [courseA, courseB] = courseIds as [CourseId, CourseId];
    const ctx: CompletionContext = { courses };
    const raw: Play[] = [
      play(courseA, "2026-04-01", { courseDisambiguatedBy: "user" }),
      play(courseB, "2026-04-01", { courseDisambiguatedBy: "user" }), // replaces the first
    ];
    const guarded = applyUserPickGuard(raw, ctx);
    expect(guarded.length).toBe(1);
    expect(guarded[0]!.courseId).toBe(courseB);
  });
});

/* ------------------------------------------------------------------ */
/* Row: date-only local_date (A2-17)                                    */
/* ------------------------------------------------------------------ */

describe("AT(6): date-only self-report (A2-17)", () => {
  it("2027-04-10 at a Central-time facility, from an Eastern-time device -> play_date = 2027-04-10 (the input is used verbatim)", () => {
    // The caller (out of scope) has already resolved the device's local
    // clock down to the FACILITY's date — packages/rules never re-derives
    // a date from any time zone; it only ever reads `Play.localDate`.
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseIds[0]!, "2027-04-10")];
    const result = evaluateVersionCompletion(v1, [v1], plays, ctx);
    expect(result.complete).toBe(true);
    expect(result.members[0]!.earliestQualifyingDate).toBe("2027-04-10");
  });
});
