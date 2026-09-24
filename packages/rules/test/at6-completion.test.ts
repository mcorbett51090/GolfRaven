/**
 * P1 AT(6): "the §8.2 completion fixtures pass in `packages/rules`" (build
 * plan §10 P1). Every fixture here maps 1:1 to a row of §8.2's own
 * golden-fixtures table (plan lines 1968-1993), cited by row text in each
 * `it`, PLUS the gate-review B1/B2/B3/S1/S4 fixtures the coordinator's
 * mutation probes found missing.
 *
 * The composite-count row is covered in `at3-marker-roster.test.ts`. O15
 * ("`n-of-m` with no `ruleSource`") and N5 ("`n` greater than the member
 * count") are SCHEMA/catalog-level gates, covered in
 * `tools/catalog/test/verify-catalog.test.ts` — `packages/rules` never
 * even sees a `RosterVersion` that fails either.
 */
import { describe, expect, it } from "vitest";
import { type CourseId, type DesignerId, type FacilityId, type RosterVersion } from "@golfraven/catalog";
import {
  applyUserPickGuard,
  evaluateVersionCompletion,
  inOrder,
  isFacilityCreditedByPlay,
  isTrailComplete,
  markerSetComplete,
  monthlyStreak,
  specialMarkerEntitlement,
  trailCompleteWithin,
  trailProgress,
  type CompletionContext,
  type CourseMeta,
  type MarkerPurchase,
  type Play,
} from "../src/completion.js";
import { maxCountBy, type AggregateContext } from "../src/aggregates.js";
import { nextId } from "./test-ids.js";

/* ------------------------------------------------------------------ */
/* Shared fixture builders                                             */
/* ------------------------------------------------------------------ */

function makeCourses(n: number): {
  courseIds: CourseId[];
  courses: CompletionContext["courses"];
} {
  const facilityId = nextId("fac") as FacilityId;
  const courseIds: CourseId[] = [];
  const courses: CompletionContext["courses"] = {};
  for (let i = 0; i < n; i += 1) {
    const courseId = nextId("crs") as CourseId;
    courseIds.push(courseId);
    // S4: `verified` defaults to true when omitted, but every fixture in
    // this file states it explicitly — this file's whole point is testing
    // qualification rules, so leaving the verification gate implicit
    // would hide exactly the kind of bug this gate review is about.
    courses[courseId] = { id: courseId, facilityId, verified: true };
  }
  return { courseIds, courses };
}

/** One course PER distinct facility — needed for every marker-roster /
 * special-marker-entitlement fixture, since the marker roster is "the set
 * of distinct FACILITIES that host a member of V" (§4.3). */
function makeCoursesOneFacilityEach(n: number): {
  courseIds: CourseId[];
  courses: CompletionContext["courses"];
} {
  const courseIds: CourseId[] = [];
  const courses: CompletionContext["courses"] = {};
  for (let i = 0; i < n; i += 1) {
    const courseId = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    courseIds.push(courseId);
    courses[courseId] = { id: courseId, facilityId, verified: true };
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
    const facilityId = nextId("fac") as FacilityId;
    const courseId = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = { [courseId]: { id: courseId, facilityId, verified: true } };
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
    const facilityId = nextId("fac") as FacilityId;
    const crsX = nextId("crs") as CourseId;
    const crsY = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [crsX]: { id: crsX, facilityId, verified: true },
      [crsY]: { id: crsY, facilityId, verified: true },
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
/* B1 (gate review): O19 money leg is per completion MEMBER              */
/* ------------------------------------------------------------------ */

describe("AT(6): B1 — the O19 money leg is judged per completion member, not per facility", () => {
  it("two course members at one facility; a money play at A only, a badge-level play at B -> not entitled", () => {
    const facilityId = nextId("fac") as FacilityId;
    const a = nextId("crs") as CourseId;
    const b = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [a]: { id: a, facilityId, verified: true },
      [b]: { id: b, facilityId, verified: true },
    };
    const v1 = courseVersion(1, [a, b]);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [
      play(a, "2026-02-01", { moneyQualifies: true }),
      play(b, "2026-02-02", { scoreBadge: 0.5, moneyQualifies: false }),
    ];
    const purchases: MarkerPurchase[] = [{ facilityId, localDate: "2026-02-01" }];
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    // A facility-level check would wrongly say "the one facility has SOME
    // money play" and call it entitled — the fix judges the money leg via
    // evaluateVersionCompletion (per-member, under completionRule), which
    // correctly sees B's member as unsatisfied in money mode.
    expect(entitlement.entitled).toBe(false);
    expect(isTrailComplete([v1], plays, ctx, { money: true })).toBe(false);
    // The badge itself is still fine (badge mode ignores moneyQualifies).
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* B2 (gate review): programmeStartsOn, separate from trackingStartsOn   */
/* ------------------------------------------------------------------ */

describe("AT(6): B2 — programmeStartsOn is a separate, money-only bound", () => {
  it("trackingStartsOn absent (launch grace) but 2019 purchases/money plays predate programmeStartsOn -> not entitled", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(1);
    const facilityId = courses[courseIds[0]!]!.facilityId;
    const v1 = courseVersion(1, courseIds); // no trackingStartsOn: launch grace
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = [{ facilityId, localDate: "2019-05-01" }];
    const plays: Play[] = [play(courseIds[0]!, "2019-05-01", { moneyQualifies: true })];
    const entitled = specialMarkerEntitlement([v1], plays, purchases, ctx, true, {
      programmeStartsOn: "2026-01-01",
    });
    expect(entitled.entitled).toBe(false);
    // Meanwhile the BADGE (no programmeStartsOn concept) still enjoys the
    // launch grace period, per the plain completion rule.
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });

  it("badge counts from trackingStartsOn, offer/marker count only from a LATER programmeStartsOn — the two dates differ by design", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(1);
    const facilityId = courses[courseIds[0]!]!.facilityId;
    const v1 = courseVersion(1, courseIds, { trackingStartsOn: "2026-01-01" });
    const ctx: CompletionContext = { courses };
    // A play/purchase after trackingStartsOn but BEFORE programmeStartsOn.
    const midDate = "2026-03-01";
    const purchases: MarkerPurchase[] = [{ facilityId, localDate: midDate }];
    const plays: Play[] = [play(courseIds[0]!, midDate, { moneyQualifies: true })];
    // Badge: satisfied (clears trackingStartsOn).
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
    // Money leg / offer: NOT satisfied (predates programmeStartsOn).
    const entitled = specialMarkerEntitlement([v1], plays, purchases, ctx, true, {
      programmeStartsOn: "2026-06-01",
    });
    expect(entitled.entitled).toBe(false);
    // Once the play/purchase is after programmeStartsOn too, it IS entitled.
    const laterPurchases: MarkerPurchase[] = [{ facilityId, localDate: "2026-07-01" }];
    const laterPlays: Play[] = [play(courseIds[0]!, "2026-07-01", { moneyQualifies: true })];
    const entitledLater = specialMarkerEntitlement([v1], laterPlays, laterPurchases, ctx, true, {
      programmeStartsOn: "2026-06-01",
    });
    expect(entitledLater.entitled).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* B3 (gate review): trailCompleteWithin searches ALL candidate windows */
/* ------------------------------------------------------------------ */

describe("AT(6): B3 — trailCompleteWithin searches every candidate window, not each member's earliest play", () => {
  it("A played in 2020 AND on 2027-05-01; B on 2027-05-10; within 30 days -> true (using the LATER A play, not the 2020 one)", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const [a, b] = courseIds as [CourseId, CourseId];
    const v1 = courseVersion(1, [a, b]);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [
      play(a, "2020-01-01"),
      play(a, "2027-05-01"),
      play(b, "2027-05-10"),
    ];
    expect(trailCompleteWithin([v1], plays, ctx, 30)).toBe(true);
  });

  it("without the later A play, only the 2020 date exists for A -> false (too far from B's 2027-05-10)", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const [a, b] = courseIds as [CourseId, CourseId];
    const v1 = courseVersion(1, [a, b]);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(a, "2020-01-01"), play(b, "2027-05-10")];
    expect(trailCompleteWithin([v1], plays, ctx, 30)).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* S1 (gate review): removedOn keyed on the course, and marker credit /  */
/* purchases respect removed_on too                                     */
/* ------------------------------------------------------------------ */

describe("AT(6): S1 — removed_on is keyed on the member's physical unit (course, for a course member)", () => {
  it("a course swapped for another course AT THE SAME FACILITY -> the dropped course's post-swap play no longer satisfies V1", () => {
    const facilityId = nextId("fac") as FacilityId;
    const a = nextId("crs") as CourseId;
    const b = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [a]: { id: a, facilityId, verified: true },
      [b]: { id: b, facilityId, verified: true },
    };
    const v1 = courseVersion(1, [a]);
    const v2 = courseVersion(2, [b], { effectiveFrom: "2026-06-01" }); // same facility, different course
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    // A play at `a`, AFTER the swap — must NOT satisfy V1 (a was dropped,
    // even though its facility still hosts a roster member via `b`).
    const plays: Play[] = [play(a, "2026-07-01")];
    expect(evaluateVersionCompletion(v1, allVersions, plays, ctx).complete).toBe(false);
    // A play BEFORE the swap still counts.
    const earlyPlays: Play[] = [play(a, "2026-03-01")];
    expect(evaluateVersionCompletion(v1, allVersions, earlyPlays, ctx).complete).toBe(true);
  });

  it("marker credit (isFacilityCreditedByPlay) respects a FACILITY's own removed_on", () => {
    const fA = nextId("fac") as FacilityId;
    const fB = nextId("fac") as FacilityId;
    const a = nextId("crs") as CourseId;
    const b = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [a]: { id: a, facilityId: fA, verified: true },
      [b]: { id: b, facilityId: fB, verified: true },
    };
    const v1 = courseVersion(1, [a, b]);
    const v2 = courseVersion(2, [b], { effectiveFrom: "2026-06-01" }); // drops facility fA entirely
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    // A post-drop play at the DROPPED facility (fA, via course a) must not
    // credit V1's marker roster. `allVersions` (not just `[v1]`) is passed
    // so `isFacilityCreditedByPlay` can see V2's drop to derive fA's
    // removed_on — `markerSetComplete` itself existentially quantifies
    // over every version, so testing IT directly here would let V2's own
    // (fully-satisfied, single-member) marker roster mask the exact
    // regression this fixture targets.
    const postDropPlays: Play[] = [play(a, "2026-07-01")];
    expect(isFacilityCreditedByPlay(fA, v1, allVersions, postDropPlays, ctx)).toBe(false);
    const preDropPlays: Play[] = [play(a, "2026-03-01")];
    expect(isFacilityCreditedByPlay(fA, v1, allVersions, preDropPlays, ctx)).toBe(true);
  });

  it("a purchase after the facility's removed_on does not satisfy the O19 purchase leg", () => {
    const fA = nextId("fac") as FacilityId;
    const fB = nextId("fac") as FacilityId;
    const a = nextId("crs") as CourseId;
    const b = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [a]: { id: a, facilityId: fA, verified: true },
      [b]: { id: b, facilityId: fB, verified: true },
    };
    const v1 = courseVersion(1, [a, b]);
    // V2 drops fA (facility a belonged to) AND is given a trackingStartsOn
    // nothing here clears, so V2 itself can never be entitled — isolating
    // this test to V1's own purchase-leg rejection.
    const v2 = courseVersion(2, [b], {
      effectiveFrom: "2026-06-01",
      trackingStartsOn: "2099-01-01",
    });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = [
      { facilityId: fA, localDate: "2026-07-01" }, // AFTER fA's removed_on (2026-06-01)
      { facilityId: fB, localDate: "2026-02-01" },
    ];
    const plays: Play[] = [
      play(a, "2026-02-01", { moneyQualifies: true }),
      play(b, "2026-02-02", { moneyQualifies: true }),
    ];
    const entitlement = specialMarkerEntitlement(allVersions, plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    expect(entitlement.missingPurchases).toContain(fA);
  });
});

/* ------------------------------------------------------------------ */
/* Row: marker parity, n-of-m + markerRule, marker_requires_completion  */
/* ------------------------------------------------------------------ */

describe("AT(6): marker vs completion parity", () => {
  it("trackingStartsOn absent, both dates before every play/purchase -> the marker set and the badge reach the same verdict for the same member set", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(3);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = courseIds.map((c, i) => play(c, `2026-01-0${i + 1}`, { moneyQualifies: true }));
    const purchases: MarkerPurchase[] = courseIds.map((c) => ({
      facilityId: courses[c]!.facilityId,
      localDate: "2026-01-01",
    }));
    const entitlement = specialMarkerEntitlement([v1], plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(true);
    expect(isTrailComplete([v1], plays, ctx)).toBe(true);
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
    expect(markerSetComplete([v1], plays, ctx)).toBe(false);
  });

  it("marker_requires_completion=true, reachable only by counting purchase corroboration (A2-19) -> not complete; no entitlement", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const facilityIds = courseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
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
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });

  it("both legs complete, but one leg on V1 and the other only on V2 -> no entitlement: both legs must hold on the same V", () => {
    const { courseIds: v1CourseIds, courses: v1Courses } = makeCoursesOneFacilityEach(2);
    const { courseIds: v2CourseIds, courses: v2Courses } = makeCoursesOneFacilityEach(2);
    const courses = { ...v1Courses, ...v2Courses };
    const v1FacilityIds = v1CourseIds.map((c) => courses[c]!.facilityId);
    const v1 = courseVersion(1, v1CourseIds, { effectiveFrom: "2026-01-01" });
    const v2 = courseVersion(2, v2CourseIds, { effectiveFrom: "2026-06-01" });
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    const purchases: MarkerPurchase[] = v1FacilityIds.map((f) => ({ facilityId: f, localDate: "2026-02-01" }));
    const plays: Play[] = v2CourseIds.map((c, i) => play(c, `2026-07-0${i + 1}`, { moneyQualifies: true }));
    const entitlement = specialMarkerEntitlement(allVersions, plays, purchases, ctx, true);
    expect(entitlement.entitled).toBe(false);
    expect(entitlement.missingMoneyPlays.length + entitlement.missingPurchases.length).toBeGreaterThan(0);
  });
});

/* ------------------------------------------------------------------ */
/* Row: O8 — a private-club member is satisfied like any other          */
/* ------------------------------------------------------------------ */

describe("AT(6): O8 — a private-club roster member", () => {
  it("a trail with one access: 'private' member; a guest play satisfies it like any other — never skipped", () => {
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseIds[0]!, "2026-03-01")];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/* Row: 36-hole course-unit member, shared polygon, dwell, user pick    */
/* ------------------------------------------------------------------ */

describe("AT(6): the user-pick member (A2-01)", () => {
  it("satisfied at badge level; no money", () => {
    const { courseIds, courses } = makeCourses(2);
    const [pickedCourse] = courseIds as [CourseId];
    const v1 = courseVersion(1, [pickedCourse]);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [
      play(pickedCourse, "2026-04-01", {
        courseDisambiguatedBy: "user",
        scoreBadge: 0.5,
        moneyQualifies: false,
      }),
    ];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
    expect(trailProgress([v1], plays, ctx, { money: true })).toBe(0);
  });

  it("the one-pick-per-facility-per-date guard: a second, different user pick on the same date replaces the first", () => {
    const { courseIds, courses } = makeCourses(2);
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
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseIds[0]!, "2027-04-10")];
    const result = evaluateVersionCompletion(v1, [v1], plays, ctx);
    expect(result.complete).toBe(true);
    expect(result.members[0]!.earliestQualifyingDate).toBe("2027-04-10");
  });
});

/* ------------------------------------------------------------------ */
/* S4 (gate review): minConfidence threshold + verified-course gate     */
/* ------------------------------------------------------------------ */

describe("AT(6): S4 — AchievementDef.minConfidence and the verified-course gate", () => {
  it("a per-achievement badgeThreshold (minConfidence) replaces the default 0.50", () => {
    const { courseIds, courses } = makeCourses(1);
    const v1 = courseVersion(1, courseIds);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseIds[0]!, "2026-01-01", { scoreBadge: 0.7 })];
    // Default threshold (0.50): satisfied.
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
    // A stricter achievement-specific threshold (0.80): NOT satisfied.
    expect(
      evaluateVersionCompletion(v1, [v1], plays, ctx, { badgeThreshold: 0.8 }).complete,
    ).toBe(false);
  });

  it("a play at an unverified (stub) course never qualifies, in either mode (G3-01)", () => {
    const facilityId = nextId("fac") as FacilityId;
    const courseId = nextId("crs") as CourseId;
    const unverifiedCourse: CourseMeta = { id: courseId, facilityId, verified: false };
    const courses: CompletionContext["courses"] = { [courseId]: unverifiedCourse };
    const v1 = courseVersion(1, [courseId]);
    const ctx: CompletionContext = { courses };
    const plays: Play[] = [play(courseId, "2026-01-01", { moneyQualifies: true })];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(false);
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx, { money: true }).complete).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/* S7 (gate review): mutation-kill fixtures — boundary/off-by-one cases */
/* a coarser fixture happens not to exercise                            */
/* ------------------------------------------------------------------ */

describe("S7 mutation-kill fixtures", () => {
  it("a play exactly ON removed_on's date does NOT satisfy the dropped member (strictly BEFORE, not on-or-before)", () => {
    const facilityId = nextId("fac") as FacilityId;
    const a = nextId("crs") as CourseId;
    const b = nextId("crs") as CourseId;
    const courses: CompletionContext["courses"] = {
      [a]: { id: a, facilityId, verified: true },
      [b]: { id: b, facilityId, verified: true },
    };
    const v1 = courseVersion(1, [a]);
    const v2 = courseVersion(2, [b], { effectiveFrom: "2026-06-01" }); // a's removed_on
    const allVersions = [v1, v2];
    const ctx: CompletionContext = { courses };
    // A play EXACTLY on removed_on's date (2026-06-01) — must NOT count.
    const onBoundary: Play[] = [play(a, "2026-06-01")];
    expect(evaluateVersionCompletion(v1, allVersions, onBoundary, ctx).complete).toBe(false);
    // The day before still counts.
    const dayBefore: Play[] = [play(a, "2026-05-31")];
    expect(evaluateVersionCompletion(v1, allVersions, dayBefore, ctx).complete).toBe(true);
  });

  it("trailCompleteWithin: a span of EXACTLY `days` apart is within the window (inclusive)", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const [a, b] = courseIds as [CourseId, CourseId];
    const v1 = courseVersion(1, [a, b]);
    const ctx: CompletionContext = { courses };
    // Exactly 30 days apart.
    const plays: Play[] = [play(a, "2027-01-01"), play(b, "2027-01-31")];
    expect(trailCompleteWithin([v1], plays, ctx, 30)).toBe(true);
    // 31 days apart is NOT within a 30-day window.
    const tooFar: Play[] = [play(a, "2027-01-01"), play(b, "2027-02-01")];
    expect(trailCompleteWithin([v1], tooFar, ctx, 30)).toBe(false);
  });

  it("isFacilityCreditedByPlay respects the VERSION's own trackingStartsOn (not just removed_on)", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(1);
    const facilityId = courses[courseIds[0]!]!.facilityId;
    const v1 = courseVersion(1, courseIds, { trackingStartsOn: "2026-06-01" });
    const ctx: CompletionContext = { courses };
    const early: Play[] = [play(courseIds[0]!, "2026-01-01")];
    expect(isFacilityCreditedByPlay(facilityId, v1, [v1], early, ctx)).toBe(false);
    const onTime: Play[] = [play(courseIds[0]!, "2026-06-02")];
    expect(isFacilityCreditedByPlay(facilityId, v1, [v1], onTime, ctx)).toBe(true);
  });

  it("a member covers a course played under its PRE-MERGE id (merge resolution in play-to-member matching, not just field aggregates)", () => {
    const facilityId = nextId("fac") as FacilityId;
    const crsX = nextId("crs") as CourseId; // pre-merge
    const crsY = nextId("crs") as CourseId; // survivor, listed on the roster
    const courses: CompletionContext["courses"] = {
      [crsX]: { id: crsX, facilityId, verified: true },
      [crsY]: { id: crsY, facilityId, verified: true },
    };
    const v1 = courseVersion(1, [crsY]); // roster lists the SURVIVOR
    const ctx: CompletionContext = {
      courses,
      ledger: {
        entries: {
          [crsX]: { id: crsX, kind: "crs", transitions: [], tombstoned: true, mergedInto: crsY },
          [crsY]: { id: crsY, kind: "crs", transitions: [] },
        },
      },
    };
    // The PLAY is recorded under the OLD (pre-merge) id.
    const plays: Play[] = [play(crsX, "2026-01-01")];
    expect(evaluateVersionCompletion(v1, [v1], plays, ctx).complete).toBe(true);
  });

  it("trailProgress is capped at 1 even when satisfiedCount exceeds an n-of-m requiredCount", () => {
    const { courseIds, courses } = makeCourses(5);
    const v1 = courseVersion(1, courseIds, {
      completionRule: { kind: "n-of-m", n: 2, ruleSource: { url: "https://example.com/r", retrieved: "2026-01-01" } },
    });
    const ctx: CompletionContext = { courses };
    // ALL 5 members satisfied, but only 2 were required — satisfiedCount
    // (5) / requiredCount (2) = 2.5 before capping.
    const plays: Play[] = courseIds.map((c, i) => play(c, `2026-01-0${i + 1}`));
    expect(trailProgress([v1], plays, ctx)).toBe(1);
  });

  it("inOrder accepts two stops played on the SAME date ('on or after', not strictly after)", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(2);
    const [a, b] = courseIds as [CourseId, CourseId];
    const versionWithOrder: RosterVersion = {
      ...courseVersion(1, [a, b]),
      members: [
        { unit: "course", courseId: a, stopOrder: 0 },
        { unit: "course", courseId: b, stopOrder: 1 },
      ],
    };
    const ctx: CompletionContext = { courses };
    const samedate: Play[] = [play(a, "2026-05-01"), play(b, "2026-05-01")];
    expect(inOrder([versionWithOrder], samedate, ctx)).toBe(true);
  });

  it("monthlyStreak resets across a gap month (non-consecutive months never combine)", () => {
    const { courseIds, courses } = makeCourses(1);
    const ctx: CompletionContext = { courses };
    // Jan, then Mar (skip Feb) — longest streak is 1, not 2.
    const plays: Play[] = [play(courseIds[0]!, "2026-01-15"), play(courseIds[0]!, "2026-03-15")];
    expect(monthlyStreak(plays, ctx)).toBe(1);
  });

  it("a purchase before the version's trackingStartsOn does not satisfy the O19 purchase leg", () => {
    const { courseIds, courses } = makeCoursesOneFacilityEach(1);
    const facilityId = courses[courseIds[0]!]!.facilityId;
    const v1 = courseVersion(1, courseIds, { trackingStartsOn: "2026-06-01" });
    const ctx: CompletionContext = { courses };
    const earlyPurchase: MarkerPurchase[] = [{ facilityId, localDate: "2026-01-01" }];
    const play_: Play[] = [play(courseIds[0]!, "2026-07-01", { moneyQualifies: true })];
    const entitlement = specialMarkerEntitlement([v1], play_, earlyPurchase, ctx, true);
    expect(entitlement.entitled).toBe(false);
    expect(entitlement.missingPurchases).toContain(facilityId);
  });

  it("maxCountBy counts one COURSE once even when it was played twice (never counts plays)", () => {
    const facilityId = nextId("fac") as FacilityId;
    const courseId = nextId("crs") as CourseId;
    const designerId = nextId("dsg") as DesignerId;
    const courses: CompletionContext["courses"] = {
      [courseId]: { id: courseId, facilityId, verified: true, designers: [designerId] },
    };
    const ctx: AggregateContext = { courses, trails: {} };
    const plays: Play[] = [play(courseId, "2026-01-01"), play(courseId, "2026-02-01")];
    expect(maxCountBy("designer", ctx, plays, {})).toBe(1);
  });
});
