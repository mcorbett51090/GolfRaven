/**
 * `evaluateRuleExpr` (§4.1's third `RuleExpr` bullet: "an evaluator in
 * packages/rules") — direct evaluation tests, including §4.1's own R-14
 * worked example of money-mode polarity (line 640-641: "a badge-level
 * play at F makes `!played(F)` false, so the 'go play F' offer is not
 * issued to someone who has already played F"), plus the gate-review
 * B2/N6/S2 fixtures.
 */
import { describe, expect, it } from "vitest";
import { type CourseId, type FacilityId, type RuleExpr, type TrailId } from "@golfraven/catalog";
import { evaluateRuleExpr, type RuleExprEvalContext } from "../src/rule-expr-eval.js";
import { nextId } from "./test-ids.js";

/** Re-gate item 1: `programmeStartsOn` is now required for any POSITIVE
 * money-mode aggregate occurrence. Fixtures below that aren't specifically
 * testing the B2 boundary itself use this "programme has always been
 * running" constant — well before any play date these fixtures use. */
const EARLY_PROGRAMME_START = "2020-01-01";

function trailContext(
  trailId: TrailId,
  courseT: CourseId,
  facilityId: FacilityId,
): RuleExprEvalContext["trails"] {
  return {
    [trailId]: [
      {
        version: 1,
        effectiveFrom: "2026-01-01",
        source: { url: "https://example.com/r", retrieved: "2026-01-01" },
        verifiedAt: "2026-01-01",
        completionUnit: "course",
        markerUnit: "facility",
        completionRule: { kind: "all" },
        markerRule: { kind: "all" },
        members: [{ unit: "course", courseId: courseT }],
      },
    ],
  };
}

describe("R-14: trailProgress(T) >= 0.5 && !played(F), money mode", () => {
  it("a badge-level (not money-qualifying) play at F makes !played(F) FALSE -> the offer is not issued", () => {
    const trailId = nextId("trl") as TrailId;
    const courseF = nextId("crs") as CourseId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "and",
      args: [
        {
          kind: "compare",
          op: ">=",
          left: { kind: "agg", name: "trailProgress", trailId },
          right: { kind: "literal", value: 0.5 },
        },
        { kind: "not", arg: { kind: "agg", name: "played", courseId: courseF } },
      ],
    };
    const ctx: RuleExprEvalContext = {
      courses: {
        [courseT]: { id: courseT, facilityId, verified: true },
        [courseF]: { id: courseF, facilityId, verified: true },
      },
      trails: trailContext(trailId, courseT, facilityId),
      plays: [
        { courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: true },
        { courseId: courseF, localDate: "2026-05-02", scoreBadge: 0.6, moneyQualifies: false },
      ],
      programmeStartsOn: EARLY_PROGRAMME_START,
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
  });

  it("S2: a negative occurrence ALSO counts a moneyQualifying play even when its own scoreBadge is below threshold", () => {
    const trailId = nextId("trl") as TrailId;
    const courseF = nextId("crs") as CourseId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "and",
      args: [
        {
          kind: "compare",
          op: ">=",
          left: { kind: "agg", name: "trailProgress", trailId },
          right: { kind: "literal", value: 0.5 },
        },
        { kind: "not", arg: { kind: "agg", name: "played", courseId: courseF } },
      ],
    };
    const ctx: RuleExprEvalContext = {
      courses: {
        [courseT]: { id: courseT, facilityId, verified: true },
        [courseF]: { id: courseF, facilityId, verified: true },
      },
      trails: trailContext(trailId, courseT, facilityId),
      plays: [
        { courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: true },
        // scoreBadge below the 0.50 default, but moneyQualifies is true —
        // S2 says the negative-occurrence play set is "scoreBadge >=
        // threshold OR moneyQualifies", so this still counts.
        { courseId: courseF, localDate: "2026-05-02", scoreBadge: 0.1, moneyQualifies: true },
      ],
      programmeStartsOn: EARLY_PROGRAMME_START,
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
  });

  it("no play at all at F -> !played(F) is TRUE, and a complete trail issues the offer", () => {
    const trailId = nextId("trl") as TrailId;
    const courseF = nextId("crs") as CourseId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "and",
      args: [
        {
          kind: "compare",
          op: ">=",
          left: { kind: "agg", name: "trailProgress", trailId },
          right: { kind: "literal", value: 0.5 },
        },
        { kind: "not", arg: { kind: "agg", name: "played", courseId: courseF } },
      ],
    };
    const ctx: RuleExprEvalContext = {
      courses: {
        [courseT]: { id: courseT, facilityId, verified: true },
        [courseF]: { id: courseF, facilityId, verified: true },
      },
      trails: trailContext(trailId, courseT, facilityId),
      plays: [{ courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: true }],
      programmeStartsOn: EARLY_PROGRAMME_START,
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(true);
  });
});

describe("B2: programmeStartsOn applies only to POSITIVE occurrences", () => {
  it("a 2019 money-qualifying play at F does not satisfy a POSITIVE trailProgress leg once programmeStartsOn is set", () => {
    const trailId = nextId("trl") as TrailId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "trailProgress", trailId },
      right: { kind: "literal", value: 0.5 },
    };
    const ctx: RuleExprEvalContext = {
      courses: { [courseT]: { id: courseT, facilityId, verified: true } },
      trails: trailContext(trailId, courseT, facilityId),
      plays: [{ courseId: courseT, localDate: "2019-01-01", scoreBadge: 1, moneyQualifies: true }],
      programmeStartsOn: "2026-01-01",
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
    // Badge mode never consults programmeStartsOn at all.
    expect(evaluateRuleExpr(rule, ctx, "badge")).toBe(true);
  });

  it("a NEGATIVE occurrence (!played(F)) still sees an EARLIER badge-level play at F, ignoring programmeStartsOn", () => {
    const trailId = nextId("trl") as TrailId;
    const courseF = nextId("crs") as CourseId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "and",
      args: [
        {
          kind: "compare",
          op: ">=",
          left: { kind: "agg", name: "trailProgress", trailId },
          right: { kind: "literal", value: 0.5 },
        },
        { kind: "not", arg: { kind: "agg", name: "played", courseId: courseF } },
      ],
    };
    const ctx: RuleExprEvalContext = {
      courses: {
        [courseT]: { id: courseT, facilityId, verified: true },
        [courseF]: { id: courseF, facilityId, verified: true },
      },
      trails: trailContext(trailId, courseT, facilityId),
      plays: [
        // trailProgress leg satisfied AFTER programmeStartsOn.
        { courseId: courseT, localDate: "2026-06-01", scoreBadge: 1, moneyQualifies: true },
        // The F play predates programmeStartsOn — a NEGATIVE occurrence
        // must still see it (it is never backdated OUT of view), so the
        // offer is correctly NOT issued.
        { courseId: courseF, localDate: "2019-01-01", scoreBadge: 1, moneyQualifies: false },
      ],
      programmeStartsOn: "2026-01-01",
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
  });
});

describe("N6: the A2-01 user-pick guard is applied inside the evaluator", () => {
  it("two user picks at the same facility/date collapse to one — uniqueCourses sees only the later pick", () => {
    const courseA = nextId("crs") as CourseId;
    const courseB = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const ctx: RuleExprEvalContext = {
      courses: {
        [courseA]: { id: courseA, facilityId, verified: true },
        [courseB]: { id: courseB, facilityId, verified: true },
      },
      trails: {},
      plays: [
        { courseId: courseA, localDate: "2026-01-01", scoreBadge: 0.5, courseDisambiguatedBy: "user" },
        { courseId: courseB, localDate: "2026-01-01", scoreBadge: 0.5, courseDisambiguatedBy: "user" },
      ],
    };
    const rule: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "uniqueCourses" },
      right: { kind: "literal", value: 2 },
    };
    // Without the guard applied, both picks would count (uniqueCourses=2,
    // rule true) — WITH it, only the later pick survives (uniqueCourses=1).
    expect(evaluateRuleExpr(rule, ctx, "badge")).toBe(false);
  });
});

describe("S7 mutation-kill: a bare BOOLEAN aggregate's own occurrence polarity", () => {
  it("a bare trailComplete(T) at money mode's top level is a POSITIVE occurrence — uses money-qualifying plays only", () => {
    const trailId = nextId("trl") as TrailId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = { kind: "agg", name: "trailComplete", trailId };
    const ctx: RuleExprEvalContext = {
      courses: { [courseT]: { id: courseT, facilityId, verified: true } },
      trails: trailContext(trailId, courseT, facilityId),
      // Badge-level only, NOT money-qualifying.
      plays: [{ courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: false }],
      programmeStartsOn: EARLY_PROGRAMME_START,
    };
    // Money mode: a positive occurrence needs a money-qualifying play —
    // there isn't one, so trailComplete is false.
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
    // Badge mode: the same badge-level play is enough.
    expect(evaluateRuleExpr(rule, ctx, "badge")).toBe(true);
  });

  it("!trailComplete(T) (a NEGATIVE occurrence via not) accepts a badge-level-only play in money mode", () => {
    const trailId = nextId("trl") as TrailId;
    const courseT = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = { kind: "not", arg: { kind: "agg", name: "trailComplete", trailId } };
    const ctx: RuleExprEvalContext = {
      courses: { [courseT]: { id: courseT, facilityId, verified: true } },
      trails: trailContext(trailId, courseT, facilityId),
      plays: [{ courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: false }],
    };
    // Negative occurrence: badge-level plays count, so trailComplete is
    // TRUE here, and !trailComplete is FALSE.
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
  });
});

describe("S7 mutation-kill: an aggregate on the RIGHT side of a comparator gets the OPPOSITE baseline polarity", () => {
  it("0 >= played(F) (right-side aggregate, NEGATIVE at baseline for '>=') still counts a badge-level-only play", () => {
    const courseF = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    // The aggregate on the right of `>=` is NEGATIVE at baseline (a
    // larger `played(F)` can only HURT "0 >= played(F)"). A negative
    // occurrence counts every badge-level play (S2), so a badge-level-
    // only play must still make `played(F)` resolve to 1, and
    // "0 >= 1" is false. If the right side wrongly inherited the LEFT
    // side's baseline (`>=` => positive), it would restrict to
    // money-qualifying plays only, `played(F)` would resolve to 0, and
    // "0 >= 0" would wrongly come out true.
    const rule: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: { kind: "literal", value: 0 },
      right: { kind: "agg", name: "played", courseId: courseF },
    };
    const ctx: RuleExprEvalContext = {
      courses: { [courseF]: { id: courseF, facilityId, verified: true } },
      trails: {},
      plays: [{ courseId: courseF, localDate: "2026-01-01", scoreBadge: 1, moneyQualifies: false }],
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
  });
});

describe("badge mode: R-01 played(courseId) >= 1", () => {
  it("evaluates true once ANY badge-level play exists at that course", () => {
    const courseId = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "played", courseId },
      right: { kind: "literal", value: 1 },
    };
    const ctx: RuleExprEvalContext = {
      courses: { [courseId]: { id: courseId, facilityId, verified: true } },
      trails: {},
      plays: [{ courseId, localDate: "2026-01-01", scoreBadge: 0.5 }],
    };
    expect(evaluateRuleExpr(rule, ctx, "badge")).toBe(true);
    expect(evaluateRuleExpr(rule, { ...ctx, plays: [] }, "badge")).toBe(false);
  });
});
