/**
 * `evaluateRuleExpr` (§4.1's third `RuleExpr` bullet: "an evaluator in
 * packages/rules") — direct evaluation tests, including §4.1's own R-14
 * worked example of money-mode polarity (line 640-641: "a badge-level
 * play at F makes `!played(F)` false, so the 'go play F' offer is not
 * issued to someone who has already played F").
 */
import { describe, expect, it } from "vitest";
import { mintId, type CourseId, type FacilityId, type RuleExpr, type TrailId } from "@golfraven/catalog";
import { evaluateRuleExpr, type RuleExprEvalContext } from "../src/rule-expr-eval.js";

describe("R-14: trailProgress(T) >= 0.5 && !played(F), money mode", () => {
  it("a badge-level (not money-qualifying) play at F makes !played(F) FALSE -> the offer is not issued", () => {
    const trailId = mintId("trl") as TrailId;
    const courseF = mintId("crs") as CourseId;
    const facilityId = mintId("fac") as FacilityId;
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
    // trailProgress(T) is driven by its OWN member (courseT), completed
    // in money mode; `!played(F)` is then tested in isolation against a
    // SEPARATE course F, where only a badge-level (not money-qualifying)
    // play exists — the negative occurrence (odd `not`) counts every
    // badge-level play, per §4.1 line 638-640, so this must still make
    // `!played(F)` false even though the play never meets the money bar.
    const courseT = mintId("crs", new Date(Date.now() + 1)) as CourseId;
    const ctx: RuleExprEvalContext = {
      courses: { [courseT]: { id: courseT, facilityId }, [courseF]: { id: courseF, facilityId } },
      trails: {
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
      },
      plays: [
        { courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: true }, // completes T in money mode
        { courseId: courseF, localDate: "2026-05-02", scoreBadge: 0.6, moneyQualifies: false }, // badge-level play at F
      ],
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
  });

  it("no play at all at F -> !played(F) is TRUE, and a complete trail issues the offer", () => {
    const trailId = mintId("trl") as TrailId;
    const courseF = mintId("crs") as CourseId;
    const courseT = mintId("crs", new Date(Date.now() + 1)) as CourseId;
    const facilityId = mintId("fac") as FacilityId;
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
      courses: { [courseT]: { id: courseT, facilityId }, [courseF]: { id: courseF, facilityId } },
      trails: {
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
      },
      plays: [{ courseId: courseT, localDate: "2026-05-01", scoreBadge: 1, moneyQualifies: true }],
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(true);
  });
});

describe("badge mode: R-01 played(courseId) >= 1", () => {
  it("evaluates true once ANY badge-level play exists at that course", () => {
    const courseId = mintId("crs") as CourseId;
    const facilityId = mintId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "played", courseId },
      right: { kind: "literal", value: 1 },
    };
    const ctx: RuleExprEvalContext = {
      courses: { [courseId]: { id: courseId, facilityId } },
      trails: {},
      plays: [{ courseId, localDate: "2026-01-01", scoreBadge: 0.5 }],
    };
    expect(evaluateRuleExpr(rule, ctx, "badge")).toBe(true);
    expect(evaluateRuleExpr(rule, { ...ctx, plays: [] }, "badge")).toBe(false);
  });
});
