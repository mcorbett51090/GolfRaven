/**
 * A2-05's must-fail fixture (§4.5 lines 1034-1041, §10 P3 AT(4)): "an
 * operator offer with `minConfidence 0.5` or `score_badge >= 0.5` is
 * rejected at save and at approval, and a row forced into the DB by SQL
 * still issues nothing on a 0.50 play."
 */
import { describe, expect, it } from "vitest";
import type { CourseId, FacilityId, RuleExpr, TrailId } from "@golfraven/catalog";
import { validateOfferEligibility } from "../src/offer-eligibility.js";
import { evaluateRuleExpr, type RuleExprEvalContext } from "../src/rule-expr-eval.js";
import { nextId } from "./test-ids.js";

describe("validateOfferEligibility (A2-05)", () => {
  it("rejects a raw eligibility value carrying a bare minConfidence field — no such RuleExpr node exists", () => {
    // The shape an operator UI (or a hand-crafted SQL row) might try:
    // smuggling a confidence threshold in directly, rather than a real
    // aggregate comparison.
    const malformed = { kind: "agg", name: "minConfidence", value: 0.5 };
    const result = validateOfferEligibility(malformed);
    expect(result.valid).toBe(false);
  });

  it("rejects a raw eligibility value carrying score_badge >= 0.5 — the offer grammar has no score_badge aggregate", () => {
    const malformed = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "score_badge" },
      right: { kind: "literal", value: 0.5 },
    };
    const result = validateOfferEligibility(malformed);
    expect(result.valid).toBe(false);
  });

  it("rejects an otherwise schema-valid money-mode rule that fails checkRuleExpr (e.g. == on an aggregate)", () => {
    const trailId = nextId("trl") as TrailId;
    const rule = {
      kind: "compare",
      op: "==",
      left: { kind: "agg", name: "trailProgress", trailId },
      right: { kind: "literal", value: 1 },
    };
    const result = validateOfferEligibility(rule);
    expect(result.valid).toBe(false);
  });

  it("accepts a genuine money-mode-clean eligibility RuleExpr", () => {
    const courseId = nextId("crs") as CourseId;
    const rule = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "played", courseId },
      right: { kind: "literal", value: 1 },
    };
    const result = validateOfferEligibility(rule);
    expect(result.valid).toBe(true);
  });

  it("issuance: whatever a forced-bad row might contain, RuleExpr has no operand that could lower the money bar — a 0.50 badge-only play never issues", () => {
    // Since `minConfidence`/`score_badge` are not real RuleExpr node
    // shapes at all (both fixtures above), there is no VALID RuleExpr a
    // forced SQL row could hold that would encode "issue at score_badge >=
    // 0.5". The closest a row COULD validly encode is an ordinary
    // `played(...)` aggregate — and the existing (unmodified) evaluator
    // already restricts a positive money-mode occurrence to
    // money-qualifying plays only, regardless of the play's badge score.
    const courseId = nextId("crs") as CourseId;
    const facilityId = nextId("fac") as FacilityId;
    const rule: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "played", courseId },
      right: { kind: "literal", value: 1 },
    };
    const ctx: RuleExprEvalContext = {
      trails: {},
      courses: { [courseId]: { id: courseId, facilityId, verified: true } },
      programmeStartsOn: "2020-01-01",
      plays: [
        // Badge-level only (0.50) — NOT money-qualifying.
        { courseId, localDate: "2026-06-01", scoreBadge: 0.5, moneyQualifies: false },
      ],
    };
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(false);
    // The same play, now money-qualifying, DOES satisfy the rule — proving
    // the money-mode gate is real (not just always-false).
    ctx.plays[0]!.moneyQualifies = true;
    expect(evaluateRuleExpr(rule, ctx, "money")).toBe(true);
  });
});
