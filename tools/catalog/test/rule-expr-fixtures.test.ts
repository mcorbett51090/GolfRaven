/**
 * P1 AT(1), the `RuleExpr` part: "R-01–R-14 must pass and R-F1–R-F7 must
 * fail, each asserting its specific error code and path" (task scope;
 * build plan §8.1, §10 P1 AT(1)). Every rule here is written out exactly
 * as §8.1's table gives it (line references in each `it`).
 *
 * **Where R-14/R-F6/R-F7 live.** R-14 is explicitly the §9.5 OFFER example
 * (not an `AchievementDef` — an offer's `RuleExpr` lives on the DB-side
 * offer instance, never in `data/achievements/*.json`, per
 * `packages/catalog/src/schema.ts`'s module doc), and R-F6/R-F7 are both
 * specifically about the `money`-mode offer grammar. All three are tested
 * here directly against `RuleExprSchema` + `checkRuleExpr`, not through a
 * full `CatalogBundle` — there is no bundle-shaped place for a bare offer
 * `RuleExpr` to live. R-01–R-13 (every real `AchievementDef`, `badge`
 * mode) are ALSO exercised through the full `verifyCatalog` pipeline
 * against `data/achievements/*.json` — see `achievements-data.test.ts`.
 */
import { describe, expect, it } from "vitest";
import {
  RuleExprSchema,
  mintId,
  type CourseId,
  type DesignerId,
  type RuleExpr,
  type TrailId,
} from "@golfraven/catalog";
import { checkRuleExpr } from "@golfraven/rules";

const TRL = mintId("trl") as TrailId;
const CRS = mintId("crs") as CourseId;
const CRS_F = mintId("crs") as CourseId;
const DSG = mintId("dsg") as DesignerId;

interface Verdict {
  ok: boolean;
  codes: string[];
}

function verdict(raw: unknown, mode: "badge" | "money"): Verdict {
  const parsed = RuleExprSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, codes: parsed.error.issues.map((i) => i.code) };
  }
  const checkerIssues = checkRuleExpr(parsed.data, { mode });
  return { ok: checkerIssues.length === 0, codes: checkerIssues.map((i) => i.code) };
}

function expectPass(raw: RuleExpr, mode: "badge" | "money" = "badge") {
  const v = verdict(raw, mode);
  if (!v.ok) {
    // eslint-disable-next-line no-console
    console.error("unexpected fail:", JSON.stringify(raw), v.codes);
  }
  expect(v.ok).toBe(true);
}

/** N3 (gate review): every R-F fixture asserts BOTH the code and the
 * path — `code` is the raw Zod issue code (this suite operates directly
 * against `RuleExprSchema`/`checkRuleExpr`, not through `verify-catalog`'s
 * `SCHEMA_INVALID` wrapping). */
function expectFailSchema(raw: unknown, path: string, code: string) {
  const parsed = RuleExprSchema.safeParse(raw);
  expect(parsed.success).toBe(false);
  if (!parsed.success) {
    expect(
      parsed.error.issues.some((i) => i.path.join(".") === path && i.code === code),
    ).toBe(true);
  }
}

describe("AT(1) must-pass fixtures R-01–R-14 (§8.1)", () => {
  it("R-01: played(courseId) >= 1 — \"First tee at <course>\" (line 1892)", () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "played", courseId: CRS },
      right: { kind: "literal", value: 1 },
    });
  });

  it("R-02: trailProgress(trailId) >= 0.25/0.5/0.75 (line 1893)", () => {
    for (const threshold of [0.25, 0.5, 0.75]) {
      expectPass({
        kind: "compare",
        op: ">=",
        left: { kind: "agg", name: "trailProgress", trailId: TRL },
        right: { kind: "literal", value: threshold },
      });
    }
  });

  it("R-03: trailComplete(trailId) — \"Trail Complete (vN)\" (line 1894)", () => {
    expectPass({ kind: "agg", name: "trailComplete", trailId: TRL });
  });

  it("R-04: trailCompleteWithin(trailId, 180) (line 1895)", () => {
    expectPass({ kind: "agg", name: "trailCompleteWithin", trailId: TRL, days: 180 });
  });

  it("R-05: inOrder(trailId) — \"In order\" (line 1896)", () => {
    expectPass({ kind: "agg", name: "inOrder", trailId: TRL });
  });

  it("R-06: uniqueCourses >= 10/25/50/100 (line 1897)", () => {
    for (const threshold of [10, 25, 50, 100]) {
      expectPass({
        kind: "compare",
        op: ">=",
        left: { kind: "agg", name: "uniqueCourses" },
        right: { kind: "literal", value: threshold },
      });
    }
  });

  it("R-07: maxCountBy(\"designer\") >= 5 (line 1898)", () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "maxCountBy", field: "designer" },
      right: { kind: "literal", value: 5 },
    });
  });

  it("R-08: countWhere(\"designer\", \"dsg_…\") >= 5 (line 1899)", () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "countWhere", field: "designer", value: DSG },
      right: { kind: "literal", value: 5 },
    });
  });

  it('R-09: countDistinct("region", { in: [4 Atlantic codes] }) >= 4 (line 1900)', () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: {
        kind: "agg",
        name: "countDistinct",
        field: "region",
        where: { in: ["CA-NB", "CA-NS", "CA-PE", "CA-NL"] },
      },
      right: { kind: "literal", value: 4 },
    });
  });

  it('R-10: countDistinct("region") >= 10 (line 1901)', () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "countDistinct", field: "region" },
      right: { kind: "literal", value: 10 },
    });
  });

  it('R-11: countDistinct("country") >= 2 (line 1902)', () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "countDistinct", field: "country" },
      right: { kind: "literal", value: 2 },
    });
  });

  it("R-12: markerSetComplete(trailId) — \"Full set\" (P5, line 1903)", () => {
    expectPass({ kind: "agg", name: "markerSetComplete", trailId: TRL });
  });

  it("R-13: monthlyStreak >= 3 (P9, line 1904)", () => {
    expectPass({
      kind: "compare",
      op: ">=",
      left: { kind: "agg", name: "monthlyStreak" },
      right: { kind: "literal", value: 3 },
    });
  });

  it("R-14: trailProgress(T) >= 0.5 && !played(F) — the §9.5 offer, money mode (line 1905)", () => {
    const rule: RuleExpr = {
      kind: "and",
      args: [
        {
          kind: "compare",
          op: ">=",
          left: { kind: "agg", name: "trailProgress", trailId: TRL },
          right: { kind: "literal", value: 0.5 },
        },
        { kind: "not", arg: { kind: "agg", name: "played", courseId: CRS_F } },
      ],
    };
    expectPass(rule, "money");
    // Also fine in badge mode (nothing about this rule is money-specific
    // syntactically — only the OFFER's evaluation is money-mode).
    expectPass(rule, "badge");
  });
});

describe("AT(1) must-fail fixtures R-F1–R-F7 (§8.1 lines 1909-1917) — N3: every fixture asserts BOTH code and path", () => {
  it("R-F1: an unknown aggregate, e.g. holesInOne() — not on the closed list", () => {
    expectFailSchema({ kind: "agg", name: "holesInOne" }, "name", "invalid_union");
  });

  it('R-F2: countDistinct("par") — "par" is not in the field enum', () => {
    // N1 (gate review): a bare numeric aggregate is legal ONLY directly
    // under `not` — wrapped here so the fixture reaches the field-enum
    // check at all, rather than failing one level higher.
    expectFailSchema(
      { kind: "not", arg: { kind: "agg", name: "countDistinct", field: "par" } },
      "arg.field",
      "invalid_value",
    );
  });

  it('R-F3: countDistinct("region", { in: ["CA-XX"] }) — unknown region value', () => {
    expectFailSchema(
      {
        kind: "not",
        arg: { kind: "agg", name: "countDistinct", field: "region", where: { in: ["CA-XX"] } },
      },
      "arg.where.in.0",
      "custom",
    );
  });

  it("R-F4: countDistinct(\"region\", { in: [4 codes] }) >= 5 — unsatisfiable", () => {
    const raw: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: {
        kind: "agg",
        name: "countDistinct",
        field: "region",
        where: { in: ["CA-NB", "CA-NS", "CA-PE", "CA-NL"] },
      },
      right: { kind: "literal", value: 5 },
    };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const issues = checkRuleExpr(parsed.data, { mode: "badge" });
      expect(issues.map((i) => i.code)).toContain("RULE_UNSATISFIABLE");
      expect(issues.some((i) => i.code === "RULE_UNSATISFIABLE" && i.path === "rule")).toBe(true);
    }
  });

  it('R-F5: countWhere("designer", "Pete Dye") — not a dsg_ id', () => {
    expectFailSchema(
      { kind: "not", arg: { kind: "agg", name: "countWhere", field: "designer", value: "Pete Dye" } },
      "arg.value",
      "custom",
    );
  });

  it("R-F6: an offer with played(\"crs_F\") == 0 — == has no polarity in money mode", () => {
    const raw: RuleExpr = {
      kind: "compare",
      op: "==",
      left: { kind: "agg", name: "played", courseId: CRS_F },
      right: { kind: "literal", value: 0 },
    };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true); // legal syntax — badge mode doesn't care
    if (parsed.success) {
      // Badge mode: polarity makes no difference — no issue.
      expect(checkRuleExpr(parsed.data, { mode: "badge" })).toEqual([]);
      // Money mode: rejected, at the compare node's own path.
      const moneyIssues = checkRuleExpr(parsed.data, { mode: "money" });
      expect(
        moneyIssues.some((i) => i.code === "RULE_MONEY_MODE_NO_POLARITY" && i.path === "rule"),
      ).toBe(true);
    }
  });

  it("R-F7: a confidence or score operand — no such operand in the offer grammar (A2-05)", () => {
    // minConfidence 0.5
    expectFailSchema({ kind: "agg", name: "minConfidence", value: 0.5 }, "name", "invalid_union");
    // score_badge >= 0.5
    expectFailSchema(
      { kind: "compare", op: ">=", left: { kind: "agg", name: "score_badge" }, right: { kind: "literal", value: 0.5 } },
      "left",
      "invalid_union",
    );
  });
});

describe("gate-review nits N2/N4/N5", () => {
  it("N2: not(unsatisfiable comparison) is satisfiable (vacuously true), never RULE_UNSATISFIABLE", () => {
    const raw: RuleExpr = {
      kind: "not",
      arg: {
        kind: "compare",
        op: ">=",
        left: {
          kind: "agg",
          name: "countDistinct",
          field: "region",
          where: { in: ["CA-NB", "CA-NS", "CA-PE", "CA-NL"] },
        },
        right: { kind: "literal", value: 5 },
      },
    };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(checkRuleExpr(parsed.data, { mode: "badge" })).toEqual([]);
    }
  });

  it("N2: RULE_MONEY_MODE_NO_POLARITY never fires on a literal-only comparison", () => {
    const raw: RuleExpr = { kind: "compare", op: "==", left: { kind: "literal", value: 1 }, right: { kind: "literal", value: 1 } };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(checkRuleExpr(parsed.data, { mode: "money" })).toEqual([]);
    }
  });

  it("N4: inOrder is rejected in a money-mode rule", () => {
    const raw: RuleExpr = { kind: "agg", name: "inOrder", trailId: TRL };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      expect(checkRuleExpr(parsed.data, { mode: "badge" })).toEqual([]);
      const moneyIssues = checkRuleExpr(parsed.data, { mode: "money" });
      expect(
        moneyIssues.some((i) => i.code === "RULE_INORDER_NOT_ALLOWED_IN_MONEY_MODE" && i.path === "rule"),
      ).toBe(true);
    }
  });

  it("N4: inOrder nested inside and()/not() is also rejected in money mode", () => {
    const raw: RuleExpr = {
      kind: "and",
      args: [
        { kind: "agg", name: "inOrder", trailId: TRL },
        { kind: "not", arg: { kind: "agg", name: "played", courseId: CRS } },
      ],
    };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const moneyIssues = checkRuleExpr(parsed.data, { mode: "money" });
      expect(moneyIssues.map((i) => i.code)).toContain("RULE_INORDER_NOT_ALLOWED_IN_MONEY_MODE");
    }
  });
});

describe("S7 mutation-kill: checker bound regressions (S5)", () => {
  it("countDistinct(\"region\", { in: [a code repeated 5 times] }) >= 2 is unsatisfiable — the bound is the DEDUPED count (1), not the raw array length (5)", () => {
    const raw: RuleExpr = {
      kind: "compare",
      op: ">=",
      left: {
        kind: "agg",
        name: "countDistinct",
        field: "region",
        where: { in: ["CA-NB", "CA-NB", "CA-NB", "CA-NB", "CA-NB"] },
      },
      right: { kind: "literal", value: 2 },
    };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const issues = checkRuleExpr(parsed.data, { mode: "badge" });
      expect(issues.map((i) => i.code)).toContain("RULE_UNSATISFIABLE");
    }
  });

  it("trailProgress(T) > 1 is unsatisfiable — trailProgress is bounded to [0, 1]", () => {
    const raw: RuleExpr = {
      kind: "compare",
      op: ">",
      left: { kind: "agg", name: "trailProgress", trailId: TRL },
      right: { kind: "literal", value: 1 },
    };
    const parsed = RuleExprSchema.safeParse(raw);
    expect(parsed.success).toBe(true);
    if (parsed.success) {
      const issues = checkRuleExpr(parsed.data, { mode: "badge" });
      expect(issues.map((i) => i.code)).toContain("RULE_UNSATISFIABLE");
    }
  });
});
