/**
 * Fifth gate, M3: "validateOfferEligibility must reject any rule where
 * evaluateRuleExpr(rule, emptyCtx, 'money') === true, unless
 * {allowUnconditional:true} is passed explicitly. Test every tautology
 * probe... Also cap depth (e.g. 64) and node count, and return invalid
 * instead of throwing a RangeError."
 */
import { describe, expect, it } from "vitest";
import { validateOfferEligibility } from "../src/offer-eligibility.js";

const crs = "crs_01J00000000000000000000000";
const played = { kind: "agg", name: "played", courseId: crs };

describe("M3: every named tautology probe is rejected by default", () => {
  const cases: [string, unknown][] = [
    ["played >= 0", { kind: "compare", op: ">=", left: played, right: { kind: "literal", value: 0 } }],
    ["played > -1", { kind: "compare", op: ">", left: played, right: { kind: "literal", value: -1 } }],
    ["0 <= played (reversed)", { kind: "compare", op: "<=", left: { kind: "literal", value: 0 }, right: played }],
    ["1 >= 0 (literals only)", { kind: "compare", op: ">=", left: { kind: "literal", value: 1 }, right: { kind: "literal", value: 0 } }],
    ["played < 1", { kind: "compare", op: "<", left: played, right: { kind: "literal", value: 1 } }],
    ["not(played)", { kind: "not", arg: played }],
  ];

  for (const [label, rule] of cases) {
    it(`rejects: ${label}`, () => {
      const result = validateOfferEligibility(rule);
      expect(result.valid).toBe(false);
      if (!result.valid) {
        expect(result.issues.some((i) => i.code === "RULE_UNCONDITIONAL_MONEY")).toBe(true);
      }
    });
  }

  it("a GENUINELY conditional rule (played >= 1) is still valid", () => {
    const rule = { kind: "compare", op: ">=", left: played, right: { kind: "literal", value: 1 } };
    expect(validateOfferEligibility(rule).valid).toBe(true);
  });
});

describe("M3: {allowUnconditional: true} opts back into an unconditional rule", () => {
  it("played >= 0 is accepted when the caller explicitly opts in", () => {
    const rule = { kind: "compare", op: ">=", left: played, right: { kind: "literal", value: 0 } };
    expect(validateOfferEligibility(rule, { allowUnconditional: true }).valid).toBe(true);
  });

  it("the default (no options) still rejects the SAME rule", () => {
    const rule = { kind: "compare", op: ">=", left: played, right: { kind: "literal", value: 0 } };
    expect(validateOfferEligibility(rule).valid).toBe(false);
  });
});

describe("M3: depth is capped (e.g. 64) — a deeply nested rule returns invalid, never throws a RangeError", () => {
  function deepNot(depth: number) {
    let r: unknown = { kind: "compare", op: ">=", left: played, right: { kind: "literal", value: 1 } };
    for (let i = 0; i < depth; i += 1) r = { kind: "not", arg: r };
    return r;
  }

  it("depth 1000 returns invalid without throwing", () => {
    expect(() => {
      const result = validateOfferEligibility(deepNot(1000));
      expect(result.valid).toBe(false);
    }).not.toThrow();
  });

  it("depth 5000 returns invalid without throwing", () => {
    expect(() => {
      const result = validateOfferEligibility(deepNot(5000));
      expect(result.valid).toBe(false);
    }).not.toThrow();
  });

  it("depth 50000 returns invalid without throwing (the probe's own adversarial case — would RangeError a naive recursive walk)", () => {
    expect(() => {
      const result = validateOfferEligibility(deepNot(50000));
      expect(result.valid).toBe(false);
    }).not.toThrow();
  });

  it("a shallow, legitimate rule (depth well under 64) is unaffected by the depth cap", () => {
    const rule = { kind: "not", arg: { kind: "not", arg: played } };
    // Not a tautology check concern here — `not(not(played))` reads as
    // `played` truthiness, itself satisfiable and non-tautological under
    // the empty-play probe (0 plays -> played=0 -> falsy -> not(not(0)) is
    // false against the empty ctx) — the point is only that it's not
    // rejected on STRUCTURAL grounds.
    expect(() => validateOfferEligibility(rule)).not.toThrow();
  });
});

describe("M3: node count is capped independently of depth — a very WIDE tree returns invalid, never hangs", () => {
  it("200,000 or-args returns invalid promptly, without throwing", () => {
    const wide = {
      kind: "or",
      args: Array.from({ length: 200_000 }, () => ({
        kind: "compare",
        op: ">=",
        left: played,
        right: { kind: "literal", value: 1 },
      })),
    };
    const t0 = Date.now();
    let result: ReturnType<typeof validateOfferEligibility> | undefined;
    expect(() => {
      result = validateOfferEligibility(wide);
    }).not.toThrow();
    const elapsedMs = Date.now() - t0;
    expect(result?.valid).toBe(false);
    // A generous ceiling — the point of the cap is to bound this well
    // under a second, not to pin an exact number.
    expect(elapsedMs).toBeLessThan(2000);
  });
});
