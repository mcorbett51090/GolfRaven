import { describe, expect, it } from "vitest";
import {
  computeK1Verdict,
  K1_CONSEQUENCE_EARLY_MISS,
  K1_CONSEQUENCE_OPERATOR_FULL_MISS,
  K1_CONSEQUENCE_SPONSOR_MISS,
  K1_CONSEQUENCE_PASS_NOTE,
} from "../src/k1-verdict.js";
import type { K1Row, K1RowType } from "../src/k1-log.js";

function row(target: string, type: K1RowType, overrides: Partial<K1Row> = {}): K1Row {
  return {
    target,
    type,
    contactedDate: null,
    callAcceptedDate: null,
    loiDate: null,
    feeWillingness: null,
    okSwapReplaces: null,
    sponsorDecisionMakerNamed: null,
    sponsorBudgetStated: null,
    sponsorAttributionInterest: null,
    notes: "",
    ...overrides,
  };
}

function baseOperatorRows(overrides: Record<string, Partial<K1Row>> = {}): K1Row[] {
  const names: [string, K1RowType][] = [
    ["Tennessee Golf Trail", "Operator (slate)"],
    ["Vancouver Island Golf Trail", "Operator (slate)"],
    ["Robert Trent Jones Golf Trail", "Operator (slate)"],
    ["Oklahoma Golf Trail", "Operator (reserve)"],
    ["Hammock Coast Golf Trail", "Operator (co-op reserve)"],
    ["Canadian Rockies Golf Consortium", "Operator (co-op reserve)"],
  ];
  return names.map(([n, t]) => row(n, t, overrides[n] ?? {}));
}

function qualifiedSponsor(target = "Alabama Tourism Department"): K1Row {
  return row(target, "Sponsor", {
    sponsorDecisionMakerNamed: "Y",
    sponsorBudgetStated: "Y",
    sponsorAttributionInterest: "Y",
  });
}

describe("computeK1Verdict: early read (decision 0001 Addendum D R1, cutoff 2026-10-19)", () => {
  it("0 acceptances -> early miss", () => {
    const result = computeK1Verdict(baseOperatorRows());
    expect(result.earlyRead.count).toBe(0);
    expect(result.earlyRead.pass).toBe(false);
    expect(result.consequenceBranch).toBe("early-miss");
    expect(result.consequenceText).toBe(K1_CONSEQUENCE_EARLY_MISS);
  });

  it("1 acceptance -> still early miss (bar is >= 2)", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-10" },
      }),
    );
    expect(result.earlyRead.count).toBe(1);
    expect(result.earlyRead.pass).toBe(false);
    expect(result.consequenceBranch).toBe("early-miss");
  });

  it("2 acceptances -> early pass", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-10" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-15" },
      }),
    );
    expect(result.earlyRead.count).toBe(2);
    expect(result.earlyRead.pass).toBe(true);
    // No LOIs logged -> full gate operators miss -> that's the reported branch.
    expect(result.consequenceBranch).toBe("operator-full-miss");
    expect(result.consequenceText).toBe(K1_CONSEQUENCE_OPERATOR_FULL_MISS);
  });

  it("5 acceptances -> early pass with count 5", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-07" },
        "Robert Trent Jones Golf Trail": { callAcceptedDate: "2026-10-08" },
        "Hammock Coast Golf Trail": { callAcceptedDate: "2026-10-09" },
        "Canadian Rockies Golf Consortium": { callAcceptedDate: "2026-10-10" },
      }),
    );
    expect(result.earlyRead.count).toBe(5);
    expect(result.earlyRead.pass).toBe(true);
  });

  it("a late acceptance (after 2026-10-19) does not count, and is reported as late", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-10" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-20" }, // late
      }),
    );
    expect(result.earlyRead.count).toBe(1);
    expect(result.earlyRead.pass).toBe(false);
    expect(result.earlyRead.late).toEqual([{ target: "Vancouver Island Golf Trail", date: "2026-10-20" }]);
  });

  it("a 6th contact (Oklahoma) does not count when the swap is not activated", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-07" },
        "Oklahoma Golf Trail": { callAcceptedDate: "2026-10-08" }, // OK contacted but swap NOT activated
      }),
    );
    expect(result.effectiveFive).not.toContain("Oklahoma Golf Trail");
    expect(result.earlyRead.count).toBe(2); // TN + VI only, OK ignored
    expect(result.okSwap.activated).toBe(false);
    expect(result.warnings.some((w) => w.includes("Oklahoma Golf Trail"))).toBe(true);
  });
});

describe("computeK1Verdict: Oklahoma Golf Trail swap activation (K1.md METHOD step 1)", () => {
  it("when activated, OK replaces the named slate trail — never a 6th", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        // TN is dropped and would otherwise pass, but must be EXCLUDED once replaced.
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06" },
        "Oklahoma Golf Trail": { callAcceptedDate: "2026-10-07", okSwapReplaces: "Tennessee Golf Trail" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-08" },
      }),
    );
    expect(result.okSwap).toEqual({ activated: true, replaces: "Tennessee Golf Trail" });
    expect(result.effectiveFive).toContain("Oklahoma Golf Trail");
    expect(result.effectiveFive).not.toContain("Tennessee Golf Trail");
    expect(result.effectiveFive).toHaveLength(5);
    // OK + VI accepted -> 2, TN's own acceptance is excluded despite being present in the data.
    expect(result.earlyRead.count).toBe(2);
    expect(result.earlyRead.pass).toBe(true);
  });

  it("when NOT activated, OK is excluded and the base 5 (TN/VI/RTJ/Hammock/Canadian Rockies) is used", () => {
    const result = computeK1Verdict(baseOperatorRows());
    expect(result.okSwap.activated).toBe(false);
    expect(result.effectiveFive).toEqual([
      "Tennessee Golf Trail",
      "Vancouver Island Golf Trail",
      "Robert Trent Jones Golf Trail",
      "Hammock Coast Golf Trail",
      "Canadian Rockies Golf Consortium",
    ]);
  });
});

describe("computeK1Verdict: full gate — operators (decision 0001 Addendum C, cutoff 2026-11-30)", () => {
  it("an LOI without recorded fee willingness does not count", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06", loiDate: "2026-11-10" }, // no feeWillingness
        "Vancouver Island Golf Trail": {
          callAcceptedDate: "2026-10-07",
          loiDate: "2026-11-10",
          feeWillingness: "Y",
        },
      }),
    );
    expect(result.fullGate.operators.count).toBe(1);
    expect(result.fullGate.operators.pass).toBe(false);
    expect(result.fullGate.operators.loiWithoutFee).toEqual([
      { target: "Tennessee Golf Trail", date: "2026-11-10" },
    ]);
  });

  it("2 qualifying LOIs (fee willingness Y, on or before 2026-11-30) pass the operator full gate", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06", loiDate: "2026-11-20", feeWillingness: "Y" },
        "Vancouver Island Golf Trail": {
          callAcceptedDate: "2026-10-07",
          loiDate: "2026-11-30", // boundary: exactly the cutoff, still counts
          feeWillingness: "Y",
        },
      }),
    );
    expect(result.fullGate.operators.count).toBe(2);
    expect(result.fullGate.operators.pass).toBe(true);
  });

  it("an LOI dated after the full-gate cutoff (2026-12-01) does not count", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { loiDate: "2026-12-01", feeWillingness: "Y" },
      }),
    );
    expect(result.fullGate.operators.count).toBe(0);
    expect(result.fullGate.operators.late).toEqual([{ target: "Tennessee Golf Trail", date: "2026-12-01" }]);
  });
});

describe("computeK1Verdict: full gate — sponsors (all 3 qualifiers)", () => {
  it("a sponsor missing one qualifier does not count", () => {
    const rows = [
      ...baseOperatorRows(),
      row("Alabama Tourism Department", "Sponsor", {
        sponsorDecisionMakerNamed: "Y",
        sponsorBudgetStated: "Y",
        // sponsorAttributionInterest missing
      }),
    ];
    const result = computeK1Verdict(rows);
    expect(result.fullGate.sponsors.count).toBe(0);
    expect(result.fullGate.sponsors.pass).toBe(false);
    expect(result.fullGate.sponsors.partial).toEqual([
      {
        target: "Alabama Tourism Department",
        missing: ["interest in special-marker attribution"],
      },
    ]);
  });

  it("a sponsor row with all 3 qualifiers recorded counts", () => {
    const rows = [...baseOperatorRows(), qualifiedSponsor()];
    const result = computeK1Verdict(rows);
    expect(result.fullGate.sponsors.count).toBe(1);
    expect(result.fullGate.sponsors.pass).toBe(true);
    expect(result.fullGate.sponsors.qualified).toEqual(["Alabama Tourism Department"]);
  });
});

describe("computeK1Verdict: consequence branches", () => {
  it("sponsor miss, operators pass", () => {
    const rows = baseOperatorRows({
      "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06", loiDate: "2026-11-10", feeWillingness: "Y" },
      "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-07", loiDate: "2026-11-10", feeWillingness: "Y" },
    });
    const result = computeK1Verdict(rows); // no sponsor rows at all
    expect(result.earlyRead.pass).toBe(true);
    expect(result.fullGate.operators.pass).toBe(true);
    expect(result.fullGate.sponsors.pass).toBe(false);
    expect(result.consequenceBranch).toBe("sponsor-miss-operators-pass");
    expect(result.consequenceText).toBe(K1_CONSEQUENCE_SPONSOR_MISS);
  });

  it("full pass: operators pass and >= 1 sponsor qualified", () => {
    const rows = [
      ...baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06", loiDate: "2026-11-10", feeWillingness: "Y" },
        "Vancouver Island Golf Trail": {
          callAcceptedDate: "2026-10-07",
          loiDate: "2026-11-10",
          feeWillingness: "Y",
        },
      }),
      qualifiedSponsor(),
    ];
    const result = computeK1Verdict(rows);
    expect(result.consequenceBranch).toBe("pass");
    expect(result.consequenceText).toBe(K1_CONSEQUENCE_PASS_NOTE);
  });
});

describe("computeK1Verdict: required rows", () => {
  it("throws when a required operator row is missing from the input", () => {
    const rows = baseOperatorRows().filter((r) => r.target !== "Canadian Rockies Golf Consortium");
    expect(() => computeK1Verdict(rows)).toThrow(/missing required operator row/);
  });

  it("throws when the Oklahoma Golf Trail row is missing", () => {
    const rows = baseOperatorRows().filter((r) => r.target !== "Oklahoma Golf Trail");
    expect(() => computeK1Verdict(rows)).toThrow(/Oklahoma Golf Trail/);
  });
});
