import { describe, expect, it } from "vitest";
import {
  computeK1Verdict,
  K1_CONSEQUENCE_EARLY_MISS,
  K1_CONSEQUENCE_OPERATOR_FULL_MISS,
  K1_CONSEQUENCE_SPONSOR_MISS,
  K1_CONSEQUENCE_FULL_GATE_PASS_NOTE,
} from "../src/k1-verdict.js";
import type { K1Row, K1RowType } from "../src/k1-log.js";

// Past BOTH window closes (2026-10-20 and 2026-12-01) — use for tests that
// want a definitive (non-pending) miss/pass read, unless a test is
// specifically about the pending state.
const PAST_BOTH_WINDOWS = "2026-12-01";

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
    sponsorConversationDate: null,
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

function qualifiedSponsor(target = "Alabama Tourism Department", conversationDate = "2026-11-01"): K1Row {
  return row(target, "Sponsor", {
    sponsorDecisionMakerNamed: "Y",
    sponsorBudgetStated: "Y",
    sponsorAttributionInterest: "Y",
    sponsorConversationDate: conversationDate,
  });
}

describe("computeK1Verdict: early read (decision 0001 Addendum D R1, cutoff 2026-10-19)", () => {
  it("0 acceptances -> early miss (once the window has closed)", () => {
    const result = computeK1Verdict(baseOperatorRows(), PAST_BOTH_WINDOWS);
    expect(result.earlyRead.count).toBe(0);
    expect(result.earlyRead.state).toBe("miss");
    expect(result.earlyRead.consequenceText).toBe(K1_CONSEQUENCE_EARLY_MISS);
  });

  it("1 acceptance -> still early miss (bar is >= 2)", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-10" },
      }),
      PAST_BOTH_WINDOWS,
    );
    expect(result.earlyRead.count).toBe(1);
    expect(result.earlyRead.state).toBe("miss");
  });

  it("2 acceptances -> early pass", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-10" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-15" },
      }),
      PAST_BOTH_WINDOWS,
    );
    expect(result.earlyRead.count).toBe(2);
    expect(result.earlyRead.state).toBe("pass");
    // No LOIs logged -> full gate operators miss, evaluated independently.
    expect(result.fullGate.state).toBe("operator-miss");
    expect(result.fullGate.consequenceText).toBe(K1_CONSEQUENCE_OPERATOR_FULL_MISS);
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
      PAST_BOTH_WINDOWS,
    );
    expect(result.earlyRead.count).toBe(5);
    expect(result.earlyRead.state).toBe("pass");
  });

  it("BOUNDARY: an acceptance dated exactly 2026-10-19 counts", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-19" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-19" },
      }),
      PAST_BOTH_WINDOWS,
    );
    expect(result.earlyRead.count).toBe(2);
    expect(result.earlyRead.late).toEqual([]);
  });

  it("BOUNDARY: an acceptance dated exactly 2026-10-20 does NOT count (late)", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-19" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-20" },
      }),
      PAST_BOTH_WINDOWS,
    );
    expect(result.earlyRead.count).toBe(1);
    expect(result.earlyRead.late).toEqual([{ target: "Vancouver Island Golf Trail", date: "2026-10-20" }]);
  });

  it("a 6th contact (Oklahoma) does not count when the swap is not activated", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-07" },
        "Oklahoma Golf Trail": { callAcceptedDate: "2026-10-08" }, // OK contacted but swap NOT activated
      }),
      PAST_BOTH_WINDOWS,
    );
    expect(result.effectiveFive).not.toContain("Oklahoma Golf Trail");
    expect(result.earlyRead.count).toBe(2); // TN + VI only, OK ignored
    expect(result.okSwap.activated).toBe(false);
    expect(result.warnings.some((w) => w.includes("Oklahoma Golf Trail"))).toBe(true);
  });
});

describe("computeK1Verdict: as-of pending states (decision 0001 Addendum I)", () => {
  it("as of 2026-10-19, the early read is pending regardless of count (window closes 2026-10-20)", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-07" },
      }),
      "2026-10-19",
    );
    expect(result.earlyRead.state).toBe("pending");
    expect(result.earlyRead.consequenceText).toMatch(/Pending \(2 so far\)/);
    // Full gate is also still pending at this as-of (window closes 2026-12-01).
    expect(result.fullGate.state).toBe("pending");
  });

  it("as of 2026-11-30, the early read has closed but the full gate is still pending", () => {
    const result = computeK1Verdict(baseOperatorRows(), "2026-11-30");
    expect(result.earlyRead.state).toBe("miss"); // window closed, 0 accepted
    expect(result.fullGate.state).toBe("pending"); // full-gate window closes 2026-12-01
  });

  it("as of 2026-12-01, the full gate has closed", () => {
    const result = computeK1Verdict(baseOperatorRows(), "2026-12-01");
    expect(result.fullGate.state).not.toBe("pending");
  });

  it("refuses a malformed --as-of", () => {
    expect(() => computeK1Verdict(baseOperatorRows(), "12/01/2026")).toThrow(/as-of/);
  });
});

describe("computeK1Verdict: probe — an early-read miss never hides a passing full gate, and vice versa", () => {
  it("0 acceptances (early miss) coexists with a passing full gate — both are visible", () => {
    const rows = [
      ...baseOperatorRows({
        "Tennessee Golf Trail": { loiDate: "2026-11-10", feeWillingness: "Y" }, // no call accepted
        "Vancouver Island Golf Trail": { loiDate: "2026-11-10", feeWillingness: "Y" },
      }),
      qualifiedSponsor(),
    ];
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.earlyRead.count).toBe(0);
    expect(result.earlyRead.state).toBe("miss");
    expect(result.fullGate.operators.pass).toBe(true);
    expect(result.fullGate.sponsors.pass).toBe(true);
    expect(result.fullGate.state).toBe("pass");
  });
});

describe("computeK1Verdict: Oklahoma Golf Trail swap activation (K1.md METHOD step 1)", () => {
  it("when activated, OK replaces the named slate trail — never a 6th", () => {
    const result = computeK1Verdict(
      baseOperatorRows({
        "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06" },
        "Oklahoma Golf Trail": { callAcceptedDate: "2026-10-07", okSwapReplaces: "Tennessee Golf Trail" },
        "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-08" },
      }),
      PAST_BOTH_WINDOWS,
    );
    expect(result.okSwap).toEqual({ activated: true, replaces: "Tennessee Golf Trail" });
    expect(result.effectiveFive).toContain("Oklahoma Golf Trail");
    expect(result.effectiveFive).not.toContain("Tennessee Golf Trail");
    expect(result.effectiveFive).toHaveLength(5);
    expect(result.earlyRead.count).toBe(2);
    expect(result.earlyRead.state).toBe("pass");
    expect(result.warnings.some((w) => w.includes('replaces "Tennessee Golf Trail"'))).toBe(true);
  });

  it("when NOT activated, OK is excluded and the base 5 is used", () => {
    const result = computeK1Verdict(baseOperatorRows(), PAST_BOTH_WINDOWS);
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
      PAST_BOTH_WINDOWS,
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
      PAST_BOTH_WINDOWS,
    );
    expect(result.fullGate.operators.count).toBe(2);
    expect(result.fullGate.operators.pass).toBe(true);
  });
});

describe("computeK1Verdict: full gate — sponsors (all 3 qualifiers + conversation date)", () => {
  it("a sponsor missing one qualifier does not count", () => {
    const rows = [
      ...baseOperatorRows(),
      row("Alabama Tourism Department", "Sponsor", {
        sponsorDecisionMakerNamed: "Y",
        sponsorBudgetStated: "Y",
        sponsorConversationDate: "2026-11-01",
        // sponsorAttributionInterest missing
      }),
    ];
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.fullGate.sponsors.count).toBe(0);
    expect(result.fullGate.sponsors.pass).toBe(false);
    expect(result.fullGate.sponsors.partial).toEqual([
      {
        target: "Alabama Tourism Department",
        missing: ["interest in special-marker attribution"],
      },
    ]);
  });

  it("a sponsor row with all 3 qualifiers but no conversation date does not count (missing the date)", () => {
    const rows = [
      ...baseOperatorRows(),
      row("Alabama Tourism Department", "Sponsor", {
        sponsorDecisionMakerNamed: "Y",
        sponsorBudgetStated: "Y",
        sponsorAttributionInterest: "Y",
      }),
    ];
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.fullGate.sponsors.count).toBe(0);
    expect(result.fullGate.sponsors.partial[0]!.missing).toContain("a recorded sponsor conversation date");
  });

  it("a sponsor row with all qualifiers and a conversation date on or before 2026-11-30 counts", () => {
    const rows = [...baseOperatorRows(), qualifiedSponsor()];
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.fullGate.sponsors.count).toBe(1);
    expect(result.fullGate.sponsors.pass).toBe(true);
    expect(result.fullGate.sponsors.qualified).toEqual(["Alabama Tourism Department"]);
  });

  it("a sponsor conversation dated after 2026-11-30 does not count", () => {
    const rows = [...baseOperatorRows(), qualifiedSponsor("Alabama Tourism Department", "2026-12-01")];
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.fullGate.sponsors.count).toBe(0);
    expect(result.fullGate.sponsors.late).toEqual([
      { target: "Alabama Tourism Department", date: "2026-12-01" },
    ]);
  });
});

describe("computeK1Verdict: full-gate state priority — operator miss before sponsor miss (decision 0001 Addendum I)", () => {
  it("sponsor miss, operators pass", () => {
    const rows = baseOperatorRows({
      "Tennessee Golf Trail": { callAcceptedDate: "2026-10-06", loiDate: "2026-11-10", feeWillingness: "Y" },
      "Vancouver Island Golf Trail": { callAcceptedDate: "2026-10-07", loiDate: "2026-11-10", feeWillingness: "Y" },
    });
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS); // no sponsor rows at all
    expect(result.earlyRead.state).toBe("pass");
    expect(result.fullGate.operators.pass).toBe(true);
    expect(result.fullGate.sponsors.pass).toBe(false);
    expect(result.fullGate.state).toBe("sponsor-miss");
    expect(result.fullGate.consequenceText).toBe(K1_CONSEQUENCE_SPONSOR_MISS);
  });

  it("both operators AND sponsors miss -> reports operator-miss (evaluated first)", () => {
    const rows = baseOperatorRows(); // no LOIs, no sponsors
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.fullGate.operators.pass).toBe(false);
    expect(result.fullGate.sponsors.pass).toBe(false);
    expect(result.fullGate.state).toBe("operator-miss");
    expect(result.fullGate.consequenceText).toBe(K1_CONSEQUENCE_OPERATOR_FULL_MISS);
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
    const result = computeK1Verdict(rows, PAST_BOTH_WINDOWS);
    expect(result.fullGate.state).toBe("pass");
    expect(result.fullGate.consequenceText).toBe(K1_CONSEQUENCE_FULL_GATE_PASS_NOTE);
  });
});

describe("computeK1Verdict: date sanity (decision 0001 Addendum I)", () => {
  it("throws on a date before 2026-09-23", () => {
    const rows = baseOperatorRows({
      "Tennessee Golf Trail": { contactedDate: "2026-09-22" },
    });
    expect(() => computeK1Verdict(rows, PAST_BOTH_WINDOWS)).toThrow(/before 2026-09-23/);
  });

  it("throws when a logged date is later than as-of", () => {
    const rows = baseOperatorRows({
      "Tennessee Golf Trail": { callAcceptedDate: "2026-11-01" },
    });
    expect(() => computeK1Verdict(rows, "2026-10-15")).toThrow(/after the as-of date/);
  });

  it("throws when an LOI is dated before its row's contacted date", () => {
    const rows = baseOperatorRows({
      "Tennessee Golf Trail": { contactedDate: "2026-10-10", loiDate: "2026-10-05", feeWillingness: "Y" },
    });
    expect(() => computeK1Verdict(rows, PAST_BOTH_WINDOWS)).toThrow(/LOI date .* is before Contacted date/);
  });

  it("throws when an acceptance is dated before its row's contacted date", () => {
    const rows = baseOperatorRows({
      "Tennessee Golf Trail": { contactedDate: "2026-10-10", callAcceptedDate: "2026-10-05" },
    });
    expect(() => computeK1Verdict(rows, PAST_BOTH_WINDOWS)).toThrow(
      /Call accepted date .* is before Contacted date/,
    );
  });
});

describe("computeK1Verdict: required rows", () => {
  it("throws when a required operator row is missing from the input", () => {
    const rows = baseOperatorRows().filter((r) => r.target !== "Canadian Rockies Golf Consortium");
    expect(() => computeK1Verdict(rows, PAST_BOTH_WINDOWS)).toThrow(/missing required operator row/);
  });

  it("throws when the Oklahoma Golf Trail row is missing", () => {
    const rows = baseOperatorRows().filter((r) => r.target !== "Oklahoma Golf Trail");
    expect(() => computeK1Verdict(rows, PAST_BOTH_WINDOWS)).toThrow(/Oklahoma Golf Trail/);
  });
});
