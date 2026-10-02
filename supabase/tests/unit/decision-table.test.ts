// supabase/tests/unit/decision-table.test.ts
//
// The §7.5 activation decision table (supabase/functions/_shared/rewards/
// decision-table.ts): every row, every precedence pair, and an exhaustive check
// against an ORACLE written independently of the implementation (a flat ordered
// rule list read straight off the plan's table, not the nested ifs the
// implementation uses).

import { describe, expect, it } from "vitest";
import { decideActivation, type ActivationFacts, type Decision } from "../../functions/_shared/rewards/decision-table.js";

const CLEAN: ActivationFacts = {
  bits: { kind: "known", bit0: false, bit1: false },
  activatingGrade: "attested",
  accountHasOpenAttestationFailed: false,
  rewardRestsOnUnattestable: false,
  accountHasPriorReward: false,
};
const f = (over: Partial<ActivationFacts> = {}): ActivationFacts => ({ ...CLEAN, ...over });
const bits = (bit0: boolean, bit1: boolean) => ({ kind: "known" as const, bit0, bit1 });

describe("§7.5 table — one test per row", () => {
  it("row 1: bit1 set -> held_review + a high-priority flagged-device signal (bit0 irrelevant)", () => {
    for (const bit0 of [false, true]) {
      const d = decideActivation(f({ bits: bits(bit0, true) }));
      expect(d.row).toBe(1);
      expect(d.outcome).toBe("held_review");
      expect(d.signals).toEqual(["flagged_device_activation"]);
      expect(d.setBit0).toBe(false);
    }
  });

  it("row 2: an open attestation_failed signal on the account -> held_review", () => {
    const d = decideActivation(f({ accountHasOpenAttestationFailed: true }));
    expect(d).toMatchObject({ row: 2, outcome: "held_review", signals: [], setBit0: false });
  });

  it("row 3: a reward resting on an unattestable co-signal -> held_review, even on a clean device", () => {
    const d = decideActivation(f({ rewardRestsOnUnattestable: true }));
    expect(d).toMatchObject({ row: 3, outcome: "held_review", signals: [], setBit0: false });
  });

  it("row 4: bit0 set, bit1 clear, no prior reward -> held_review + multi_account_device (never refused)", () => {
    const d = decideActivation(f({ bits: bits(true, false), accountHasPriorReward: false }));
    expect(d).toMatchObject({ row: 4, outcome: "held_review", signals: ["multi_account_device"], setBit0: false });
  });

  it("row 5: bit0 set, bit1 clear, a prior reward -> activate, and bit0 is NOT re-set", () => {
    const d = decideActivation(f({ bits: bits(true, false), accountHasPriorReward: true }));
    expect(d).toMatchObject({ row: 5, outcome: "activate", signals: [], setBit0: false });
  });

  it("row 6: clear/clear -> activate, and bit0 is set", () => {
    const d = decideActivation(f());
    expect(d).toMatchObject({ row: 6, outcome: "activate", signals: [], setBit0: true });
  });

  it("a prior reward does not matter on a clean device (row 6 either way)", () => {
    expect(decideActivation(f({ accountHasPriorReward: true })).row).toBe(6);
  });
});

describe("§7.5 table — precedence (rows are checked in order, first match wins; G3-08)", () => {
  it("an unattestable-resting reward on a clean device matches rows 3 AND 6: held, not activated", () => {
    const d = decideActivation(f({ rewardRestsOnUnattestable: true }));
    expect(d.outcome).toBe("held_review");
    expect(d.row).toBe(3);
  });

  it("an open attestation_failed signal beats a repeat user on a bit0 device (row 2 over row 5)", () => {
    const d = decideActivation(f({ bits: bits(true, false), accountHasPriorReward: true, accountHasOpenAttestationFailed: true }));
    expect(d).toMatchObject({ row: 2, outcome: "held_review" });
  });

  it("row 1 beats rows 2 and 3 (and its signal is still raised)", () => {
    const d = decideActivation(f({ bits: bits(false, true), accountHasOpenAttestationFailed: true, rewardRestsOnUnattestable: true }));
    expect(d.row).toBe(1);
    expect(d.signals).toEqual(["flagged_device_activation"]);
  });

  it("row 2 beats row 3", () => {
    expect(decideActivation(f({ accountHasOpenAttestationFailed: true, rewardRestsOnUnattestable: true })).row).toBe(2);
  });

  it("row 3 beats rows 4 and 5 for the OUTCOME (an unattestable reward on a bit0 device is held by row 3)", () => {
    for (const prior of [false, true]) {
      const d = decideActivation(f({ bits: bits(true, false), accountHasPriorReward: prior, rewardRestsOnUnattestable: true }));
      expect(d.row).toBe(3);
      expect(d.outcome).toBe("held_review");
    }
  });
});

describe("M2 — first match decides the outcome, EVERY matching row raises its signals", () => {
  it("probe C: first account, bit0 device, unattestable reward -> held by row 3 WITH multi_account_device (row 4 also matches)", () => {
    const d = decideActivation(f({ bits: bits(true, false), accountHasPriorReward: false, rewardRestsOnUnattestable: true }));
    expect(d.row).toBe(3);
    expect(d.outcome).toBe("held_review");
    expect(d.matchedRows).toEqual([3, 4]);
    expect(d.signals).toEqual(["multi_account_device"]);
  });
  it("with a prior reward, rows 3 and 5 match and there is no signal to raise", () => {
    const d = decideActivation(f({ bits: bits(true, false), accountHasPriorReward: true, rewardRestsOnUnattestable: true }));
    expect(d.matchedRows).toEqual([3, 5]);
    expect(d.signals).toEqual([]);
  });
  it("an open attestation_failed signal on a bit0 device with no prior reward still raises multi_account_device", () => {
    const d = decideActivation(f({ bits: bits(true, false), accountHasOpenAttestationFailed: true }));
    expect(d.row).toBe(2);
    expect(d.signals).toEqual(["multi_account_device"]);
  });
  it("a failed or unattestable activating device on a bit0 device raises it too", () => {
    for (const g of ["failed", "unattestable"] as const) {
      expect(decideActivation(f({ bits: bits(true, false), activatingGrade: g })).signals).toEqual(["multi_account_device"]);
    }
  });
  it("bit1 (row 1) excludes rows 4-6, so the two signals never co-occur", () => {
    const d = decideActivation(f({ bits: bits(true, true), accountHasOpenAttestationFailed: true, rewardRestsOnUnattestable: true }));
    expect(d.matchedRows).toEqual([1, 2, 3]);
    expect(d.signals).toEqual(["flagged_device_activation"]);
  });
  it("matchedRows lists every row in evaluation order and starts with the deciding row", () => {
    const d = decideActivation(f({ bits: { kind: "none" }, accountHasOpenAttestationFailed: true, rewardRestsOnUnattestable: true }));
    expect(d.matchedRows).toEqual([2, 3, "no_persistent_signal"]);
    expect(d.matchedRows[0]).toBe(d.row);
  });
});

describe("the activating device's own grade", () => {
  it("a failed grade holds (it joins row 2: the signal it opens holds the account's activations)", () => {
    expect(decideActivation(f({ activatingGrade: "failed" }))).toMatchObject({ row: 2, outcome: "held_review" });
  });
  it("an unattestable device's reward goes to held_review (§7.5 Role) — never activated", () => {
    expect(decideActivation(f({ activatingGrade: "unattestable" }))).toMatchObject({ row: 3, outcome: "held_review" });
  });
  it("bit1 still outranks a failed or unattestable grade", () => {
    for (const g of ["failed", "unattestable"] as const) {
      expect(decideActivation(f({ bits: bits(false, true), activatingGrade: g })).row).toBe(1);
    }
  });
});

describe("no persistent signal on this platform (Android without device recall, A20)", () => {
  it("an attested device with no bits is held_review, never activated and never refused", () => {
    expect(decideActivation(f({ bits: { kind: "none" } }))).toMatchObject({ row: "no_persistent_signal", outcome: "held_review", setBit0: false });
  });
  it("rows 2 and 3 still win over it", () => {
    expect(decideActivation(f({ bits: { kind: "none" }, accountHasOpenAttestationFailed: true })).row).toBe(2);
    expect(decideActivation(f({ bits: { kind: "none" }, rewardRestsOnUnattestable: true })).row).toBe(3);
  });
});

// ---------------------------------------------------------------------------
// Exhaustive check against an independent oracle.
// ---------------------------------------------------------------------------
type Oracle = { outcome: "activate" | "held_review"; row: Decision["row"]; matched: Array<Decision["row"]>; signals: string[] };

/** The plan's table as a flat, ordered list of (predicate, outcome). The first
 * predicate that matches wins. Rows 7 ("no persistent signal") is the plan's
 * Android contract (§7.5), placed where rows 4-6 would otherwise need bits. */
const ORDERED_RULES: Array<[Decision["row"], (x: ActivationFacts) => boolean, "activate" | "held_review"]> = [
  [1, (x) => x.bits.kind === "known" && x.bits.bit1, "held_review"],
  [2, (x) => x.accountHasOpenAttestationFailed || x.activatingGrade === "failed", "held_review"],
  [3, (x) => x.rewardRestsOnUnattestable || x.activatingGrade === "unattestable", "held_review"],
  ["no_persistent_signal", (x) => x.bits.kind === "none", "held_review"],
  [4, (x) => x.bits.kind === "known" && x.bits.bit0 && !x.bits.bit1 && !x.accountHasPriorReward, "held_review"],
  [5, (x) => x.bits.kind === "known" && x.bits.bit0 && !x.bits.bit1 && x.accountHasPriorReward, "activate"],
  [6, (x) => x.bits.kind === "known" && !x.bits.bit0 && !x.bits.bit1, "activate"],
];
const SIGNAL_OF_ROW: Partial<Record<string, string>> = { "1": "flagged_device_activation", "4": "multi_account_device" };
function oracle(x: ActivationFacts): Oracle {
  const hits = ORDERED_RULES.filter(([, pred]) => pred(x));
  const first = hits[0];
  if (!first) throw new Error("oracle: the table is not total over this input");
  const signals = [...new Set(hits.map(([row]) => SIGNAL_OF_ROW[String(row)]).filter((v): v is string => v !== undefined))];
  return { row: first[0], outcome: first[2], matched: hits.map(([row]) => row), signals };
}

describe("exhaustive: decideActivation equals the independent oracle over the whole input space", () => {
  const bitsSpace = [{ kind: "none" as const }, bits(false, false), bits(true, false), bits(false, true), bits(true, true)];
  const grades = ["attested", "unattestable", "failed"] as const;
  const bools = [false, true];
  let n = 0;
  it("every combination of bits x grade x open-failed x rests-on-unattestable x prior-reward", () => {
    for (const b of bitsSpace) {
      for (const grade of grades) {
        for (const openFailed of bools) {
          for (const unatt of bools) {
            for (const prior of bools) {
              const facts: ActivationFacts = { bits: b, activatingGrade: grade, accountHasOpenAttestationFailed: openFailed, rewardRestsOnUnattestable: unatt, accountHasPriorReward: prior };
              const got = decideActivation(facts);
              const want = oracle(facts);
              expect({ facts, row: got.row, outcome: got.outcome, matched: got.matchedRows, signals: got.signals }).toEqual({
                facts,
                row: want.row,
                outcome: want.outcome,
                matched: want.matched,
                signals: want.signals,
              });
              n++;
            }
          }
        }
      }
    }
    expect(n).toBe(5 * 3 * 2 * 2 * 2);
  });

  it("the ONLY way to activate is a clean/clear or repeat-user reading on an attested device with no open signal and an attestable reward", () => {
    for (const b of bitsSpace) {
      for (const grade of grades) {
        for (const openFailed of bools) {
          for (const unatt of bools) {
            for (const prior of bools) {
              const facts: ActivationFacts = { bits: b, activatingGrade: grade, accountHasOpenAttestationFailed: openFailed, rewardRestsOnUnattestable: unatt, accountHasPriorReward: prior };
              if (decideActivation(facts).outcome === "activate") {
                expect(grade).toBe("attested");
                expect(openFailed).toBe(false);
                expect(unatt).toBe(false);
                expect(b.kind).toBe("known");
                if (b.kind === "known") {
                  expect(b.bit1).toBe(false);
                  expect(b.bit0 ? prior : true).toBe(true);
                }
              }
            }
          }
        }
      }
    }
  });

  it("setBit0 is true ONLY for row 6", () => {
    for (const b of bitsSpace) {
      for (const grade of grades) {
        const d = decideActivation({ ...CLEAN, bits: b, activatingGrade: grade });
        expect(d.setBit0).toBe(d.row === 6);
      }
    }
  });

  it("there is no 'refused' outcome: every decision is activate or held_review", () => {
    for (const b of bitsSpace) {
      for (const grade of grades) {
        expect(["activate", "held_review"]).toContain(decideActivation({ ...CLEAN, bits: b, activatingGrade: grade }).outcome);
      }
    }
  });
});
