import { describe, expect, it } from "vitest";
import { ADVISORY_THRESHOLD, GATE_THRESHOLD, computeK2Counts } from "../src/k2-count";

const DAY0 = "2026-10-05T00:00:00.000Z";

function rowsOf(n: number, confirmedAt: string, emailPrefix = "user"): { email_lc: string; confirmed_at: string }[] {
  return Array.from({ length: n }, (_, i) => ({ email_lc: `${emailPrefix}${i}@example.com`, confirmed_at: confirmedAt }));
}

describe("computeK2Counts", () => {
  it("refuses to run when day 0 is missing", () => {
    expect(() => computeK2Counts({ rows: [], day0: "", excludedAddresses: [] })).toThrow(/day 0/i);
  });

  it("refuses to run when day 0 is not a valid date", () => {
    expect(() => computeK2Counts({ rows: [], day0: "not-a-date", excludedAddresses: [] })).toThrow(/valid/i);
  });

  it("never counts unconfirmed rows", () => {
    const rows = [{ email_lc: "a@example.com", confirmed_at: null }, { email_lc: "b@example.com" }];
    const result = computeK2Counts({ rows, day0: DAY0, excludedAddresses: [] });
    expect(result.advisoryCount).toBe(0);
    expect(result.gateCount).toBe(0);
  });

  it("dedupes duplicate-case-variant email addresses to one distinct signup", () => {
    const rows = [
      { email_lc: "Player@Example.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
      { email_lc: "player@example.com", confirmed_at: "2026-10-07T00:00:00.000Z" },
      { email_lc: "PLAYER@EXAMPLE.COM", confirmed_at: "2026-10-08T00:00:00.000Z" },
    ];
    const result = computeK2Counts({ rows, day0: DAY0, excludedAddresses: [] });
    expect(result.distinctConfirmed).toBe(1);
    expect(result.advisoryCount).toBe(1);
  });

  it("excludes an address in the excluded list, case-insensitively", () => {
    const rows = [
      { email_lc: "owner@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
      { email_lc: "real@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
    ];
    const result = computeK2Counts({ rows, day0: DAY0, excludedAddresses: ["Owner@Example.com"] });
    expect(result.excludedMatchCount).toBe(1);
    expect(result.distinctConfirmed).toBe(1);
    expect(result.advisoryCount).toBe(1);
  });

  it("a confirmation exactly AT the advisory/gate cutoff is excluded (strictly-before rule)", () => {
    const advisoryCutoff = new Date(new Date(DAY0).getTime() + 14 * 86400000).toISOString();
    const gateCutoff = new Date(new Date(DAY0).getTime() + 42 * 86400000).toISOString();
    const rows = [
      { email_lc: "exact-advisory@example.com", confirmed_at: advisoryCutoff },
      { email_lc: "exact-gate@example.com", confirmed_at: gateCutoff },
      { email_lc: "one-ms-before-gate@example.com", confirmed_at: new Date(new Date(gateCutoff).getTime() - 1).toISOString() },
    ];
    const result = computeK2Counts({ rows, day0: DAY0, excludedAddresses: [] });
    // exact-advisory confirmed AT the advisory cutoff: excluded from advisory,
    // but well before the gate cutoff so it DOES count toward the gate.
    // exact-gate confirmed AT the gate cutoff: excluded from both.
    // one-ms-before-gate: counts toward the gate (and, since it's after the
    // advisory cutoff, not toward advisory).
    expect(result.advisoryCount).toBe(0);
    expect(result.gateCount).toBe(2); // exact-advisory + one-ms-before-gate
  });

  it("computes advisory/gate pass-bar verdicts against the pre-registered thresholds", () => {
    const belowThreshold = rowsOf(ADVISORY_THRESHOLD - 1, "2026-10-06T00:00:00.000Z");
    const resultFail = computeK2Counts({ rows: belowThreshold, day0: DAY0, excludedAddresses: [] });
    expect(resultFail.advisoryPass).toBe(false);
    expect(resultFail.gatePass).toBe(false);

    const atGate = rowsOf(GATE_THRESHOLD, "2026-10-06T00:00:00.000Z");
    const resultPass = computeK2Counts({ rows: atGate, day0: DAY0, excludedAddresses: [] });
    expect(resultPass.advisoryPass).toBe(true);
    expect(resultPass.gatePass).toBe(true);
  });

  it("an unsubscribed-but-confirmed-before-cutoff address still counts (counts confirmations, not current subscribers)", () => {
    // The export row shape only ever carries email_lc/confirmed_at — this
    // test documents that the function has no unsubscribed_at concept at
    // all, so a caller cannot accidentally wire it in to exclude one.
    const rows = [{ email_lc: "left@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" }];
    const result = computeK2Counts({ rows, day0: DAY0, excludedAddresses: [] });
    expect(result.advisoryCount).toBe(1);
    expect(result.gateCount).toBe(1);
  });

  it("handles a `wrangler d1 execute --json`-shaped export via the CLI's row extractor semantics (rows array itself)", () => {
    // computeK2Counts itself only takes a plain rows array — the
    // wrangler-shape unwrapping happens in scripts/k2-count.mjs — this
    // test just confirms the plain-array contract it's fed.
    const rows = [{ email_lc: "a@example.com", confirmed_at: "2026-10-06T00:00:00.000Z" }];
    const result = computeK2Counts({ rows, day0: DAY0, excludedAddresses: [] });
    expect(result.totalRows).toBe(1);
  });
});
