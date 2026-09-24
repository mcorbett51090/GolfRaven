/**
 * Fifth gate, H2: "There is no input validator." Regression tests for
 * `parseEvidence`/`parseScorePlayInput` (`../src/parse-evidence.js`) —
 * strict shape, finite numbers, enum membership, non-empty string ids, the
 * localDate/capturedAt tz cross-check, and `scorePlay`'s own "runs it
 * first, fails closed, never throws" integration.
 */
import { describe, expect, it } from "vitest";
import { parseEvidence, parseScorePlayInput } from "../src/parse-evidence.js";
import { scorePlay } from "../src/score-play.js";
import { PLAY_FACILITY_ID, PLAY_LOCAL_DATE, PLAY_LOCAL_DATE_MS, baseCtx, goodFix, staffPresence } from "./score-play-helpers.js";

describe("H2: parseEvidence accepts a well-formed row and rejects a malformed one", () => {
  it("accepts a structurally valid staff_presence row (round-trips through the SAME shape scorePlay's own test helpers build)", () => {
    const row = staffPresence({ coSignalFix: goodFix() });
    const result = parseEvidence(row);
    expect(result.success).toBe(true);
  });

  it("rejects an unknown/malformed source (probe 10's __proto__ case) — never throws", () => {
    const result = parseEvidence({ id: "x", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "__proto__" });
    expect(result.success).toBe(false);
  });

  it("rejects a foreground_checkin whose fix.token is undefined (probe 10)", () => {
    const badFix = { ...goodFix(), token: undefined };
    const result = parseEvidence({
      id: "c1",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "foreground_checkin",
      fix: badFix,
    });
    expect(result.success).toBe(false);
  });

  it("rejects a staff_presence row whose coSignalFix is null (probe 10) — never throws", () => {
    const result = parseEvidence({
      id: "s1",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "staff_presence",
      scanAt: PLAY_LOCAL_DATE_MS,
      coSignalFix: null,
    });
    expect(result.success).toBe(false);
  });

  it("rejects an extra, unrecognized key on the row (strict object)", () => {
    const row = { ...staffPresence({ coSignalFix: goodFix() }), extraField: "smuggled" };
    const result = parseEvidence(row);
    expect(result.success).toBe(false);
  });

  it("rejects an extra, unrecognized key inside the fix (strict object)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), extraFixField: "smuggled" } as any });
    const result = parseEvidence(row);
    expect(result.success).toBe(false);
  });
});

describe("H2: finite numbers — accuracyMeters/capturedAt/scanAt never accept Infinity/NaN/a string", () => {
  it('rejects accuracyMeters: "10" (a string, probe 11)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), accuracyMeters: "10" } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it("rejects capturedAt: Infinity", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt: Infinity } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it("rejects capturedAt: 1e300 only if it also fails the tz cross-check (it does — resolves to a date far outside any real calendar; Intl still returns SOME string, so this is caught by the cross-check, not finiteness) — either way, never succeeds", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt: 1e300 } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it("rejects scanAt: NaN", () => {
    const row = staffPresence({ scanAt: NaN, coSignalFix: goodFix() });
    expect(parseEvidence(row).success).toBe(false);
  });
});

describe("H2: enum allow-lists reject an out-of-set value", () => {
  it('rejects token.grade: "ATTESTED" (wrong case — not in the enum)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), token: { present: true, grade: "ATTESTED" } } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it('rejects receipt status: "bogus" (probe 12)', () => {
    const result = parseEvidence({
      id: "r1",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "receipt_green_fee",
      status: "bogus",
    });
    expect(result.success).toBe(false);
  });

  it('rejects geometryKind: "circle" (not polygon/radius)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), geometryKind: "circle" } as any });
    expect(parseEvidence(row).success).toBe(false);
  });
});

describe("H2 / M1: fixId and paymentRef must be non-empty strings; objects/other shapes are rejected", () => {
  it("rejects fixId: 123 (a number)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: 123 } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it("rejects fixId: '' (empty string)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: "" } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it("rejects fixId: {} (an object)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: {} } as any });
    expect(parseEvidence(row).success).toBe(false);
  });

  it("rejects paymentRef: {} (an object) on a booking row", () => {
    const result = parseEvidence({
      id: "b1",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "booking",
      paymentRef: { forged: true },
    });
    expect(result.success).toBe(false);
  });

  it("rejects paymentRef: '' (empty string) on a receipt row", () => {
    const result = parseEvidence({
      id: "r1",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "receipt_green_fee",
      status: "approved",
      paymentRef: "",
    });
    expect(result.success).toBe(false);
  });

  it("accepts a normal non-empty paymentRef", () => {
    const result = parseEvidence({
      id: "r2",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "receipt_green_fee",
      status: "approved",
      paymentRef: "pay_123",
    });
    expect(result.success).toBe(true);
  });
});

describe("H2: the localDate/capturedAt facility-tz cross-check", () => {
  it("rejects a fix captured on D+3 but labelled localDate=D (the probe's own case)", () => {
    const row = staffPresence({
      coSignalFix: { ...goodFix(), capturedAt: PLAY_LOCAL_DATE_MS + 3 * 86_400_000, localDate: PLAY_LOCAL_DATE } as any,
    });
    const result = parseEvidence(row);
    expect(result.success).toBe(false);
  });

  it("accepts a fix whose capturedAt and localDate genuinely agree (UTC default)", () => {
    const row = staffPresence({ coSignalFix: goodFix() });
    expect(parseEvidence(row).success).toBe(true);
  });

  it("respects an explicit facilityTz: a fix at 23:30 US/Pacific labelled the PACIFIC calendar date is accepted under that tz, even though it's already the next UTC day", () => {
    // 2026-06-01T23:30:00-07:00 == 2026-06-02T06:30:00Z. Under UTC this is
    // June 2nd; under US/Pacific it is still June 1st.
    const capturedAt = Date.parse("2026-06-02T06:30:00.000Z");
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt, localDate: "2026-06-01" } as any });
    expect(parseEvidence(row, "America/Los_Angeles").success).toBe(true);
    // The SAME row, under the UTC default, disagrees (it's June 2nd in UTC).
    expect(parseEvidence(row, "UTC").success).toBe(false);
  });

  it("rejects when facilityTz itself isn't a recognized IANA timezone", () => {
    const row = staffPresence({ coSignalFix: goodFix() });
    expect(parseEvidence(row, "Not/A_Real_Timezone").success).toBe(false);
  });
});

describe("H2 / M4: parseScorePlayInput's row cap (200)", () => {
  it("accepts exactly 200 rows", () => {
    const evidence = Array.from({ length: 200 }, (_, i) => ({
      ...staffPresence({ id: `s_${i}` } as any),
    }));
    const result = parseScorePlayInput({ evidence, ctx: baseCtx() });
    expect(result.success).toBe(true);
  });

  it("rejects 201 rows outright, fail-closed, with a reason — never partially processes them", () => {
    const evidence = Array.from({ length: 201 }, (_, i) => ({
      ...staffPresence({ id: `s_${i}` } as any),
    }));
    const result = parseScorePlayInput({ evidence, ctx: baseCtx() });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reasons.some((r) => r.includes("200"))).toBe(true);
    }
  });

  it("scorePlay itself fails closed (money: false, reasons present) on a >200-row payload, never throws", () => {
    const evidence = Array.from({ length: 5000 }, (_, i) => ({
      ...staffPresence({ id: `s_${i}` } as any),
    }));
    const result = scorePlay(evidence as any, baseCtx());
    expect(result.money).toBe(false);
    expect(result.contributions).toEqual([]);
    expect(result.reasons).toBeDefined();
  });
});

describe("H2: scorePlay integrates the parser — a parse failure fails closed, never throws, and a success carries an inputDigest", () => {
  it("a malformed evidence row makes the WHOLE scorePlay call fail closed", () => {
    const result = scorePlay([{ id: "x", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "__proto__" } as any], baseCtx());
    expect(result.money).toBe(false);
    expect(result.score_badge).toBe(0);
    expect(result.reasons).toBeDefined();
    expect(result.inputDigest).toBeUndefined();
  });

  it("a well-formed call succeeds and carries a hex inputDigest, no reasons", () => {
    const result = scorePlay([staffPresence({ coSignalFix: goodFix() })], baseCtx());
    expect(result.reasons).toBeUndefined();
    expect(result.inputDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("inputDigest is deterministic for the same input and differs for a different one", () => {
    const a = scorePlay([staffPresence({ coSignalFix: goodFix() })], baseCtx());
    const b = scorePlay([staffPresence({ coSignalFix: goodFix() })], baseCtx());
    // Different fixId (goodFix() auto-increments) — so a and b must differ.
    expect(a.inputDigest).not.toBe(b.inputDigest);
    const sameRow = staffPresence({ id: "fixed_id", coSignalFix: goodFix({ fixId: "fixed_fix" }) });
    const c = scorePlay([sameRow], baseCtx());
    const d = scorePlay([sameRow], baseCtx());
    expect(c.inputDigest).toBe(d.inputDigest);
  });

  it("a malformed ctx (e.g. playFacilityId missing) fails closed too", () => {
    const result = scorePlay([staffPresence({ coSignalFix: goodFix() })], {} as any);
    expect(result.money).toBe(false);
    expect(result.reasons).toBeDefined();
  });
});
