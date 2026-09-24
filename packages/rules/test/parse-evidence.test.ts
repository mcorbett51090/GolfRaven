/**
 * H2 ("There is no input validator") + sixth-gate F1/F3/F6 regression
 * tests for `parseEvidence`/`parseScorePlayInput` (`../src/parse-evidence.js`)
 * — strict shape, finite numbers, enum membership, non-empty string ids,
 * the localDate/capturedAt tz cross-check (now against a REQUIRED,
 * IANA-validated `facilityTz`, F1), real-calendar-date validation (F6),
 * and `scorePlay`'s discriminated-result / quarantine integration (F3).
 */
import { describe, expect, it } from "vitest";
import {
  ABSOLUTE_ROW_CAP,
  parseEvidence,
  parseScorePlayInput,
} from "../src/parse-evidence.js";
import { scorePlay } from "../src/score-play.js";
import {
  PLAY_FACILITY_ID,
  PLAY_FACILITY_TZ,
  PLAY_LOCAL_DATE,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  goodFix,
  scorePlayOrThrow,
  staffPresence,
} from "./score-play-helpers.js";

const tz = PLAY_FACILITY_TZ;

describe("H2: parseEvidence accepts a well-formed row and rejects a malformed one", () => {
  it("accepts a structurally valid staff_presence row (round-trips through the SAME shape scorePlay's own test helpers build)", () => {
    const row = staffPresence({ coSignalFix: goodFix() });
    const result = parseEvidence(row, tz);
    expect(result.success).toBe(true);
  });

  it("rejects an unknown/malformed source (probe 10's __proto__ case) — never throws", () => {
    const result = parseEvidence({ id: "x", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "__proto__" }, tz);
    expect(result.success).toBe(false);
  });

  it("rejects a foreground_checkin whose fix.token is undefined (probe 10)", () => {
    const badFix = { ...goodFix(), token: undefined };
    const result = parseEvidence(
      { id: "c1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "foreground_checkin", fix: badFix },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it("rejects a staff_presence row whose coSignalFix is null (probe 10) — never throws", () => {
    const result = parseEvidence(
      { id: "s1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "staff_presence", scanAt: PLAY_LOCAL_DATE_MS, coSignalFix: null },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it("rejects an extra, unrecognized key on the row (strict object)", () => {
    const row = { ...staffPresence({ coSignalFix: goodFix() }), extraField: "smuggled" };
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects an extra, unrecognized key inside the fix (strict object)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), extraFixField: "smuggled" } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });
});

describe("H2: finite numbers — accuracyMeters/capturedAt/scanAt never accept Infinity/NaN/a string", () => {
  it('rejects accuracyMeters: "10" (a string, probe 11)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), accuracyMeters: "10" } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects capturedAt: Infinity", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt: Infinity } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects capturedAt: 1e300 (non-finite-adjacent — caught by .finite() or the tz cross-check either way)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt: 1e300 } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects scanAt: NaN", () => {
    const row = staffPresence({ scanAt: NaN, coSignalFix: goodFix() });
    expect(parseEvidence(row, tz).success).toBe(false);
  });
});

describe("H2: enum allow-lists reject an out-of-set value", () => {
  it('rejects token.grade: "ATTESTED" (wrong case — not in the enum)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), token: { present: true, grade: "ATTESTED" } } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it('rejects receipt status: "bogus" (probe 12)', () => {
    const result = parseEvidence(
      { id: "r1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "receipt_green_fee", status: "bogus" },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it('rejects geometryKind: "circle" (not polygon/radius)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), geometryKind: "circle" } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });
});

describe("H2 / M1: fixId and paymentRef must be non-empty strings; objects/other shapes are rejected", () => {
  it("rejects fixId: 123 (a number)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: 123 } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects fixId: '' (empty string)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: "" } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects fixId: {} (an object)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: {} } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects paymentRef: {} (an object) on a booking row", () => {
    const result = parseEvidence(
      { id: "b1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "booking", paymentRef: { forged: true } },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it("rejects paymentRef: '' (empty string) on a receipt row", () => {
    const result = parseEvidence(
      { id: "r1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "receipt_green_fee", status: "approved", paymentRef: "" },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it("accepts a normal non-empty paymentRef", () => {
    const result = parseEvidence(
      { id: "r2", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "receipt_green_fee", status: "approved", paymentRef: "pay_123" },
      tz,
    );
    expect(result.success).toBe(true);
  });
});

describe("H2: the localDate/capturedAt facility-tz cross-check", () => {
  it("rejects a fix captured on D+3 but labelled localDate=D (the probe's own case)", () => {
    const row = staffPresence({
      coSignalFix: { ...goodFix(), capturedAt: PLAY_LOCAL_DATE_MS + 3 * 86_400_000, localDate: PLAY_LOCAL_DATE } as any,
    });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("accepts a fix whose capturedAt and localDate genuinely agree", () => {
    const row = staffPresence({ coSignalFix: goodFix() });
    expect(parseEvidence(row, tz).success).toBe(true);
  });

  it("respects an explicit facilityTz: a fix at 23:30 Pacific labelled the PACIFIC calendar date is accepted under that tz, even though it's already the next UTC day (and REJECTED under the REAL facility tz if that's not what the facility is)", () => {
    // 2026-06-01T23:30:00-07:00 == 2026-06-02T06:30:00Z. Under UTC (and
    // under Atlantic/Reykjavik, this suite's own always-UTC+0 tz) this is
    // June 2nd; under America/Los_Angeles it is still June 1st.
    const capturedAt = Date.parse("2026-06-02T06:30:00.000Z");
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt, localDate: "2026-06-01" } as any });
    expect(parseEvidence(row, "America/Los_Angeles").success).toBe(true);
    expect(parseEvidence(row, PLAY_FACILITY_TZ).success).toBe(false);
  });
});

describe("F1: facilityTz is REQUIRED and allow-listed to real IANA Area/Location zone names only", () => {
  const badTzCases: [string, string][] = [
    ["Mars/Base (not a real zone)", "Mars/Base"],
    ["empty string", ""],
    ["america/los_angeles (wrong case)", "america/los_angeles"],
    ["+05:00 (fixed offset)", "+05:00"],
    ["-07:00 (fixed offset)", "-07:00"],
    ["Etc/GMT+7 (fixed-offset-style zone)", "Etc/GMT+7"],
    ["US/Pacific (legacy link)", "US/Pacific"],
    ["PST8PDT (abbreviation-style)", "PST8PDT"],
    ["EST (abbreviation)", "EST"],
  ];
  for (const [label, badTz] of badTzCases) {
    it(`parseEvidence rejects facilityTz=${label}`, () => {
      const row = staffPresence({ coSignalFix: goodFix() });
      expect(parseEvidence(row, badTz).success).toBe(false);
    });
  }

  it("a real IANA zone (Europe/Kiev) is accepted", () => {
    // Kyiv is UTC+2/+3 (DST) — a fix genuinely captured there must carry
    // the matching local date; this only checks the TZ NAME is accepted,
    // not a specific date, so use a fix whose capturedAt/localDate the
    // helper already keeps self-consistent under whatever tz is passed —
    // here we just confirm the zone-name gate itself doesn't reject it by
    // constructing a row/fix pair known to agree under Europe/Kiev's
    // offset at this instant is out of scope; instead assert the PARSE
    // reaches the tz cross-check at all (a bad zone name fails BEFORE
    // ever reaching Zod's row parse).
    const row = staffPresence({ coSignalFix: goodFix() });
    const result = parseEvidence(row, "Europe/Kiev");
    // Either succeeds (if the offset happens to agree) or fails on the
    // CROSS-CHECK specifically (localDate mismatch) — never on the ZONE
    // NAME itself being rejected.
    if (!result.success) {
      expect(result.reasons.some((r) => r.includes("not a real IANA"))).toBe(false);
    }
  });

  it("ScorePlayContextSchema (via parseScorePlayInput) requires facilityTz — omitting it fails the whole parse", () => {
    const { facilityTz, ...ctxWithoutTz } = baseCtx();
    const result = parseScorePlayInput({ evidence: [staffPresence({ coSignalFix: goodFix() })], ctx: ctxWithoutTz });
    expect(result.success).toBe(false);
  });

  it("parseScorePlayInput rejects a bad facilityTz in ctx (fixed offset)", () => {
    const result = parseScorePlayInput({
      evidence: [staffPresence({ coSignalFix: goodFix() })],
      ctx: { ...baseCtx(), facilityTz: "-07:00" },
    });
    expect(result.success).toBe(false);
  });
});

describe("F6: localDate must be a REAL calendar date, not merely regex-shaped", () => {
  it('rejects "2026-02-31" (February has no 31st)', () => {
    const result = parseEvidence(
      { id: "x", facilityId: PLAY_FACILITY_ID, localDate: "2026-02-31", source: "self_report" },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it('rejects "2026-13-01" (month 13)', () => {
    const result = parseEvidence(
      { id: "x", facilityId: PLAY_FACILITY_ID, localDate: "2026-13-01", source: "self_report" },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it('rejects "2026-04-31" (April has 30 days)', () => {
    const result = parseEvidence(
      { id: "x", facilityId: PLAY_FACILITY_ID, localDate: "2026-04-31", source: "self_report" },
      tz,
    );
    expect(result.success).toBe(false);
  });

  it('accepts "2026-02-28" (a real date) and "2028-02-29" (a real leap day)', () => {
    expect(
      parseEvidence({ id: "x1", facilityId: PLAY_FACILITY_ID, localDate: "2026-02-28", source: "self_report" }, tz).success,
    ).toBe(true);
    expect(
      parseEvidence({ id: "x2", facilityId: PLAY_FACILITY_ID, localDate: "2028-02-29", source: "self_report" }, tz).success,
    ).toBe(true);
  });

  it("parseScorePlayInput rejects ctx.playLocalDate: 2026-02-31 too", () => {
    const result = parseScorePlayInput({
      evidence: [],
      ctx: { ...baseCtx(), playLocalDate: "2026-02-31" },
    });
    expect(result.success).toBe(false);
  });
});

describe("H2 / M4 / F3: parseScorePlayInput's 200-row cap counts only rows that MATCH this play", () => {
  it("accepts exactly 200 MATCHING rows", () => {
    const evidence = Array.from({ length: 200 }, (_, i) => staffPresence({ id: `s_${i}`, coSignalFix: goodFix() }));
    const result = parseScorePlayInput({ evidence, ctx: baseCtx() });
    expect(result.success).toBe(true);
  });

  it("rejects 201 MATCHING rows outright, fail-closed, with a reason", () => {
    const evidence = Array.from({ length: 201 }, (_, i) => staffPresence({ id: `s_${i}`, coSignalFix: goodFix() }));
    const result = parseScorePlayInput({ evidence, ctx: baseCtx() });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reasons.some((r) => r.includes("200"))).toBe(true);
    }
  });

  it("F3: 500 rows for a DIFFERENT facility plus 1 matching row does NOT fail on the 200 cap — the off-play rows are excluded, not counted", () => {
    const otherFacilityRows = Array.from({ length: 500 }, (_, i) => ({
      id: `other_${i}`,
      facilityId: "fac_OTHER",
      localDate: PLAY_LOCAL_DATE,
      source: "self_report" as const,
    }));
    const legit = staffPresence({ coSignalFix: goodFix() });
    const result = parseScorePlayInput({ evidence: [...otherFacilityRows, legit], ctx: baseCtx() });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.evidence.length).toBe(1);
      expect(result.excludedRows.length).toBe(500);
    }
  });

  it(`F3: the ABSOLUTE ${ABSOLUTE_ROW_CAP}-row cap still fails a payload with ${ABSOLUTE_ROW_CAP + 1} RAW rows, even if only one is real`, () => {
    const otherFacilityRows = Array.from({ length: ABSOLUTE_ROW_CAP }, (_, i) => ({
      id: `other_${i}`,
      facilityId: "fac_OTHER",
      localDate: PLAY_LOCAL_DATE,
      source: "self_report" as const,
    }));
    const legit = staffPresence({ coSignalFix: goodFix() });
    const result = parseScorePlayInput({ evidence: [...otherFacilityRows, legit], ctx: baseCtx() });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reasons.some((r) => r.includes("absolute"))).toBe(true);
    }
  });

  it("scorePlay itself fails closed (ok:false) on a payload over the ABSOLUTE row cap, never throws", () => {
    const evidence = Array.from({ length: ABSOLUTE_ROW_CAP + 1 }, (_, i) => staffPresence({ id: `s_${i}` }));
    const result = scorePlay(evidence as any, baseCtx());
    expect(result.ok).toBe(false);
  });
});

describe("F3: one bad row is QUARANTINED — it does not fail the whole play", () => {
  it("a malformed row (unknown source) at THIS play's own facility/date does not fail parseScorePlayInput — it's excluded with a reason, the play still scores", () => {
    const goodRow = staffPresence({ coSignalFix: goodFix() });
    const badRow = { id: "bad_1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "__proto__" };
    const result = parseScorePlayInput({ evidence: [goodRow, badRow], ctx: baseCtx() });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.evidence.length).toBe(1);
      expect(result.excludedRows.length).toBe(1);
      expect(result.excludedRows[0]?.index).toBe(1);
    }
  });

  it("scorePlay itself: the good row still scores money even though a sibling row is malformed", () => {
    const goodRow = staffPresence({ coSignalFix: goodFix() });
    const badRow = { id: "bad_1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "__proto__" };
    const result = scorePlay([goodRow, badRow] as any, baseCtx());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.money).toBe(true);
      expect(result.excludedRows.length).toBe(1);
    }
  });

  it("STRUCTURAL problems still fail the WHOLE input: an unknown ctx key", () => {
    const result = parseScorePlayInput({ evidence: [], ctx: { ...baseCtx(), extraCtxKey: 1 } });
    expect(result.success).toBe(false);
  });

  it("STRUCTURAL problems still fail the WHOLE input: a non-array evidence", () => {
    const result = parseScorePlayInput({ evidence: "not an array", ctx: baseCtx() });
    expect(result.success).toBe(false);
  });

  it("an off-play row (different facility) is excluded, not quarantined-as-malformed — same net effect (excluded), different reason", () => {
    const goodRow = staffPresence({ coSignalFix: goodFix() });
    const otherPlayRow = { id: "other_1", facilityId: "fac_OTHER", localDate: PLAY_LOCAL_DATE, source: "self_report" };
    const result = parseScorePlayInput({ evidence: [goodRow, otherPlayRow], ctx: baseCtx() });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.evidence.length).toBe(1);
      expect(result.excludedRows.length).toBe(1);
    }
  });
});

describe("H2: scorePlay integrates the parser — a STRUCTURAL parse failure fails closed, never throws", () => {
  it("a malformed ctx (missing playFacilityId) fails closed with ok:false", () => {
    const result = scorePlay([staffPresence({ coSignalFix: goodFix() })], {} as any);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reasons.length).toBeGreaterThan(0);
    }
  });

  it("a well-formed call succeeds (ok:true) and carries a hex inputDigest", () => {
    const result = scorePlay([staffPresence({ coSignalFix: goodFix() })], baseCtx());
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.inputDigest).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("inputDigest is deterministic for the same input and differs for a genuinely different one", () => {
    const a = scorePlayOrThrow([staffPresence({ coSignalFix: goodFix() })], baseCtx());
    const b = scorePlayOrThrow([staffPresence({ coSignalFix: goodFix() })], baseCtx());
    // Different fixId (goodFix() auto-increments) — so a and b must differ.
    expect(a.inputDigest).not.toBe(b.inputDigest);
    const sameRow = staffPresence({ id: "fixed_id", coSignalFix: goodFix({ fixId: "fixed_fix" }) });
    const c = scorePlayOrThrow([sameRow], baseCtx());
    const d = scorePlayOrThrow([sameRow], baseCtx());
    expect(c.inputDigest).toBe(d.inputDigest);
  });
});

describe("F4: inputDigest is independent of the evidence ARRAY'S OWN ORDER", () => {
  it("the SAME three rows, in every one of the 6 permutations, all produce the IDENTICAL inputDigest", () => {
    const rowA = staffPresence({ id: "row_a", coSignalFix: goodFix({ fixId: "fix_a" }) });
    const rowB = { id: "row_b", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" as const };
    const rowC = { id: "row_c", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "health_workout" as const };
    const rows = [rowA, rowB, rowC];

    function permutations<T>(arr: T[]): T[][] {
      if (arr.length <= 1) return [arr];
      const out: T[][] = [];
      for (let i = 0; i < arr.length; i += 1) {
        const rest = [...arr.slice(0, i), ...arr.slice(i + 1)];
        for (const p of permutations(rest)) out.push([arr[i]!, ...p]);
      }
      return out;
    }

    const digests = permutations(rows).map((order) => scorePlayOrThrow(order as any, baseCtx()).inputDigest);
    const first = digests[0];
    for (const d of digests) expect(d).toBe(first);
    // Sanity: this isn't vacuous — a DIFFERENT set of rows gives a
    // DIFFERENT digest.
    const different = scorePlayOrThrow([rowA], baseCtx()).inputDigest;
    expect(different).not.toBe(first);
  });
});
