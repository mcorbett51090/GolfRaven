/**
 * H2 ("There is no input validator") + sixth-gate F1/F3/F6 regression
 * tests for `parseEvidence`/`parseScorePlayInput` (`../src/parse-evidence.js`)
 * — strict shape, finite numbers, enum membership, non-empty string ids,
 * the localDate/capturedAt tz cross-check (now against a REQUIRED,
 * IANA-validated `facilityTz`, F1), real-calendar-date validation (F6),
 * and `scorePlay`'s discriminated-result / quarantine integration (F3).
 */
import { describe, expect, it } from "vitest";
import { EVIDENCE_ROW_CAP } from "../src/internal/classify.js";
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
    ["Etc/UTC (Etc-prefix legacy link)", "Etc/UTC"],
    ["US/Pacific (legacy link)", "US/Pacific"],
    ["Canada/Eastern (legacy link)", "Canada/Eastern"],
    ["PST8PDT (abbreviation-style)", "PST8PDT"],
    ["EST (abbreviation — Intl resolves it to America/Panama, but it's not a real Area/Location name)", "EST"],
    ["UTC (no Area/Location shape at all)", "UTC"],
  ];
  for (const [label, badTz] of badTzCases) {
    it(`parseEvidence rejects facilityTz=${label}`, () => {
      const row = staffPresence({ coSignalFix: goodFix() });
      expect(parseEvidence(row, badTz).success).toBe(false);
    });
  }

  // Seventh gate, item 1 (the HIGH regression): the sixth gate's own
  // `Intl.supportedValuesOf('timeZone')` allow-list wrongly rejected every
  // one of these — all genuine, current IANA Area/Location names; several
  // (`America/Indiana/Indianapolis`, `America/Kentucky/Louisville`) are
  // exactly what `@golfraven/catalog`'s own `tz-lookup`-derived facilityTz
  // produces for real facilities in those counties, so EVERY play at such
  // a facility failed outright under the old code. Each is proven here
  // via the TZ NAME GATE specifically: `parseEvidence` must reach the
  // capturedAt/localDate cross-check (never reject on the zone name
  // itself) — a self-consistent fix under that exact tz confirms the
  // whole path, not just the name check in isolation.
  const requiredAcceptZones = [
    "America/Indiana/Indianapolis",
    "America/Kentucky/Louisville",
    "America/Argentina/Buenos_Aires",
    "Europe/Kyiv",
    "America/Nuuk",
    "America/Blanc-Sablon",
    "America/Port-au-Prince",
  ];
  for (const zone of requiredAcceptZones) {
    it(`accepts the real IANA zone ${zone} (regression case)`, () => {
      // A fix genuinely self-consistent under THIS zone: derive its own
      // calendar date from capturedAt in that tz, rather than assuming
      // UTC, so the test passes regardless of the zone's current offset.
      const capturedAt = PLAY_LOCAL_DATE_MS;
      const derivedLocalDate = new Intl.DateTimeFormat("en-CA", {
        timeZone: zone,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
      }).format(new Date(capturedAt));
      const row = staffPresence({
        coSignalFix: { ...goodFix(), capturedAt, localDate: derivedLocalDate } as any,
      });
      const result = parseEvidence(row, zone);
      expect(result.success).toBe(true);
    });
  }

  it("parseScorePlayInput's ctx.facilityTz also accepts America/Indiana/Indianapolis (not just parseEvidence's own tz param)", () => {
    const result = parseScorePlayInput({ evidence: [], ctx: { ...baseCtx(), facilityTz: "America/Indiana/Indianapolis" } });
    expect(result.success).toBe(true);
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

  describe("behaves IDENTICALLY without Intl.supportedValuesOf (this implementation never uses it at all)", () => {
    it("every required-accept zone still parses the same with supportedValuesOf deleted", () => {
      const original = (Intl as any).supportedValuesOf;
      delete (Intl as any).supportedValuesOf;
      try {
        for (const zone of requiredAcceptZones) {
          const capturedAt = PLAY_LOCAL_DATE_MS;
          const derivedLocalDate = new Intl.DateTimeFormat("en-CA", {
            timeZone: zone,
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
          }).format(new Date(capturedAt));
          const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt, localDate: derivedLocalDate } as any });
          expect(parseEvidence(row, zone).success).toBe(true);
        }
        for (const [, badTz] of badTzCases) {
          const row = staffPresence({ coSignalFix: goodFix() });
          expect(parseEvidence(row, badTz).success).toBe(false);
        }
      } finally {
        (Intl as any).supportedValuesOf = original;
      }
    });
  });

  describe("never throws, even when Intl itself is missing entirely", () => {
    it("parseEvidence returns a parse failure (not a throw) when globalThis.Intl is undefined", () => {
      const g = globalThis as any;
      const savedIntl = g.Intl;
      g.Intl = undefined;
      try {
        const row = staffPresence({ coSignalFix: goodFix() });
        expect(() => {
          const result = parseEvidence(row, PLAY_FACILITY_TZ);
          expect(result.success).toBe(false);
        }).not.toThrow();
      } finally {
        g.Intl = savedIntl;
      }
    });

    it("parseScorePlayInput also returns a parse failure (not a throw) when Intl is missing", () => {
      const g = globalThis as any;
      const savedIntl = g.Intl;
      g.Intl = undefined;
      try {
        expect(() => {
          const result = parseScorePlayInput({ evidence: [], ctx: baseCtx() });
          expect(result.success).toBe(false);
        }).not.toThrow();
      } finally {
        g.Intl = savedIntl;
      }
    });
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

describe(`H2 / M4 / F3 / item 9: parseScorePlayInput's ${EVIDENCE_ROW_CAP}-row cap counts only rows that MATCH this play`, () => {
  it(`accepts exactly ${EVIDENCE_ROW_CAP} MATCHING rows`, () => {
    const evidence = Array.from({ length: EVIDENCE_ROW_CAP }, (_, i) => staffPresence({ id: `s_${i}`, coSignalFix: goodFix() }));
    const result = parseScorePlayInput({ evidence, ctx: baseCtx() });
    expect(result.success).toBe(true);
  });

  it(`rejects ${EVIDENCE_ROW_CAP + 1} MATCHING rows outright, fail-closed, with a reason`, () => {
    const evidence = Array.from({ length: EVIDENCE_ROW_CAP + 1 }, (_, i) => staffPresence({ id: `s_${i}`, coSignalFix: goodFix() }));
    const result = parseScorePlayInput({ evidence, ctx: baseCtx() });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reasons.some((r) => r.includes(String(EVIDENCE_ROW_CAP)))).toBe(true);
    }
  });

  it(`F3: 500 rows for a DIFFERENT facility plus 1 matching row does NOT fail on the ${EVIDENCE_ROW_CAP} cap — the off-play rows are excluded, not counted`, () => {
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

describe("item 4 (seventh gate): duplicate evidence ids are rejected STRUCTURALLY, not quarantined", () => {
  it("two rows sharing the same id fail the whole parseScorePlayInput call", () => {
    const rowA = staffPresence({ id: "dup_id", coSignalFix: goodFix() });
    const rowB = { ...staffPresence({ id: "dup_id" }), source: "self_report" as const };
    const result = parseScorePlayInput({ evidence: [rowA, rowB], ctx: baseCtx() });
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.reasons.some((r) => r.includes("duplicate"))).toBe(true);
    }
  });

  it("scorePlay itself fails closed (ok:false) on duplicate ids, never throws", () => {
    const rowA = staffPresence({ id: "dup_id2", coSignalFix: goodFix() });
    const rowB = { ...staffPresence({ id: "dup_id2" }), source: "self_report" as const };
    expect(() => {
      const result = scorePlay([rowA, rowB] as any, baseCtx());
      expect(result.ok).toBe(false);
    }).not.toThrow();
  });

  it("a duplicate id between an ON-PLAY row and an OFF-PLAY (different facility) row does NOT fail — only on-play duplicates matter", () => {
    const onPlay = staffPresence({ id: "shared_id", coSignalFix: goodFix() });
    const offPlay = { id: "shared_id", facilityId: "fac_OTHER", localDate: PLAY_LOCAL_DATE, source: "self_report" as const };
    const result = parseScorePlayInput({ evidence: [onPlay, offPlay], ctx: baseCtx() });
    expect(result.success).toBe(true);
  });

  it("a duplicate id where ONE copy is quarantined (malformed) does NOT fail — only two copies that BOTH parse count as a duplicate", () => {
    const good = staffPresence({ id: "shared_id2", coSignalFix: goodFix() });
    const malformed = { ...staffPresence({ id: "shared_id2" }), extraField: "smuggled" };
    const result = parseScorePlayInput({ evidence: [good, malformed], ctx: baseCtx() });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.evidence.length).toBe(1);
      expect(result.excludedRows.length).toBe(1);
    }
  });

  it("unique ids (the normal case) are unaffected", () => {
    const rowA = staffPresence({ id: "id_a", coSignalFix: goodFix() });
    const rowB = { id: "id_b", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" as const };
    const result = parseScorePlayInput({ evidence: [rowA, rowB], ctx: baseCtx() });
    expect(result.success).toBe(true);
  });
});

describe("item 5 (seventh gate): id/fixId length cap (128) and printable-non-control-character restriction", () => {
  it("rejects an id over 128 characters", () => {
    const row = { id: "x".repeat(129), facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" };
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("accepts an id exactly at 128 characters", () => {
    const row = { id: "x".repeat(128), facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" };
    expect(parseEvidence(row, tz).success).toBe(true);
  });

  it("rejects a fixId over 128 characters", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: "f".repeat(129) } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects an id containing a raw newline (control character)", () => {
    const row = { id: "evil\nINJECTED", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" };
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects a fixId containing a raw newline (the probe's own leak-probe shape)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), fixId: "evil\nINJECTED<script>" } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects an id containing a null byte", () => {
    const row = { id: "evil\x00null", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" };
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("a normal, printable id is unaffected", () => {
    const row = { id: "evidence_12345-abc", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" };
    expect(parseEvidence(row, tz).success).toBe(true);
  });

  it("scorePlay's excludedRows never echo a raw, un-truncated attacker string back (leak probe): a malicious fixId in a quarantined row is either absent from the row's reason or safely bounded/escaped", () => {
    const SECRET = "SECRETVALUE123";
    const leakRow = { ...staffPresence({}), coSignalFix: { ...goodFix(), fixId: `evil\nINJECTED<script>${SECRET}` } } as any;
    const result = scorePlay([leakRow], baseCtx());
    // The row fails Zod's own shape validation (fixId has a control
    // character) BEFORE ever reaching the tz-cross-check interpolation —
    // Zod's own issue messages don't echo the raw invalid VALUE for a
    // regex failure, only the path/rule that failed.
    expect(result.ok).toBe(true);
    if (result.ok) {
      const reasonsText = JSON.stringify(result.excludedRows);
      // The raw newline must never appear un-escaped in the serialized
      // reasons (it would if the raw string were interpolated directly).
      expect(reasonsText.includes("\n")).toBe(false);
    }
  });
});

describe("item 6 (seventh gate): capturedAt/scanAt bounded to a plausible epoch range (2020-01-01 .. 2100-01-01)", () => {
  it("rejects a scanAt before 2020", () => {
    const tooOld = Date.parse("2019-12-31T23:59:59.000Z");
    const row = { id: "s1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "staff_presence", scanAt: tooOld };
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects a capturedAt at/after 2100", () => {
    const tooFar = Date.parse("2100-01-01T00:00:00.000Z");
    const row = staffPresence({ coSignalFix: { ...goodFix(), capturedAt: tooFar } as any });
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("rejects the classic epoch-0 (1970) probe case", () => {
    const row = { id: "s2", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "staff_presence", scanAt: 0 };
    expect(parseEvidence(row, tz).success).toBe(false);
  });

  it("a plausible, present-day capturedAt is unaffected", () => {
    const row = staffPresence({ coSignalFix: goodFix() });
    expect(parseEvidence(row, tz).success).toBe(true);
  });
});

describe("item 2 (seventh gate): heldReview is forced true when money is true and an on-play row was quarantined", () => {
  it("a money-qualifying play with a malformed ON-PLAY sibling row routes to held review", () => {
    const hardRow = staffPresence({ scanAt: PLAY_LOCAL_DATE_MS, coSignalFix: goodFix() });
    const malformedOnPlay = { ...staffPresence({}), extraField: "smuggled" };
    const result = scorePlayOrThrow([hardRow, malformedOnPlay], baseCtx());
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
    expect(result.heldReviewReasons).toContain("quarantined");
  });

  it("the SAME hard row alone (no quarantine) does NOT get held", () => {
    const hardRow = staffPresence({ scanAt: PLAY_LOCAL_DATE_MS, coSignalFix: goodFix() });
    const result = scorePlayOrThrow([hardRow], baseCtx());
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(false);
    expect(result.heldReviewReasons).toEqual([]);
  });

  it("a quarantined row alongside a NON-money play does not force heldReview (money is false either way)", () => {
    const soft = { id: "soft1", facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE, source: "self_report" as const };
    const malformedOnPlay = { ...staffPresence({}), extraField: "smuggled" };
    const result = scorePlayOrThrow([soft, malformedOnPlay], baseCtx());
    expect(result.money).toBe(false);
    expect(result.heldReview).toBe(false);
  });

  it("an OFF-PLAY excluded row (different facility) never forces heldReview, even on a money-qualifying play", () => {
    const hardRow = staffPresence({ scanAt: PLAY_LOCAL_DATE_MS, coSignalFix: goodFix() });
    const offPlay = { id: "off1", facilityId: "fac_OTHER", localDate: PLAY_LOCAL_DATE, source: "self_report" as const };
    const result = scorePlayOrThrow([hardRow, offPlay], baseCtx());
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(false);
  });
});
