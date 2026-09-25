/**
 * Fifth gate, M2: "Require Number.isFinite on capturedAt and scanAt. Cap
 * dwell duration: anything over 12h, or a derived negative duration, means
 * the dwell is ineligible. Test the Infinity and 1e300 probe cases."
 */
import { describe, expect, it } from "vitest";
import { MAX_DWELL_MINUTES, classifyEvidenceRow } from "../src/internal/classify.js";
import type { Evidence } from "../src/score-play.js";
import { PLAY_LOCAL_DATE_MS, baseCtx, dwell, goodFix, scorePlayOrThrow } from "./score-play-helpers.js";

describe("M2: foreground_dwell — Infinity/1e300 capturedAt never produces an eligible dwell", () => {
  it("checkoutFix.capturedAt: Infinity — classifyEvidenceRow never throws, contributes 0 (probe 7)", () => {
    const row = dwell({ checkoutFix: goodFix({ capturedAt: Infinity }) });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });

  it("checkoutFix.capturedAt: 1e300 — classifyEvidenceRow never throws, contributes 0 (probe 7b)", () => {
    const row = dwell({ checkoutFix: goodFix({ capturedAt: 1e300 }) });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });

  it("scorePlay's own top-level call is safe for both — never throws; the row is quarantined (not a whole-play failure), money stays false", () => {
    for (const capturedAt of [Infinity, 1e300]) {
      const result = scorePlayOrThrow(
        [dwell({ checkoutFix: goodFix({ capturedAt }) }) as Evidence],
        baseCtx(),
      );
      expect(result.money).toBe(false);
    }
  });
});

describe("M2: a dwell over MAX_DWELL_MINUTES (12h) is ineligible, even with two individually well-formed (finite) fixes", () => {
  it(`a dwell ${MAX_DWELL_MINUTES + 1} minutes apart is ineligible`, () => {
    const row = dwell({
      checkinFix: goodFix(),
      checkoutFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + (MAX_DWELL_MINUTES + 1) * 60_000 }),
      apartMinutes: MAX_DWELL_MINUTES + 1,
      holes: 18,
    });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });

  it(`a dwell exactly at MAX_DWELL_MINUTES (12h, inclusive) is still eligible`, () => {
    const row = dwell({
      checkinFix: goodFix(),
      checkoutFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + MAX_DWELL_MINUTES * 60_000 }),
      apartMinutes: MAX_DWELL_MINUTES,
      holes: 18,
    });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBeGreaterThan(0);
  });
});

describe("M2: a NEGATIVE derived duration (checkout before checkin) is ineligible, never folded into \"apart enough\" by Math.abs", () => {
  it("checkoutFix.capturedAt BEFORE checkinFix.capturedAt is ineligible even though |delta| exceeds the threshold", () => {
    const row = dwell({
      checkinFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 100 * 60_000 }),
      checkoutFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS }), // BEFORE checkin
      apartMinutes: 100,
      holes: 18,
    });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });
});

describe("M2: Number.isFinite on scanAt — a non-finite scanAt never satisfies the staff hard-window", () => {
  it("scanAt: Infinity never resolves hard, never throws", () => {
    const row: Evidence = {
      id: "s1",
      facilityId: goodFix().facilityId,
      localDate: goodFix().localDate,
      source: "staff_presence",
      scanAt: Infinity,
      coSignalFix: goodFix(),
    };
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
  });

  it("scanAt: NaN never resolves hard, never throws", () => {
    const row: Evidence = {
      id: "s2",
      facilityId: goodFix().facilityId,
      localDate: goodFix().localDate,
      source: "staff_presence",
      scanAt: NaN,
      coSignalFix: goodFix(),
    };
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
  });
});
