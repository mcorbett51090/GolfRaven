/**
 * Fifth gate, M4:
 * - "Add a `default` branch to the classify switch so an unknown source
 *   contributes 0."
 * - "A null or undefined `token`/`coSignalFix`/`fix` contributes 0 and
 *   never throws."
 * - "Cap evidence rows per play at 200." (covered in `parse-evidence.test.ts`,
 *   since that's the parser's own job — this file covers the
 *   `classifyEvidenceRow`-direct defence-in-depth layer, which is what
 *   still matters if the parser is ever bypassed.)
 */
import { describe, expect, it } from "vitest";
import { classifyEvidenceRow } from "../src/internal/classify.js";
import { baseCtx, goodFix } from "./score-play-helpers.js";

describe("M4: an unknown/malformed evidence source hits the default branch — contributes 0, never throws", () => {
  it('source: "__proto__" (probe 10) contributes nothing and doesn\'t throw', () => {
    const row = {
      id: "weird_1",
      facilityId: baseCtx().playFacilityId,
      localDate: baseCtx().playLocalDate,
      source: "__proto__",
    };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
      expect(c.moneyEligible).toBe(false);
      expect(c.hard).toBe(false);
      expect(c.evidenceId).toBe("weird_1");
    }).not.toThrow();
  });

  it("source: undefined contributes nothing and doesn't throw", () => {
    const row = { id: "weird_2", facilityId: baseCtx().playFacilityId, localDate: baseCtx().playLocalDate, source: undefined };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });

  it("a row with NO id at all still returns a contribution (falls back to \"unknown\"), never throws", () => {
    const row = { facilityId: baseCtx().playFacilityId, localDate: baseCtx().playLocalDate, source: "totally_bogus" };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.evidenceId).toBe("unknown");
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });
});

describe("M4: null/undefined token/coSignalFix/fix contribute 0, never throw", () => {
  const facilityId = baseCtx().playFacilityId;
  const localDate = baseCtx().playLocalDate;

  it("staff_presence with coSignalFix: null", () => {
    const row = { id: "s1", facilityId, localDate, source: "staff_presence", scanAt: 0, coSignalFix: null };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.hard).toBe(false);
      expect(c.moneyEligible).toBe(false);
    }).not.toThrow();
  });

  it("booking with presenceFix: null", () => {
    const row = { id: "b1", facilityId, localDate, source: "booking", presenceFix: null };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.hard).toBe(false);
    }).not.toThrow();
  });

  it("receipt_green_fee with coSignalFix: null", () => {
    const row = { id: "r1", facilityId, localDate, source: "receipt_green_fee", status: "approved", coSignalFix: null };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.moneyEligible).toBe(false);
    }).not.toThrow();
  });

  it("foreground_checkin with fix: null (required field, violated at runtime)", () => {
    const row = { id: "c1", facilityId, localDate, source: "foreground_checkin", fix: null };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
      expect(c.moneyEligible).toBe(false);
    }).not.toThrow();
  });

  it("foreground_checkin with fix: undefined", () => {
    const row = { id: "c2", facilityId, localDate, source: "foreground_checkin", fix: undefined };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });

  it("foreground_dwell with checkinFix: null", () => {
    const row = { id: "d1", facilityId, localDate, source: "foreground_dwell", checkinFix: null, checkoutFix: goodFix(), apartMinutes: 100, holes: 18 };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });

  it("foreground_dwell with checkoutFix: null", () => {
    const row = { id: "d2", facilityId, localDate, source: "foreground_dwell", checkinFix: goodFix(), checkoutFix: null, apartMinutes: 100, holes: 18 };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });

  it("foreground_dwell with BOTH fixes null", () => {
    const row = { id: "d3", facilityId, localDate, source: "foreground_dwell", checkinFix: null, checkoutFix: null, apartMinutes: 100, holes: 18 };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });

  it("a fix object whose OWN token is null (not the fix itself) contributes 0, never throws", () => {
    const row = { id: "c3", facilityId, localDate, source: "foreground_checkin", fix: { ...goodFix(), token: null } };
    expect(() => {
      const c = classifyEvidenceRow(row as any, baseCtx());
      expect(c.badgeWeight).toBe(0);
    }).not.toThrow();
  });
});
