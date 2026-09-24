/**
 * Fifth gate, H1: "Attestation, challenge and simulated checks use
 * deny-lists, so they fail open." Every case below is drawn directly from
 * the security reviewer's probe files (`/tmp/srprobe/probe.test.ts` and
 * `probe4.test.ts`), turned into a real regression. Tested at TWO layers:
 *
 * 1. `resolveFixGrade`/`isQualityCoSignalFix`/`deviceRowFixGateOk`/
 *    `deviceFixMultiplier`/`deviceRowMoneyEligible` directly (via
 *    `classifyEvidenceRow`, imported from `../src/internal/classify.js` —
 *    the same "tests reach it directly" path the fourth gate established)
 *    — this is the defence-in-depth layer H1 asked for, and it's what a
 *    `parseEvidence`/`parseScorePlayInput` bypass would still be safe
 *    against.
 * 2. `scorePlay` (the public, parser-fronted entry point) — every one of
 *    these malformed shapes is now ALSO rejected outright at the parser
 *    (H2), which is the stronger, earlier-blocking outcome; asserted
 *    separately so a future change to the parser's strictness doesn't
 *    silently stop testing layer 1.
 */
import { describe, expect, it } from "vitest";
import { classifyEvidenceRow, resolveFixGrade } from "../src/internal/classify.js";
import { scorePlay } from "../src/score-play.js";
import { baseCtx, goodFix, staffPresence, vendorRound } from "./score-play-helpers.js";

describe("H1: resolveFixGrade is an allow-list — anything not {attested, unattestable} is \"failed\"", () => {
  it('token:{present:true} with no grade at all resolves to "failed"', () => {
    expect(resolveFixGrade({ present: true } as any)).toBe("failed");
  });
  it('token:{present:true, grade:"bogus"} resolves to "failed", not "bogus"', () => {
    expect(resolveFixGrade({ present: true, grade: "bogus" } as any)).toBe("failed");
  });
  it('token:{present:"false", ...} — a TRUTHY STRING, not the boolean false — resolves to "failed"', () => {
    expect(resolveFixGrade({ present: "false", hardwareSupportsAttestation: true } as any)).toBe("failed");
  });
  it("token: null resolves to \"failed\", never throws", () => {
    expect(resolveFixGrade(null as any)).toBe("failed");
  });
  it("token: undefined resolves to \"failed\", never throws", () => {
    expect(resolveFixGrade(undefined as any)).toBe("failed");
  });
  it('the CONTROL case still works: present:false, hardwareSupportsAttestation:false -> "unattestable"', () => {
    expect(resolveFixGrade({ present: false, hardwareSupportsAttestation: false })).toBe("unattestable");
  });
  it('the CONTROL case still works: present:true, grade:"attested" -> "attested"', () => {
    expect(resolveFixGrade({ present: true, grade: "attested" })).toBe("attested");
  });
});

describe("H1: a staff_presence row with a garbage token never becomes hard/money-eligible (gate's own exploit shapes)", () => {
  const rowWith = (token: unknown) =>
    staffPresence({ scanAt: undefined as any, coSignalFix: { ...goodFix(), token } as any });

  it('token:{present:true} (no grade) — classifyEvidenceRow', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), token: { present: true } } as any });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
    expect(c.moneyEligible).toBe(false);
  });

  it('token:{present:true, grade:"bogus"} — classifyEvidenceRow (probe 11d)', () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), token: { present: true, grade: "bogus" } } as any });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
    expect(c.moneyEligible).toBe(false);
  });

  it('token.present:"no" (truthy string) with grade undefined — classifyEvidenceRow (probe 11e)', () => {
    const row = staffPresence({
      coSignalFix: { ...goodFix(), token: { present: "no", hardwareSupportsAttestation: true } } as any,
    });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
    expect(c.moneyEligible).toBe(false);
  });

  it('token.present:"false" (truthy string) — classifyEvidenceRow (probe4)', () => {
    const row = staffPresence({
      coSignalFix: { ...goodFix(), token: { present: "false", hardwareSupportsAttestation: true } } as any,
    });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
    expect(c.moneyEligible).toBe(false);
  });

  it("SAME shapes, through the public scorePlay entry point, all fail closed via the parser (H2)", () => {
    for (const token of [
      { present: true },
      { present: true, grade: "bogus" },
      { present: "no", hardwareSupportsAttestation: true },
    ]) {
      const result = scorePlay(
        [staffPresence({ coSignalFix: { ...goodFix(), token } as any }) as any],
        baseCtx(),
      );
      expect(result.money).toBe(false);
      expect(result.reasons).toBeDefined();
    }
  });
});

describe("H1: challenge is an allow-list ({live, prefetched}) — undefined/bogus is never a valid co-signal", () => {
  it("challenge: undefined never satisfies the staff hard-window (gate's own exploit)", () => {
    const row = staffPresence({ coSignalFix: { ...goodFix(), challenge: undefined } as any });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
    expect(c.moneyEligible).toBe(false);
  });

  it('challenge: "none" (control) still fails the same way', () => {
    const row = staffPresence({ coSignalFix: goodFix({ challenge: "none" }) });
    const c = classifyEvidenceRow(row, baseCtx());
    expect(c.hard).toBe(false);
  });

  it("a foreground_checkin whose fix has challenge: undefined pays the ×0.6 unattestable-or-no-challenge penalty, not full weight (probe4's own case)", () => {
    // Isolate the multiplier: grade stays "attested" (so the ONLY thing
    // suppressing weight is the challenge check), simulated stays false.
    const row = {
      id: "checkin_1",
      facilityId: (goodFix() as any).facilityId,
      localDate: goodFix().localDate,
      source: "foreground_checkin" as const,
      fix: { ...goodFix(), challenge: undefined } as any,
    };
    const c = classifyEvidenceRow(row as any, baseCtx());
    // Full weight would be 0.30; the no-challenge penalty must apply.
    expect(c.badgeWeight).toBeLessThan(0.3);
    expect(c.badgeWeight).toBeCloseTo(0.3 * 0.6, 10);
  });
});

describe("H1: simulated is an allow-list (=== false) — undefined never counts as \"not simulated\" (gate's own exploit)", () => {
  it("a receipt co-signal with simulated: undefined is never money-eligible", () => {
    const row = {
      id: "r1",
      facilityId: goodFix().facilityId,
      localDate: goodFix().localDate,
      source: "receipt_green_fee" as const,
      status: "approved" as const,
      coSignalFix: { ...goodFix(), simulated: undefined } as any,
    };
    const c = classifyEvidenceRow(row as any, baseCtx());
    expect(c.moneyEligible).toBe(false);
  });

  it("insideBuffer: 'true' (a string, not the boolean) is never treated as inside the buffer", () => {
    const row = {
      id: "r2",
      facilityId: goodFix().facilityId,
      localDate: goodFix().localDate,
      source: "receipt_green_fee" as const,
      status: "approved" as const,
      coSignalFix: { ...goodFix(), insideBuffer: "true" } as any,
    };
    const c = classifyEvidenceRow(row as any, baseCtx());
    expect(c.moneyEligible).toBe(false);
  });

  it("fromApp: 'yes' (a truthy string, not the boolean) is never treated as fromApp", () => {
    const row = {
      id: "r3",
      facilityId: goodFix().facilityId,
      localDate: goodFix().localDate,
      source: "receipt_green_fee" as const,
      status: "approved" as const,
      coSignalFix: { ...goodFix(), fromApp: "yes" } as any,
    };
    const c = classifyEvidenceRow(row as any, baseCtx());
    expect(c.moneyEligible).toBe(false);
  });
});

describe("H1: verificationTier is an allow-list ({listed-verified, play-verified}) at the device-row gate", () => {
  it('deviceRowFixGateOk rejects a bogus verificationTier, not just "unverified" specifically', () => {
    const row = {
      id: "c1",
      facilityId: goodFix().facilityId,
      localDate: goodFix().localDate,
      source: "foreground_checkin" as const,
      fix: { ...goodFix(), verificationTier: "bogus-tier" } as any,
    };
    const c = classifyEvidenceRow(row as any, baseCtx());
    expect(c.badgeWeight).toBe(0);
    expect(c.moneyEligible).toBe(false);
  });
});
