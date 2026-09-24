/**
 * P3b re-gate on commit b95bbfc — 4 blocking findings + should-fix items,
 * each reproduced here as a failing-first regression before its fix (the
 * fixes themselves live in `src/score-play.ts`, cited inline below).
 */
import { describe, expect, it } from "vitest";
import { scorePlay } from "../src/score-play.js";
import {
  PLAY_FACILITY_ID,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  booking,
  checkin,
  dwell,
  goodFix,
  receipt,
  staffPresence,
  tokenState,
  vendorRound,
} from "./score-play-helpers.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const OFF_DATE = "2026-05-31"; // the day before PLAY_LOCAL_DATE

describe("Blocking 1: check-ins/dwells from another date must not count toward money", () => {
  it("fixture #14 + an off-date check-in stays at 0.84, no money (the off-date row contributes nothing)", () => {
    const result = scorePlay(
      [
        checkin({ fix: goodFix({ token: tokenState("unattestable") }) }),
        receipt({ status: "approved", coSignalFix: goodFix({ token: tokenState("unattestable") }) }),
        checkin({ localDate: OFF_DATE, fix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - DAY_MS }) }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.84);
    expect(result.score_monetary).toBe(0.84);
    expect(result.money).toBe(false);
  });

  it("a dwell from the previous day contributes nothing", () => {
    const priorDayDwell = scorePlay(
      [
        dwell({
          localDate: OFF_DATE,
          checkinFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - DAY_MS }),
          checkoutFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - DAY_MS + 95 * 60_000 }),
        }),
      ],
      baseCtx(),
    );
    expect(priorDayDwell.score_badge).toBe(0);
    expect(priorDayDwell.money).toBe(false);
  });
});

describe("Blocking 2: staff-scan and vendor rows must be checked against the play date", () => {
  it("a Garmin sensor round dated off-play plus an unattestable check-in on the play date is NOT 0.88/money (P8 AT(6))", () => {
    const result = scorePlay(
      [
        vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true, localDate: "2026-06-02" }),
        checkin({ fix: goodFix({ token: tokenState("unattestable") }) }),
      ],
      baseCtx(),
    );
    // The off-date vendor round is dropped entirely — only the unattestable
    // check-in remains: 0.30 × 0.6 = 0.18.
    expect(result.score_badge).toBeCloseTo(0.18, 10);
    expect(result.score_monetary).toBeCloseTo(0.18, 10);
    expect(result.money).toBe(false);
  });

  it("a staff scan whose scan/co-signal/row are all on D+1, plus a check-in on D, is NOT hard/money", () => {
    const nextDayMs = PLAY_LOCAL_DATE_MS + DAY_MS;
    const result = scorePlay(
      [
        staffPresence({
          localDate: "2026-06-02",
          scanAt: nextDayMs,
          coSignalFix: goodFix({ localDate: "2026-06-02", capturedAt: nextDayMs, facilityId: PLAY_FACILITY_ID }),
        }),
        checkin({ fix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.contributions.some((c) => c.hard)).toBe(false);
    expect(result.money).toBe(false);
    // Only the on-date check-in (0.30) remains — the D+1 staff row is
    // dropped entirely by the top-level date filter.
    expect(result.score_badge).toBe(0.3);
  });
});

describe("Blocking 3: a user-picked course must never reach money through a hard class", () => {
  it("staffPresence user-picked, otherwise a perfect hard co-signal: money must be false", () => {
    const result = scorePlay([staffPresence({ courseDisambiguatedBy: "user", coSignalFix: goodFix() })], baseCtx());
    expect(result.score_monetary).toBe(0);
    expect(result.contributions.every((c) => !c.hard)).toBe(true);
    expect(result.money).toBe(false);
  });

  it("booking user-picked + a same-day check-in: money must be false", () => {
    const result = scorePlay([booking({ courseDisambiguatedBy: "user" }), checkin({})], baseCtx());
    expect(result.score_monetary).toBe(0);
    expect(result.money).toBe(false);
  });
});

describe("Blocking 4: heldReview must reflect the fix that actually established the winning result", () => {
  it("staff scan with an unattestable co-signal, plus an UNRELATED attested check-in 5h later — heldReview stays true", () => {
    const fiveHoursLater = PLAY_LOCAL_DATE_MS + 5 * 60 * 60_000;
    const result = scorePlay(
      [
        staffPresence({ coSignalFix: goodFix({ token: tokenState("unattestable") }) }),
        checkin({ fix: goodFix({ token: tokenState("attested"), capturedAt: fiveHoursLater }) }),
      ],
      baseCtx(),
    );
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });
});

describe("Should-fix: staff-scan absorption from an external fix", () => {
  it("staffPresence({}) + an unattestable check-in at +3 min is hard, 0.95, heldReview", () => {
    const result = scorePlay(
      [
        staffPresence({}),
        checkin({ fix: goodFix({ token: tokenState("unattestable"), capturedAt: PLAY_LOCAL_DATE_MS + 3 * 60_000 }) }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.95);
    expect(result.score_monetary).toBe(0.95);
    expect(result.contributions.some((c) => c.hard)).toBe(true);
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });
});

describe("Should-fix: a booking with a BAD inline fix still becomes hard through a same-day receipt co-signal (plan line 967)", () => {
  it("booking's own inline fix fails, but a paymentRef-correlated receipt's co-signal qualifies", () => {
    const result = scorePlay(
      [
        booking({
          paymentRef: "pay_bad_inline",
          presenceFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - DAY_MS }), // bad: off-date
        }),
        receipt({ paymentRef: "pay_bad_inline", status: "approved", coSignalFix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.9);
    expect(result.score_monetary).toBe(0.9);
    expect(result.contributions.some((c) => c.hard)).toBe(true);
    expect(result.money).toBe(true);
  });
});

describe("Should-fix: order independence — a hard result must not depend on row order", () => {
  it("[staffHard, booking] and [booking, staffHard] score identically when both would independently be hard", () => {
    // Construct a scenario where staff and booking end up in the SAME
    // derived group: both absorb the SAME external fix (no inline fix on
    // either), so a fixId-free but date/window-shared external check-in
    // links them transitively.
    const sharedFix = goodFix();
    const staffRow = staffPresence({ scanAt: PLAY_LOCAL_DATE_MS });
    const bookingRow = booking({});
    const linkingCheckin = checkin({ fix: sharedFix });

    const forward = scorePlay([staffRow, bookingRow, linkingCheckin], baseCtx());
    const reversed = scorePlay([bookingRow, staffRow, linkingCheckin], baseCtx());

    expect(forward.score_badge).toBe(reversed.score_badge);
    expect(forward.score_monetary).toBe(reversed.score_monetary);
    expect(forward.money).toBe(reversed.money);
    // Both orders should resolve to the HIGHER-weight hard class
    // (staff_presence_hard, 0.95), deterministically.
    expect(forward.score_badge).toBe(0.95);
    expect(reversed.score_badge).toBe(0.95);
  });
});

describe("Should-fix: deviceRowFixGateOk fails closed on an unverified facility", () => {
  it("a check-in fix at an unverified facility contributes nothing", () => {
    const result = scorePlay([checkin({ fix: goodFix({ verificationTier: "unverified" }) })], baseCtx());
    expect(result.score_badge).toBe(0);
  });

  it("a check-in fix at a listed-verified (radius) facility still contributes, capped", () => {
    const result = scorePlay(
      [checkin({ fix: goodFix({ verificationTier: "listed-verified", geometryKind: "radius" }) })],
      baseCtx(),
    );
    expect(result.score_badge).toBeGreaterThan(0);
    expect(result.score_badge).toBeLessThanOrEqual(0.5);
  });
});

describe("Should-fix: apartMinutes is derived from the two fixes, not trusted from the stored field", () => {
  it("a stored apartMinutes of 95 is overridden by a derived 45 (the fixes actually disagree) — dwell scores 0", () => {
    const result = scorePlay(
      [
        dwell({
          apartMinutes: 95, // claims 95, but the fixes below are only 45 min apart
          checkinFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS }),
          checkoutFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 45 * 60_000 }),
          holes: 18,
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0); // 45 < 90 min threshold for 18 holes
  });

  it("a stored apartMinutes of 10 is overridden by a derived 95 (the fixes actually agree with reality) — dwell qualifies", () => {
    const result = scorePlay(
      [
        dwell({
          apartMinutes: 10, // wrong on paper
          checkinFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS }),
          checkoutFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 95 * 60_000 }),
          holes: 18,
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBeGreaterThan(0);
  });
});
