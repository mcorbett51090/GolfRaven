/**
 * P3b third re-gate on commit 2989ba8 — 2 blocking findings + should-fix
 * items, each reproduced here as a failing-first regression before its
 * fix in `src/score-play.ts` / `test/score-play-oracle.ts`.
 */
import { describe, expect, it } from "vitest";
import { classify, scorePlay, type Evidence } from "../src/score-play.js";
import {
  PLAY_FACILITY_ID,
  PLAY_LOCAL_DATE,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  booking,
  checkin,
  goodFix,
  tokenState,
  vendorRound,
} from "./score-play-helpers.js";
import { oracle } from "./score-play-oracle.js";

const OFF_DATE = "2026-05-31";

describe("Blocking 1: heldReview must consider the presence fix, not only the money-merged set", () => {
  it("Garmin sensor round (0.85) + staff scan whose unattestable co-signal is OUTSIDE its own window (soft) — held true", () => {
    const result = scorePlay(
      [
        vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true }),
        {
          id: "staff_soft",
          facilityId: PLAY_FACILITY_ID,
          localDate: PLAY_LOCAL_DATE,
          source: "staff_presence",
          scanAt: PLAY_LOCAL_DATE_MS,
          coSignalFix: goodFix({ token: tokenState("unattestable"), capturedAt: PLAY_LOCAL_DATE_MS + 30 * 60_000 }),
        },
      ],
      baseCtx(),
    );
    // The staff scan's co-signal is 30 min away — outside its own ±10 min
    // window, so it stays `staff_presence_soft` (never hard, never
    // money-eligible) — but it's STILL the only thing making
    // `presence_signal` true, and it's unattestable.
    expect(result.contributions.every((c) => !c.hard)).toBe(true);
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });

  it("Garmin sensor round + a user-picked unattestable check-in — held true", () => {
    const result = scorePlay(
      [
        vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true }),
        checkin({ courseDisambiguatedBy: "user", fix: goodFix({ token: tokenState("unattestable") }) }),
      ],
      baseCtx(),
    );
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });

  it("mutation guard: forcing `!hasAttested && hasUnattestable` to `false` in the non-hard branch alone would NOT be caught without the presence leg", () => {
    // A scenario where the SCORE leg (moneyMerged) is unattestable-only
    // AND reaches money, while an INDEPENDENT attested fix (on a
    // user-picked, money-excluded row) covers presence — isolates the
    // score-leg computation specifically (see should-fix mutation #3).
    const result = scorePlay(
      [
        {
          id: "receipt_unatt",
          facilityId: PLAY_FACILITY_ID,
          localDate: PLAY_LOCAL_DATE,
          source: "receipt_green_fee",
          status: "approved",
          coSignalFix: goodFix({ token: tokenState("unattestable") }),
        },
        booking({ presenceFix: goodFix({ simulated: true }) }), // bad inline fix: stays booking_alone, no absorption
        checkin({ courseDisambiguatedBy: "user", fix: goodFix() }), // attested, presence-only
      ],
      baseCtx(),
    );
    expect(result.score_monetary).toBeGreaterThanOrEqual(0.85);
    expect(result.contributions.every((c) => !c.hard)).toBe(true);
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });
});

describe("Blocking 2: the oracle is fix-attributes-only — no row-level or user-pick clause", () => {
  it("Garmin sensor round + a user-picked check-in: money=true and oracle(E)=true", () => {
    const evidence: Evidence[] = [
      vendorRound("garmin", { vendorCourseMapped: true, sensorProvenance: true }),
      checkin({ courseDisambiguatedBy: "user", fix: goodFix() }),
    ];
    const ctx = baseCtx();
    const result = scorePlay(evidence, ctx);
    expect(result.money).toBe(true);
    expect(oracle(evidence, ctx)).toBe(true);
  });

  it("fixture #16 shape: a user-picked fix alone still satisfies the oracle (plan line 933)", () => {
    const evidence: Evidence[] = [checkin({ courseDisambiguatedBy: "user", fix: goodFix() })];
    const ctx = baseCtx();
    expect(oracle(evidence, ctx)).toBe(true);
  });
});

describe("Should-fix: heldReview is order-independent across TWO INDEPENDENT hard contributions", () => {
  it("[unattestable staff-hard, attested booking-hard] and the reverse both give heldReview=false", () => {
    const staffHard: Evidence = {
      id: "staff_hard",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "staff_presence",
      scanAt: PLAY_LOCAL_DATE_MS,
      coSignalFix: goodFix({ token: tokenState("unattestable") }),
    };
    const bookingHard: Evidence = booking({ presenceFix: goodFix({ token: tokenState("attested") }) });

    const forward = scorePlay([staffHard, bookingHard], baseCtx());
    const reversed = scorePlay([bookingHard, staffHard], baseCtx());

    expect(forward.money).toBe(true);
    expect(reversed.money).toBe(true);
    // An attested hard proof exists (booking) even though an unattestable
    // one also exists (staff) — the reward is soundly backed either way,
    // so this must NOT be held, regardless of array order.
    expect(forward.heldReview).toBe(false);
    expect(reversed.heldReview).toBe(false);
  });
});

describe("Should-fix: verificationTier must be strictly play-verified for money (build plan §4.2's own tier table)", () => {
  it("#14 + a check-in whose fix reports listed-verified/polygon (an inconsistent combination) never reaches money", () => {
    const result = scorePlay(
      [
        checkin({ fix: goodFix({ token: tokenState("unattestable") }) }),
        {
          id: "receipt_14",
          facilityId: PLAY_FACILITY_ID,
          localDate: PLAY_LOCAL_DATE,
          source: "receipt_green_fee",
          status: "approved",
          coSignalFix: goodFix({ token: tokenState("unattestable") }),
        },
        checkin({ fix: goodFix({ verificationTier: "listed-verified", geometryKind: "polygon" }) }),
      ],
      baseCtx(),
    );
    const badTierContribution = result.contributions.find(
      (c) => c.classId === "foreground_checkin" && c.badgeWeight === 0.3,
    );
    expect(badTierContribution?.moneyEligible).toBe(false);
  });

  it("a bare listed-verified/polygon check-in alone is never money-eligible", () => {
    const result = scorePlay([checkin({ fix: goodFix({ verificationTier: "listed-verified", geometryKind: "polygon" }) })], baseCtx());
    expect(result.score_monetary).toBe(0);
    expect(result.money).toBe(false);
  });
});

describe("Should-fix: the hard winner is chosen AFTER the user-pick cap, not before", () => {
  it("a user-picked staff-hard candidate (raw 0.95) must not beat a non-user-picked booking-hard candidate (raw 0.90)", () => {
    const sharedFix = goodFix();
    const staffRow: Evidence = {
      id: "staff_up",
      facilityId: PLAY_FACILITY_ID,
      localDate: PLAY_LOCAL_DATE,
      source: "staff_presence",
      scanAt: PLAY_LOCAL_DATE_MS,
      courseDisambiguatedBy: "user",
      // No inline fix — absorbs `sharedFix` via the generic fallback.
    };
    const bookingRow: Evidence = booking({}); // no inline fix, not user-picked — also absorbs
    const linkingCheckin = checkin({ fix: sharedFix });

    const result = scorePlay([staffRow, bookingRow, linkingCheckin], baseCtx());
    // Without the fix: the raw-weight comparison picks staff (0.95 > 0.90)
    // as the group's hard winner, THEN the user-pick cap strips it to
    // `hard: false, moneyEligible: false` — discarding the whole group
    // (booking's legitimate claim included) down to badgeWeight 0.50 and
    // score_monetary 0. With the fix: booking wins the selection outright.
    expect(result.score_monetary).toBe(0.9);
    expect(result.money).toBe(true);
    expect(result.contributions.some((c) => c.hard && c.classId === "booking_hard")).toBe(true);
  });
});

describe("Defence-in-depth: class-level date/facility anchors inside classify(), unit-tested directly (bypassing scorePlay's top-level filter)", () => {
  it("classify() alone rejects a booking row whose OWN localDate disagrees with ctx.playLocalDate", () => {
    const row: Evidence = booking({ localDate: OFF_DATE, presenceFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - 24 * 60 * 60 * 1000 }) });
    const contribution = classify(row, baseCtx());
    expect(contribution.classId).toBe("booking_alone");
    expect(contribution.hard).toBe(false);
  });

  it("classify() alone rejects a receipt row whose OWN localDate disagrees with ctx.playLocalDate", () => {
    const row: Evidence = {
      id: "r_off",
      facilityId: PLAY_FACILITY_ID,
      localDate: OFF_DATE,
      source: "receipt_green_fee",
      status: "approved",
      coSignalFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - 24 * 60 * 60 * 1000 }),
    };
    const contribution = classify(row, baseCtx());
    expect(contribution.moneyEligible).toBe(false);
  });

  it("classify() alone rejects a foreground_checkin row whose OWN localDate disagrees with ctx.playLocalDate", () => {
    const row: Evidence = checkin({ localDate: OFF_DATE, fix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - 24 * 60 * 60 * 1000 }) });
    const contribution = classify(row, baseCtx());
    expect(contribution.badgeWeight).toBe(0);
  });
});
