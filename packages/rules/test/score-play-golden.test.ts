/**
 * §4.5's 16 money golden fixtures (lines 1058-1080), asserted VERBATIM: the
 * plan's own table is "Columns 4-7 are assertions (set in v3, unchanged in
 * v4), which the P3 tests encode exactly (G2-04)." Column 3 (v1's single
 * score) is historical illustration only and is not asserted.
 *
 * Each `it` cites its row number and quotes the "Combination" column so a
 * diff against the plan is a one-line lookup.
 */
import { describe, expect, it } from "vitest";
import { MONEY_MIN } from "../src/score-play.js";
import {
  scorePlayOrThrow,
  PLAY_FACILITY_ID,
  PLAY_LOCAL_DATE,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  booking,
  checkin,
  connectIq,
  dwell,
  fileImport,
  ghin,
  goodFix,
  healthRoute,
  receipt,
  staffPresence,
  tokenState,
  vendorRound,
} from "./score-play-helpers.js";

describe("scorePlay — §4.5 money golden fixtures (P3 AT(4))", () => {
  it("#1: Approved receipt (no co-signal) + forged GPX file_import", () => {
    const result = scorePlayOrThrow(
      [receipt({ status: "approved" }), fileImport({ matchedRoute: true })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.88);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#2: Relayed staff scan without co-signal + forged GPX", () => {
    const result = scorePlayOrThrow(
      [staffPresence({}), fileImport({ matchedRoute: true })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.88);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#3: Staff scan without co-signal + Health route + dwell", () => {
    // Should-fix (re-gate): staff-scan hard-class absorption from an
    // external fix is now enabled (mirroring booking's), so this
    // fixture's dwell must NOT coincidentally open within the staff
    // scan's own ±10 min window — that would make it "WITH co-signal"
    // (hard), contradicting this row's own stated meaning. The dwell's
    // check-in fix is moved 30 min after the default scan time, well
    // outside the window, while every other quality attribute (and the
    // 95 min apart-duration) is unchanged.
    const dwellStart = PLAY_LOCAL_DATE_MS + 30 * 60_000;
    const result = scorePlayOrThrow(
      [
        staffPresence({}),
        healthRoute({ insideRatio: 0.85 }),
        dwell({
          checkinFix: goodFix({ capturedAt: dwellStart }),
          checkoutFix: goodFix({ capturedAt: dwellStart + 95 * 60_000 }),
          apartMinutes: 95,
          holes: 18,
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.96);
    expect(result.score_monetary).toBe(0.5);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#4: P7 booking alone + its own prepay receipt (no co-signal): a correlated pair", () => {
    // Finding 1(b): correlation is derived from the DATA — a shared
    // `paymentRef` (the same booking/prepay id), never a caller-asserted
    // `correlationId`.
    const result = scorePlayOrThrow(
      [
        booking({ paymentRef: "pay_4" }),
        receipt({ status: "approved", paymentRef: "pay_4" }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8); // max, not noisy-OR
    expect(result.score_monetary).toBe(0.7);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#5: Health route + Connect IQ trace + file import (device-only)", () => {
    const result = scorePlayOrThrow(
      [
        healthRoute({ insideRatio: 0.9 }),
        connectIq({ variant: "route" }),
        fileImport({ matchedRoute: true }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8); // device-GPS cap
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#6: P8 GHIN-posted round alone", () => {
    const result = scorePlayOrThrow([ghin({})], baseCtx());
    expect(result.score_badge).toBe(0.4);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#7: P8 Garmin sensor round alone, no app fix — no presence fact", () => {
    const result = scorePlayOrThrow(
      [
        vendorRound("garmin", {
          vendorCourseMapped: true,
          sensorProvenance: true,
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.85);
    expect(result.score_monetary).toBe(0.85);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false); // no presence fact, despite score >= MONEY_MIN
  });

  it("#8: Marker scratch code + its same-date co-signal check-in — corroboration cannot cross 0.50", () => {
    const result = scorePlayOrThrow(
      [checkin({ fix: goodFix() })],
      baseCtx({
        purchases: [
          { facilityId: PLAY_FACILITY_ID, localDate: PLAY_LOCAL_DATE },
        ],
      }),
    );
    expect(result.score_badge).toBe(0.3);
    expect(result.score_monetary).toBe(0.3);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#9: Approved receipt + co-signal from the QR session (no separate check-in)", () => {
    const result = scorePlayOrThrow(
      [
        receipt({ status: "approved", coSignalFix: goodFix() }),
        checkin({ fix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.86);
    expect(result.score_monetary).toBe(0.86);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
  });

  it("#10 [alternative encoding]: a single booking row carrying its presence fix inline", () => {
    const result = scorePlayOrThrow([booking({ presenceFix: goodFix() })], baseCtx());
    expect(result.score_badge).toBe(0.9);
    expect(result.score_monetary).toBe(0.9);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
  });

  it("#10 [verbatim]: P7 booking + dwell on the booking date — TWO rows, as the table describes it", () => {
    // The plan's own words for row #10 are "P7 booking + dwell on the
    // booking date" — a booking row and a SEPARATE dwell row, not one row
    // carrying an inline fix. The booking carries NO inline `presenceFix`
    // (should-fix hard-class absorption, §4.5 "hard classes contain their
    // presence fact"): the dwell's own check-in/check-out fixes, both on
    // the booking's date, satisfy the booking's same-day-presence window
    // and the whole group collapses to `booking_hard` alone — never
    // double-scored as booking 0.70 + dwell 0.50 (A2-20d), and never
    // landing on exactly 0.85 (the should-fix item's own stated risk).
    const result = scorePlayOrThrow([booking({}), dwell({})], baseCtx());
    expect(result.score_badge).toBe(0.9);
    expect(result.score_monetary).toBe(0.9);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
    expect(result.contributions.some((c) => c.hard)).toBe(true);
    expect(result.score_badge).not.toBe(0.85);
  });

  it("#11: Offline-code staff scan + a prefetched-challenge fix 6 min later", () => {
    const result = scorePlayOrThrow(
      [
        staffPresence({
          scanAt: PLAY_LOCAL_DATE_MS,
          coSignalFix: goodFix({
            challenge: "prefetched",
            capturedAt: PLAY_LOCAL_DATE_MS + 6 * 60_000,
          }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.95);
    expect(result.score_monetary).toBe(0.95);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
  });

  it("#12 [alternative encoding]: no fix at all", () => {
    const result = scorePlayOrThrow([staffPresence({})], baseCtx());
    expect(result.score_badge).toBe(0.8);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#12 [verbatim]: a fix EXISTS but is outside the ±10 min window", () => {
    // The table's own words: "no fix within ± 10 min" — read literally, a
    // fix was captured, just not close enough in time to the scan. It
    // still qualifies as a co-signal on its OWN (same-date) terms — so
    // `presence_signal` is TRUE here (A2-06: computed only from fixes,
    // independent of any one class's window) — but staff_presence still
    // stays SOFT (its own ±10 min window failed) and no other class is
    // money-eligible, so `money` is still `false` overall.
    const result = scorePlayOrThrow(
      [
        staffPresence({
          scanAt: PLAY_LOCAL_DATE_MS,
          coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 15 * 60_000 }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#13: Check-in whose attestation failed + approved receipt", () => {
    const result = scorePlayOrThrow(
      [
        checkin({ fix: goodFix({ token: tokenState("failed") }) }),
        receipt({ status: "approved" }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(false);
    expect(result.money).toBe(false);
  });

  it("#14: `unattestable` check-in (0.30 × 0.6) + approved receipt — below 0.85", () => {
    const result = scorePlayOrThrow(
      [
        checkin({ fix: goodFix({ token: tokenState("unattestable") }) }),
        receipt({
          status: "approved",
          coSignalFix: goodFix({ token: tokenState("unattestable") }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.84);
    expect(result.score_monetary).toBe(0.84);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });

  it("#15: Staff scan + `unattestable` co-signal — hard class, routed to held_review", () => {
    const result = scorePlayOrThrow(
      [
        staffPresence({
          coSignalFix: goodFix({ token: tokenState("unattestable") }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.95);
    expect(result.score_monetary).toBe(0.95);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(true);
    // §7.5 row 3 (should-fix): the reward rests on an unattestable
    // co-signal, so it routes to held_review — never silently issued.
    expect(result.heldReview).toBe(true);
  });

  it("#16: 36-hole site, shared polygon, dwell, course-unit trail, user pick", () => {
    const result = scorePlayOrThrow(
      [dwell({ courseDisambiguatedBy: "user", apartMinutes: 95, holes: 18 })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.5);
    expect(result.score_monetary).toBe(0.0);
    expect(result.presence_signal).toBe(true);
    expect(result.money).toBe(false);
  });
});

describe("scorePlay — MONEY_MIN is a literal code constant (A2-05)", () => {
  it("MONEY_MIN === 0.85, literally", () => {
    expect(MONEY_MIN).toBe(0.85);
  });

  it("a fixture landing in [0.84, 0.85) is genuinely below the floor (fixture #14)", () => {
    const result = scorePlayOrThrow(
      [
        checkin({ fix: goodFix({ token: tokenState("unattestable") }) }),
        receipt({ status: "approved", coSignalFix: goodFix({ token: tokenState("unattestable") }) }),
      ],
      baseCtx(),
    );
    expect(result.score_monetary).toBeGreaterThanOrEqual(0.84);
    expect(result.score_monetary).toBeLessThan(0.85);
    expect(result.money).toBe(false);
  });
});

describe("scorePlay — finding 1: same-class dedup and derived (not caller-asserted) correlation", () => {
  it("fixture #14 plus TWO unattestable check-ins (tagged a/b, same class) ⇒ still 0.84, no money", () => {
    // "Two rows of the same class do not stack" (§4.5 line 890) — a
    // SECOND `foreground_checkin` row must not push the score past the
    // single-check-in fixture #14 result, however it's tagged.
    const result = scorePlayOrThrow(
      [
        checkin({ id: "checkin_a", fix: goodFix({ token: tokenState("unattestable") }) }),
        checkin({ id: "checkin_b", fix: goodFix({ token: tokenState("unattestable") }) }),
        receipt({ status: "approved", coSignalFix: goodFix({ token: tokenState("unattestable") }) }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.84);
    expect(result.score_monetary).toBe(0.84);
    expect(result.money).toBe(false);
  });

  it("two receipts with co-signals under DISTINCT ids ⇒ no double count (same-class dedup, not noisy-OR)", () => {
    const withOneReceipt = scorePlayOrThrow([receipt({ status: "approved", coSignalFix: goodFix() })], baseCtx());
    const withTwoReceipts = scorePlayOrThrow(
      [
        receipt({ id: "receipt_a", status: "approved", coSignalFix: goodFix() }),
        receipt({ id: "receipt_b", status: "approved", coSignalFix: goodFix() }),
      ],
      baseCtx(),
    );
    // A naive noisy-OR over two 0.80 receipts would give 1-(0.2*0.2)=0.96 —
    // "two rows of the same class do not stack" means the SECOND receipt
    // contributes nothing beyond the first.
    expect(withTwoReceipts.score_badge).toBe(withOneReceipt.score_badge);
    expect(withTwoReceipts.score_monetary).toBe(withOneReceipt.score_monetary);
  });

  it("a `correlationId` hint that DISAGREES with the data is ignored, never trusted (finding 1)", () => {
    // Two rows tagged with the SAME correlationId but sharing neither a
    // fixId, a paymentRef nor a round — must combine ordinarily (noisy-OR),
    // proving `correlationId` has no effect on combination.
    const result = scorePlayOrThrow(
      [
        booking({ correlationId: "bogus" }),
        receipt({ status: "approved", correlationId: "bogus" }),
      ],
      baseCtx(),
    );
    // booking_alone (0.70) noisy-ORed with receipt (0.80, no co-signal):
    // 1-(0.3*0.2) = 0.94 — NOT max(0.70,0.80)=0.80, because nothing in the
    // DATA correlates them (no shared paymentRef).
    expect(result.score_badge).toBe(0.94);
  });
});
