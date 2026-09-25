/**
 * P3b fourth re-gate on commit 68d9139 — should-fix items not covered by
 * `score-play-internal-classify.test.ts` (blocking finding 1's fix).
 */
import { describe, expect, it } from "vitest";
import { type Evidence } from "../src/score-play.js";
import {
  scorePlayOrThrow,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  booking,
  checkin,
  dwell,
  goodFix,
  staffPresence,
  tokenState,
} from "./score-play-helpers.js";

describe("Should-fix: the hard winner's SATISFYING FIX is order-independent (prefers attested)", () => {
  it("staffPresence({}) + [unattestable check-in @+1min, attested check-in @+2min] and the reverse both give heldReview=false", () => {
    const unattestedCheckin: Evidence = checkin({
      id: "checkin_unattested",
      fix: goodFix({ token: tokenState("unattestable"), capturedAt: PLAY_LOCAL_DATE_MS + 1 * 60_000 }),
    });
    const attestedCheckin: Evidence = checkin({
      id: "checkin_attested",
      fix: goodFix({ token: tokenState("attested"), capturedAt: PLAY_LOCAL_DATE_MS + 2 * 60_000 }),
    });
    const staffRow: Evidence = staffPresence({ scanAt: PLAY_LOCAL_DATE_MS }); // no inline fix — absorbs

    const forward = scorePlayOrThrow([staffRow, unattestedCheckin, attestedCheckin], baseCtx());
    const reversed = scorePlayOrThrow([staffRow, attestedCheckin, unattestedCheckin], baseCtx());

    expect(forward.score_badge).toBe(0.95);
    expect(reversed.score_badge).toBe(0.95);
    expect(forward.money).toBe(true);
    expect(reversed.money).toBe(true);
    // An attested satisfying fix exists (the +2min check-in) — the hard
    // winner must prefer it over the unattestable one, regardless of which
    // one the search happens to encounter first.
    expect(forward.heldReview).toBe(false);
    expect(reversed.heldReview).toBe(false);
  });

  it("booking({}) + [unattestable dwell, attested check-in @+3h] and the reverse both give heldReview=false", () => {
    const unattestedDwell: Evidence = dwell({
      id: "dwell_unattested",
      checkinFix: goodFix({ token: tokenState("unattestable") }),
      checkoutFix: goodFix({ token: tokenState("unattestable"), capturedAt: PLAY_LOCAL_DATE_MS + 95 * 60_000 }),
      apartMinutes: 95,
      holes: 18,
    });
    const attestedCheckin: Evidence = checkin({
      id: "checkin_far_attested",
      fix: goodFix({ token: tokenState("attested"), capturedAt: PLAY_LOCAL_DATE_MS + 3 * 60 * 60_000 }),
    });
    const bookingRow: Evidence = booking({}); // no inline fix — absorbs (same-day window)

    const forward = scorePlayOrThrow([bookingRow, unattestedDwell, attestedCheckin], baseCtx());
    const reversed = scorePlayOrThrow([bookingRow, attestedCheckin, unattestedDwell], baseCtx());

    expect(forward.score_badge).toBe(0.9);
    expect(reversed.score_badge).toBe(0.9);
    expect(forward.money).toBe(true);
    expect(reversed.money).toBe(true);
    expect(forward.heldReview).toBe(false);
    expect(reversed.heldReview).toBe(false);
  });
});
