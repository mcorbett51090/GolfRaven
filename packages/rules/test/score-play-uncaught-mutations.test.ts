/**
 * P3b re-gate on b95bbfc: "the tests pass even when each of these is
 * broken; add a test that fails under each." Each test below is designed
 * to distinguish the CORRECT behaviour from its named mutation as sharply
 * as possible (several earlier attempts at this kind of test were
 * tautological — e.g. same-class dedup already produces the same number
 * whether or not fingerprint voiding fires — so several of these
 * deliberately combine the mutated mechanism with an INDEPENDENT class or
 * a weight ordering that only diverges when the real mechanism is live).
 *
 * Each was proven, for real, against a temporarily mutated copy of
 * `src/score-play.ts` (mutation applied, this exact test run and observed
 * to fail, mutation reverted via `git diff`/manual undo, test re-run and
 * observed to pass) — see the session's final report for each mutation's
 * literal before/after `pnpm vitest run` output.
 */
import { describe, expect, it } from "vitest";
import { scorePlay, type Evidence } from "../src/score-play.js";
import {
  PLAY_FACILITY_ID,
  PLAY_LOCAL_DATE,
  PLAY_LOCAL_DATE_MS,
  baseCtx,
  booking,
  checkin,
  goodFix,
  healthRoute,
  receipt,
  staffPresence,
  tokenState,
} from "./score-play-helpers.js";

const DAY_MS = 24 * 60 * 60 * 1000;
const OFF_DATE = "2026-05-31";

describe("uncaught mutation: simulated fixes allowed into money", () => {
  it("a perfect check-in, simulated=true, is never money-eligible even alone", () => {
    const result = scorePlay([checkin({ fix: goodFix({ simulated: true }) })], baseCtx());
    // badgeWeight = 0.30 × 0.3 = 0.09 > 0, so this isn't the gate — it's
    // specifically the money exclusion under test.
    expect(result.score_badge).toBeGreaterThan(0);
    expect(result.score_monetary).toBe(0);
    const contribution = result.contributions.find((c) => c.classId === "foreground_checkin");
    expect(contribution?.moneyEligible).toBe(false);
  });
});

describe("uncaught mutation: fix-id correlation removed", () => {
  it("a staff scan and a check-in sharing the SAME fixId combine by max (0.95), not noisy-OR (would be ~0.965)", () => {
    const sharedFix = goodFix();
    const result = scorePlay([staffPresence({ coSignalFix: sharedFix }), checkin({ fix: sharedFix })], baseCtx());
    // With fix-id correlation: the group collapses to staff_presence_hard
    // alone (0.95). Without it: noisyOr(0.95, 0.30) = 1-(0.05*0.70) = 0.965.
    expect(result.score_badge).toBe(0.95);
  });
});

describe("uncaught mutation: same-round correlation removed", () => {
  it("a health_route and a file_import of the SAME round combine by max, not noisy-OR", () => {
    const startedAt = PLAY_LOCAL_DATE_MS;
    const result = scorePlay(
      [
        healthRoute({ insideRatio: 0.9, startedAt }),
        { id: "fi_round", facilityId: PLAY_FACILITY_ID, localDate: baseCtx().playLocalDate, source: "file_import", matchedRoute: true, startedAt: startedAt + 5 * 60_000 },
      ],
      baseCtx(),
    );
    // With round correlation: max(0.60, 0.40) = 0.60, capped by the
    // device-GPS group cap trivially. Without it: noisyOr(0.60, 0.40) =
    // 1-(0.4*0.6) = 0.76.
    expect(result.score_badge).toBe(0.6);
  });
});

describe("uncaught mutation: device-row fix facility check removed", () => {
  it("a check-in fix at a DIFFERENT facility contributes nothing", () => {
    const result = scorePlay([checkin({ fix: goodFix({ facilityId: "fac_other" }) })], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

describe("uncaught mutation: device-gate insideBuffer check removed", () => {
  it("a check-in fix outside the buffer (insideBuffer=false) contributes nothing", () => {
    const result = scorePlay([checkin({ fix: goodFix({ insideBuffer: false }) })], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

describe("uncaught mutation: fingerprint voiding disabled (non-tautological — distinct weights, not distinct classes)", () => {
  it("a pending receipt (0.20) plus a LATER duplicate-fingerprint 'approved' receipt (would be 0.80) stays at 0.20", () => {
    // Deliberately NOT two receipts of equal-or-lower weight (same-class
    // dedup would mask voiding either way) — the second row's OWN weight
    // (0.80, approved) is HIGHER than the first's (0.20, pending), so
    // same-class dedup's max-pick would produce a DIFFERENT number (0.80)
    // if voiding did not fire, and the correct, lower number (0.20) only
    // when voiding actually suppresses the duplicate to 0.
    const result = scorePlay(
      [
        receipt({ id: "r1", status: "pending", fingerprint: "fp_dup" }),
        receipt({ id: "r2", status: "approved", fingerprint: "fp_dup", coSignalFix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.2);
    expect(result.score_monetary).toBe(0);
  });
});

describe("uncaught mutation: booking row-date anchor removed", () => {
  it("a booking row dated off-play is dropped entirely, even with an otherwise-perfect inline presence fix", () => {
    const result = scorePlay(
      [
        booking({
          localDate: OFF_DATE,
          presenceFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - DAY_MS }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
    expect(result.money).toBe(false);
  });
});

describe("uncaught mutation: receipt row-date anchor removed", () => {
  it("a receipt row dated off-play is dropped entirely, even with an approved status and a perfect co-signal", () => {
    const result = scorePlay(
      [receipt({ localDate: OFF_DATE, status: "approved", coSignalFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS - DAY_MS }) })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
    expect(result.money).toBe(false);
  });
});

describe("uncaught mutation: hard-group collapse disabled", () => {
  it("staff with NO inline fix, absorbing an external check-in, resolves HARD (0.95) — not a max-pick 0.80", () => {
    // Deliberately uses the ABSORPTION path (staff carries no inline fix
    // at all) rather than a shared-fixId inline case: if `classify` alone
    // already produced a hard contribution (an inline fix would do that),
    // `combine`'s own ordinary max-pick would coincidentally reproduce the
    // right number even with the explicit `resolveGroups` collapse
    // disabled, making that shape a bad discriminator. Here, `classify`'s
    // OWN per-row pass gives staff `staff_presence_soft` (0.80, not hard,
    // not money-eligible) — ONLY the collapse step in `resolveGroups` can
    // turn this into `staff_presence_hard` (0.95). Without it: max(0.80
    // soft, 0.18 unattestable check-in) = 0.80, money 0.18 < 0.85.
    const result = scorePlay(
      [
        staffPresence({}),
        checkin({ fix: goodFix({ token: { present: true, grade: "unattestable" }, capturedAt: PLAY_LOCAL_DATE_MS + 3 * 60_000 }) }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.95);
    expect(result.score_monetary).toBe(0.95);
    expect(result.money).toBe(true);
  });
});

describe("uncaught mutation (third re-gate): the fix-date check inside deviceRowFixGateOk", () => {
  it("a check-in whose fix.localDate disagrees with the play's date contributes nothing, even though the ROW itself is on-date", () => {
    // The row is dated correctly (so it survives scorePlay's top-level
    // filter and reaches deviceRowFixGateOk at all) — only the FIX's own
    // `localDate` is off, isolating that ONE check specifically.
    const result = scorePlay(
      [checkin({ fix: goodFix({ localDate: OFF_DATE }) })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
  });
});

describe("uncaught mutation (third re-gate): the fix-date clause of the staff window", () => {
  it("a staff co-signal within ±10 min NUMERICALLY, but whose fix.localDate disagrees with the play's date, stays soft", () => {
    const result = scorePlay(
      [
        staffPresence({
          scanAt: PLAY_LOCAL_DATE_MS,
          coSignalFix: goodFix({ localDate: OFF_DATE, capturedAt: PLAY_LOCAL_DATE_MS + 3 * 60_000 }),
        }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8); // staff_presence_soft, not hard (0.95)
    expect(result.contributions.every((c) => !c.hard)).toBe(true);
  });
});

describe("uncaught mutation (third re-gate): the non-hard heldReview branch forced to false", () => {
  it("scoreHeld (unattestable-only money-merged set) alone, with an independent attested presence fix, still yields heldReview=true", () => {
    // Presence is covered by an INDEPENDENT attested fix (a user-picked,
    // money-excluded check-in), so `presenceHeld` alone is `false` — ONLY
    // the score-path's `scoreHeld` computation (an unattestable-only
    // money-merged set reaching MONEY_MIN) can produce `heldReview: true`
    // here. Forcing `scoreHeld` to `false` unconditionally flips this
    // test's own assertion (proven for real below).
    const evidence: Evidence[] = [
      {
        id: "receipt_unatt_mut",
        facilityId: PLAY_FACILITY_ID,
        localDate: PLAY_LOCAL_DATE,
        source: "receipt_green_fee",
        status: "approved",
        coSignalFix: goodFix({ token: tokenState("unattestable") }),
      },
      booking({ presenceFix: goodFix({ simulated: true }) }), // bad inline fix — stays booking_alone, no absorption
      checkin({ courseDisambiguatedBy: "user", fix: goodFix() }), // attested, presence-only, money-excluded
    ];
    const result = scorePlay(evidence, baseCtx());
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });
});
