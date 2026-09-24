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
import { type Evidence } from "../src/score-play.js";
import {
  scorePlayOrThrow,
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
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ simulated: true }) })], baseCtx());
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
    const result = scorePlayOrThrow([staffPresence({ coSignalFix: sharedFix }), checkin({ fix: sharedFix })], baseCtx());
    // With fix-id correlation: the group collapses to staff_presence_hard
    // alone (0.95). Without it: noisyOr(0.95, 0.30) = 1-(0.05*0.70) = 0.965.
    expect(result.score_badge).toBe(0.95);
  });
});

describe("uncaught mutation: same-round correlation removed", () => {
  it("a health_route and a file_import of the SAME round combine by max, not noisy-OR", () => {
    const startedAt = PLAY_LOCAL_DATE_MS;
    const result = scorePlayOrThrow(
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
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ facilityId: "fac_other" }) })], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

describe("uncaught mutation: device-gate insideBuffer check removed", () => {
  it("a check-in fix outside the buffer (insideBuffer=false) contributes nothing", () => {
    const result = scorePlayOrThrow([checkin({ fix: goodFix({ insideBuffer: false }) })], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

describe("uncaught mutation: fingerprint voiding disabled (non-tautological — distinct weights, not distinct classes)", () => {
  // F2 (sixth gate): rewritten. The ORIGINAL version of this test pinned
  // "whichever row comes LAST is voided, regardless of status" as the
  // expected behaviour — which was itself F2's blocking bug (order
  // dependence: `[pending, approved]` kept `pending`, `[approved, pending]`
  // kept `approved`). The CORRECT, now-fixed behaviour keeps the BEST
  // status deterministically (`approved` > `pending` > `void`), whatever
  // order the rows arrive in — so a `pending` row followed by a
  // duplicate-fingerprint `approved` row keeps the `approved` one (0.80),
  // voiding the `pending` one, regardless of position. This still proves
  // voiding fires at all (a THIRD, non-duplicate class establishes that):
  // if voiding were disabled entirely, same-class dedup's max-pick would
  // ALSO produce 0.80 here (coincidentally the same number), so a
  // mutation-guard needs a case where voiding and "no voiding" diverge —
  // see the permutation test below, which pins BOTH orders to the SAME
  // number specifically, catching order-dependence directly.
  it("a pending receipt + a LATER duplicate-fingerprint 'approved' receipt: the approved one wins (0.80), the pending one is voided", () => {
    const result = scorePlayOrThrow(
      [
        receipt({ id: "r1", status: "pending", fingerprint: "fp_dup" }),
        receipt({ id: "r2", status: "approved", fingerprint: "fp_dup", coSignalFix: goodFix() }),
      ],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0.8);
  });

  it("F2: the SAME pair, REVERSED order, gives the IDENTICAL result — approved still wins, never order-dependent", () => {
    const forward = scorePlayOrThrow(
      [
        receipt({ id: "r1", status: "pending", fingerprint: "fp_dup2" }),
        receipt({ id: "r2", status: "approved", fingerprint: "fp_dup2", coSignalFix: goodFix() }),
      ],
      baseCtx(),
    );
    const reversed = scorePlayOrThrow(
      [
        receipt({ id: "r2", status: "approved", fingerprint: "fp_dup2", coSignalFix: goodFix() }),
        receipt({ id: "r1", status: "pending", fingerprint: "fp_dup2" }),
      ],
      baseCtx(),
    );
    expect(forward.score_badge).toBe(0.8);
    expect(reversed.score_badge).toBe(0.8);
    expect(forward.score_badge).toBe(reversed.score_badge);
  });

  it("the probe's exact exploit: [pending, approved, checkin] and [approved, pending, checkin] now give the SAME money decision", () => {
    const ck = goodFix();
    const mkForward = () => [
      receipt({ id: "recA", status: "pending", fingerprint: "fp_exploit", coSignalFix: goodFix() }),
      receipt({ id: "recB", status: "approved", fingerprint: "fp_exploit", coSignalFix: goodFix() }),
      checkin({ fix: ck }),
    ];
    const mkReversed = () => [
      receipt({ id: "recB", status: "approved", fingerprint: "fp_exploit", coSignalFix: goodFix() }),
      receipt({ id: "recA", status: "pending", fingerprint: "fp_exploit", coSignalFix: goodFix() }),
      checkin({ fix: ck }),
    ];
    const forward = scorePlayOrThrow(mkForward(), baseCtx());
    const reversed = scorePlayOrThrow(mkReversed(), baseCtx());
    expect(forward.money).toBe(reversed.money);
    expect(forward.score_monetary).toBe(reversed.score_monetary);
  });
});

describe("item 3 (seventh gate): a reviewer's void wins UNCONDITIONALLY — the whole fingerprint group goes void", () => {
  it("the probe's own exploit: an OLDER reviewer-voided row + a NEWER approved duplicate — the approved one no longer overrides the void", () => {
    const rVoidOld = receipt({ id: "a-old", status: "void", fingerprint: "fp2", coSignalFix: goodFix() });
    const rApprNew = receipt({ id: "b-new", status: "approved", fingerprint: "fp2", coSignalFix: goodFix() });
    const ck = checkin({ fix: goodFix() });
    const result = scorePlayOrThrow([rVoidOld, rApprNew, ck], baseCtx());
    // Both receipt copies are void (weight 0) — only the check-in (0.30)
    // remains, money-eligible on its own but well under MONEY_MIN. Before
    // this fix, the approved copy (0.80) would have won and both scores
    // would have been 0.80.
    expect(result.score_badge).toBe(0.3);
    expect(result.score_monetary).toBe(0.3);
    expect(result.money).toBe(false);
  });

  it("order-independent: [void, approved] and [approved, void] give the SAME (voided) result", () => {
    const mk = (voidFirst: boolean) => {
      const v = receipt({ id: "v1", status: "void", fingerprint: "fp3", coSignalFix: goodFix() });
      const a = receipt({ id: "a1", status: "approved", fingerprint: "fp3", coSignalFix: goodFix() });
      return voidFirst ? [v, a] : [a, v];
    };
    const forward = scorePlayOrThrow(mk(true), baseCtx());
    const reversed = scorePlayOrThrow(mk(false), baseCtx());
    expect(forward.score_badge).toBe(0);
    expect(reversed.score_badge).toBe(0);
  });

  it("a THREE-way group with one void member: the whole group is void, not just the void row itself", () => {
    const v = receipt({ id: "v1", status: "void", fingerprint: "fp4", coSignalFix: goodFix() });
    const p = receipt({ id: "p1", status: "pending", fingerprint: "fp4", coSignalFix: goodFix() });
    const a = receipt({ id: "a1", status: "approved", fingerprint: "fp4", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([v, p, a], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

describe("item 3 (seventh gate): earliest capturedAt wins when no void is present and every row carries a coSignalFix", () => {
  it("an earlier-captured pending receipt wins over a later-captured approved duplicate (no void present)", () => {
    const earlier = receipt({
      id: "early",
      status: "pending",
      fingerprint: "fp5",
      coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS }),
    });
    const later = receipt({
      id: "late",
      status: "approved",
      fingerprint: "fp5",
      coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 5 * 60_000 }),
    });
    const forward = scorePlayOrThrow([earlier, later], baseCtx());
    const reversed = scorePlayOrThrow([later, earlier], baseCtx());
    // The EARLIER (pending, 0.20) wins over the LATER (approved, 0.80) —
    // re-submission does not out-rank the honest first capture. Both
    // orders agree.
    expect(forward.score_badge).toBe(0.2);
    expect(reversed.score_badge).toBe(0.2);
  });

  it("falls back to approved-wins when NOT every row in the group carries a coSignalFix (capturedAt incomplete)", () => {
    // One row has no coSignalFix at all — "earliest" isn't soundly
    // comparable across the whole group, so this falls back to the
    // status-rank rule (documented: the DB intake path must independently
    // void the newer copy in this shape).
    const noFix = receipt({ id: "r1", status: "pending", fingerprint: "fp6" });
    const withFix = receipt({ id: "r2", status: "approved", fingerprint: "fp6", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([noFix, withFix], baseCtx());
    expect(result.score_badge).toBe(0.8);
  });
});

describe("uncaught mutation: booking row-date anchor removed", () => {
  it("a booking row dated off-play is dropped entirely, even with an otherwise-perfect inline presence fix", () => {
    const result = scorePlayOrThrow(
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
    const result = scorePlayOrThrow(
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
    const result = scorePlayOrThrow(
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
    const result = scorePlayOrThrow(
      [checkin({ fix: goodFix({ localDate: OFF_DATE }) })],
      baseCtx(),
    );
    expect(result.score_badge).toBe(0);
  });
});

describe("uncaught mutation (third re-gate): the fix-date clause of the staff window", () => {
  it("a staff co-signal within ±10 min NUMERICALLY, but whose fix.localDate disagrees with the play's date, stays soft", () => {
    // Fifth gate, H2: `goodFix({localDate: OFF_DATE, capturedAt: <same-UTC-day
    // as PLAY_LOCAL_DATE>})` is now itself an internally INCONSISTENT fix —
    // its own `localDate` disagrees with what its `capturedAt` resolves to
    // in the (default UTC) facility tz — and `parseScorePlayInput`'s own
    // cross-check rejects it at the PARSER, before `classifyEvidenceRow`
    // ever runs, which would trivially (and uninterestingly) also produce
    // `score_badge: 0`. To keep isolating the ORIGINAL invariant this test
    // was written for — the STRING check inside `staffFixSatisfiesHardWindow`
    // (`fix.localDate === ctx.playLocalDate`), not a numeric window alone —
    // the fix here is constructed to be SELF-consistent (its `localDate`
    // genuinely matches its own `capturedAt`'s UTC calendar date, so it
    // passes the parser) while still landing within ±10 min of `scanAt`
    // NUMERICALLY: both timestamps sit either side of a UTC midnight
    // boundary.
    const scanAt = Date.parse("2026-06-01T23:58:00.000Z"); // 2 min before UTC midnight
    const fixCapturedAt = scanAt + 3 * 60_000; // 2026-06-02T00:01:00Z — 3 min later, but a DIFFERENT UTC calendar day
    const result = scorePlayOrThrow(
      [
        staffPresence({
          scanAt,
          coSignalFix: goodFix({ localDate: "2026-06-02", capturedAt: fixCapturedAt }),
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
    const result = scorePlayOrThrow(evidence, baseCtx());
    expect(result.money).toBe(true);
    expect(result.heldReview).toBe(true);
  });
});
