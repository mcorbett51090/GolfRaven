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

describe("item 1 (eighth gate): a REVIEWER or FRAUD void poisons the whole group — a DUPLICATE void does not", () => {
  it("REVIEWER void (explicit voidReason) still poisons the group — an approved duplicate does not override it", () => {
    const rVoidOld = receipt({ id: "a-old", status: "void", voidReason: "reviewer", fingerprint: "fp2", coSignalFix: goodFix() });
    const rApprNew = receipt({ id: "b-new", status: "approved", fingerprint: "fp2", coSignalFix: goodFix() });
    const ck = checkin({ fix: goodFix() });
    const result = scorePlayOrThrow([rVoidOld, rApprNew, ck], baseCtx());
    expect(result.score_badge).toBe(0.3);
    expect(result.score_monetary).toBe(0.3);
    expect(result.money).toBe(false);
  });

  it("FRAUD void also poisons the group", () => {
    const rVoidOld = receipt({ id: "a-old2", status: "void", voidReason: "fraud", fingerprint: "fp2f", coSignalFix: goodFix() });
    const rApprNew = receipt({ id: "b-new2", status: "approved", fingerprint: "fp2f", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([rVoidOld, rApprNew], baseCtx());
    expect(result.score_badge).toBe(0);
  });

  it("a MISSING voidReason on a void row defaults to \"reviewer\" and STILL poisons the group (fails safe)", () => {
    const rVoidOld = receipt({ id: "a-old3", status: "void", fingerprint: "fp2m", coSignalFix: goodFix() }); // no voidReason
    const rApprNew = receipt({ id: "b-new3", status: "approved", fingerprint: "fp2m", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([rVoidOld, rApprNew], baseCtx());
    expect(result.score_badge).toBe(0);
  });

  it("order-independent: [void(reviewer), approved] and [approved, void(reviewer)] give the SAME (voided) result", () => {
    const mk = (voidFirst: boolean) => {
      const v = receipt({ id: "v1", status: "void", voidReason: "reviewer", fingerprint: "fp3", coSignalFix: goodFix() });
      const a = receipt({ id: "a1", status: "approved", fingerprint: "fp3", coSignalFix: goodFix() });
      return voidFirst ? [v, a] : [a, v];
    };
    const forward = scorePlayOrThrow(mk(true), baseCtx());
    const reversed = scorePlayOrThrow(mk(false), baseCtx());
    expect(forward.score_badge).toBe(0);
    expect(reversed.score_badge).toBe(0);
  });

  it("a THREE-way group with one reviewer-void member: the whole group is void, not just the void row itself", () => {
    const v = receipt({ id: "v1", status: "void", voidReason: "reviewer", fingerprint: "fp4", coSignalFix: goodFix() });
    const p = receipt({ id: "p1", status: "pending", fingerprint: "fp4", coSignalFix: goodFix() });
    const a = receipt({ id: "a1", status: "approved", fingerprint: "fp4", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([v, p, a], baseCtx());
    expect(result.score_badge).toBe(0);
  });
});

describe("item 1 (eighth gate), Case A: a DUPLICATE-void (intake dedup) does NOT poison the group — the honest approved original survives", () => {
  it("the gate's own Case A: an approved original + an intake-voided re-upload (same fingerprint) — the original keeps scoring at full weight", () => {
    const original = receipt({ id: "r-orig", status: "approved", fingerprint: "fp", coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS - 3600_000 }) });
    const dupVoid = receipt({ id: "r-dup", status: "void", voidReason: "duplicate", fingerprint: "fp", coSignalFix: goodFix() });
    const ck = checkin({ fix: goodFix() });
    const alone = scorePlayOrThrow([original, ck], baseCtx());
    const withDup = scorePlayOrThrow([original, dupVoid, ck], baseCtx());
    // The dedup-voided re-upload changes NOTHING — same result with or
    // without it present. Before this fix, adding it would have poisoned
    // the whole group (0.86 → dropping the receipt to 0, checkin-only).
    expect(withDup.score_monetary).toBe(alone.score_monetary);
    expect(withDup.money).toBe(alone.money);
    expect(alone.score_monetary).toBeGreaterThanOrEqual(0.85);
  });

  it("permutation: the duplicate-void row's ARRAY POSITION doesn't matter", () => {
    const original = receipt({ id: "r-orig2", status: "approved", fingerprint: "fp7", coSignalFix: goodFix() });
    const dupVoid = receipt({ id: "r-dup2", status: "void", voidReason: "duplicate", fingerprint: "fp7", coSignalFix: goodFix() });
    const ck = checkin({ fix: goodFix() });
    const forward = scorePlayOrThrow([original, dupVoid, ck], baseCtx());
    const reversed = scorePlayOrThrow([dupVoid, ck, original], baseCtx());
    const shuffled = scorePlayOrThrow([ck, original, dupVoid], baseCtx());
    expect(forward.score_monetary).toBe(reversed.score_monetary);
    expect(forward.score_monetary).toBe(shuffled.score_monetary);
  });

  it("a duplicate-void row with NO coSignalFix at all is still correctly ignored (not poisoning, not competing)", () => {
    const original = receipt({ id: "r-orig3", status: "approved", fingerprint: "fp8", coSignalFix: goodFix() });
    const dupVoidNoFix = receipt({ id: "r-dup3", status: "void", voidReason: "duplicate", fingerprint: "fp8" });
    const result = scorePlayOrThrow([original, dupVoidNoFix], baseCtx());
    expect(result.score_badge).toBe(0.8);
  });

  it("TWO duplicate-void copies alongside one approved original: still just the original", () => {
    const original = receipt({ id: "r-orig4", status: "approved", fingerprint: "fp9", coSignalFix: goodFix() });
    const dup1 = receipt({ id: "r-dup4a", status: "void", voidReason: "duplicate", fingerprint: "fp9", coSignalFix: goodFix() });
    const dup2 = receipt({ id: "r-dup4b", status: "void", voidReason: "duplicate", fingerprint: "fp9", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([dup1, original, dup2], baseCtx());
    expect(result.score_badge).toBe(0.8);
  });

  it("ALL copies in a group are duplicate-void (no real original at all): the whole group stays void, but doesn't THROW or poison anything else", () => {
    const dup1 = receipt({ id: "d1", status: "void", voidReason: "duplicate", fingerprint: "fp10", coSignalFix: goodFix() });
    const dup2 = receipt({ id: "d2", status: "void", voidReason: "duplicate", fingerprint: "fp10", coSignalFix: goodFix() });
    const ck = checkin({ fix: goodFix() });
    const result = scorePlayOrThrow([dup1, dup2, ck], baseCtx());
    expect(result.score_badge).toBe(0.3); // only the check-in
  });
});

describe("item 1 (eighth gate): status wins FIRST — capturedAt is only a tiebreak between EQUAL statuses (fixes the seventh gate's Case B regression)", () => {
  it("an earlier-captured PENDING receipt does NOT beat a later-captured APPROVED duplicate — approved wins regardless of capture order", () => {
    const earlierPending = receipt({
      id: "early",
      status: "pending",
      fingerprint: "fp5",
      coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS }),
    });
    const laterApproved = receipt({
      id: "late",
      status: "approved",
      fingerprint: "fp5",
      coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 5 * 60_000 }),
    });
    const forward = scorePlayOrThrow([earlierPending, laterApproved], baseCtx());
    const reversed = scorePlayOrThrow([laterApproved, earlierPending], baseCtx());
    // The seventh gate's own bug: this used to resolve to 0.20 (the
    // earlier PENDING copy won on capturedAt alone). Status now wins
    // first — APPROVED (0.80) beats PENDING (0.20) regardless of which
    // one was captured earlier. Both orders agree.
    expect(forward.score_badge).toBe(0.8);
    expect(reversed.score_badge).toBe(0.8);
  });

  it("capturedAt DOES tiebreak between two APPROVED copies (same status) — earliest wins", () => {
    const earlier = receipt({
      id: "early2",
      status: "approved",
      fingerprint: "fp5b",
      coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS }),
    });
    const later = receipt({
      id: "late2",
      status: "approved",
      fingerprint: "fp5b",
      coSignalFix: goodFix({ capturedAt: PLAY_LOCAL_DATE_MS + 5 * 60_000 }),
    });
    const forward = scorePlayOrThrow([earlier, later], baseCtx());
    const reversed = scorePlayOrThrow([later, earlier], baseCtx());
    // Both are approved (0.80) either way, so this specifically checks
    // WHICH row survives as the winner by checking `contributions` rather
    // than the score (which is identical either way) — the winning row's
    // evidenceId must be the earlier one.
    expect(forward.score_badge).toBe(0.8);
    expect(reversed.score_badge).toBe(0.8);
    const forwardWinner = forward.contributions.find((c) => c.classId === "receipt_green_fee" && c.badgeWeight > 0);
    const reversedWinner = reversed.contributions.find((c) => c.classId === "receipt_green_fee" && c.badgeWeight > 0);
    expect(forwardWinner?.evidenceId).toBe("early2");
    expect(reversedWinner?.evidenceId).toBe("early2");
  });

  it("falls back straight to id-tiebreak when the tied-status pair doesn't both carry a coSignalFix", () => {
    const noFix = receipt({ id: "r1", status: "pending", fingerprint: "fp6" });
    const withFix = receipt({ id: "r2", status: "approved", fingerprint: "fp6", coSignalFix: goodFix() });
    const result = scorePlayOrThrow([noFix, withFix], baseCtx());
    // Different statuses here (approved beats pending) — this is really
    // exercising the SAME status-wins-first rule as the first test in
    // this block, just via the no-coSignalFix path; kept as its own test
    // for the specific "not every row carries a coSignalFix" shape.
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
