/**
 * The §10 P3 AT(4) / §4.5 (lines 971-987) money-invariant ORACLE, written
 * INDEPENDENTLY of `scorePlay`'s own scoring logic (task instruction:
 * "must not import scorePlay internals"). This file imports only the
 * `Evidence`/`AppFix`/`TokenState` TYPES from `score-play.ts` — the shared
 * input shape the generator has to produce SOMETHING for `scorePlay` to
 * consume — and re-derives every predicate (the co-signal fix-quality
 * gate, G3-08's no-token grading) from the §4.5 prose from scratch, rather
 * than calling `resolveFixGrade` / the module-private `isQualityCoSignalFix`
 * that `score-play.ts` uses internally. A regression in the SCORER's own
 * copy of these rules therefore cannot silently satisfy the invariant by
 * both sides agreeing with each other.
 *
 * §10 P3 AT(4), quoted verbatim: "oracle reads raw fix attributes and
 * requires one fix that is: from our app; against a live or prefetched
 * challenge; `simulated = false`; foreground; graded anything other than
 * `failed`; inside the polygon+50m of a `play-verified` facility; on the
 * play's facility-local date." Every clause names a FIX attribute
 * (`fromApp`, `challenge`, `simulated`, `foreground`, grade, geometry/
 * tier/buffer, `localDate`) — including "a `play-verified` facility",
 * which is the FIX's OWN `facilityId` matching the play's (finding 3 of
 * the first re-gate: this clause is load-bearing, not implicit). Nothing
 * in AT(4)'s own wording mentions the wrapping ROW's `facilityId`,
 * `localDate` or `courseDisambiguatedBy` at all.
 *
 * **Third re-gate (commit 2989ba8), finding 2 — this file WAS wrong,
 * corrected here.** The second re-gate (commit b95bbfc) added row-level
 * facility/date/user-pick clauses on top of AT(4)'s six fix-attribute
 * conditions, reasoning that `scorePlay`'s own top-level filter drops an
 * off-date/off-facility ROW before its fix is ever examined. That
 * reasoning held for the facility/date clauses (removing them would not
 * have broken `money(E) ⇒ oracle(E)` either way, since the row-level
 * filter already guarantees them whenever `money` is true) — but the
 * user-pick clause was an actual BUG, not a redundant tightening: the
 * scorer's own `presence_signal` is computed from EVERY qualifying fix
 * regardless of `courseDisambiguatedBy` (§4.5 line 933, and money golden
 * fixture #16's own "presence = true" on a user-picked row) — a
 * user-picked row's course credit is money-EXCLUDED, but its FIX still
 * counts as presence. Excluding it from the oracle made the oracle
 * STRICTER than the code it was checking, which is exactly backwards for
 * an implication oracle: `money(E) ⇒ oracle(E)` broke for real (a Garmin
 * sensor round alone reaches 0.85, and a user-picked check-in's fix is the
 * only thing making `presence_signal` — and therefore `money` — true; the
 * old oracle said `false`). All three row-level clauses are removed below,
 * reverting to AT(4)'s literal fix-attributes-only definition; see
 * `test/score-play-regate3.test.ts` for the regression.
 */
import type {
  AppFix,
  Evidence,
  ScorePlayContext,
  TokenState,
} from "../src/score-play.js";

/** G3-08, re-derived independently: "a submission that carries no token is
 * graded at intake: on hardware that supports attestation it is `failed`,
 * and otherwise `unattestable`." */
function oracleGrade(
  token: TokenState,
): "attested" | "unattestable" | "failed" {
  if (token.present) return token.grade;
  return token.hardwareSupportsAttestation ? "failed" : "unattestable";
}

/** Every fix a raw `Evidence` row could carry, found by walking the union
 * shape directly — not by calling `score-play.ts`'s own `collectFixes`. */
function oracleFixesOf(evidence: Evidence[]): AppFix[] {
  const fixes: AppFix[] = [];
  for (const row of evidence) {
    if (row.source === "staff_presence" && row.coSignalFix) fixes.push(row.coSignalFix);
    if (row.source === "booking" && row.presenceFix) fixes.push(row.presenceFix);
    if (row.source === "receipt_green_fee" && row.coSignalFix) fixes.push(row.coSignalFix);
    if (row.source === "foreground_dwell") fixes.push(row.checkinFix, row.checkoutFix);
    if (row.source === "foreground_checkin") fixes.push(row.fix);
  }
  return fixes;
}

/** The oracle's single fix predicate — AT(4)'s six conditions, verbatim
 * (the facility clause is the fix's OWN `facilityId`, per the module doc
 * above — never a row-level field). */
function oracleFixQualifies(fix: AppFix, playFacilityId: string, playLocalDate: string): boolean {
  return (
    fix.facilityId === playFacilityId &&
    fix.fromApp === true &&
    (fix.challenge === "live" || fix.challenge === "prefetched") &&
    fix.simulated === false &&
    fix.foreground === true &&
    oracleGrade(fix.token) !== "failed" &&
    fix.geometryKind === "polygon" &&
    fix.verificationTier === "play-verified" &&
    fix.insideBuffer === true &&
    fix.localDate === playLocalDate
  );
}

/** `oracle(E)` — true iff SOME fix in `evidence` satisfies every AT(4)
 * condition at the play's own facility, on the play's own facility-local
 * date. */
export function oracle(evidence: Evidence[], ctx: ScorePlayContext): boolean {
  return oracleFixesOf(evidence).some((fix) => oracleFixQualifies(fix, ctx.playFacilityId, ctx.playLocalDate));
}
