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
 * "The generator enumerates class × fix attribute exhaustively... A second
 * property: 'a class label without a qualifying fix ⇒ ¬money'" (§4.5 lines
 * 976-987). §10 P3 AT(4): "money(E) ⇒ oracle(E)", oracle reads raw fix
 * attributes and requires one fix that is: from our app; against a live or
 * prefetched challenge; `simulated = false`; foreground; graded anything
 * other than `failed`; inside the polygon+50m of a `play-verified`
 * facility THAT IS THE PLAY'S OWN FACILITY; on the play's facility-local
 * date. (Gate finding 3: the facility clause is load-bearing, not
 * implicit — see `oracleFixQualifies`.)
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
    if (row.source === "staff_presence" && row.coSignalFix)
      fixes.push(row.coSignalFix);
    if (row.source === "booking" && row.presenceFix)
      fixes.push(row.presenceFix);
    if (row.source === "receipt_green_fee" && row.coSignalFix)
      fixes.push(row.coSignalFix);
    if (row.source === "foreground_dwell")
      fixes.push(row.checkinFix, row.checkoutFix);
    if (row.source === "foreground_checkin") fixes.push(row.fix);
  }
  return fixes;
}

/** The oracle's single fix predicate — the six AT(4) conditions, PLUS the
 * facility anchor (gate finding 3: "Update the oracle too, independently:
 * its facility check is missing" — an earlier revision of this file
 * incorrectly argued the check away as redundant with "one call = one
 * play"; that argument was wrong precisely because `evidence[]` can
 * legitimately contain a row/fix for a DIFFERENT facility, which
 * `scorePlay` must reject and this independent oracle must reject too, on
 * its own logic, not by assuming the input is already clean). */
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
