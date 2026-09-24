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
 * facility; on the play's facility-local date.
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

/** The oracle's single fix predicate — the six conditions §10 P3 AT(4)
 * states, and nothing else. */
function oracleFixQualifies(fix: AppFix, playLocalDate: string): boolean {
  return (
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
 * condition on the play's own facility-local date. Facility identity is
 * not separately checked here: every fixture/generator case in this suite
 * builds evidence for exactly one play (module doc's "one call = one
 * play" contract in `score-play.ts`), so a fix's `localDate` match against
 * `ctx.playLocalDate` is the only date/place anchor the oracle needs — the
 * same simplification `computePresenceSignal` documents on the scorer
 * side, arrived at independently here from the AT(4) wording itself. */
export function oracle(evidence: Evidence[], ctx: ScorePlayContext): boolean {
  return oracleFixesOf(evidence).some((fix) =>
    oracleFixQualifies(fix, ctx.playLocalDate),
  );
}
