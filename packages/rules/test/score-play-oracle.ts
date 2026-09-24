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
 *
 * **P3b re-gate (commit b95bbfc), two more independent checks added:**
 * (1) the ROW carrying the fix must itself be dated/located at the play
 * (mirrors `scorePlay`'s own row-level filter, re-derived here rather than
 * assumed — `evidence[]` can legitimately contain an off-date or
 * off-facility ROW even when its embedded fix's OWN fields look fine); (2)
 * a fix on a `courseDisambiguatedBy: 'user'` row is excluded — a
 * user-picked course can never back a money reward (blocking finding 3),
 * so the oracle's own "a qualifying fix exists" claim must not be true
 * for one, or the oracle would be a strictly WEAKER, less useful
 * restatement of the money rule than the code it's checking.
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

interface OracleFix {
  fix: AppFix;
  /** The row's own facility (may legitimately differ from `fix.facilityId`
   * in malformed/adversarial input — both are checked, independently). */
  rowFacilityId: string;
  rowLocalDate: string;
  rowUserPicked: boolean;
}

/** Every fix a raw `Evidence` row could carry, found by walking the union
 * shape directly — not by calling `score-play.ts`'s own `collectFixes` —
 * paired with the ROW-level facts (`facilityId`, `localDate`,
 * `courseDisambiguatedBy`) the P3b re-gate's row-level checks need. */
function oracleFixesOf(evidence: Evidence[]): OracleFix[] {
  const out: OracleFix[] = [];
  const push = (row: Evidence, fix: AppFix | undefined) => {
    if (!fix) return;
    out.push({
      fix,
      rowFacilityId: row.facilityId,
      rowLocalDate: row.localDate,
      rowUserPicked: row.courseDisambiguatedBy === "user",
    });
  };
  for (const row of evidence) {
    if (row.source === "staff_presence") push(row, row.coSignalFix);
    if (row.source === "booking") push(row, row.presenceFix);
    if (row.source === "receipt_green_fee") push(row, row.coSignalFix);
    if (row.source === "foreground_dwell") {
      push(row, row.checkinFix);
      push(row, row.checkoutFix);
    }
    if (row.source === "foreground_checkin") push(row, row.fix);
  }
  return out;
}

/** The oracle's single fix predicate — the six AT(4) conditions, PLUS the
 * facility anchor (gate finding 3), PLUS (P3b re-gate) the fix's date,
 * the ROW's own facility/date, and the user-pick exclusion. */
function oracleFixQualifies(entry: OracleFix, playFacilityId: string, playLocalDate: string): boolean {
  const { fix } = entry;
  return (
    entry.rowFacilityId === playFacilityId &&
    entry.rowLocalDate === playLocalDate &&
    !entry.rowUserPicked &&
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

/** `oracle(E)` — true iff SOME fix in `evidence`, on a row that is itself
 * at the play's facility and date and NOT a user pick, satisfies every
 * AT(4) condition at the play's own facility, on the play's own
 * facility-local date. */
export function oracle(evidence: Evidence[], ctx: ScorePlayContext): boolean {
  return oracleFixesOf(evidence).some((entry) => oracleFixQualifies(entry, ctx.playFacilityId, ctx.playLocalDate));
}
