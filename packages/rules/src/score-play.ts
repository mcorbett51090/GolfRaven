/**
 * `scorePlay` — §4.5 "Evidence classes and confidence scoring (policy v1)".
 * Pure TS, no I/O (build plan §3.1 row E): takes one play's evidence rows
 * (`app.evidence`, §4.4) plus a small amount of context and returns
 * `{score_badge, score_monetary, presence_signal, money, heldReview,
 * policyVersion, contributions[], reasons?, inputDigest?}`. Money-path code
 * (build plan §4.5 "Money rule", A2-05/A2-06/A2-07/A2-20) — correctness
 * here gates a marketing incentive, so every rule below cites the exact
 * plan line it implements.
 *
 * **Fifth gate (H2): `scorePlay` runs `parseScorePlayInput`
 * (`./parse-evidence.js`) FIRST, always** — see the `scorePlay` function's
 * OWN doc comment (below) for the full TRUST TABLE (which fields are
 * server-derived, and by what server path) that parser enforces the shape
 * of. A parse failure returns a fail-closed result (`money: false`,
 * `reasons: [...]`) and never reaches the scoring logic in this file with
 * unvalidated data.
 *
 * **Fourth re-gate (commit 68d9139), blocking finding 1: the per-row
 * classifier moved to `./internal/classify.js`.** It used to be exported
 * directly from this file, which made it PUBLIC API via `index.ts`'s
 * `export *` — reachable WITHOUT `scorePlay`'s own top-level facility/date
 * filter, so a caller could get `hard: true, moneyEligible: true` back for
 * a row whose facility/date plainly disagreed with the play, as long as
 * its embedded fix happened to carry the right facility/date. This file
 * now `import`s `classifyEvidenceRow` (and the low-level quality-gate
 * predicates it shares with `deriveGroups`/`resolveGroups` below) from
 * that internal module and never re-exports the function name — see that
 * module's own doc for the defence-in-depth row-level checks it ALSO
 * added. Every type this file's own public API needs (`AppFix`,
 * `Evidence`, `ScorePlayContext`, `ScorePlayContribution`, …) is defined
 * in the internal module and re-exported HERE, by name — the dependency
 * runs one way only (this file depends on the internal module, never the
 * reverse), so there is no import cycle.
 *
 * **Scope boundary (stated once, so it isn't re-litigated per class).**
 * `scorePlay` computes the two scores, `presence_signal`, `money` and a
 * `heldReview` routing flag (§7.5 row 3: an `unattestable` co-signal routes
 * a reward to `held_review`, never refused) — it never touches
 * `play.status` (`disputed` via event-time velocity) or writes
 * `fraud_signal` rows; those are DB-side effects of a different function.
 * A `failed`-grade fix is still zeroed here (§4.5 G3-08: "nothing can be
 * earned on it") — that IS a scoring effect — but the accompanying
 * `fraud_signal` is not.
 *
 * **One call = one play.** `evidence[]` here is every `app.evidence` row
 * already attributed to ONE `play`. `ctx.playFacilityId` /
 * `ctx.playLocalDate` are the play's own anchors — EVERY facility and date
 * check in this module is anchored to these two fields, never to a row's
 * or a fix's own copies of them. A row whose own `facilityId`/`localDate`
 * disagrees with `ctx.playFacilityId`/`ctx.playLocalDate` is dropped
 * before scoring — it is evidence for a DIFFERENT play and must not
 * silently contribute to this one.
 */
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  bookingFixSatisfiesHardWindow,
  classifyEvidenceRow,
  CORROBORATION_ELIGIBLE_THRESHOLD,
  DEVICE_GPS_SUBTOTAL_CAP,
  EVIDENCE_ROW_CAP,
  finish,
  fixesOfEvidenceRow,
  GROUP,
  isQualityCoSignalFix,
  OVERALL_SCORE_CAP,
  resolveFixGrade,
  staffFixSatisfiesHardWindow,
  WEIGHT,
  windowMs,
  type AppFix,
  type ChallengeKind,
  type Evidence,
  type EvidenceClassId,
  type EvidenceGroup,
  type FixGrade,
  type PurchaseCorroboration,
  type ScorePlayContext,
  type ScorePlayContribution,
  type TokenState,
} from "./internal/classify.js";
import { parseScorePlayInput } from "./parse-evidence.js";

export { parseEvidence, parseScorePlayInput } from "./parse-evidence.js";
export type {
  EvidenceParseResult,
  ScorePlayInputParseResult,
} from "./parse-evidence.js";

/** Re-exported, by name, from the internal classification module — this is
 * the package's real public type/value surface for these; see this file's
 * module doc for why the dependency runs this direction only. */
export type {
  AppFix,
  ChallengeKind,
  Evidence,
  EvidenceClassId,
  EvidenceGroup,
  FixGrade,
  PurchaseCorroboration,
  ScorePlayContext,
  ScorePlayContribution,
  TokenState,
};
export { resolveFixGrade };

/** §4.5's money-only floor. A CODE CONSTANT (A2-05): "No catalog or DB
 * datum can lower it." Every money decision in this module reads this
 * constant directly — never a parameter, never data. */
export const MONEY_MIN = 0.85;

/** Policy v1 (§4.5 heading). Kept as its OWN constant, deliberately
 * separate from `index.ts`'s `POLICY_VERSION`, which an existing,
 * unmodified test pins at 0. */
export const SCORE_PLAY_POLICY_VERSION = 1;

/* ------------------------------------------------------------------ */
/* Receipt fingerprint voiding (should-fix, §4.4/§4.5 line 996)         */
/* ------------------------------------------------------------------ */

/** A second (or later) receipt row sharing a non-empty `fingerprint` with
 * an earlier one, WITHIN the same `scorePlay` call, is void — mirrors
 * `receipt_fingerprint`'s cross-user dedupe (§4.4), applied here at the
 * narrower scope this package can see (one call's own evidence). */
function voidDuplicateFingerprints(evidence: Evidence[]): Evidence[] {
  const seen = new Set<string>();
  return evidence.map((row) => {
    if (row.source !== "receipt_green_fee" || !row.fingerprint) return row;
    if (seen.has(row.fingerprint)) {
      return { ...row, status: "void" as const };
    }
    seen.add(row.fingerprint);
    return row;
  });
}

/* ------------------------------------------------------------------ */
/* Derived correlation (finding 1) + hard-class absorption (should-fix) */
/* ------------------------------------------------------------------ */

/**
 * The fix ids eligible for finding-1(b)'s "same fix reused" correlation —
 * SCOPED EXACTLY to the plan's two fix-identity pairs: "a staff scan and a
 * check-in that reuse the same fix" and "a dwell and the check-in that
 * OPENED it" (`checkinFix` only, never `checkoutFix` — the check-out is a
 * different physical capture). `receipt_green_fee.coSignalFix` and
 * `booking.presenceFix` are DELIBERATELY excluded: neither pair is in the
 * plan's list (a booking correlates with a RECEIPT via `paymentRef`, never
 * via fix reuse), and A2-20b explicitly requires the opposite behaviour for
 * a receipt: "A receipt whose co-signal is the QR-session fix... scores
 * EXACTLY LIKE a receipt with a separate check-in" — i.e. noisy-OR, not
 * `max` — money golden fixture #9 (0.86) is the regression test for this;
 * an earlier, over-generalized version of this function (every fix-carrying
 * row, unconditionally) would have wrongly collapsed #9 to `max(0.80,
 * 0.30) = 0.80`. */
function correlationFixIdsOfRow(row: Evidence): string[] {
  switch (row.source) {
    case "staff_presence":
      return row.coSignalFix ? [row.coSignalFix.fixId] : [];
    case "foreground_dwell":
      return [row.checkinFix.fixId];
    case "foreground_checkin":
      return [row.fix.fixId];
    default:
      return [];
  }
}

/** Fifth gate: now just `internal/classify.ts`'s shared
 * `fixesOfEvidenceRow`, under this file's existing local name — see that
 * export's own doc for why it moved (avoiding drift with
 * `parse-evidence.ts`'s identical need). */
const fixesOfRow = fixesOfEvidenceRow;

class Dsu {
  private readonly parent: number[];
  constructor(n: number) {
    this.parent = Array.from({ length: n }, (_, i) => i);
  }
  find(x: number): number {
    while (this.parent[x] !== x) {
      this.parent[x] = this.parent[this.parent[x]!]!;
      x = this.parent[x]!;
    }
    return x;
  }
  union(a: number, b: number): void {
    const ra = this.find(a);
    const rb = this.find(b);
    if (ra !== rb) this.parent[ra] = rb;
  }
}

/**
 * Finding 1(a)+(b): derives every group of rows that combine by `max`
 * instead of noisy-OR, from the DATA alone:
 *   - every row of the SAME classId (line 890: "two rows of the same class
 *     do not stack");
 *   - a `fixId` shared by two rows (a staff scan / booking / receipt reusing
 *     the same fix as a standalone `foreground_checkin`/`foreground_dwell`
 *     row);
 *   - a `paymentRef` shared by a `booking` and a `receipt_green_fee` row;
 *   - a `health_route` and a `file_import` of the same round (start ±15
 *     min, same facility, both already filtered to `ctx.playFacilityId`).
 *
 * ALSO folds in the should-fix hard-class-absorption rule: a
 * `staff_presence`/`booking` row is unioned with ANY OTHER row that
 * carries a fix satisfying that row's OWN hard-window (±10 min of `scanAt`
 * for staff, same-`ctx.playLocalDate` for booking) — "derive the hard
 * class from any qualifying fix on the same date and facility, whether it
 * comes inline or as a separate check-in/dwell row."
 */
function deriveGroups(evidence: Evidence[], contributions: ScorePlayContribution[], ctx: ScorePlayContext): number[] {
  const n = evidence.length;
  const dsu = new Dsu(n);

  const byClass = new Map<EvidenceClassId, number[]>();
  contributions.forEach((c, i) => {
    const arr = byClass.get(c.classId) ?? [];
    arr.push(i);
    byClass.set(c.classId, arr);
  });
  for (const idxs of byClass.values()) for (let k = 1; k < idxs.length; k += 1) dsu.union(idxs[0]!, idxs[k]!);

  const byFixId = new Map<string, number[]>();
  evidence.forEach((row, i) => {
    for (const fixId of correlationFixIdsOfRow(row)) {
      const arr = byFixId.get(fixId) ?? [];
      arr.push(i);
      byFixId.set(fixId, arr);
    }
  });
  for (const idxs of byFixId.values()) for (let k = 1; k < idxs.length; k += 1) dsu.union(idxs[0]!, idxs[k]!);

  const byPayment = new Map<string, number[]>();
  evidence.forEach((row, i) => {
    const ref = (row.source === "booking" || row.source === "receipt_green_fee") && row.paymentRef;
    if (ref) {
      const arr = byPayment.get(ref) ?? [];
      arr.push(i);
      byPayment.set(ref, arr);
    }
  });
  for (const idxs of byPayment.values()) for (let k = 1; k < idxs.length; k += 1) dsu.union(idxs[0]!, idxs[k]!);

  const roundRows: { i: number; facilityId: string; startedAt: number }[] = [];
  evidence.forEach((row, i) => {
    if ((row.source === "health_route" || row.source === "file_import") && row.startedAt !== undefined) {
      roundRows.push({ i, facilityId: row.facilityId, startedAt: row.startedAt });
    }
  });
  for (let a = 0; a < roundRows.length; a += 1) {
    for (let b = a + 1; b < roundRows.length; b += 1) {
      if (
        roundRows[a]!.facilityId === roundRows[b]!.facilityId &&
        windowMs(roundRows[a]!.startedAt, roundRows[b]!.startedAt, 15 * 60_000)
      ) {
        dsu.union(roundRows[a]!.i, roundRows[b]!.i);
      }
    }
  }

  // Should-fix: hard-class absorption via an external, non-inline fix —
  // but ONLY as a FALLBACK when the row carries NO inline fix of its own
  // at all (`coSignalFix`/`presenceFix` undefined). A row that DOES embed
  // its own fix is making a SPECIFIC claim about what proves it, and that
  // claim is judged on its own merits, never broadened by an unrelated fix
  // elsewhere in the same evidence set — this is what keeps "a booking
  // dated D whose OWN presence fix is on D+1, plus an unrelated check-in on
  // D" at `booking_alone` (0.79 combined with the check-in) rather than
  // wrongly promoting it to `booking_hard` (finding 4's regression test).
  // Fixture #10's NATURAL two-row encoding (a bare `booking({})` with no
  // inline fix, plus a separate `foreground_dwell` on the booking's date)
  // is exactly the case this fallback exists for — and, symmetrically, a
  // bare `staffPresence({})` plus an external fix within ±10 min of
  // `scanAt` (should-fix item, re-gate).
  //
  // Booking-with-a-BAD-inline-fix is handled SEPARATELY, unconditionally,
  // by the `byPayment` union ABOVE: a booking correlates with a receipt
  // sharing its `paymentRef` regardless of whether the booking's own
  // inline fix succeeded (plan line 967) — that union already ran, so by
  // the time `resolveGroups` searches a group's members, a payment-
  // correlated receipt is already IN it even when this fallback doesn't
  // fire for the booking row itself.
  //
  // Money golden fixture #3 ("staff scan without co-signal + Health route
  // + dwell", 0.96, `staff_presence_soft`) is NOT at risk from re-enabling
  // staff absorption: its own fixture data was corrected (the dwell's
  // opening fix moved outside the ±10 min window) specifically so it no
  // longer coincidentally collides with the default `scanAt` — see
  // `score-play-golden.test.ts`.
  evidence.forEach((row, i) => {
    if (row.source === "staff_presence" && row.coSignalFix === undefined) {
      for (let j = 0; j < n; j += 1) {
        if (j === i) continue;
        for (const fix of fixesOfRow(evidence[j]!)) {
          if (staffFixSatisfiesHardWindow(fix, row.scanAt, ctx)) dsu.union(i, j);
        }
      }
    }
    if (row.source === "booking" && row.presenceFix === undefined && row.localDate === ctx.playLocalDate) {
      for (let j = 0; j < n; j += 1) {
        if (j === i) continue;
        for (const fix of fixesOfRow(evidence[j]!)) {
          if (bookingFixSatisfiesHardWindow(fix, ctx)) dsu.union(i, j);
        }
      }
    }
  });

  return evidence.map((_, i) => dsu.find(i));
}

/** Fourth re-gate, should-fix: picks ONE fix among every fix in `fixes`
 * that satisfies `satisfies`, preferring an `attested` one when any exists
 * — deterministic regardless of array order. When no `attested` candidate
 * exists, every remaining satisfying fix is `unattestable` (a `failed`
 * grade never satisfies `staffFixSatisfiesHardWindow`/
 * `bookingFixSatisfiesHardWindow`, both of which require
 * `isQualityCoSignalFix`), so the GRADE of whichever one is returned is
 * itself order-independent even though the specific fix OBJECT picked
 * among several unattestable ones is not — and grade is the only thing
 * `governingGrade` (and therefore `computeHeldReview`) ever reads. Fixes
 * the order-dependence the gate found: `[staffPresence({}),
 * checkin(unattestable, +1 min), checkin(attested, +2 min)]` previously
 * picked whichever check-in's fix came FIRST in the flattened search
 * order (the unattestable one), while the reverse row order picked the
 * attested one — both must resolve to the SAME `governingGrade`. */
function pickBestSatisfyingFix(fixes: AppFix[], satisfies: (fix: AppFix) => boolean): AppFix | undefined {
  const satisfying = fixes.filter(satisfies);
  if (satisfying.length === 0) return undefined;
  const attested = satisfying.find((fix) => resolveFixGrade(fix.token) === "attested");
  return attested ?? satisfying[0];
}

/**
 * Collapses each derived group down to ONE contribution: if the group
 * contains (after absorption) a hard-eligible `staff_presence`/`booking`
 * row, the WHOLE group becomes that single hard contribution (the group's
 * other members — e.g. an absorbed `foreground_checkin`/`foreground_dwell`
 * — are dropped, never double-counted); otherwise the group becomes its
 * single MAX-weight member (badge pipeline: max over every member; money
 * pipeline: max over the money-eligible subset only, or nothing if none
 * are money-eligible).
 */
interface ResolvedContribution {
  contribution: ScorePlayContribution;
  /** The group this contribution still belongs to — carried through so
   * `combine` can correctly pick the max-weight member PER PIPELINE for a
   * non-hard group (a hard winner is already alone in its own group by
   * construction, since it replaces every other member). Regression note:
   * an earlier revision discarded this (recomputing trivial per-index
   * groups downstream), which silently undid finding-1's own fix by
   * letting a `paymentRef`-correlated pair noisy-OR together again instead
   * of taking their max — money golden fixture #4 is the regression test. */
  groupId: number;
}

function resolveGroups(
  evidence: Evidence[],
  contributions: ScorePlayContribution[],
  groups: number[],
  ctx: ScorePlayContext,
): ResolvedContribution[] {
  const byGroup = new Map<number, number[]>();
  groups.forEach((g, i) => {
    const arr = byGroup.get(g) ?? [];
    arr.push(i);
    byGroup.set(g, arr);
  });

  const resolved: ResolvedContribution[] = [];
  for (const idxs of byGroup.values()) {
    // Hard candidates: every `staff_presence`/`booking` row in this group
    // whose hard-window is satisfied by SOME fix among the group's OWN
    // members (inline or absorbed) — searched over the WHOLE group
    // unconditionally now. This is sound because `deriveGroups` already
    // decided group MEMBERSHIP correctly: a row with its own (possibly
    // bad) inline fix stays in a singleton group unless a LEGITIMATE
    // correlation (same fixId, same `paymentRef`, same round, or the
    // no-inline-fix absorption fallback) put something else in it — so by
    // the time we're here, "search the whole group" and "search only rows
    // legitimately correlated with this one" are the same set.
    //
    // Should-fix (order dependence, group-level): collect every candidate
    // first, then pick ONE winner by a rule that doesn't depend on which
    // order the rows were passed in — the highest class WEIGHT
    // (`staff_presence_hard` 0.95 beats `booking_hard` 0.90).
    //
    // Should-fix (order dependence, fix-level, fourth re-gate): the
    // SATISFYING FIX itself is picked via `pickBestSatisfyingFix`
    // (prefers `attested`), not `.find` — see that function's doc.
    interface HardCandidate {
      row: Evidence;
      contribution: ScorePlayContribution;
      classId: EvidenceClassId;
      satisfyingFix: AppFix;
    }
    const candidates: HardCandidate[] = [];
    for (const i of idxs) {
      const row = evidence[i]!;
      const contribution = contributions[i]!;
      if (row.source === "staff_presence") {
        const satisfyingFix = pickBestSatisfyingFix(
          idxs.flatMap((j) => fixesOfRow(evidence[j]!)),
          (fix) => staffFixSatisfiesHardWindow(fix, row.scanAt, ctx),
        );
        if (satisfyingFix) candidates.push({ row, contribution, classId: "staff_presence_hard", satisfyingFix });
      } else if (row.source === "booking" && row.localDate === ctx.playLocalDate) {
        const satisfyingFix = pickBestSatisfyingFix(
          idxs.flatMap((j) => fixesOfRow(evidence[j]!)),
          (fix) => bookingFixSatisfiesHardWindow(fix, ctx),
        );
        if (satisfyingFix) candidates.push({ row, contribution, classId: "booking_hard", satisfyingFix });
      }
    }
    // Every group gets its own fresh id in the OUTPUT (`resolved`'s own
    // index space), distinct from the input `groups` numbering — a hard
    // winner collapses a whole group into one item, so its identity here
    // doesn't matter (nothing else shares it); a non-hard group's members
    // all share THIS SAME id so `combine` can pick a max per pipeline.
    const outputGroupId = resolved.length;
    if (candidates.length > 0) {
      // Should-fix: apply the §4.3 A2-01 user-pick exclusion BEFORE
      // picking a winner, not after. `finish()` (in `internal/classify.ts`)
      // strips `hard`/`moneyEligible` from a user-picked row's
      // contribution — but the winner-selection comparison ran on the RAW
      // class weight (0.95/0.90), so a user-picked staff-scan candidate
      // could win over a non-user-picked booking candidate on raw weight,
      // then get reduced to non-hard/non-money by `finish()`, DISCARDING
      // the legitimate booking candidate along with it (each group
      // produces exactly one contribution). A user-picked candidate's
      // effective weight is treated as below every real weight (never
      // `0` — two user-picked candidates still need to compare against
      // each other for the `hard: false` fallthrough to at least be
      // deterministic).
      const effectiveWeight = (c: HardCandidate) => (c.row.courseDisambiguatedBy === "user" ? -1 : WEIGHT[c.classId]);
      let winner = candidates[0]!;
      for (const c of candidates) if (effectiveWeight(c) > effectiveWeight(winner)) winner = c;
      resolved.push({
        contribution: finish(winner.row, {
          classId: winner.classId,
          group: GROUP[winner.classId],
          hard: true,
          badgeWeight: WEIGHT[winner.classId],
          moneyEligible: true,
          governingGrade: resolveFixGrade(winner.satisfyingFix.token),
        }),
        groupId: outputGroupId,
      });
      continue;
    }
    // No hard winner: the group's members all carry the SAME `groupId` so
    // `combine` can pick a max-weight member per pipeline (badge over
    // every member; money over the money-eligible subset only).
    for (const i of idxs) resolved.push({ contribution: contributions[i]!, groupId: outputGroupId });
  }
  return resolved;
}

/* ------------------------------------------------------------------ */
/* Combination (noisy-OR, group max, device-GPS cap)                    */
/* ------------------------------------------------------------------ */

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}

function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

function noisyOr(weights: number[]): number {
  let q = 1;
  for (const w of weights) q *= 1 - clamp01(w);
  return 1 - q;
}

/** Picks the single max-weight member of each already-resolved group
 * (finding 1(a): same-class dedup + derived correlated pairs both land
 * here as ordinary groups by the time this runs, EXCEPT a resolved hard
 * winner, which `resolveGroups` has already reduced to one contribution
 * per group — so this is only ever picking among GENUINE remaining
 * ambiguity, never re-deciding hard status). */
function pickMaxPerGroup(contributions: ScorePlayContribution[], groups: number[], weightOf: (c: ScorePlayContribution) => number): ScorePlayContribution[] {
  const byGroup = new Map<number, ScorePlayContribution[]>();
  contributions.forEach((c, i) => {
    const g = groups[i]!;
    const arr = byGroup.get(g) ?? [];
    arr.push(c);
    byGroup.set(g, arr);
  });
  const out: ScorePlayContribution[] = [];
  for (const members of byGroup.values()) {
    let best = members[0]!;
    for (const m of members) if (weightOf(m) > weightOf(best)) best = m;
    out.push(best);
  }
  return out;
}

interface CombineResult {
  score: number;
  /** Blocking finding 4: the exact contributions that fed the final
   * noisy-OR sum for this pipeline — `computeHeldReview` reads
   * `governingGrade` from ONLY these (never from any other fix elsewhere
   * in `evidence[]`), so an unrelated attested fix that never actually
   * entered the winning combination can't paper over an unattestable one
   * that did. */
  merged: ScorePlayContribution[];
}

function combine(contributions: ScorePlayContribution[], groups: number[], pipeline: "badge" | "money"): CombineResult {
  const weightOf = (c: ScorePlayContribution) => (pipeline === "badge" ? c.badgeWeight : c.moneyWeight);
  const indices = contributions
    .map((_, i) => i)
    .filter((i) => pipeline === "badge" || contributions[i]!.moneyEligible);
  const pool = indices.map((i) => contributions[i]!);
  const poolGroups = indices.map((i) => groups[i]!);
  const merged = pickMaxPerGroup(pool, poolGroups, weightOf);
  const deviceGps = merged.filter((c) => c.group === "device-gps");
  const rest = merged.filter((c) => c.group !== "device-gps");
  const finalWeights = rest.map(weightOf);
  if (deviceGps.length > 0) {
    const subtotal = Math.min(noisyOr(deviceGps.map(weightOf)), DEVICE_GPS_SUBTOTAL_CAP);
    finalWeights.push(subtotal);
  }
  return { score: Math.min(noisyOr(finalWeights), OVERALL_SCORE_CAP), merged };
}

/* ------------------------------------------------------------------ */
/* presence_signal (§4.5, A2-06)                                        */
/* ------------------------------------------------------------------ */

function collectFixes(evidence: Evidence[]): AppFix[] {
  const fixes: AppFix[] = [];
  for (const row of evidence) fixes.push(...fixesOfRow(row));
  return fixes;
}

/** Every fix in `evidence` that satisfies the co-signal quality gate on the
 * play's own facility/date — i.e. every fix `presence_signal` itself
 * accepts as ITS proof (`presence_signal = qualifyingPresenceFixes(...)
 * .length > 0`, computed inline in `scorePlay`). Also used by (third
 * re-gate, finding 1) `computeHeldReview`, which needs the SAME set:
 * `money` requires `presence_signal` unconditionally, so the grade of
 * whichever fix(es) establish presence is just as load-bearing for
 * held_review as the grade of whichever fix establishes the score/hard
 * path — a row that is neither hard nor money-eligible (soft
 * `staff_presence`, a user-picked check-in) can still be presence's ONLY
 * proof. */
function qualifyingPresenceFixes(evidence: Evidence[], ctx: ScorePlayContext): AppFix[] {
  return collectFixes(evidence).filter(
    (fix) => isQualityCoSignalFix(fix, ctx.playFacilityId) && fix.localDate === ctx.playLocalDate,
  );
}

/**
 * Third re-gate, finding 1: `money = presence_signal && (hardSignal ||
 * score_monetary >= MONEY_MIN)` — `presence_signal` is an UNCONDITIONAL
 * requirement of `money`, not merely an optional booster, so whichever
 * fix(es) establish IT are just as load-bearing for held_review as
 * whichever fix(es) establish the hard/score path. A row that is neither
 * `hard` nor money-eligible (a soft `staff_presence` outside its own ±10
 * min window; a user-picked check-in, money-capped to 0 but still
 * presence-eligible per A2-06/line 933) can still be presence's ONLY
 * proof — reading `governingGrade` from only the hard winner or only
 * `moneyMerged` misses this entirely (the gate's own failing cases: a
 * Garmin sensor round alone reaches 0.85, and an UNRELATED unattestable
 * fix elsewhere is the only thing making `presence_signal` true).
 *
 * Order-independence (should-fix): both legs below are computed with
 * `.some(...)` over an unordered SET condition (does ANY contributing
 * fix/contribution grade unattestable, and does NONE grade attested) —
 * neither leg picks "the first" or "the last" of anything, so the result
 * cannot depend on `evidence[]`'s row order or `playContributions`' own
 * order. See `test/score-play-regate3.test.ts`'s permutation test.
 */
function computeHeldReview(
  playContributions: ScorePlayContribution[],
  moneyMerged: ScorePlayContribution[],
  presenceFixes: AppFix[],
  hardSignal: boolean,
  money: boolean,
): boolean {
  if (!money) return false;

  // Fifth gate, H1: generalized from "exactly `unattestable`" to "any
  // governing grade that isn't cleanly `attested`" — `resolveFixGrade`
  // (fixed this round to allow-list `{attested, unattestable}` and treat
  // everything else, including a malformed/adversarial grade, as
  // `"failed"`) already stops a `"failed"`-graded fix from ever becoming a
  // qualifying presence fix in the first place, so this is defence in
  // depth: even if that upstream invariant were ever violated, a grade
  // that is neither `"attested"` nor the specific literal `"unattestable"`
  // still routes to held_review here, rather than silently falling
  // through to `held: false` because it matched neither exact string.
  const presenceHasAttested = presenceFixes.some((fix) => resolveFixGrade(fix.token) === "attested");
  const presenceHasNonAttested = presenceFixes.some((fix) => resolveFixGrade(fix.token) !== "attested");
  const presenceHeld = !presenceHasAttested && presenceHasNonAttested;

  if (hardSignal) {
    // Should-fix (order independence): `.filter` + `.some` over the SET of
    // hard contributions — not `.find`, which picked whichever hard
    // contribution happened to come FIRST in `evidence[]`'s own order.
    // Two independent hard contributions (e.g. an unattestable staff-hard
    // AND an attested booking-hard, neither correlated with the other) are
    // now judged together: an attested one ANYWHERE in the hard set is
    // enough to not hold, regardless of array order.
    const hardOnes = playContributions.filter((c) => c.hard);
    // H1: same generalization as `presenceHeld` above — any DEFINED,
    // non-`"attested"` governing grade counts (not just the specific
    // literal `"unattestable"`), fail-safe against a hypothetical
    // malformed grade that got this far.
    const hardHasAttested = hardOnes.some((c) => c.governingGrade === "attested");
    const hardHasNonAttested = hardOnes.some((c) => c.governingGrade !== undefined && c.governingGrade !== "attested");
    const hardHeld = !hardHasAttested && hardHasNonAttested;
    return hardHeld || presenceHeld;
  }
  const hasAttested = moneyMerged.some((c) => c.governingGrade === "attested");
  const hasNonAttested = moneyMerged.some((c) => c.governingGrade !== undefined && c.governingGrade !== "attested");
  const scoreHeld = !hasAttested && hasNonAttested;
  return scoreHeld || presenceHeld;
}

/* ------------------------------------------------------------------ */
/* Purchase corroboration (§4.5 line 1005, §4.6)                       */
/* ------------------------------------------------------------------ */

function daysBetween(a: string, b: string): number {
  const msPerDay = 24 * 60 * 60 * 1000;
  return Math.abs(Date.parse(b) - Date.parse(a)) / msPerDay;
}

function corroborationApplies(ctx: ScorePlayContext): boolean {
  const purchases = ctx.purchases ?? [];
  return purchases.some((p) => p.facilityId === ctx.playFacilityId && daysBetween(p.localDate, ctx.playLocalDate) <= 7);
}

/* ------------------------------------------------------------------ */
/* scorePlay                                                            */
/* ------------------------------------------------------------------ */

export interface ScorePlayResult {
  score_badge: number;
  score_monetary: number;
  presence_signal: boolean;
  money: boolean;
  /** §7.5 row 3 (should-fix): true when `money` rests entirely on an
   * `unattestable`-grade co-signal — the reward this play backs must route
   * to `held_review`, never auto-issue and never auto-refuse. */
  heldReview: boolean;
  policyVersion: number;
  contributions: ScorePlayContribution[];
  /** H2 (fifth gate): present ONLY on a fail-closed result — `parseScorePlayInput`
   * rejected the raw `{evidence, ctx}` input before any scoring ran. Every
   * other field still holds its safe "nothing happened" default
   * (`money: false`, empty `contributions`, …), so a caller that doesn't
   * check `reasons` still gets a conservative, non-throwing result. */
  reasons?: string[];
  /** M5 (fifth gate): SHA-256 (hex) over the canonicalized, ALREADY-PARSED
   * `{evidence, ctx}` this result was computed from — present only when
   * parsing succeeded (a failed parse has no "parsed input" to digest).
   * Lets a caller (or an audit trail) prove exactly which validated input
   * produced a given money decision, independent of the raw/pre-parse
   * bytes that arrived over the wire. */
  inputDigest?: string;
}

/**
 * §4.5's scorer, policy v1. Pure, deterministic, no I/O.
 *
 * **H2 (fifth gate) — the TRUST TABLE.** `parseScorePlayInput`
 * (`./parse-evidence.js`) runs FIRST, always, before a single byte of
 * `evidenceIn`/`ctx` is trusted — this table is what that parser enforces,
 * field by field, so a reader can see at a glance what is (and isn't)
 * server-derived, and where. "server-derived" means the FIELD's value is
 * meant to be produced by server-side code the client cannot forge (a
 * token/attestation service, the matching pipeline, the booking/payment
 * ledger, staff tooling) — the parser can only enforce SHAPE (type, enum
 * membership, finiteness, non-empty strings); it cannot itself verify
 * PROVENANCE, which is why every field below still names the server path
 * that is trusted to have produced it honestly.
 *
 * | Field | Server-derived? | Produced by |
 * |---|---|---|
 * | `token.grade` (attestation) | Yes | the device-attestation verification service (App Attest / Play Integrity) — never trust a client-reported grade string directly |
 * | `hardwareSupportsAttestation` | Yes | the same attestation service's device-capability report |
 * | `challenge` | Yes | the server-issued challenge nonce record (`live`/`prefetched`) — a fix is only ever `"live"`/`"prefetched"` if the server itself issued and later matched that challenge |
 * | `facilityId` (on a fix or a row) | Partially | the client reports which facility it THINKS it's at; `@golfraven/matching`'s geometry match is what actually confirms it (`insideBuffer`/`geometryKind`/`verificationTier` below) |
 * | `verificationTier` | Yes | `@golfraven/matching`'s facility-verification pipeline (never client-set) |
 * | `geometryKind` | Yes | `@golfraven/matching`'s own polygon/radius-fallback determination |
 * | `insideBuffer` | Yes | `@golfraven/matching`'s point-in-polygon (or -circle) containment check against the fix's device-reported coordinates |
 * | `accuracyMeters` | No (device-reported) | the device's own GPS accuracy claim — trusted only as a QUALITY signal (capped, never a proof of anything), never as an identity/location proof by itself |
 * | `localDate` | Partially | derived server-side from `capturedAt` in the facility's tz (H2's own cross-check, this parser) — a fix whose client-labelled `localDate` disagrees with that derivation is rejected outright |
 * | `capturedAt` | No (device clock) | the device's own clock — never trusted alone; corroborated via the `localDate` cross-check and the co-signal/hard-window comparisons throughout `internal/classify.ts` |
 * | `fixId` | Yes | the challenge id or assertion hash the attestation exchange itself produced — never a client-invented string (M1) |
 * | `paymentRef` | Yes | the booking/payment ledger's own reference id (M1) |
 * | `vendorCourseMapped` / `sensorProvenance` | Yes | the vendor-sync pipeline's own course-matching and device-provenance checks (Garmin/Arccos) — never client-set |
 * | receipt `status` | Yes | the green-fee receipt/POS integration, never the app client |
 * | `courseDisambiguatedBy` | Yes | whichever server-side step actually resolved the course ambiguity (`geometry`/`staff`); `"user"` specifically marks a PLAYER's own pick, which is exactly why it's money-capped (A2-01) |
 * | staff `scanAt` | Yes | the staff-facing scan tool's own server timestamp, not the player's device |
 *
 * **Scope boundary (stated once, so it isn't re-litigated per class).**
 * `scorePlay` computes the two scores, `presence_signal`, `money` and a
 * `heldReview` routing flag (§7.5 row 3: an `unattestable` co-signal routes
 * a reward to `held_review`, never refused) — it never touches
 * `play.status` (`disputed` via event-time velocity) or writes
 * `fraud_signal` rows; those are DB-side effects of a different function.
 * A `failed`-grade fix is still zeroed here (§4.5 G3-08: "nothing can be
 * earned on it") — that IS a scoring effect — but the accompanying
 * `fraud_signal` is not.
 */
export function scorePlay(evidenceIn: Evidence[], ctx: ScorePlayContext): ScorePlayResult {
  // H2 (fifth gate): the parser runs FIRST, always — see this function's
  // own TRUST TABLE doc for exactly what it closes. A parse failure
  // returns the safe "nothing happened" default (`money: false`, empty
  // `contributions`) plus `reasons`, and NEVER throws — the scoring logic
  // below never runs on unparsed/untrusted data.
  const parsed = parseScorePlayInput({ evidence: evidenceIn, ctx });
  if (!parsed.success) {
    return {
      score_badge: 0,
      score_monetary: 0,
      presence_signal: false,
      money: false,
      heldReview: false,
      policyVersion: SCORE_PLAY_POLICY_VERSION,
      contributions: [],
      reasons: parsed.reasons,
    };
  }
  const result = scorePlayOnParsedInput(parsed.evidence, parsed.ctx);
  return { ...result, inputDigest: computeInputDigest(parsed.evidence, parsed.ctx) };
}

/** Canonical (sorted-key) JSON serialization — the same value serializes
 * identically regardless of the source object's own key insertion order,
 * which `JSON.stringify` alone does not guarantee. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === "object") {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      sorted[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return sorted;
  }
  return value;
}

/** M5 (fifth gate): SHA-256 (hex) over the canonicalized, ALREADY-PARSED
 * `{evidence, ctx}` — computed AFTER `parseScorePlayInput` has already
 * validated it, so this digest is over trusted, shape-checked data, never
 * the raw pre-parse bytes.
 *
 * **Deliberately `@noble/hashes`, never `node:crypto`.** This package's
 * own module doc says it plainly: "authoritative on the server,
 * preview-only on DEVICE" — the device is the React Native app, which has
 * no `node:crypto`. `@noble/hashes` is pure JS (MIT, audited,
 * zero-dependency) and runs identically in both places, so `scorePlay`
 * stays host-neutral rather than silently gaining a Node-only dependency
 * the app build can't satisfy. */
function computeInputDigest(evidence: Evidence[], ctx: ScorePlayContext): string {
  const canonical = JSON.stringify(canonicalize({ evidence, ctx }));
  // `utf8ToBytes` (not the DOM-only `TextEncoder`, which this package's
  // "ES2022"-only `lib` doesn't type and which isn't guaranteed on every
  // host this pure-TS package runs on) — same `@noble/hashes` package as
  // `sha256`/`bytesToHex`, so no new dependency for this one conversion.
  return bytesToHex(sha256(utf8ToBytes(canonical)));
}

/**
 * The actual scorer, run on ALREADY-PARSED (`parseScorePlayInput`) input —
 * every other doc comment on `scorePlay` (the money rule, the trust table,
 * the scope boundary) describes this function's behaviour; it's split out
 * only so `scorePlay` itself can wrap it with the parse-first/fail-closed
 * step and the `inputDigest` computation above.
 */
function scorePlayOnParsedInput(evidenceIn: Evidence[], ctx: ScorePlayContext): ScorePlayResult {
  // Finding 3 + blocking finding 2 (second re-gate): drop any row whose OWN
  // facility OR OWN date disagrees with the play being scored, before
  // anything else runs — this is what stops a vendor round or a staff scan
  // dated on a DIFFERENT day from contributing to this play at all. Every
  // class-specific date check elsewhere (booking's same-day presence, a
  // receipt's same-date co-signal, a device row's own fix date, and now
  // `classifyEvidenceRow`'s own `rowOk` defence-in-depth check) is
  // additional, narrower anchoring on top of this blanket row-level filter
  // — not a substitute for it.
  // H3 (fifth gate): the course anchor — see `ScorePlayContext.playCourseId`'s
  // own doc (`internal/classify.js`). Applied at this SAME top-level filter
  // as the facility/date drop, for the same reason: a wrong-course row must
  // never reach `deriveGroups`/`resolveGroups` at all, not merely be zeroed
  // downstream.
  const evidence = voidDuplicateFingerprints(evidenceIn).filter(
    (row) =>
      row.facilityId === ctx.playFacilityId &&
      row.localDate === ctx.playLocalDate &&
      (row.courseId === undefined || ctx.playCourseId === undefined || row.courseId === ctx.playCourseId),
  );

  const rawContributions = evidence.map((row) => classifyEvidenceRow(row, ctx));
  const groups = deriveGroups(evidence, rawContributions, ctx);
  const resolved = resolveGroups(evidence, rawContributions, groups, ctx);
  const playContributions = resolved.map((r) => r.contribution);
  const playGroups = resolved.map((r) => r.groupId);

  const playClassesBadge = combine(playContributions, playGroups, "badge").score;
  const hasPlayClass = playContributions.length > 0;
  const corroborationEligible =
    hasPlayClass && playClassesBadge >= CORROBORATION_ELIGIBLE_THRESHOLD && corroborationApplies(ctx);

  const allContributions: ScorePlayContribution[] = [...playContributions];
  if (corroborationApplies(ctx)) {
    allContributions.push({
      evidenceId: "purchase_corroboration",
      classId: "purchase_corroboration",
      group: "corroboration",
      hard: false,
      badgeWeight: WEIGHT.purchase_corroboration,
      moneyEligible: false,
      moneyWeight: 0,
    });
  }

  const scoreBadge = corroborationEligible
    ? Math.min(noisyOr([playClassesBadge, WEIGHT.purchase_corroboration]), OVERALL_SCORE_CAP)
    : playClassesBadge;

  const moneyCombined = combine(playContributions, playGroups, "money");
  const scoreMonetary = moneyCombined.score;

  const presenceFixes = qualifyingPresenceFixes(evidence, ctx);
  const presenceSignal = presenceFixes.length > 0;
  const hardSignal = playContributions.some((c) => c.hard);
  const money = presenceSignal && (hardSignal || scoreMonetary >= MONEY_MIN);
  const heldReview = computeHeldReview(playContributions, moneyCombined.merged, presenceFixes, hardSignal, money);

  return {
    score_badge: round2(scoreBadge),
    score_monetary: round2(scoreMonetary),
    presence_signal: presenceSignal,
    money,
    heldReview,
    policyVersion: SCORE_PLAY_POLICY_VERSION,
    contributions: allContributions,
  };
}
