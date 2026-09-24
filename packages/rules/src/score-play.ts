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
 * silently contribute to this one. **The caller does not have to
 * pre-filter to one play's rows before calling** — `scorePlay` scores ONE
 * PLAY PER CALL regardless of how many OTHER plays' rows ride along in
 * `evidence[]`; those are harmlessly excluded (`parse-evidence.js`'s loose
 * facility/date/course filter), never quarantined, never counted against
 * `EVIDENCE_ROW_CAP` (the real per-play row bound — see that constant's
 * own doc, `internal/classify.js`, for the split from `ABSOLUTE_ROW_CAP`,
 * the much larger pure-DoS bound on the raw, unfiltered array).
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

/** F5 (sixth gate): `deriveGroups`'s "same round" correlation window
 * (`health_route`/`file_import`, both already filtered to
 * `ctx.playFacilityId`) — hoisted from an inline `15 * 60_000` literal. */
export const ROUND_CORRELATION_WINDOW_MS = 15 * 60_000;

/** F5 (sixth gate): `corroborationApplies`'s purchase-corroboration
 * window, in days — hoisted from an inline `<= 7` literal. */
export const CORROBORATION_WINDOW_DAYS = 7;

/* ------------------------------------------------------------------ */
/* Receipt fingerprint voiding (should-fix, §4.4/§4.5 line 996)         */
/* ------------------------------------------------------------------ */

/** Status rank among the NON-poisoning, NON-ignored candidates in a
 * fingerprint group (`voidDuplicateFingerprints`) — `approved` beats
 * `pending`. A candidate is never itself `void` (a `"duplicate"`-void row
 * is filtered out before this ever runs; a `"reviewer"`/`"fraud"`-void row
 * poisons the whole group before this ever runs) — `void: 0` stays only
 * as a defensive floor, unreachable in the normal flow. */
const RECEIPT_STATUS_RANK: Record<"approved" | "pending" | "void", number> = {
  approved: 2,
  pending: 1,
  void: 0,
};

type ReceiptRow = Extract<Evidence, { source: "receipt_green_fee" }>;

/** Eighth gate, item 1: "missing reason on a void row is treated as
 * `reviewer`, which fails safe." */
function effectiveVoidReason(row: ReceiptRow): "duplicate" | "reviewer" | "fraud" {
  return row.voidReason ?? "reviewer";
}

/**
 * A second (or later) receipt row sharing a non-empty `fingerprint` with
 * an earlier one, WITHIN the same `scorePlay` call, is void — mirrors
 * `receipt_fingerprint`'s cross-user dedupe (§4.4), applied here at the
 * narrower scope this package can see (one call's own evidence).
 *
 * **Eighth gate, item 1: the seventh gate's "any void poisons the whole
 * group" rule was ITSELF a regression** — it could not tell "a reviewer
 * flagged this CLAIM as fraud/duplicate" (which really should poison
 * every row sharing that fingerprint) apart from "intake's own dedup
 * quietly voided a re-photographed copy of an otherwise honest, approved
 * receipt" (which should NOT poison anything — the original approved
 * receipt is still perfectly good evidence). Case A from the gate: an
 * approved original plus an intake-voided re-upload of the SAME receipt
 * dropped from 0.86 to 0.30 under the seventh gate's rule, because the
 * dedup-void poisoned the group and took the honest original down with
 * it. `voidReason` (`internal/classify.js`) is the fix:
 *
 * 1. **`"duplicate"`-void rows are simply IGNORED** — removed from
 *    consideration entirely, neither poisoning nor competing to win. An
 *    approved original next to its own dedup-voided re-upload scores
 *    exactly as if the re-upload had never been submitted.
 * 2. **`"reviewer"`/`"fraud"`-void rows POISON the whole group**, same as
 *    the seventh gate's rule — a human/fraud-check flag on the CLAIM
 *    (not merely "this exact row is a copy") taints every row sharing
 *    that fingerprint. A MISSING `voidReason` on a void row defaults to
 *    `"reviewer"` (fails safe: absent evidence it was a harmless dedup,
 *    assume the more cautious case).
 * 3. **Among what's left (never `void` — `"duplicate"`-void is gone,
 *    `"reviewer"`/`"fraud"`-void already poisoned the group and returned
 *    early): BEST STATUS WINS FIRST** (`approved` > `pending`) — this is
 *    the seventh gate's OWN regression (Case B): an earlier-captured
 *    `pending` copy used to beat a later `approved` one outright, because
 *    that gate made `capturedAt` the PRIMARY comparator. `capturedAt` is
 *    now ONLY a tiebreak BETWEEN ROWS OF THE SAME STATUS (earliest wins,
 *    when both sides carry a `coSignalFix`) — never a way for a `pending`
 *    row to out-rank an `approved` one. Smallest `id` is the final
 *    tiebreak, same as before.
 *
 * **Ninth gate, BLOCKING (score-play.ts:200-250 in that review's line
 * numbers): the winner comparison above was INTRANSITIVE.** The eighth
 * gate's winner-selection loop compared `capturedAt` "ONLY when BOTH the
 * candidate and the CURRENT WINNER happen to carry a `coSignalFix` —
 * otherwise fall straight through to `id`." That is not one order at
 * all: WHICH tiebreak rule fires depends on which two rows happen to be
 * compared against each other, which is exactly how a cycle becomes
 * possible. Concretely (all three `approved`, same fingerprint): A (has a
 * fix, `capturedAt` T-2s, id `"z"`), B (no fix, id `"m"`), C (has a fix,
 * `capturedAt` T-1s, id `"a"`). A vs B: B has no fix, so the comparison
 * falls through to id — `"m" < "z"`, B wins. C vs B: same — `"a" < "m"`,
 * C wins. But A vs C: BOTH have a fix, so `capturedAt` decides — A's
 * earlier `capturedAt` wins. That's A beats C, C beats B, B beats A: a
 * genuine rock-paper-scissors cycle, and the greedy left-to-right fold
 * the old code used to pick a "winner" is order-dependent whenever the
 * candidate set contains one. The exploit: with a fold instead of a
 * total order, 4 of the 6 permutations of `[A, B, C]` give money and 2
 * give none, all four under the SAME `inputDigest` (order-independence
 * only, per F4 — but the actual winner, hence the actual MONEY
 * determination, still silently varied with array order).
 *
 * **The fix: ONE strict total order, applied via a real comparator
 * (`compareCandidates`, below) and `Array.prototype.sort`, never a
 * pairwise fold.** A sort's comparator is called on many pairs and their
 * results must be mutually consistent (transitive) for the sort itself
 * to be well-defined — which forces the tiebreak rule to be a SINGLE
 * lexicographic key that never depends on which two rows are being
 * compared:
 *   1. status rank, descending (`approved` > `pending`);
 *   2. HAS a `coSignalFix`, true first (a row with a fix always outranks
 *      one without, regardless of anything about `capturedAt` — this is
 *      the piece the eighth gate's fold got wrong: it let "no fix"
 *      compare directly against "has fix" via id, which is exactly the
 *      cross-group comparison that created the cycle);
 *   3. `capturedAt`, ascending (only ever compared between two rows that
 *      BOTH have a fix, guaranteed by rule 2 already having tied them on
 *      "has a fix" — so this is always a well-defined, real comparison
 *      wherever it's reached, never a fabricated default for a fixless
 *      row);
 *   4. `id`, ascending — final tiebreak, unchanged.
 * Sorting by this key is provably transitive (lexicographic order over
 * four independently well-ordered components), so the winner is now the
 * SAME regardless of the candidates' array order — no fold, no cycle.
 *
 * **Order-independent throughout** (F2, sixth gate, preserved): every
 * comparison here is over the SET of a fingerprint's members, never "the
 * first/last in array order." */
function compareCandidates(a: ReceiptRow, b: ReceiptRow): number {
  const rankDiff = RECEIPT_STATUS_RANK[b.status] - RECEIPT_STATUS_RANK[a.status]; // descending: approved(2) before pending(1)
  if (rankDiff !== 0) return rankDiff;

  const aHasFix = a.coSignalFix !== undefined;
  const bHasFix = b.coSignalFix !== undefined;
  if (aHasFix !== bHasFix) return aHasFix ? -1 : 1; // a row WITH a fix always sorts first

  if (aHasFix && bHasFix) {
    // Both have a fix (guaranteed by the check above once we reach here
    // with aHasFix === bHasFix === true) — capturedAt is always
    // well-defined for both sides, never a fabricated stand-in.
    const atDiff = a.coSignalFix!.capturedAt - b.coSignalFix!.capturedAt; // ascending: earliest first
    if (atDiff !== 0) return atDiff;
  }

  if (a.id < b.id) return -1; // ascending id, final tiebreak
  if (a.id > b.id) return 1;
  return 0;
}
function voidDuplicateFingerprints(evidence: Evidence[]): Evidence[] {
  const byFingerprint = new Map<string, ReceiptRow[]>();
  for (const row of evidence) {
    if (row.source === "receipt_green_fee" && row.fingerprint) {
      const arr = byFingerprint.get(row.fingerprint) ?? [];
      arr.push(row);
      byFingerprint.set(row.fingerprint, arr);
    }
  }
  const allVoidFingerprints = new Set<string>();
  const winnerIdByFingerprint = new Map<string, string>();
  for (const [fingerprint, rows] of byFingerprint) {
    if (rows.length < 2) continue; // not actually a duplicate group

    const poisons = (r: ReceiptRow) => r.status === "void" && effectiveVoidReason(r) !== "duplicate";
    if (rows.some(poisons)) {
      allVoidFingerprints.add(fingerprint);
      continue;
    }

    // "duplicate"-void rows are ignored entirely — they never compete to
    // win (they're already `void` via their own `status`, so leaving them
    // out of `winnerIdByFingerprint` and letting the generic map step
    // below re-confirm `void` on them is a no-op either way).
    const candidates = rows.filter((r) => r.status !== "void");
    if (candidates.length === 0) continue; // every copy was a dedup-void; nothing to pick, nothing to poison

    // Ninth gate: a single Array.prototype.sort over the transitive
    // `compareCandidates` total order — NOT a pairwise fold (see this
    // function's own doc for exactly why a fold went wrong here).
    const winner = candidates.slice().sort(compareCandidates)[0]!;
    winnerIdByFingerprint.set(fingerprint, winner.id);
  }
  return evidence.map((row) => {
    if (row.source !== "receipt_green_fee" || !row.fingerprint) return row;
    if (allVoidFingerprints.has(row.fingerprint)) return { ...row, status: "void" as const };
    const winnerId = winnerIdByFingerprint.get(row.fingerprint);
    if (winnerId === undefined || row.id === winnerId) return row;
    return { ...row, status: "void" as const };
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
        windowMs(roundRows[a]!.startedAt, roundRows[b]!.startedAt, ROUND_CORRELATION_WINDOW_MS)
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
  return purchases.some((p) => p.facilityId === ctx.playFacilityId && daysBetween(p.localDate, ctx.playLocalDate) <= CORROBORATION_WINDOW_DAYS);
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
   * to `held_review`, never auto-issue and never auto-refuse. Item 2
   * (seventh gate): ALSO true whenever `money` is true and at least one
   * ON-PLAY row was quarantined (`excludedRows` below, `kind:
   * "quarantined"`) — a malformed row that otherwise belonged to this
   * play, present alongside a money-qualifying result, is exactly what a
   * manipulation attempt or a genuine data problem both look like; either
   * way this reward must not auto-issue on it. */
  heldReview: boolean;
  /** Item 2 (seventh gate): populated with `"quarantined"` when
   * `heldReview` was forced true by the quarantine rule just above — NOT
   * a complete reason list for every hold (the pre-existing attestation
   * -grade holds don't populate this; only the quarantine-forced case
   * does, this gate's own scope). Always present; empty when not
   * applicable. */
  heldReviewReasons: string[];
  policyVersion: number;
  contributions: ScorePlayContribution[];
  /** M5 (fifth gate): SHA-256 (hex) over the canonicalized, ALREADY-PARSED
   * `{evidence, ctx}` this result was computed from. Lets a caller (or an
   * audit trail) prove exactly which validated input produced a given
   * money decision, independent of the raw/pre-parse bytes that arrived
   * over the wire. F4 (sixth gate): independent of the EVIDENCE ARRAY'S
   * OWN ORDER — `computeInputDigest` sorts by `id` first — so passing the
   * same rows in a different order can never change the digest. */
  inputDigest: string;
  /** F3 (sixth gate): every raw row that did NOT make it into
   * `contributions` — an off-play row (different facility/date/course) or
   * a QUARANTINED one (matched this play, but failed strict validation).
   * Quarantined rows contribute 0 to both scores, exactly as if absent,
   * but are listed here (with `index` into the ORIGINAL raw `evidence[]`
   * and `reasons`) rather than silently vanishing OR failing the whole
   * play — see `parseScorePlayInput`'s own doc (`./parse-evidence.js`).
   * Empty when every raw row matched and parsed cleanly. */
  excludedRows: import("./parse-evidence.js").ExcludedRow[];
}

/** F3 (sixth gate): "Return a discriminated result... so a caller can
 * never persist a failed parse as a real 0 score." `scorePlay` used to
 * return the SAME shape (`ScorePlayResult`) whether parsing succeeded or
 * failed, distinguished only by an optional `reasons` field a caller could
 * forget to check — and a forgotten check reads a fail-closed `money:
 * false` result as an honest "this play didn't qualify" ZERO, which is
 * not what happened at all. The discriminant (`ok`) makes that
 * impossible to skip at the type level: `ScorePlayResult`'s fields are
 * only reachable after narrowing `ok === true`. */
export type ScorePlaySuccess = { ok: true } & ScorePlayResult;
export interface ScorePlayFailure {
  ok: false;
  /** STRUCTURAL problems only (F3): an unrecognized `ctx` key, a missing
   * required `ctx` field, a non-array `evidence`, or a row count over the
   * ABSOLUTE cap. A malformed INDIVIDUAL row is never one of these — see
   * `ScorePlaySuccess.excludedRows` for that (quarantine, not failure). */
  reasons: string[];
}
export type ScorePlayOutcome = ScorePlaySuccess | ScorePlayFailure;

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
 * | `localDate` (on a fix) | No, CROSS-CHECKED against a server-derivable fact | the CLIENT labels it, but it is REJECTED unless it agrees with `capturedAt` (device clock) reprojected through `ctx.facilityTz` (F1, sixth gate: `facilityTz` is itself catalog data, below) — corrected from the fifth gate's wording ("derived server-side"), which overstated it: the parser doesn't COMPUTE `localDate` for the caller, it only REJECTS a claimed one that disagrees with the derivation |
 * | `capturedAt` | No (device clock) | the device's own clock — never trusted alone; corroborated via the `localDate` cross-check and the co-signal/hard-window comparisons throughout `internal/classify.ts` |
 * | `fixId` | Yes | the challenge id or assertion hash the attestation exchange itself produced — never a client-invented string (M1) |
 * | `paymentRef` | Yes | the booking/payment ledger's own reference id (M1) |
 * | `vendorCourseMapped` / `sensorProvenance` | Yes | the vendor-sync pipeline's own course-matching and device-provenance checks (Garmin/Arccos) — never client-set |
 * | receipt `status` | Yes | the green-fee receipt/POS integration, never the app client |
 * | receipt `voidReason` | Yes | the review queue (`"reviewer"`/`"fraud"`) or intake's own fingerprint-dedup step (`"duplicate"`) — never the app client. A missing value on a `status: "void"` row defaults to `"reviewer"` (item 1, eighth gate: fails safe) |
 * | `courseDisambiguatedBy` | Yes | whichever server-side step actually resolved the course ambiguity (`geometry`/`staff`); `"user"` specifically marks a PLAYER's own pick, which is exactly why it's money-capped (A2-01) |
 * | staff `scanAt` | Yes | the staff-facing scan tool's own server timestamp, not the player's device |
 * | `ctx.playFacilityId` | Yes | the `play` row itself (already resolved/created server-side before `scorePlay` is ever called for it) |
 * | `ctx.playLocalDate` | Yes | the `play` row's own facility-local date, computed server-side at play-creation time — never re-derived from a row's `capturedAt` here |
 * | `ctx.playCourseId` | Yes (H3 residual, seventh gate: now REQUIRED in BOTH the parser schema and the TypeScript type, item 8) | the `play` row's resolved course, at a multi-course (e.g. 36-hole) facility — a `courses` table lookup, never client-supplied; a row WITHOUT its own `courseId` is facility-level evidence and stays allowed regardless (H3's residual rule) — the DB's `play_evidence UNIQUE(evidence_id)` constraint (migration 0017) is the separate guarantee that stops the SAME evidence row being attributed to two different plays at all |
 * | `ctx.facilityTz` | Yes (F1, sixth gate: now REQUIRED; corrected, seventh gate item 1: validated via `@golfraven/catalog`'s `isValidIanaTimeZoneName` — an `Intl.DateTimeFormat` try/catch — PLUS an Area/Location shape rule, never `Intl.supportedValuesOf('timeZone')`, which wrongly excludes several genuine, still-current zone names — see `parse-evidence.ts`'s own doc for the exact regression) | the FACILITY'S OWN catalog row (`@golfraven/catalog`'s facility timezone field, itself typically `tz-lookup`-derived) — never derived from a fix, a device, or a client-supplied guess |
 * | `ctx.purchases` | Yes | the `purchase_evidence` table (§4.6) — a DIFFERENT table than `app.evidence`, joined in server-side before this call |
 *
 * **Policy-pin immutability (item 3, eighth gate).** `SCORE_PLAY_POLICY_VERSION`
 * (below) is pinned to a content hash of every named SCORING-policy
 * constant (`WEIGHT`, `MONEY_MIN`, the caps, penalty multipliers,
 * thresholds, windows — `test/score-play-policy-hash.test.ts`'s own
 * `policyConstants()`, which is the single source of truth for what
 * counts). **Once any production play has been scored under a given
 * version, that version's pinned hash is IMMUTABLE** — re-pinning the
 * SAME version key after real plays exist would silently rewrite, after
 * the fact, what "version N" is claimed to have meant for plays already
 * scored under it, indistinguishable from backdating a policy change.
 * Any change to a pinned constant — for ANY reason, deliberate or a bug
 * fix — MUST bump `SCORE_PLAY_POLICY_VERSION` to a NEW key with its own
 * new `POLICY_HASHES` entry once that point is reached; before it (this
 * pre-launch gate cycle, no production play yet), re-pinning the current
 * version in place is how the constant set is allowed to stabilize
 * without spawning a new version on every iteration. `EVIDENCE_ROW_CAP`/
 * `ABSOLUTE_ROW_CAP` are deliberately EXCLUDED from the pinned set
 * (item 3): they are input-validation/DoS limits (`parse-evidence.ts`),
 * not scoring policy — see the policy-hash test's own module doc for
 * why conflating the two made the pin's history harder to read.
 *
 * **Open owner question (item 11, seventh gate): composite courses.**
 * `ctx.playCourseId`/a row's own `courseId` are compared with STRICT
 * equality (`internal/classify.js`'s `courseOk`) — a row whose `courseId`
 * is one of a COMPOSITE 18's two component nines (the build plan's own
 * `Course.composite?: [CourseId, CourseId]`, §4.1, G-P0-13 — "an 18
 * formed from two nines, e.g. Red+White") does NOT match a play whose
 * `playCourseId` is the composite 18's OWN id, or vice versa, even though
 * the build plan treats a composite play as satisfying BOTH the composite
 * AND its two nines for ROSTER/COMPLETION credit (§4.1 line 744-745,
 * `uniqueCourses`/A2-18 — `packages/rules`' own `completion.ts`/
 * `aggregates.ts`, unaffected by this). The build plan (grepped for
 * "composite" in full, `docs/golf-trails/02-build-plan.md`) defines
 * `composite` ONLY at the catalog/roster-credit layer — it never states
 * which `courseId` the MONEY-PATH EVIDENCE MATCHER (`@golfraven/matching`,
 * the system that would populate a row's `courseId` for `app.evidence`)
 * should record for a play on a composite 18: the composite's own id, one
 * (or both) of the component nines' ids, or something else. Absent that
 * answer, this module keeps strict equality (the safe default — it can
 * only ever be OVER-strict, never under-strict, so a composite-course
 * play at worst loses its course anchor's benefit of the doubt and still
 * scores as facility-level evidence would if the matcher simply omits
 * `courseId` for such a row) rather than guessing a matching rule that
 * could be wrong. **Owner: whoever specs the evidence matcher's
 * `courseId` assignment for composite courses — this needs an explicit
 * answer before a 27/36-hole facility with COURSE-scoped evidence rows
 * (not just facility-level ones) can be trusted not to silently
 * under-count money-eligible plays on its composite tee sheets.**
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
export function scorePlay(evidenceIn: Evidence[], ctx: ScorePlayContext): ScorePlayOutcome {
  // H2 (fifth gate): the parser runs FIRST, always — see this function's
  // own TRUST TABLE doc for exactly what it closes. F3 (sixth gate): a
  // STRUCTURAL parse failure returns `{ok: false, reasons}` and NEVER
  // throws — the scoring logic below never runs on unparsed/untrusted
  // data. A per-ROW problem is no longer structural (see
  // `parseScorePlayInput`'s own doc) — it comes back as a successful
  // parse whose `excludedRows` lists the quarantined row instead.
  const parsed = parseScorePlayInput({ evidence: evidenceIn, ctx });
  if (!parsed.success) {
    return { ok: false, reasons: parsed.reasons };
  }
  const result = scorePlayOnParsedInput(parsed.evidence, parsed.ctx);
  // Item 2 (seventh gate): a money-qualifying result backed by evidence
  // that ALSO includes an on-play quarantined row must route to review,
  // never auto-issue — see `ScorePlayResult.heldReview`'s own doc.
  const onPlayQuarantined = parsed.excludedRows.some((r) => r.kind === "quarantined");
  const quarantineForcesHold = result.money && onPlayQuarantined && !result.heldReview;
  return {
    ok: true,
    ...result,
    heldReview: result.heldReview || (result.money && onPlayQuarantined),
    heldReviewReasons: quarantineForcesHold ? ["quarantined"] : [],
    excludedRows: parsed.excludedRows,
    inputDigest: computeInputDigest(parsed.evidence, parsed.ctx),
  };
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
 * **F4 (sixth gate): sorted by `id` first, so the digest is independent
 * of the EVIDENCE ARRAY'S OWN ORDER.** `evidence` is a caller-assembled
 * array (typically a DB query result) whose row order carries no meaning
 * `scorePlay` itself assigns anywhere else — `deriveGroups`/`resolveGroups`
 * are already order-independent (fourth/fifth gate); the digest must be
 * too, or the SAME validated evidence set could produce two different
 * digests depending on how the caller happened to fetch it.
 *
 * **Deliberately `@noble/hashes`, never `node:crypto`.** This package's
 * own module doc says it plainly: "authoritative on the server,
 * preview-only on DEVICE" — the device is the React Native app, which has
 * no `node:crypto`. `@noble/hashes` is pure JS (MIT, audited,
 * zero-dependency) and runs identically in both places, so `scorePlay`
 * stays host-neutral rather than silently gaining a Node-only dependency
 * the app build can't satisfy. */
function computeInputDigest(evidence: Evidence[], ctx: ScorePlayContext): string {
  const sortedEvidence = [...evidence].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const canonical = JSON.stringify(canonicalize({ evidence: sortedEvidence, ctx }));
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
 * step and the `inputDigest`/`excludedRows`/`heldReviewReasons` fields
 * above. Returns everything `ScorePlayResult` needs EXCEPT those three —
 * `scorePlay` adds them (the digest needs the parsed `{evidence, ctx}`
 * this function doesn't return; `excludedRows` comes straight from
 * `parseScorePlayInput`; `heldReviewReasons`/the quarantine-forced
 * `heldReview` override, item 2, needs `excludedRows` to even exist yet).
 */
function scorePlayOnParsedInput(
  evidenceIn: Evidence[],
  ctx: ScorePlayContext,
): Omit<ScorePlayResult, "inputDigest" | "excludedRows" | "heldReviewReasons"> {
  // Finding 3 + blocking finding 2 (second re-gate): drop any row whose OWN
  // facility OR OWN date disagrees with the play being scored, before
  // anything else runs. F3 (sixth gate): `evidenceIn` here is ALREADY
  // `parseScorePlayInput`'s own filtered `parsed.evidence` — every row in
  // it already passed the loose facility/date/course match AND the strict
  // per-row parse, so this filter is now REDUNDANT by construction. Kept
  // anyway, as defence in depth (the same layered pattern this module uses
  // throughout — `classifyEvidenceRow`'s own `rowOk` is the same idea one
  // layer down): if this function is ever called some OTHER way, it stays
  // safe on its own.
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
