/**
 * `scorePlay` — §4.5 "Evidence classes and confidence scoring (policy v1)".
 * Pure TS, no I/O (build plan §3.1 row E): takes one play's evidence rows
 * (`app.evidence`, §4.4) plus a small amount of context and returns
 * `{score_badge, score_monetary, presence_signal, money, policyVersion,
 * contributions[]}`. Money-path code (build plan §4.5 "Money rule",
 * A2-05/A2-06/A2-07/A2-20) — correctness here gates a marketing incentive,
 * so every rule below cites the exact plan line/ruling it implements.
 *
 * **Scope boundary (stated once, so it isn't re-litigated per class).**
 * `scorePlay` computes ONLY the two scores, `presence_signal` and `money` —
 * it never touches `play.status` (`disputed` via event-time velocity,
 * §4.5's caps-and-penalties bullet list) or `fraud_signal` rows. Those are
 * DB-side side effects of a *different* function (the evidence/scorer fn),
 * not part of this package's `{score_badge, score_monetary, presence_signal,
 * money, policyVersion, contributions[]}` return contract, and the task's
 * own "Build" list (1)-(6) never asks for them. A `failed`-grade fix is
 * still zeroed here (§4.5 G3-08: "nothing can be earned on it") — that part
 * of the rule IS a scoring effect — but the accompanying `fraud_signal` is
 * not.
 *
 * **One call = one play (design decision, not explicit in the plan).**
 * `evidence[]` here is every `app.evidence` row already attributed to ONE
 * `play` (one user, one course, one facility-local `play_date` — the `play`
 * table's own uniqueness, §4.4). `ctx.playFacilityId` / `ctx.playLocalDate`
 * are passed explicitly (never inferred from the rows) so `presence_signal`
 * — "a co-signal exists AT THAT FACILITY on THE PLAY's facility-local date"
 * (§4.5 line 933) — has an unambiguous anchor even when `evidence[]` is
 * empty or every row is malformed.
 *
 * **"Counted once" is a construction discipline the CALLER owns, not a
 * runtime dedup `scorePlay` performs (A2-20b).** §4.5's "a co-signal fix
 * enters the score once, as its own `foreground_checkin` row, whichever
 * flow captured it" is a statement about how `app.evidence` rows are
 * WRITTEN at ingestion (one row per physical fix, referenced — never
 * duplicated — by whichever class uses it as a co-signal). `scorePlay`
 * therefore expects the same physical fix to appear in `evidence[]` at most
 * once; it does not attempt to detect and collapse two rows that happen to
 * describe the same underlying capture. The one behaviour this package DOES
 * enforce structurally: a `staff_presence`/`booking` row that resolves to
 * its **hard** class (§4.5 "Hard classes contain their presence fact")
 * carries its qualifying fix INLINE (`coSignalFix` / `presenceFix`) rather
 * than as a reference to a separate row, so there is no separate
 * `foreground_checkin`/`foreground_dwell` row left to double-count in the
 * first place — the hard class's own weight already *is* the whole
 * contribution (A2-20d: "never also scored as booking 0.70 + check-in
 * 0.30"). See this module's test/golden-fixture file for the money golden
 * fixtures #10/#11 that this shape resolves.
 */
import type { GeometryKind, VerificationTier } from "@golfraven/matching";
import type { CourseDisambiguatedBy } from "./completion.js";

/** §4.5's money-only floor. A CODE CONSTANT (A2-05): "No catalog or DB
 * datum can lower it." Every money decision in this module reads this
 * constant directly — never a parameter, never data. */
export const MONEY_MIN = 0.85;

/** Policy v1 (§4.5 heading). Bumped whenever a scoring rule here changes
 * (§4.5 design note: "Policy changes bump `policyVersion` and re-score
 * plays"). Kept as its OWN constant, deliberately separate from `index.ts`'s
 * `POLICY_VERSION` — that export is pinned at its P0 value by an existing,
 * unmodified test (`test/index.test.ts`: "exports POLICY_VERSION = 0 until
 * P1/§8 defines real rules"), and this task's own Done criterion requires
 * existing tests stay unchanged. `scorePlay`'s `policyVersion` output is
 * this constant, not that one. */
export const SCORE_PLAY_POLICY_VERSION = 1;

/* ------------------------------------------------------------------ */
/* Attestation grade (G3-08)                                           */
/* ------------------------------------------------------------------ */

export type FixGrade = "attested" | "unattestable" | "failed";

/**
 * "Every fix records one of three grades... there is no fourth grade
 * (G3-08). A submission that carries no token is graded AT INTAKE: on
 * hardware that supports attestation it is `failed`, and otherwise
 * `unattestable`." (§4.5 lines 910-918.) `TokenState` models the intake
 * input this rule runs over — a token was presented (its grade is already
 * settled), or it wasn't (only the hardware capability is known, and this
 * module derives the grade via `resolveFixGrade`).
 */
export type TokenState =
  | { present: true; grade: FixGrade }
  | { present: false; hardwareSupportsAttestation: boolean };

/** G3-08's intake-grading rule, applied verbatim. */
export function resolveFixGrade(token: TokenState): FixGrade {
  if (token.present) return token.grade;
  return token.hardwareSupportsAttestation ? "failed" : "unattestable";
}

/* ------------------------------------------------------------------ */
/* The co-signal fix (§4.5 "Co-signal" definition)                     */
/* ------------------------------------------------------------------ */

export type ChallengeKind = "live" | "prefetched" | "none";

/**
 * A single device fix, carrying exactly the raw attributes the §4.5
 * co-signal definition (and the oracle) read. `verificationTier` /
 * `geometryKind` reuse `@golfraven/matching`'s own vocabulary (build plan
 * §7.4) rather than re-deriving it — the facility-verification and
 * polygon-vs-radius distinctions are that package's, and `scorePlay`
 * consumes its output, never recomputes it.
 */
export interface AppFix {
  /** Taken by our app (never true for a Health route, a file import, a
   * Connect IQ fix, a GHIN post or a vendor round — §4.5 line 908). */
  fromApp: boolean;
  /** iOS `isSimulatedBySoftware` / Android mock-location (§4.5 caps). */
  simulated: boolean;
  foreground: boolean;
  /** "taken against a server challenge: live, or prefetched ≤24h ahead...
   * `none` = no challenge at all (offline, prefetched challenges used up,
   * §7.6) — never a co-signal, and the ×0.6 penalty case below. */
  challenge: ChallengeKind;
  token: TokenState;
  /** Facility verification tier of the facility this fix was matched
   * against (build plan §4.2/§7.4, `@golfraven/matching`'s own vocabulary).
   * A co-signal requires `'play-verified'` — "a radius-fallback circle
   * never qualifies" (§4.5 line 901) is exactly `geometryKind !== 'polygon'`
   * OR `verificationTier !== 'play-verified'`. */
  verificationTier: VerificationTier;
  geometryKind: GeometryKind;
  /** Raw geometric containment: inside the polygon+50m buffer, or inside
   * the radius-fallback circle+50m — whichever `geometryKind` names. The
   * co-signal quality gate additionally requires `geometryKind ===
   * 'polygon'`, so a `radius`-kind fix can never itself be a co-signal even
   * when this is `true`. */
  insideBuffer: boolean;
  accuracyMeters: number;
  /** Epoch ms the fix was captured. */
  capturedAt: number;
  /** Facility-local calendar date (`YYYY-MM-DD`) the fix was captured on
   * (§4.1 `tz`). Kept as its own field, distinct from any row's own
   * `localDate`, specifically so a fix captured on a DIFFERENT date than
   * the play/row it's attached to can be modelled and rejected by the
   * date-based co-signal windows (§10 P3 AT(4)'s "±1 day across a tz
   * boundary" generator axis). */
  localDate: string;
}

/**
 * The co-signal FIX-QUALITY gate (§4.5 "Co-signal" bullets 1-3; the window
 * bullet, #4, is class-specific and applied by each class's own weight
 * function below, and separately by `computePresenceSignal`, which uses
 * the "same facility-local date" window verbatim — see that function's
 * doc). `grade !== 'failed'` is folded in here (not a separate check)
 * because §4.5 line 920 states it as part of the same definition: "A
 * `failed` fix is never a co-signal."
 */
function isQualityCoSignalFix(fix: AppFix): boolean {
  return (
    fix.fromApp &&
    !fix.simulated &&
    fix.foreground &&
    fix.challenge !== "none" &&
    fix.accuracyMeters <= 50 &&
    fix.geometryKind === "polygon" &&
    fix.verificationTier === "play-verified" &&
    fix.insideBuffer &&
    resolveFixGrade(fix.token) !== "failed"
  );
}

/* ------------------------------------------------------------------ */
/* Evidence classes (§4.5's class table, 16 rows incl. corroboration)  */
/* ------------------------------------------------------------------ */

export type EvidenceClassId =
  | "staff_presence_hard"
  | "staff_presence_soft"
  | "vendor_sensor"
  | "self_posted"
  | "booking_hard"
  | "booking_alone"
  | "receipt_green_fee"
  | "health_route"
  | "connect_iq_route"
  | "connect_iq_checkin"
  | "foreground_dwell"
  | "file_import"
  | "foreground_checkin"
  | "health_workout"
  | "self_report"
  | "purchase_corroboration";

export type EvidenceGroup =
  | "partner"
  | "vendor"
  | "self-posted"
  | "booking"
  | "review"
  | "device-gps"
  | "self"
  | "corroboration";

interface EvidenceBase {
  /** Caller-assigned, unique within one `scorePlay` call. Echoed back on
   * `contributions[]` so a caller/test can trace a score back to its row. */
  id: string;
  facilityId: string;
  courseId?: string;
  /** The facility-local date THIS ROW's own underlying event (a scan, a
   * receipt, a booking, a route) is attributed to — for a play's own
   * evidence this is ordinarily `ctx.playLocalDate`, but is its own field
   * (not inferred) so a genuinely mis-dated row is modellable. */
  localDate: string;
  /** §4.3 A2-01: "the course credit uses the facility-level weight, capped
   * at 0.50, in `score_badge`, and 0 in `score_monetary`" whenever a
   * device-GPS-ish row's course was a `'user'` pick (§4.5 caps-and-penalties
   * bullet list). Only meaningful on a row that carries a course credit at
   * all; ignored otherwise. */
  courseDisambiguatedBy?: CourseDisambiguatedBy;
  /** §4.5 "Correlated pairs combine by `max`, not noisy-OR" — the four
   * named pairs (a booking + its own receipt; a staff scan + a check-in
   * reusing the same fix; a dwell + the check-in that opened it; a
   * Health route + a file import of the same round). Two rows sharing the
   * same non-empty `correlationId` are merged (this module's `mergeByMax`)
   * before combination. Caller-supplied — deciding which real-world rows
   * are "the same underlying proof" is a matching/ingestion concern
   * upstream of `scorePlay` (see module doc's "Counted once" note). */
  correlationId?: string;
}

export type Evidence =
  | (EvidenceBase & {
      source: "staff_presence";
      scanAt: number;
      coSignalFix?: AppFix;
    })
  | (EvidenceBase & {
      source: "arccos" | "garmin";
      vendorCourseMapped: boolean;
      sensorProvenance: boolean;
    })
  | (EvidenceBase & { source: "ghin" })
  | (EvidenceBase & { source: "booking"; presenceFix?: AppFix })
  | (EvidenceBase & {
      source: "receipt_green_fee";
      status: "approved" | "pending";
      coSignalFix?: AppFix;
    })
  | (EvidenceBase & {
      source: "health_route";
      sourceAllowListed: boolean;
      insideRatio: number;
      simulated: boolean;
      geometryKind: GeometryKind;
    })
  | (EvidenceBase & {
      source: "connect_iq";
      variant: "route" | "checkin";
      k4bPassed: boolean;
      insidePolygon: boolean;
      durationMinutes: number;
      simulated: boolean;
    })
  | (EvidenceBase & {
      source: "foreground_dwell";
      checkinFix: AppFix;
      checkoutFix: AppFix;
      apartMinutes: number;
      holes: 9 | 18;
    })
  | (EvidenceBase & {
      source: "file_import";
      matchedRoute: boolean;
      geometryKind?: GeometryKind;
    })
  | (EvidenceBase & { source: "foreground_checkin"; fix: AppFix })
  | (EvidenceBase & { source: "health_workout" })
  | (EvidenceBase & { source: "self_report" });

/** The §4.6 purchase-corroboration leg (a `purchase_evidence.valid` row) —
 * a DIFFERENT table than `app.evidence` (§4.4), so it travels on `ctx`
 * rather than in `evidence[]`. Mirrors `completion.ts`'s `MarkerPurchase`
 * shape deliberately (same two fields, same source concept). */
export interface PurchaseCorroboration {
  facilityId: string;
  /** Facility-local date of the purchase. */
  localDate: string;
}

export interface ScorePlayContext {
  playFacilityId: string;
  /** Facility-local date of the play being scored (§4.1 `tz`). */
  playLocalDate: string;
  /** §4.5's purchase-corroboration row: "`purchase_evidence.valid` at the
   * same facility within ±7 days" (line 1005). Only rows within that window
   * of `playLocalDate`, AT `playFacilityId`, are eligible — `scorePlay`
   * applies both the facility and the ±7-day filters itself. */
  purchases?: PurchaseCorroboration[];
}

/* ------------------------------------------------------------------ */
/* Weights (§4.5's class table, verbatim)                               */
/* ------------------------------------------------------------------ */

const WEIGHT: Record<EvidenceClassId, number> = {
  staff_presence_hard: 0.95,
  staff_presence_soft: 0.8,
  vendor_sensor: 0.85,
  self_posted: 0.4,
  booking_hard: 0.9,
  booking_alone: 0.7,
  receipt_green_fee: 0.8, // approved; 0.20 while pending (applied below)
  health_route: 0.6, // insideRatio >= 0.8; 0.40 at [0.6, 0.8) (applied below)
  connect_iq_route: 0.5,
  connect_iq_checkin: 0.3,
  foreground_dwell: 0.5,
  file_import: 0.4, // matched; 0.10 without a matched route (applied below)
  foreground_checkin: 0.3,
  health_workout: 0.15,
  self_report: 0.1,
  purchase_corroboration: 0.3,
};

const GROUP: Record<EvidenceClassId, EvidenceGroup> = {
  staff_presence_hard: "partner",
  staff_presence_soft: "partner",
  vendor_sensor: "vendor",
  self_posted: "self-posted",
  booking_hard: "booking",
  booking_alone: "booking",
  receipt_green_fee: "review",
  health_route: "device-gps",
  connect_iq_route: "device-gps",
  connect_iq_checkin: "device-gps",
  foreground_dwell: "device-gps",
  file_import: "device-gps", // overridden to "self" for the unmatched variant
  foreground_checkin: "device-gps",
  health_workout: "self",
  self_report: "self",
  purchase_corroboration: "corroboration",
};

const HARD: ReadonlySet<EvidenceClassId> = new Set([
  "staff_presence_hard",
  "booking_hard",
]);

/** §4.5's `score_monetary` include/exclude list (lines 944-957), keyed by
 * class id. `foreground_checkin` / `foreground_dwell` are money-eligible
 * only when POLYGON-matched — that's applied per-row below, alongside the
 * radius/user-pick caps, not baked into this static table. */
const MONEY_ELIGIBLE_BASE: ReadonlySet<EvidenceClassId> = new Set([
  "staff_presence_hard", // staff_presence WITH co-signal
  "vendor_sensor",
  "booking_hard",
  "booking_alone",
  "receipt_green_fee", // only WITH co-signal — gated per-row below
  "foreground_checkin",
  "foreground_dwell",
]);

/* ------------------------------------------------------------------ */
/* Device-class caps and penalties (§4.5 "Caps and penalties" bullets) */
/* ------------------------------------------------------------------ */

/**
 * The `simulated`×0.3 and `unattestable`/no-challenge×0.6 penalties, for a
 * class whose weight comes directly from a raw device fix (`foreground_checkin`
 * / `foreground_dwell`). §4.5 line 1009-1013. A `failed` grade is handled
 * separately (zeroes the fix outright) — see `fixDeviceWeight`.
 */
function deviceFixMultiplier(
  fix: Pick<AppFix, "simulated" | "token" | "challenge">,
): number {
  let m = 1;
  if (fix.simulated) m *= 0.3;
  const grade = resolveFixGrade(fix.token);
  if (grade === "unattestable" || fix.challenge === "none") m *= 0.6;
  return m;
}

/** A device fix's own class weight, in [0, base], after the §4.5 penalties:
 * `failed` zeroes it outright ("A `failed` fix is never a co-signal... a
 * `failed` grade zeroes the fix", lines 920, 1012); otherwise the
 * simulated/unattestable/no-challenge multipliers apply. */
function fixDeviceWeight(
  base: number,
  fix: Pick<AppFix, "simulated" | "token" | "challenge">,
): number {
  if (resolveFixGrade(fix.token) === "failed") return 0;
  return base * deviceFixMultiplier(fix);
}

/** §4.5's radius-fallback cap ("capped at 0.50") and the §4.3/A2-01
 * user-pick cap (badge capped at 0.50, money excluded), applied uniformly
 * to any row that carries a course credit. Returns the capped badge weight
 * and whether money-eligibility survives. */
function applyCourseCaps(
  badgeWeight: number,
  geometryKind: GeometryKind | undefined,
  courseDisambiguatedBy: CourseDisambiguatedBy | undefined,
  moneyEligible: boolean,
): { badgeWeight: number; moneyEligible: boolean } {
  let w = badgeWeight;
  let money = moneyEligible;
  if (geometryKind === "radius") {
    w = Math.min(w, 0.5);
    money = false;
  }
  if (courseDisambiguatedBy === "user") {
    w = Math.min(w, 0.5);
    money = false;
  }
  return { badgeWeight: w, moneyEligible: money };
}

/* ------------------------------------------------------------------ */
/* Per-row classification                                              */
/* ------------------------------------------------------------------ */

export interface ScorePlayContribution {
  evidenceId: string;
  classId: EvidenceClassId;
  group: EvidenceGroup;
  hard: boolean;
  /** Final weight to use in `score_badge`'s combination, after every
   * per-row cap/penalty (before noisy-OR/correlation combination). */
  badgeWeight: number;
  /** Whether this row is a candidate for `score_monetary` at all (§4.5's
   * include/exclude list, plus the radius/user-pick exclusions). When
   * `false`, `moneyWeight` is `0` and the contribution never enters the
   * money combination. */
  moneyEligible: boolean;
  /** Weight to use in `score_monetary`'s combination — equal to
   * `badgeWeight` when `moneyEligible`, else `0`. Kept as its own field
   * (rather than reusing `badgeWeight` conditionally at every call site)
   * because a few classes (e.g. `receipt_green_fee`) are money-eligible
   * only per-row (co-signal present), not per-class. */
  moneyWeight: number;
  correlationId?: string;
}

function windowMinutes(aMs: number, bMs: number, minutes: number): boolean {
  return Math.abs(aMs - bMs) <= minutes * 60_000;
}

/** Builds a `ScorePlayContribution` from `row`, spreading `correlationId`
 * only when `row` actually has one (`exactOptionalPropertyTypes`: an
 * optional property must be OMITTED, never explicitly set to `undefined` —
 * the same pattern `@golfraven/matching`'s `checkin.ts` already uses for
 * `attestationAssertion`). Keeps every `classify` branch below to exactly
 * the fields that differ per class. */
function finish(
  row: Evidence,
  fields: Omit<ScorePlayContribution, "evidenceId" | "correlationId">,
): ScorePlayContribution {
  return {
    evidenceId: row.id,
    ...fields,
    ...(row.correlationId !== undefined
      ? { correlationId: row.correlationId }
      : {}),
  };
}

function classify(row: Evidence): ScorePlayContribution {
  switch (row.source) {
    case "staff_presence": {
      // §4.5 line 990: "a co-signal within ±10 min (critic SP13)."
      const hasCoSignal =
        row.coSignalFix !== undefined &&
        isQualityCoSignalFix(row.coSignalFix) &&
        windowMinutes(row.coSignalFix.capturedAt, row.scanAt, 10);
      const classId: EvidenceClassId = hasCoSignal
        ? "staff_presence_hard"
        : "staff_presence_soft";
      const badgeWeight = WEIGHT[classId];
      // Excluded from score_monetary when co-signal-less (line 991).
      const moneyEligible = hasCoSignal;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId),
        badgeWeight,
        moneyEligible,
        moneyWeight: moneyEligible ? badgeWeight : 0,
      });
    }
    case "arccos":
    case "garmin": {
      const isSensorVendor = row.vendorCourseMapped && row.sensorProvenance;
      const classId: EvidenceClassId = isSensorVendor
        ? "vendor_sensor"
        : "self_posted";
      const badgeWeight = WEIGHT[classId];
      // "Counts in score_monetary, but money still needs presence_signal"
      // (line 992) — vendor_sensor is money-eligible; a vendor round
      // without sensor provenance scores as `self_posted`, badge-only.
      const moneyEligible = isSensorVendor;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight,
        moneyEligible,
        moneyWeight: moneyEligible ? badgeWeight : 0,
      });
    }
    case "ghin": {
      const classId: EvidenceClassId = "self_posted";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: WEIGHT[classId],
        moneyEligible: false,
        moneyWeight: 0,
      });
    }
    case "booking": {
      // "same-day presence (a co-signal on the booking's date)" (line 994)
      // — the same-DATE window, not ±10 min (that window is staff scan
      // specific, §4.5's co-signal definition bullet list).
      const hasPresence =
        row.presenceFix !== undefined &&
        isQualityCoSignalFix(row.presenceFix) &&
        row.presenceFix.localDate === row.localDate;
      const classId: EvidenceClassId = hasPresence
        ? "booking_hard"
        : "booking_alone";
      const badgeWeight = WEIGHT[classId];
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId),
        badgeWeight,
        moneyEligible: true, // both booking classes count in score_monetary (line 947)
        moneyWeight: badgeWeight,
      });
    }
    case "receipt_green_fee": {
      const classId: EvidenceClassId = "receipt_green_fee";
      const badgeWeight = row.status === "approved" ? WEIGHT[classId] : 0.2;
      // "Counts in score_monetary ONLY with a same-date co-signal" (line 996).
      const moneyEligible =
        row.coSignalFix !== undefined &&
        isQualityCoSignalFix(row.coSignalFix) &&
        row.coSignalFix.localDate === row.localDate;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight,
        moneyEligible,
        moneyWeight: moneyEligible ? badgeWeight : 0,
      });
    }
    case "health_route": {
      const classId: EvidenceClassId = "health_route";
      // §4.5 line 997: allow-listed insideRatio >= 0.8 -> 0.60; [0.6, 0.8)
      // -> 0.40 (the matcher's own acceptance floor, §7.4 step 4/G2-07);
      // an unlisted source overrides both bands to 0.10 (ruling SP1-2 lane
      // 5).
      const base = !row.sourceAllowListed
        ? 0.1
        : row.insideRatio >= 0.8
          ? 0.6
          : 0.4;
      // Only the `simulated`×0.3 penalty applies here — a Health route is
      // structurally never captured against a server challenge (it isn't a
      // checkin-style fix at all, §4.5 line 908), so the ×0.6
      // "unattestable / no challenge" penalty (which is about a CHECK-IN's
      // OWN device signal) has no analogue to apply to a route-level
      // weight; deliberately not reusing `fixDeviceWeight`, which would
      // wrongly fire the ×0.6 leg on every row.
      const badgeWeight0 = row.simulated ? base * 0.3 : base;
      const capped = applyCourseCaps(
        badgeWeight0,
        row.geometryKind,
        row.courseDisambiguatedBy,
        false,
      );
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: false, // excluded (line 953)
        moneyWeight: 0,
      });
    }
    case "connect_iq": {
      const classId: EvidenceClassId =
        row.variant === "route" ? "connect_iq_route" : "connect_iq_checkin";
      let badgeWeight: number;
      if (row.variant === "route") {
        // "only if K4b passed"; "inside polygon, ≥90min" (line 998)
        badgeWeight =
          row.k4bPassed && row.insidePolygon && row.durationMinutes >= 90
            ? WEIGHT[classId]
            : 0;
      } else {
        badgeWeight = WEIGHT[classId]; // the K4b-fail one-tap shape — always qualifies as itself
      }
      if (row.simulated) badgeWeight *= 0.3;
      const capped = applyCourseCaps(
        badgeWeight,
        undefined,
        row.courseDisambiguatedBy,
        false,
      );
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: false, // excluded (line 954, FM-30)
        moneyWeight: 0,
      });
    }
    case "foreground_dwell": {
      const classId: EvidenceClassId = "foreground_dwell";
      const threshold = row.holes === 9 ? 50 : 90; // line 1000
      if (row.apartMinutes < threshold) {
        return finish(row, {
          classId,
          group: GROUP[classId],
          hard: false,
          badgeWeight: 0,
          moneyEligible: false,
          moneyWeight: 0,
        });
      }
      // Conservative (documented [inference]): the dwell's own multiplier
      // is the WORSE of its two fixes' individual multipliers — the plan
      // states the per-fix penalties but not how to combine two fixes'
      // penalties for one dwell class weight.
      const openW = fixDeviceWeight(1, row.checkinFix);
      const closeW = fixDeviceWeight(1, row.checkoutFix);
      const badgeWeight0 = WEIGHT[classId] * Math.min(openW, closeW);
      const bothPolygon =
        row.checkinFix.geometryKind === "polygon" &&
        row.checkoutFix.geometryKind === "polygon";
      const geometryKind: GeometryKind = bothPolygon ? "polygon" : "radius";
      const moneyBase = MONEY_ELIGIBLE_BASE.has(classId); // true
      const capped = applyCourseCaps(
        badgeWeight0,
        geometryKind,
        row.courseDisambiguatedBy,
        moneyBase,
      );
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: capped.moneyEligible,
        moneyWeight: capped.moneyEligible ? capped.badgeWeight : 0,
      });
    }
    case "file_import": {
      const classId: EvidenceClassId = "file_import";
      const badgeWeight0 = row.matchedRoute ? 0.4 : 0.1;
      const group: EvidenceGroup = row.matchedRoute ? "device-gps" : "self";
      const capped = applyCourseCaps(
        badgeWeight0,
        row.matchedRoute ? row.geometryKind : undefined,
        row.courseDisambiguatedBy,
        false,
      );
      return finish(row, {
        classId,
        group,
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: false, // excluded (line 954)
        moneyWeight: 0,
      });
    }
    case "foreground_checkin": {
      const classId: EvidenceClassId = "foreground_checkin";
      const badgeWeight0 = fixDeviceWeight(WEIGHT[classId], row.fix);
      const moneyBase = MONEY_ELIGIBLE_BASE.has(classId); // true — polygon-matched only, enforced below
      const capped = applyCourseCaps(
        badgeWeight0,
        row.fix.geometryKind,
        row.courseDisambiguatedBy,
        moneyBase,
      );
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: capped.moneyEligible,
        moneyWeight: capped.moneyEligible ? capped.badgeWeight : 0,
      });
    }
    case "health_workout": {
      const classId: EvidenceClassId = "health_workout";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: WEIGHT[classId],
        moneyEligible: false,
        moneyWeight: 0,
      });
    }
    case "self_report": {
      const classId: EvidenceClassId = "self_report";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: WEIGHT[classId],
        moneyEligible: false,
        moneyWeight: 0,
      });
    }
  }
}

/* ------------------------------------------------------------------ */
/* Combination (noisy-OR, correlated-pair max, device-GPS cap)         */
/* ------------------------------------------------------------------ */

function clamp01(x: number): number {
  return Math.max(0, Math.min(1, x));
}

/** `numeric(3,2)` display rounding (§4.4, A2-20d) — applied ONLY to the
 * value `scorePlay` returns, never to a value any internal comparison
 * (correlated-pair max, the device-GPS cap, or the `MONEY_MIN` check) uses. */
function round2(x: number): number {
  return Math.round(x * 100) / 100;
}

/** "Scores are combined with a noisy-OR over distinct classes: `c = 1 −
 * Π(1 − wᵢ)`... The combiner compares UNROUNDED scores" (§4.5 lines 888,
 * 893). */
function noisyOr(weights: number[]): number {
  let q = 1;
  for (const w of weights) q *= 1 - clamp01(w);
  return 1 - q;
}

/** "Two rows of the same class do not stack" (line 890) + "Correlated pairs
 * combine by `max`" (line 891/958-964): group by (classId for same-class
 * dedup, OR explicit correlationId for a cross-class correlated pair), keep
 * only the max-weight member of each group. Operates on a single pipeline's
 * weight field (`badge` or `money`) — see `combine` below, which calls this
 * twice with different weight selectors. */
function mergeByMax<
  T extends { classId: EvidenceClassId; correlationId?: string },
>(items: T[], weightOf: (item: T) => number): T[] {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    // Grouped by explicit `correlationId` when present (a caller-declared
    // correlated pair), else by `classId` — "two rows of the same class do
    // not stack" (line 890) falls out of the same grouping-then-max-pick
    // mechanism as an explicit correlated pair.
    const key = item.correlationId ?? `__class__:${item.classId}`;
    const existing = groups.get(key);
    if (existing) existing.push(item);
    else groups.set(key, [item]);
  }
  const out: T[] = [];
  for (const group of groups.values()) {
    let best = group[0]!;
    for (const item of group) {
      if (weightOf(item) > weightOf(best)) best = item;
    }
    out.push(best);
  }
  return out;
}

/**
 * Combines a set of already-classified contributions into one score.
 * `pipeline: 'badge'` uses every contribution's `badgeWeight`; `'money'`
 * filters to `moneyEligible` contributions and uses `moneyWeight`
 * (identical to `badgeWeight` on a money-eligible row — see
 * `ScorePlayContribution`'s doc). "In both scores, the device-GPS group is
 * combined first and capped at 0.80" (line 965) is applied identically in
 * both pipelines, just over each pipeline's own filtered contribution set —
 * this is why a device-only MONEY score can never reach 0.85 even before
 * the top-level combination (line 966).
 */
function combine(
  contributions: ScorePlayContribution[],
  pipeline: "badge" | "money",
): number {
  const weightOf = (c: ScorePlayContribution) =>
    pipeline === "badge" ? c.badgeWeight : c.moneyWeight;
  const pool =
    pipeline === "badge"
      ? contributions
      : contributions.filter((c) => c.moneyEligible);
  const merged = mergeByMax(pool, weightOf);
  const deviceGps = merged.filter((c) => c.group === "device-gps");
  const rest = merged.filter((c) => c.group !== "device-gps");
  const finalWeights = rest.map(weightOf);
  if (deviceGps.length > 0) {
    const subtotal = Math.min(noisyOr(deviceGps.map(weightOf)), 0.8);
    finalWeights.push(subtotal);
  }
  return Math.min(noisyOr(finalWeights), 0.99);
}

/* ------------------------------------------------------------------ */
/* presence_signal (§4.5, A2-06)                                        */
/* ------------------------------------------------------------------ */

/** Every raw `AppFix` embedded anywhere in `evidence[]` — the only inputs
 * `presence_signal` is computed from (A2-06: "computed only from fixes,
 * never from a class label, a vendor flag or `hard_signal`"). */
function collectFixes(evidence: Evidence[]): AppFix[] {
  const fixes: AppFix[] = [];
  for (const row of evidence) {
    switch (row.source) {
      case "staff_presence":
        if (row.coSignalFix) fixes.push(row.coSignalFix);
        break;
      case "booking":
        if (row.presenceFix) fixes.push(row.presenceFix);
        break;
      case "receipt_green_fee":
        if (row.coSignalFix) fixes.push(row.coSignalFix);
        break;
      case "foreground_dwell":
        fixes.push(row.checkinFix, row.checkoutFix);
        break;
      case "foreground_checkin":
        fixes.push(row.fix);
        break;
      default:
        break;
    }
  }
  return fixes;
}

/** "`presence_signal` = a co-signal exists at that facility on the play's
 * facility-local date... computed only from fixes" (§4.5 lines 933-935). The
 * co-signal window used HERE is the "same facility-local date" variant —
 * the one the definition names for "a `presence_signal`" specifically
 * (line 904) — never the ±10 min / ≤120s windows, which are class-specific
 * (staff-scan / rotating-QR) gates on a DIFFERENT question (whether THAT
 * class resolves hard). This is also exactly the oracle's own fix
 * predicate (§10 P3 AT(4)) minus the facility-id check, which every row
 * passed to one `scorePlay` call already shares by construction (module
 * doc's "one call = one play").
 */
function computePresenceSignal(
  evidence: Evidence[],
  playLocalDate: string,
): boolean {
  return collectFixes(evidence).some(
    (fix) => isQualityCoSignalFix(fix) && fix.localDate === playLocalDate,
  );
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
  return purchases.some(
    (p) =>
      p.facilityId === ctx.playFacilityId &&
      daysBetween(p.localDate, ctx.playLocalDate) <= 7,
  );
}

/* ------------------------------------------------------------------ */
/* scorePlay                                                            */
/* ------------------------------------------------------------------ */

export interface ScorePlayResult {
  score_badge: number;
  score_monetary: number;
  presence_signal: boolean;
  money: boolean;
  policyVersion: number;
  contributions: ScorePlayContribution[];
}

/**
 * §4.5's scorer, policy v1. Pure, deterministic, no I/O. See this module's
 * doc for the "one call = one play" and "counted once" contracts `evidence`
 * and `ctx` must already satisfy.
 */
export function scorePlay(
  evidence: Evidence[],
  ctx: ScorePlayContext,
): ScorePlayResult {
  const playContributions = evidence.map((row) => classify(row));

  // "Purchase corroboration... applies only if at least one play class is
  // present... and only once the play classes alone reach 0.50. It can
  // raise a badge score but is never what crosses the badge threshold
  // (A2-19). It never counts in score_monetary." (§4.5 line 1005.)
  const playClassesBadge = combine(playContributions, "badge");
  const hasPlayClass = playContributions.length > 0;
  const corroborationEligible =
    hasPlayClass && playClassesBadge >= 0.5 && corroborationApplies(ctx);

  const allContributions: ScorePlayContribution[] = [...playContributions];
  if (corroborationApplies(ctx)) {
    // Always reported in `contributions[]` (so a caller can see the
    // purchase leg was present), even when it didn't end up applying —
    // `scoreBadge` below only folds it in when `corroborationEligible`.
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
    ? Math.min(noisyOr([playClassesBadge, WEIGHT.purchase_corroboration]), 0.99)
    : playClassesBadge;

  const scoreMonetary = combine(playContributions, "money"); // corroboration is never money-eligible

  const presenceSignal = computePresenceSignal(evidence, ctx.playLocalDate);
  const hardSignal = playContributions.some((c) => c.hard);
  // The money rule is evaluated against the UNROUNDED score (A2-20d: "The
  // combiner compares unrounded scores; numeric(3,2) is for storage only")
  // — rounding happens only on the way out, below, never before this
  // comparison.
  const money = presenceSignal && (hardSignal || scoreMonetary >= MONEY_MIN);

  return {
    // `numeric(3,2)` storage rounding (§4.4 `play.score_badge`/
    // `score_monetary`), applied on the way out only — see the `money`
    // comparison immediately above, which deliberately uses the unrounded
    // `scoreMonetary`.
    score_badge: round2(scoreBadge),
    score_monetary: round2(scoreMonetary),
    presence_signal: presenceSignal,
    money,
    policyVersion: SCORE_PLAY_POLICY_VERSION,
    contributions: allContributions,
  };
}
