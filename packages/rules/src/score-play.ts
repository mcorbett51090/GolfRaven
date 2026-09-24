/**
 * `scorePlay` — §4.5 "Evidence classes and confidence scoring (policy v1)".
 * Pure TS, no I/O (build plan §3.1 row E): takes one play's evidence rows
 * (`app.evidence`, §4.4) plus a small amount of context and returns
 * `{score_badge, score_monetary, presence_signal, money, heldReview,
 * policyVersion, contributions[]}`. Money-path code (build plan §4.5
 * "Money rule", A2-05/A2-06/A2-07/A2-20) — correctness here gates a
 * marketing incentive, so every rule below cites the exact plan line it
 * implements.
 *
 * **Post-gate rework (this revision).** The Opus command-review gate on
 * commit 0ff5cd7 found 4 blocking money-path gaps in the previous
 * revision: (1) cross-row combination trusted a caller-supplied
 * `correlationId` instead of deriving correlation from the data itself;
 * (2) `foreground_checkin`/`foreground_dwell` skipped several fix-quality
 * checks (`fromApp`, `foreground`, finite accuracy) that a co-signal
 * requires; (3) nothing checked a fix's or a row's facility against the
 * play being scored; (4) same-date checks were anchored to a ROW's own
 * date instead of `ctx.playLocalDate`. All four are fixed below, each
 * cited at its own site; see `test/score-play-regression.test.ts` for the
 * failing-first reproduction of each.
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
 * or a fix's own copies of them (finding 4). A row whose own
 * `facilityId` disagrees with `ctx.playFacilityId` is dropped before
 * scoring (finding 3) — it is evidence for a DIFFERENT facility and must
 * not silently contribute to this play.
 */
import type { GeometryKind, VerificationTier } from "@golfraven/matching";
import type { CourseDisambiguatedBy } from "./completion.js";

/** §4.5's money-only floor. A CODE CONSTANT (A2-05): "No catalog or DB
 * datum can lower it." Every money decision in this module reads this
 * constant directly — never a parameter, never data. */
export const MONEY_MIN = 0.85;

/** Policy v1 (§4.5 heading). Kept as its OWN constant, deliberately
 * separate from `index.ts`'s `POLICY_VERSION`, which an existing,
 * unmodified test pins at 0. */
export const SCORE_PLAY_POLICY_VERSION = 1;

/* ------------------------------------------------------------------ */
/* Attestation grade (G3-08)                                           */
/* ------------------------------------------------------------------ */

export type FixGrade = "attested" | "unattestable" | "failed";

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

export interface AppFix {
  /** A caller-assigned identity for the PHYSICAL fix (not the evidence
   * row). Finding 1(b): two rows that embed the same `fixId` are, by
   * definition, proof of the SAME underlying capture (a staff scan and a
   * check-in reusing one fix; a dwell and the check-in that opened it) —
   * this is the only thing `scorePlay` trusts for that specific
   * correlation, never a row-level `correlationId`. */
  fixId: string;
  /** Finding 3: the facility this fix was matched against. Every
   * co-signal/hard-class/presence check requires this to equal
   * `ctx.playFacilityId` — a fix captured at a different facility is never
   * evidence for THIS play, however good its other attributes are. */
  facilityId: string;
  /** Taken by our app (never true for a Health route, a file import, a
   * Connect IQ fix, a GHIN post or a vendor round — §4.5 line 908). */
  fromApp: boolean;
  /** iOS `isSimulatedBySoftware` / Android mock-location (§4.5 caps). */
  simulated: boolean;
  foreground: boolean;
  /** "taken against a server challenge: live, or prefetched ≤24h ahead...
   * `none` = no challenge at all — never a co-signal. */
  challenge: ChallengeKind;
  token: TokenState;
  /** Facility verification tier of the facility this fix was matched
   * against (`@golfraven/matching`'s own vocabulary). A co-signal requires
   * `'play-verified'` — "a radius-fallback circle never qualifies" is
   * exactly `geometryKind !== 'polygon'` OR `verificationTier !==
   * 'play-verified'`. Deliberately decoupled from `geometryKind` (a
   * `play-verified` facility can still produce a `radius`-kind fix, e.g. a
   * temporary geometry gap) — both are checked independently. */
  verificationTier: VerificationTier;
  geometryKind: GeometryKind;
  /** Raw geometric containment: inside the polygon+50m buffer, or inside
   * the radius-fallback circle+50m — whichever `geometryKind` names. */
  insideBuffer: boolean;
  accuracyMeters: number;
  /** Epoch ms the fix was captured. */
  capturedAt: number;
  /** Facility-local calendar date (`YYYY-MM-DD`) the fix was captured on. */
  localDate: string;
}

function finiteInRange(x: number, min: number, max: number): boolean {
  // NaN-safe by construction: every comparison below is written so a NaN
  // input fails to satisfy it (Number.isFinite(NaN) === false short-circuits
  // before any `<=`/`>=` on NaN could silently pass).
  return Number.isFinite(x) && x >= min && x <= max;
}

/**
 * The co-signal FIX-QUALITY gate (§4.5 "Co-signal" bullets 1-3, plus
 * finding 3's facility anchor). `playFacilityId` is REQUIRED — every call
 * site anchors to `ctx.playFacilityId`, never to a row's own copy.
 * `grade !== 'failed'` is folded in here because §4.5 line 920 states it as
 * part of the same definition: "A `failed` fix is never a co-signal."
 * Accuracy is checked with `finiteInRange` so `NaN`/`Infinity`/a negative
 * value all fail closed rather than silently passing a `<=` comparison.
 */
function isQualityCoSignalFix(fix: AppFix, playFacilityId: string): boolean {
  return (
    fix.facilityId === playFacilityId &&
    fix.fromApp &&
    !fix.simulated &&
    fix.foreground &&
    fix.challenge !== "none" &&
    finiteInRange(fix.accuracyMeters, 0, 50) &&
    fix.geometryKind === "polygon" &&
    fix.verificationTier === "play-verified" &&
    fix.insideBuffer &&
    resolveFixGrade(fix.token) !== "failed"
  );
}

/**
 * Re-gate finding 1/2: staff_presence's ±10 min hard-window, as ONE shared
 * predicate — used identically by `classify` (the row's own inline fix)
 * AND `resolveGroups` (a fix absorbed from elsewhere in the same derived
 * group), so the two can never drift apart the way they did before (the
 * gate that found this duplication was itself evidence of the risk).
 * Requires the fix's OWN date to match `ctx.playLocalDate` — NOT merely
 * that it falls within ±10 min of `scanAt` — because a scan and a fix
 * that are both mis-dated (or a scan whose own `scanAt` epoch happens to
 * be close to a fix on a genuinely different calendar day, e.g. a
 * malformed or adversarial input) must not resolve hard just because the
 * millisecond delta between two absolute timestamps happens to be small.
 */
function staffFixSatisfiesHardWindow(fix: AppFix, scanAt: number, ctx: ScorePlayContext): boolean {
  return (
    isQualityCoSignalFix(fix, ctx.playFacilityId) &&
    fix.localDate === ctx.playLocalDate &&
    windowMs(fix.capturedAt, scanAt, 10 * 60_000)
  );
}

/** Same idea for `booking`'s same-day-presence hard-window (a whole-day
 * window, not a minute delta — so this needs no `scanAt`-analogue). */
function bookingFixSatisfiesHardWindow(fix: AppFix, ctx: ScorePlayContext): boolean {
  return isQualityCoSignalFix(fix, ctx.playFacilityId) && fix.localDate === ctx.playLocalDate;
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
  /** Caller-assigned, unique within one `scorePlay` call. */
  id: string;
  /** Finding 3: every row is checked against `ctx.playFacilityId` before
   * scoring — a row whose own facility disagrees is dropped entirely. */
  facilityId: string;
  courseId?: string;
  /** This row's own facility-local date. Finding 4: this is used only
   * where the plan itself compares a ROW's date to something — every
   * same-date CHECK in this module (booking's same-day presence, a
   * receipt's same-date co-signal) is anchored to `ctx.playLocalDate`
   * directly, never to this field compared against a fix's date. */
  localDate: string;
  /** §4.3 A2-01 user-pick cap — applied to EVERY class uniformly (not just
   * device-GPS ones; should-fix item, plan line 956: "the course credit"
   * is not class-scoped in the plan's own wording). */
  courseDisambiguatedBy?: CourseDisambiguatedBy;
  /** Optional, NEVER trusted for combination (finding 1). A caller may set
   * this for its own tracing/debugging; `scorePlay` derives every real
   * correlation from the data itself (`deriveCorrelationGroups` below) and
   * ignores this field entirely when deciding how rows combine. */
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
  | (EvidenceBase & {
      source: "booking";
      presenceFix?: AppFix;
      /** Finding 1(b): "a booking and the receipt for the SAME booking or
       * prepay id" — the data-derived correlation key, never a
       * `correlationId`. */
      paymentRef?: string;
    })
  | (EvidenceBase & {
      source: "receipt_green_fee";
      status: "approved" | "pending" | "void";
      coSignalFix?: AppFix;
      paymentRef?: string;
      /** Should-fix: a receipt fingerprint. A second row (in the SAME
       * `evidence[]` call) sharing a non-empty fingerprint with an earlier
       * one is treated as void (§4.4: "duplicate-fingerprint receipts are
       * void", §4.5 line 996), regardless of its own `status`. */
      fingerprint?: string;
    })
  | (EvidenceBase & {
      source: "health_route";
      sourceAllowListed: boolean;
      insideRatio: number;
      simulated: boolean;
      geometryKind: GeometryKind;
      /** Finding 1(b): epoch ms, for the "same round" correlation with a
       * `file_import` of the same round (start ±15 min, same facility). */
      startedAt?: number;
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
      startedAt?: number;
    })
  | (EvidenceBase & { source: "foreground_checkin"; fix: AppFix })
  | (EvidenceBase & { source: "health_workout" })
  | (EvidenceBase & { source: "self_report" });

/** The §4.6 purchase-corroboration leg (a `purchase_evidence.valid` row) —
 * a DIFFERENT table than `app.evidence`, so it travels on `ctx`. */
export interface PurchaseCorroboration {
  facilityId: string;
  localDate: string;
}

export interface ScorePlayContext {
  playFacilityId: string;
  playLocalDate: string;
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
  receipt_green_fee: 0.8,
  health_route: 0.6,
  connect_iq_route: 0.5,
  connect_iq_checkin: 0.3,
  foreground_dwell: 0.5,
  file_import: 0.4,
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
  file_import: "device-gps",
  foreground_checkin: "device-gps",
  health_workout: "self",
  self_report: "self",
  purchase_corroboration: "corroboration",
};

const HARD: ReadonlySet<EvidenceClassId> = new Set(["staff_presence_hard", "booking_hard"]);

const MONEY_ELIGIBLE_BASE: ReadonlySet<EvidenceClassId> = new Set([
  "staff_presence_hard",
  "vendor_sensor",
  "booking_hard",
  "booking_alone",
  "receipt_green_fee",
  "foreground_checkin",
  "foreground_dwell",
]);

/* ------------------------------------------------------------------ */
/* Device-row full fix-quality gate (finding 2)                        */
/* ------------------------------------------------------------------ */

/**
 * `foreground_checkin`/`foreground_dwell` are the classes THAT PRODUCE a
 * co-signal fix, so their own fix must pass the FULL co-signal-quality
 * gate as a hard entry condition — not merely a weight multiplier. A fix
 * that fails `fromApp`/`foreground`/accuracy/`insideBuffer`/facility is not
 * a valid capture at all and contributes NOTHING (weight 0), exactly like
 * a `failed` grade. `requireChallenge` is `true` for `foreground_dwell`
 * (plan line 1000: "both against a challenge" is a DEFINING condition, not
 * a penalty — "a `none` challenge makes the dwell ineligible, not ×0.6")
 * and `false` for `foreground_checkin` (a `none` challenge there stays a
 * ×0.6 penalty via `deviceFixMultiplier`, unchanged).
 */
function deviceRowFixGateOk(
  fix: AppFix,
  playFacilityId: string,
  playLocalDate: string,
  requireChallenge: boolean,
): boolean {
  if (fix.facilityId !== playFacilityId) return false;
  // Re-gate finding 1: the fix's own date must match the play's date — a
  // check-in/dwell fix from another day is not evidence for THIS play,
  // however good its other attributes are.
  if (fix.localDate !== playLocalDate) return false;
  // Should-fix: fail closed on an unverified facility. `listed-verified`
  // (the radius-fallback tier) is deliberately still allowed THROUGH the
  // gate — a radius-matched check-in/dwell is a legitimate, reduced-weight
  // contribution (capped separately, by `geometryKind`, in `classify`);
  // only `unverified` is a hard exclusion here.
  if (fix.verificationTier === "unverified") return false;
  if (!fix.fromApp) return false;
  if (!fix.foreground) return false;
  if (!finiteInRange(fix.accuracyMeters, 0, 50)) return false;
  if (!fix.insideBuffer) return false;
  if (requireChallenge && fix.challenge === "none") return false;
  if (resolveFixGrade(fix.token) === "failed") return false;
  return true;
}

/** The `simulated`×0.3 and `unattestable`/no-challenge×0.6 penalties,
 * applied only AFTER `deviceRowFixGateOk` has already passed. */
function deviceFixMultiplier(fix: Pick<AppFix, "simulated" | "token" | "challenge">): number {
  let m = 1;
  if (fix.simulated) m *= 0.3;
  const grade = resolveFixGrade(fix.token);
  if (grade === "unattestable" || fix.challenge === "none") m *= 0.6;
  return m;
}

/**
 * Finding 2's "not simulated for money": a simulated fix is never a
 * co-signal (§4.5 line 1010-1011) — `foreground_checkin`/`foreground_dwell`
 * are money-eligible only because they otherwise act as a co-signal, so a
 * simulated one is excluded from money OUTRIGHT, not merely weight-reduced
 * (weight-reduction alone still applies to `score_badge`).
 *
 * Third re-gate, should-fix: ALSO require `verificationTier ===
 * 'play-verified'` here, strictly — never derive money-eligibility from
 * `geometryKind` alone. Build plan §4.2's own tier table: "`play-verified`
 * | `listed-verified` + a polygon... | Everything, including route
 * matching at full weight and **money** (every programme facility must be
 * `play-verified`)." `play-verified` is DEFINED as `listed-verified` PLUS
 * a polygon — so a fix reporting `verificationTier: 'listed-verified'`
 * with `geometryKind: 'polygon'` is an inconsistent/adversarial
 * combination that should never occur in honest data (a facility with a
 * matchable polygon is, by that definition, already `play-verified`).
 * Without this check, `applyCourseCaps`'s radius cap (keyed on
 * `geometryKind`, not `verificationTier`) would wave it through at full
 * weight and full money-eligibility purely because `geometryKind` says
 * `'polygon'` — the exact gap the third re-gate found (fixture #14 + a
 * `listed-verified`/`polygon` check-in reached 0.86 with `money: true`).
 */
function deviceRowMoneyEligible(fix: AppFix): boolean {
  return !fix.simulated && fix.verificationTier === "play-verified";
}

/** §4.5's radius-fallback cap and the §4.3/A2-01 user-pick cap. Applied
 * uniformly to every class now (should-fix): `courseDisambiguatedBy` lives
 * on every row, and the plan's own wording ("the course credit") is not
 * class-scoped. */
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
  badgeWeight: number;
  moneyEligible: boolean;
  moneyWeight: number;
  /** Blocking finding 4: the attestation grade of the SPECIFIC fix that
   * backs this contribution's hard/money status (the staff scan's or
   * booking's winning co-signal, a check-in's own fix, a dwell's
   * worse-of-two-fixes grade, a receipt's co-signal when money-eligible).
   * `undefined` for a class with no single governing fix (vendor, ghin,
   * health_route, connect_iq, file_import, self/health_workout, a
   * `booking_alone`/soft `staff_presence` with no qualifying fix). Used by
   * `computeHeldReview` — scoped to ONLY the fix(es) that actually
   * established the winning result, never any unrelated fix elsewhere in
   * the same evidence set. */
  governingGrade?: FixGrade;
}

function windowMs(aMs: number, bMs: number, ms: number): boolean {
  // NaN-safe: Math.abs(NaN) is NaN, and `NaN <= ms` is false, so a NaN
  // timestamp never satisfies a window.
  return Math.abs(aMs - bMs) <= ms;
}

function finish(
  row: Evidence,
  fields: Omit<ScorePlayContribution, "evidenceId" | "moneyWeight">,
): ScorePlayContribution {
  const capped = applyCourseCaps(
    fields.badgeWeight,
    undefined, // geometry-kind caps are already applied per-class before this call
    row.courseDisambiguatedBy,
    fields.moneyEligible,
  );
  return {
    evidenceId: row.id,
    ...fields,
    badgeWeight: capped.badgeWeight,
    // Blocking finding 3: `hard` is a MONEY-path signal only (it never
    // affects `score_badge`, which is driven by `badgeWeight` alone) — so
    // a user-picked course, which `applyCourseCaps` already strips of
    // money-eligibility, must ALSO lose its `hard` flag. Leaving `hard:
    // true` here let `hardSignal` bypass the money-eligibility cap
    // entirely (`money = presence && (hardSignal || score >= MONEY_MIN)`),
    // so a user-picked staff-scan/booking could still reach `money: true`
    // through the `hardSignal` branch even though its OWN contribution was
    // correctly excluded from `score_monetary`.
    hard: fields.hard && capped.moneyEligible,
    moneyEligible: capped.moneyEligible,
    moneyWeight: capped.moneyEligible ? capped.badgeWeight : 0,
  };
}

/**
 * Exported (third re-gate, should-fix) so the CLASS-LEVEL date/facility
 * anchors inside each `case` below (e.g. `foreground_checkin`'s own
 * `row.localDate === ctx.playLocalDate` check) can be unit-tested
 * DIRECTLY, bypassing `scorePlay`'s top-level row filter. Those anchors
 * are otherwise unreachable from `scorePlay`'s own entry point (the
 * top-level filter already drops an off-date/off-facility row before
 * `classify` ever sees it) — kept anyway as defence in depth (a future
 * change to the top-level filter, or a caller that invokes `classify`
 * some other way, should not silently lose this protection), which only
 * has real meaning if something actually exercises them. Not part of
 * `scorePlay`'s own contract — a normal caller uses `scorePlay`, not this.
 */
export function classify(row: Evidence, ctx: ScorePlayContext): ScorePlayContribution {
  switch (row.source) {
    case "staff_presence": {
      // §4.5 line 990: "a co-signal within ±10 min", now including the
      // fix's OWN date matching `ctx.playLocalDate` (finding 1/re-gate) —
      // see `staffFixSatisfiesHardWindow`, shared with `resolveGroups`.
      const hasCoSignal = row.coSignalFix !== undefined && staffFixSatisfiesHardWindow(row.coSignalFix, row.scanAt, ctx);
      const classId: EvidenceClassId = hasCoSignal ? "staff_presence_hard" : "staff_presence_soft";
      const badgeWeight = WEIGHT[classId];
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId),
        badgeWeight,
        moneyEligible: hasCoSignal,
        ...(hasCoSignal ? { governingGrade: resolveFixGrade(row.coSignalFix!.token) } : {}),
      });
    }
    case "arccos":
    case "garmin": {
      const isSensorVendor = row.vendorCourseMapped && row.sensorProvenance;
      const classId: EvidenceClassId = isSensorVendor ? "vendor_sensor" : "self_posted";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: WEIGHT[classId],
        moneyEligible: isSensorVendor,
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
      });
    }
    case "booking": {
      // Finding 4: anchored to `ctx.playLocalDate`, never to `row.localDate`
      // compared against the fix — see `bookingFixSatisfiesHardWindow`,
      // shared with `resolveGroups`.
      const hasPresence =
        row.localDate === ctx.playLocalDate &&
        row.presenceFix !== undefined &&
        bookingFixSatisfiesHardWindow(row.presenceFix, ctx);
      const classId: EvidenceClassId = hasPresence ? "booking_hard" : "booking_alone";
      const badgeWeight = WEIGHT[classId];
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId),
        badgeWeight,
        moneyEligible: true, // both booking classes count in score_monetary (line 947)
        ...(hasPresence ? { governingGrade: resolveFixGrade(row.presenceFix!.token) } : {}),
      });
    }
    case "receipt_green_fee": {
      const classId: EvidenceClassId = "receipt_green_fee";
      const badgeWeight = row.status === "approved" ? WEIGHT[classId] : row.status === "pending" ? 0.2 : 0;
      // Finding 4: anchored to `ctx.playLocalDate`.
      const moneyEligible =
        row.status !== "void" &&
        row.localDate === ctx.playLocalDate &&
        row.coSignalFix !== undefined &&
        isQualityCoSignalFix(row.coSignalFix, ctx.playFacilityId) &&
        row.coSignalFix.localDate === ctx.playLocalDate;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight,
        moneyEligible,
        ...(moneyEligible ? { governingGrade: resolveFixGrade(row.coSignalFix!.token) } : {}),
      });
    }
    case "health_route": {
      const classId: EvidenceClassId = "health_route";
      // Should-fix: insideRatio below 0.6, or non-finite, scores 0.
      if (!Number.isFinite(row.insideRatio) || row.insideRatio < 0.6) {
        return finish(row, {
          classId,
          group: GROUP[classId],
          hard: false,
          badgeWeight: 0,
          moneyEligible: false,
        });
      }
      const base = !row.sourceAllowListed ? 0.1 : row.insideRatio >= 0.8 ? 0.6 : 0.4;
      const badgeWeight0 = row.simulated ? base * 0.3 : base;
      const capped = applyCourseCaps(badgeWeight0, row.geometryKind, row.courseDisambiguatedBy, false);
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: false, // excluded (line 953)
      });
    }
    case "connect_iq": {
      const classId: EvidenceClassId = row.variant === "route" ? "connect_iq_route" : "connect_iq_checkin";
      let badgeWeight: number;
      if (row.variant === "route") {
        badgeWeight =
          row.k4bPassed && row.insidePolygon && Number.isFinite(row.durationMinutes) && row.durationMinutes >= 90
            ? WEIGHT[classId]
            : 0;
      } else {
        badgeWeight = WEIGHT[classId];
      }
      if (row.simulated) badgeWeight *= 0.3;
      const capped = applyCourseCaps(badgeWeight, undefined, row.courseDisambiguatedBy, false);
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: false, // excluded (line 954, FM-30)
      });
    }
    case "foreground_dwell": {
      const classId: EvidenceClassId = "foreground_dwell";
      const threshold = row.holes === 9 ? 50 : 90; // line 1000
      // Should-fix: derive `apartMinutes` from the two fixes' OWN
      // `capturedAt` rather than trusting the stored field — if they
      // disagree, the derived value wins (both are always present on a
      // `foreground_dwell` row, so this is unconditional, not a fallback:
      // a client-computed `apartMinutes` that doesn't match the fixes it
      // was supposedly computed from is exactly the kind of stored-value
      // drift this guards against).
      const derivedApart = Math.abs(row.checkoutFix.capturedAt - row.checkinFix.capturedAt) / 60_000;
      // Finding 2: `!(apart >= threshold)` so a NaN derived duration fails
      // (`NaN >= threshold` is false, so a NaIVE `apart < threshold` guard
      // would have let NaN silently pass).
      const durationOk = !(!(derivedApart >= threshold));
      // Finding 1: the row's OWN date must match the play's date too, not
      // just each fix's own date (checked inside `deviceRowFixGateOk`).
      const rowDateOk = row.localDate === ctx.playLocalDate;
      const openOk = deviceRowFixGateOk(row.checkinFix, ctx.playFacilityId, ctx.playLocalDate, true);
      const closeOk = deviceRowFixGateOk(row.checkoutFix, ctx.playFacilityId, ctx.playLocalDate, true);
      if (!durationOk || !rowDateOk || !openOk || !closeOk) {
        return finish(row, {
          classId,
          group: GROUP[classId],
          hard: false,
          badgeWeight: 0,
          moneyEligible: false,
        });
      }
      const openM = deviceFixMultiplier(row.checkinFix);
      const closeM = deviceFixMultiplier(row.checkoutFix);
      const badgeWeight0 = WEIGHT[classId] * Math.min(openM, closeM);
      const bothPolygon = row.checkinFix.geometryKind === "polygon" && row.checkoutFix.geometryKind === "polygon";
      const geometryKind: GeometryKind = bothPolygon ? "polygon" : "radius";
      const moneyBase =
        MONEY_ELIGIBLE_BASE.has(classId) && deviceRowMoneyEligible(row.checkinFix) && deviceRowMoneyEligible(row.checkoutFix);
      const capped = applyCourseCaps(badgeWeight0, geometryKind, row.courseDisambiguatedBy, moneyBase);
      // The "worse" of the two fixes' grades — a dwell that rests even
      // PARTLY on an unattestable fix should route to held_review; only if
      // BOTH fixes are attested does the whole dwell count as attested.
      const openGrade = resolveFixGrade(row.checkinFix.token);
      const closeGrade = resolveFixGrade(row.checkoutFix.token);
      const governingGrade: FixGrade = openGrade === "unattestable" || closeGrade === "unattestable" ? "unattestable" : openGrade;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: capped.moneyEligible,
        governingGrade,
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
      });
    }
    case "foreground_checkin": {
      const classId: EvidenceClassId = "foreground_checkin";
      // Finding 1: the row's own date must match too, not just the fix's.
      const rowDateOk = row.localDate === ctx.playLocalDate;
      const gateOk = rowDateOk && deviceRowFixGateOk(row.fix, ctx.playFacilityId, ctx.playLocalDate, false);
      if (!gateOk) {
        return finish(row, {
          classId,
          group: GROUP[classId],
          hard: false,
          badgeWeight: 0,
          moneyEligible: false,
        });
      }
      const badgeWeight0 = WEIGHT[classId] * deviceFixMultiplier(row.fix);
      const moneyBase = MONEY_ELIGIBLE_BASE.has(classId) && deviceRowMoneyEligible(row.fix);
      const capped = applyCourseCaps(badgeWeight0, row.fix.geometryKind, row.courseDisambiguatedBy, moneyBase);
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: capped.moneyEligible,
        governingGrade: resolveFixGrade(row.fix.token),
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
      });
    }
  }
}

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

function fixesOfRow(row: Evidence): AppFix[] {
  switch (row.source) {
    case "staff_presence":
      return row.coSignalFix ? [row.coSignalFix] : [];
    case "booking":
      return row.presenceFix ? [row.presenceFix] : [];
    case "receipt_green_fee":
      return row.coSignalFix ? [row.coSignalFix] : [];
    case "foreground_dwell":
      return [row.checkinFix, row.checkoutFix];
    case "foreground_checkin":
      return [row.fix];
    default:
      return [];
  }
}

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
    // Should-fix (order dependence): collect every candidate first, then
    // pick ONE winner by a rule that doesn't depend on which order the
    // rows were passed in — the highest class WEIGHT (`staff_presence_hard`
    // 0.95 beats `booking_hard` 0.90). The previous "last one processed
    // wins" rule made `[staffHard, booking]` and `[booking, staffHard]`
    // score differently for the identical evidence, just reordered.
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
        const satisfyingFix = idxs
          .flatMap((j) => fixesOfRow(evidence[j]!))
          .find((fix) => staffFixSatisfiesHardWindow(fix, row.scanAt, ctx));
        if (satisfyingFix) candidates.push({ row, contribution, classId: "staff_presence_hard", satisfyingFix });
      } else if (row.source === "booking" && row.localDate === ctx.playLocalDate) {
        const satisfyingFix = idxs.flatMap((j) => fixesOfRow(evidence[j]!)).find((fix) => bookingFixSatisfiesHardWindow(fix, ctx));
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
      // picking a winner, not after. `finish()` (below) strips
      // `hard`/`moneyEligible` from a user-picked row's contribution — but
      // the winner-selection comparison ran on the RAW class weight
      // (0.95/0.90), so a user-picked staff-scan candidate could win over
      // a non-user-picked booking candidate on raw weight, then get
      // reduced to non-hard/non-money by `finish()`, DISCARDING the
      // legitimate booking candidate along with it (each group produces
      // exactly one contribution). A user-picked candidate's effective
      // weight is treated as below every real weight (never `0` — two
      // user-picked candidates still need to compare against each other
      // for the `hard: false` fallthrough to at least be deterministic).
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
    const subtotal = Math.min(noisyOr(deviceGps.map(weightOf)), 0.8);
    finalWeights.push(subtotal);
  }
  return { score: Math.min(noisyOr(finalWeights), 0.99), merged };
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
 * Should-fix / §7.5 row 3 / blocking finding 4: "the reward rests on an
 * `unattestable` co-signal -> `held_review` (C5 item 3)... it is never
 * refused." Scoped to ONLY the fix(es) that actually established the
 * winning result — never any unrelated fix sitting elsewhere in
 * `evidence[]` — per the gate's own wording: "compute the grade from the
 * fixes that actually establish hard status or the winning score."
 *
 *   - If `hardSignal` is what makes `money` true, look at ONLY the hard
 *     contribution's own `governingGrade` (the specific fix that satisfied
 *     its window — inline or absorbed, per `resolveGroups`).
 *   - Otherwise (money via `score_monetary >= MONEY_MIN`, no hard class),
 *     look at ONLY the contributions `combine`'s MONEY pipeline actually
 *     merged into that score (`moneyMerged`) — if any of THOSE grades
 *     `unattestable` and none grades `attested`, held.
 *
 * An unrelated attested fix elsewhere in the play (e.g. a check-in hours
 * later that has nothing to do with why this play reached `money`) must
 * never cancel this — that was the exact bug the gate found.
 */
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

  const presenceHasAttested = presenceFixes.some((fix) => resolveFixGrade(fix.token) === "attested");
  const presenceHasUnattestable = presenceFixes.some((fix) => resolveFixGrade(fix.token) === "unattestable");
  const presenceHeld = !presenceHasAttested && presenceHasUnattestable;

  if (hardSignal) {
    // Should-fix (order independence): `.filter` + `.some` over the SET of
    // hard contributions — not `.find`, which picked whichever hard
    // contribution happened to come FIRST in `evidence[]`'s own order.
    // Two independent hard contributions (e.g. an unattestable staff-hard
    // AND an attested booking-hard, neither correlated with the other) are
    // now judged together: an attested one ANYWHERE in the hard set is
    // enough to not hold, regardless of array order.
    const hardOnes = playContributions.filter((c) => c.hard);
    const hardHasAttested = hardOnes.some((c) => c.governingGrade === "attested");
    const hardHasUnattestable = hardOnes.some((c) => c.governingGrade === "unattestable");
    const hardHeld = !hardHasAttested && hardHasUnattestable;
    return hardHeld || presenceHeld;
  }
  const hasAttested = moneyMerged.some((c) => c.governingGrade === "attested");
  const hasUnattestable = moneyMerged.some((c) => c.governingGrade === "unattestable");
  const scoreHeld = !hasAttested && hasUnattestable;
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
}

/**
 * §4.5's scorer, policy v1. Pure, deterministic, no I/O.
 */
export function scorePlay(evidenceIn: Evidence[], ctx: ScorePlayContext): ScorePlayResult {
  // Finding 3 + blocking finding 2: drop any row whose OWN facility OR
  // OWN date disagrees with the play being scored, before anything else
  // runs — this is what stops a vendor round or a staff scan dated on a
  // DIFFERENT day (no per-class date check ever ran for those classes)
  // from contributing to this play at all. Every class-specific date check
  // elsewhere in this module (booking's same-day presence, a receipt's
  // same-date co-signal, a device row's own fix date) is additional,
  // narrower anchoring on top of this blanket row-level filter — not a
  // substitute for it.
  const evidence = voidDuplicateFingerprints(evidenceIn).filter(
    (row) => row.facilityId === ctx.playFacilityId && row.localDate === ctx.playLocalDate,
  );

  const rawContributions = evidence.map((row) => classify(row, ctx));
  const groups = deriveGroups(evidence, rawContributions, ctx);
  const resolved = resolveGroups(evidence, rawContributions, groups, ctx);
  const playContributions = resolved.map((r) => r.contribution);
  const playGroups = resolved.map((r) => r.groupId);

  const playClassesBadge = combine(playContributions, playGroups, "badge").score;
  const hasPlayClass = playContributions.length > 0;
  const corroborationEligible = hasPlayClass && playClassesBadge >= 0.5 && corroborationApplies(ctx);

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
    ? Math.min(noisyOr([playClassesBadge, WEIGHT.purchase_corroboration]), 0.99)
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
