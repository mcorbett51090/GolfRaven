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
function deviceRowFixGateOk(fix: AppFix, playFacilityId: string, requireChallenge: boolean): boolean {
  if (fix.facilityId !== playFacilityId) return false;
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

/** Finding 2's "not simulated for money": a simulated fix is never a
 * co-signal (§4.5 line 1010-1011) — `foreground_checkin`/`foreground_dwell`
 * are money-eligible only because they otherwise act as a co-signal, so a
 * simulated one is excluded from money OUTRIGHT, not merely weight-reduced
 * (weight-reduction alone still applies to `score_badge`). */
function deviceRowMoneyEligible(fix: AppFix): boolean {
  return !fix.simulated;
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
    moneyEligible: capped.moneyEligible,
    moneyWeight: capped.moneyEligible ? capped.badgeWeight : 0,
  };
}

function classify(row: Evidence, ctx: ScorePlayContext): ScorePlayContribution {
  switch (row.source) {
    case "staff_presence": {
      // §4.5 line 990: "a co-signal within ±10 min." Finding 4: the window
      // anchor is `row.scanAt` itself (a timestamp, not a calendar date) —
      // unaffected by the date-anchoring fix, which is about DATE
      // comparisons specifically.
      const hasCoSignal =
        row.coSignalFix !== undefined &&
        isQualityCoSignalFix(row.coSignalFix, ctx.playFacilityId) &&
        windowMs(row.coSignalFix.capturedAt, row.scanAt, 10 * 60_000);
      const classId: EvidenceClassId = hasCoSignal ? "staff_presence_hard" : "staff_presence_soft";
      const badgeWeight = WEIGHT[classId];
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId),
        badgeWeight,
        moneyEligible: hasCoSignal,
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
      // Finding 4: anchored to `ctx.playLocalDate`, not to `row.localDate`
      // compared against the fix — a booking row (or its fix) dated off
      // the actual play's date can never manufacture same-day presence.
      const hasPresence =
        row.localDate === ctx.playLocalDate &&
        row.presenceFix !== undefined &&
        isQualityCoSignalFix(row.presenceFix, ctx.playFacilityId) &&
        row.presenceFix.localDate === ctx.playLocalDate;
      const classId: EvidenceClassId = hasPresence ? "booking_hard" : "booking_alone";
      const badgeWeight = WEIGHT[classId];
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId),
        badgeWeight,
        moneyEligible: true, // both booking classes count in score_monetary (line 947)
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
      // Finding 2: `!(apart >= threshold)` so a NaN `apartMinutes` fails
      // (`NaN >= threshold` is false, so a NaIVE `apartMinutes < threshold`
      // guard would have let NaN silently pass).
      const durationOk = !(!(row.apartMinutes >= threshold));
      const openOk = deviceRowFixGateOk(row.checkinFix, ctx.playFacilityId, true);
      const closeOk = deviceRowFixGateOk(row.checkoutFix, ctx.playFacilityId, true);
      if (!durationOk || !openOk || !closeOk) {
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
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: capped.badgeWeight,
        moneyEligible: capped.moneyEligible,
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
      const gateOk = deviceRowFixGateOk(row.fix, ctx.playFacilityId, false);
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

function fixIdsOfRow(row: Evidence): string[] {
  switch (row.source) {
    case "staff_presence":
      return row.coSignalFix ? [row.coSignalFix.fixId] : [];
    case "booking":
      return row.presenceFix ? [row.presenceFix.fixId] : [];
    case "receipt_green_fee":
      return row.coSignalFix ? [row.coSignalFix.fixId] : [];
    case "foreground_dwell":
      return [row.checkinFix.fixId, row.checkoutFix.fixId];
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
    for (const fixId of fixIdsOfRow(row)) {
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
  // but ONLY as a fallback when the row carries NO inline fix of its own
  // at all (`presenceFix` undefined). A row that DOES embed its own fix is
  // making a SPECIFIC claim about what proves it, and that claim is judged
  // on its own merits, never broadened by an unrelated fix elsewhere in
  // the same evidence set — this is what keeps "a booking dated D whose
  // OWN presence fix is on D+1, plus an unrelated check-in on D" at
  // `booking_alone` (0.79 combined with the check-in) rather than wrongly
  // promoting it to `booking_hard` (finding 4's regression test). Fixture
  // #10's NATURAL two-row encoding (a bare `booking({})` with no inline
  // fix, plus a separate `foreground_dwell` on the booking's date) is
  // exactly the case this fallback exists for.
  //
  // BOOKING ONLY, deliberately NOT `staff_presence` — a booking's
  // same-DAY window is a wide, date-grained window where "some qualifying
  // fix exists that day" is a plausible corroboration signal; a staff
  // scan's ±10-MINUTE window is narrow enough that an unrelated device
  // fix (e.g. an independent dwell's check-in, from a totally different
  // evidentiary flow) can coincidentally land inside it in realistic data
  // — money golden fixture #3 ("staff scan without co-signal + Health
  // route + dwell", verbatim table result 0.96, `staff_presence_soft`)
  // depends on exactly this NOT happening: extending absorption to staff
  // scans made that fixture wrongly resolve to `staff_presence_hard`
  // (0.98) by coincidentally absorbing the dwell's opening fix, which sits
  // at the same default test timestamp purely by construction, not by any
  // real relationship to the scan.
  evidence.forEach((row, i) => {
    if (row.source === "booking" && row.presenceFix === undefined && row.localDate === ctx.playLocalDate) {
      for (let j = 0; j < n; j += 1) {
        if (j === i) continue;
        for (const fix of fixesOfRow(evidence[j]!)) {
          if (isQualityCoSignalFix(fix, ctx.playFacilityId) && fix.localDate === ctx.playLocalDate) {
            dsu.union(i, j);
          }
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
function resolveGroups(
  evidence: Evidence[],
  contributions: ScorePlayContribution[],
  groups: number[],
  ctx: ScorePlayContext,
): ScorePlayContribution[] {
  const byGroup = new Map<number, number[]>();
  groups.forEach((g, i) => {
    const arr = byGroup.get(g) ?? [];
    arr.push(i);
    byGroup.set(g, arr);
  });

  const resolved: ScorePlayContribution[] = [];
  for (const idxs of byGroup.values()) {
    // Hard absorption: does this group contain a `booking` row whose
    // hard-window is satisfied by SOME fix among the group's own rows
    // (inline or absorbed)? `staff_presence` is deliberately excluded here
    // too — see `deriveGroups`'s matching comment (money golden fixture
    // #3). A row WITH its own inline fix is judged on that fix alone.
    let hardWinner: { row: Evidence; contribution: ScorePlayContribution } | undefined;
    for (const i of idxs) {
      const row = evidence[i]!;
      const contribution = contributions[i]!;
      if (row.source === "staff_presence") {
        // Inline-only (no absorption) — see the module-level comment above.
        const satisfied =
          row.coSignalFix !== undefined &&
          isQualityCoSignalFix(row.coSignalFix, ctx.playFacilityId) &&
          windowMs(row.coSignalFix.capturedAt, row.scanAt, 10 * 60_000);
        if (satisfied) hardWinner = { row, contribution };
      } else if (row.source === "booking" && row.localDate === ctx.playLocalDate) {
        const ownFix = row.presenceFix;
        const searchIdxs = ownFix === undefined ? idxs : [i];
        const satisfied = searchIdxs.some((j) =>
          fixesOfRow(evidence[j]!).some(
            (fix) => isQualityCoSignalFix(fix, ctx.playFacilityId) && fix.localDate === ctx.playLocalDate,
          ),
        );
        if (satisfied) hardWinner = { row, contribution };
      }
    }
    if (hardWinner) {
      const classId: EvidenceClassId = hardWinner.row.source === "staff_presence" ? "staff_presence_hard" : "booking_hard";
      resolved.push(
        finish(hardWinner.row, {
          classId,
          group: GROUP[classId],
          hard: true,
          badgeWeight: WEIGHT[classId],
          moneyEligible: true,
        }),
      );
      continue;
    }
    // No hard winner: the group becomes its own max-weight member — badge
    // and money use the SAME grouping, so both are handled by `combine`
    // filtering to the money-eligible subset before picking a max within
    // each pipeline; here we just keep every member and let `combine`
    // pick.
    for (const i of idxs) resolved.push(contributions[i]!);
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

function combine(
  contributions: ScorePlayContribution[],
  groups: number[],
  pipeline: "badge" | "money",
): number {
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
  return Math.min(noisyOr(finalWeights), 0.99);
}

/* ------------------------------------------------------------------ */
/* presence_signal (§4.5, A2-06)                                        */
/* ------------------------------------------------------------------ */

function collectFixes(evidence: Evidence[]): AppFix[] {
  const fixes: AppFix[] = [];
  for (const row of evidence) fixes.push(...fixesOfRow(row));
  return fixes;
}

/** "`presence_signal` = a co-signal exists at that facility on the play's
 * facility-local date" (§4.5 lines 933-935) — anchored to `ctx.playFacilityId`
 * / `ctx.playLocalDate` directly (findings 3/4), never to a row's own copies. */
function computePresenceSignal(evidence: Evidence[], ctx: ScorePlayContext): boolean {
  return collectFixes(evidence).some(
    (fix) => isQualityCoSignalFix(fix, ctx.playFacilityId) && fix.localDate === ctx.playLocalDate,
  );
}

/** Should-fix / §7.5 row 3: "the reward rests on an `unattestable`
 * co-signal -> `held_review` (C5 item 3)... it is never refused." True
 * when `money` is only reachable because the qualifying fix(es) grade
 * `unattestable` — i.e. no `attested` qualifying fix exists, but an
 * `unattestable` one does. */
function computeHeldReview(evidence: Evidence[], ctx: ScorePlayContext, money: boolean): boolean {
  if (!money) return false;
  const qualifying = collectFixes(evidence).filter(
    (fix) => isQualityCoSignalFix(fix, ctx.playFacilityId) && fix.localDate === ctx.playLocalDate,
  );
  const hasAttested = qualifying.some((fix) => resolveFixGrade(fix.token) === "attested");
  const hasUnattestable = qualifying.some((fix) => resolveFixGrade(fix.token) === "unattestable");
  return !hasAttested && hasUnattestable;
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
  // Finding 3: drop any row whose OWN facility disagrees with the play
  // being scored, before anything else runs.
  const evidence = voidDuplicateFingerprints(evidenceIn).filter((row) => row.facilityId === ctx.playFacilityId);

  const rawContributions = evidence.map((row) => classify(row, ctx));
  const groups = deriveGroups(evidence, rawContributions, ctx);
  const playContributions = resolveGroups(evidence, rawContributions, groups, ctx);
  // `resolveGroups` already reduced each group to its final member(s); the
  // remaining "group id" for `combine`'s own (now-redundant) grouping step
  // is therefore just each contribution's own index — every entry in
  // `playContributions` is already a fully-resolved, standalone
  // contribution with no further same-group sibling to compare against.
  const playGroups = playContributions.map((_, i) => i);

  const playClassesBadge = combine(playContributions, playGroups, "badge");
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

  const scoreMonetary = combine(playContributions, playGroups, "money");

  const presenceSignal = computePresenceSignal(evidence, ctx);
  const hardSignal = playContributions.some((c) => c.hard);
  const money = presenceSignal && (hardSignal || scoreMonetary >= MONEY_MIN);
  const heldReview = computeHeldReview(evidence, ctx, money);

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
