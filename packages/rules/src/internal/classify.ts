/**
 * The evidence-row classification engine (§4.5's class table) — moved into
 * `src/internal/` (fourth re-gate, blocking finding 1) specifically so its
 * per-row classifier is NEVER part of `@golfraven/rules`'s public surface.
 * Everything exported from this file (`classifyEvidenceRow`, `finish`,
 * `WEIGHT`, `isQualityCoSignalFix`, …) is package-internal: `package.json`
 * exposes only `"."`, and nothing here is re-exported from `index.ts`. Never
 * add a subpath export for `internal/` — callers must go through `scorePlay`.
 *
 * **Why this file exists at all.** The classifier used to be a plain,
 * exported function directly in `score-play.ts` — which meant it was also
 * exported through `score-play.ts`'s `export *` re-export in `index.ts`,
 * making it PUBLIC API. Public API skips `scorePlay`'s own top-level
 * facility/date filter entirely, so a caller reaching this function
 * directly could get `hard: true, moneyEligible: true` back for a row
 * whose FACILITY OR DATE plainly disagreed with the play, as long as the
 * row's own EMBEDDED FIX happened to carry the right facility/date (the
 * gate's own failing cases: a `staff_presence` row at `facilityId:
 * "OTHER"` whose `coSignalFix` was otherwise perfect; a vendor round dated
 * off-play). Nothing in `@golfraven/rules`'s package entry point
 * (`index.ts`) re-exports this module — `score-play.ts` `import`s
 * `classifyEvidenceRow` for its OWN internal use inside `scorePlay`, and
 * never re-exports the name. Tests reach it directly via this file's own
 * path (`../src/internal/classify.js`), bypassing `score-play.ts`/
 * `index.ts` entirely — see `test/score-play-internal-classify.test.ts`.
 *
 * **Defence in depth (should-fix, this revision).** Every branch below now
 * ALSO checks the ROW's own `facilityId`/`localDate` against
 * `ctx.playFacilityId`/`ctx.playLocalDate` directly — not just the
 * embedded fix's copies. `scorePlay`'s top-level filter (`score-play.ts`)
 * already guarantees this for any row reaching `classifyEvidenceRow`
 * through it, so these checks are REDUNDANT from that one call path — but
 * this function is no longer guaranteed to only ever be reached that way
 * (tests call it directly, by design), so it has to be safe on its own.
 *
 * Every OTHER type/helper this module needs (`AppFix`, `Evidence`,
 * `ScorePlayContext`, `ScorePlayContribution`, `resolveFixGrade`, …) is
 * defined here and RE-EXPORTED, by name, from `score-play.ts` — never the
 * reverse — so there is no import cycle between the two files.
 */
import type { GeometryKind, VerificationTier } from "@golfraven/matching";
import type { CourseDisambiguatedBy } from "../completion.js";

/* ------------------------------------------------------------------ */
/* F5 (sixth gate): every inline policy literal, hoisted into a named    */
/* constant — "so changing a weight without bumping the version fails    */
/* CI" now covers these too, not just the WEIGHT table/MONEY_MIN/caps    */
/* that were already pinned. Grouped here, at the top of the module, so  */
/* a reader (or `score-play-policy-hash.test.ts`) can see every money-   */
/* path number in one place instead of hunting inline literals.          */
/* ------------------------------------------------------------------ */

/** The co-signal / device-row-fix accuracy ceiling (meters). */
export const ACCURACY_METERS_MAX = 50;
/** staff_presence's hard-window half-width. */
export const STAFF_HARD_WINDOW_MS = 10 * 60_000;
/** The `simulated` penalty multiplier (device-row classes). */
export const SIMULATED_PENALTY_MULTIPLIER = 0.3;
/** The `unattestable`-grade / no-challenge penalty multiplier. */
export const UNATTESTABLE_OR_NO_CHALLENGE_PENALTY_MULTIPLIER = 0.6;
/** A `pending`-status receipt's badge weight. */
export const RECEIPT_PENDING_WEIGHT = 0.2;
/** `health_route`'s minimum `insideRatio` to score anything at all. */
export const HEALTH_ROUTE_MIN_INSIDE_RATIO = 0.6;
/** `health_route`'s `insideRatio` threshold for the HIGH weight tier. */
export const HEALTH_ROUTE_HIGH_INSIDE_RATIO = 0.8;
/** `health_route`'s weight when `sourceAllowListed` is false. */
export const HEALTH_ROUTE_LOW_WEIGHT = 0.1;
/** `health_route`'s weight for `insideRatio` in `[MIN, HIGH)`. */
export const HEALTH_ROUTE_MID_WEIGHT = 0.4;
/** `health_route`'s weight for `insideRatio >= HIGH`. */
export const HEALTH_ROUTE_HIGH_WEIGHT = 0.6;
/** `connect_iq` route variant's minimum duration to score anything. */
export const CONNECT_IQ_ROUTE_MIN_DURATION_MINUTES = 90;
/** `foreground_dwell`'s minimum apart-time for a 9-hole round. */
export const DWELL_THRESHOLD_9_HOLES_MINUTES = 50;
/** `foreground_dwell`'s minimum apart-time for an 18-hole round. */
export const DWELL_THRESHOLD_18_HOLES_MINUTES = 90;
/** `file_import`'s weight when it matched a route. */
export const FILE_IMPORT_MATCHED_WEIGHT = 0.4;
/** `file_import`'s weight when it did NOT match a route. */
export const FILE_IMPORT_UNMATCHED_WEIGHT = 0.1;

/* ------------------------------------------------------------------ */
/* Attestation grade (G3-08)                                           */
/* ------------------------------------------------------------------ */

export type FixGrade = "attested" | "unattestable" | "failed";

export type TokenState =
  | { present: true; grade: FixGrade }
  | { present: false; hardwareSupportsAttestation: boolean };

/**
 * G3-08's intake-grading rule — rewritten as an ALLOW-LIST (fifth gate,
 * H1): a deny-list version of this exact function (`if (token.present)
 * return token.grade;`) is what let `token:{present:true}` with no
 * `grade`, `grade:"bogus"`, and `present:"false"` (a truthy STRING, not
 * the boolean `false`) all fail OPEN — `if (token.present)` treats any
 * truthy value as "present", and an unchecked `token.grade` passes
 * whatever string (or `undefined`) was given straight through as a
 * `FixGrade`, which every money-path caller then trusts. This function
 * now accepts `token` as fundamentally UNTRUSTED at runtime (never mind
 * what `TokenState` claims at the type level — a caller reaching this
 * directly, or a schema/parser bug upstream, can hand it anything): every
 * boolean is compared with `=== true`/`=== false`, `grade` is allow-listed
 * to exactly `{attested, unattestable}`, and anything else — a malformed
 * shape, `null`, a non-object, an unrecognized grade string, a `present`
 * that is truthy-but-not-`true` — resolves to `"failed"`, never throws.
 */
export function resolveFixGrade(token: TokenState): FixGrade {
  const t: unknown = token;
  if (t !== null && typeof t === "object") {
    const rec = t as Record<string, unknown>;
    if (rec.present === true) {
      return rec.grade === "attested" || rec.grade === "unattestable" ? rec.grade : "failed";
    }
    if (rec.present === false && rec.hardwareSupportsAttestation === false) {
      return "unattestable";
    }
  }
  // Fail closed: `present === false && hardwareSupportsAttestation ===
  // true` (a device that COULD attest but didn't), any other malformed
  // shape, or a non-object entirely.
  return "failed";
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
export function isQualityCoSignalFix(fix: AppFix, playFacilityId: string): boolean {
  // Fifth gate, H1: `fix` is treated as untrusted at runtime — a `null`/
  // non-object reaching here (M4: a malformed `coSignalFix`/`presenceFix`/
  // `fix`) must never throw on the property reads below.
  if (fix === null || typeof fix !== "object") return false;
  return (
    fix.facilityId === playFacilityId &&
    // Every boolean below is an ALLOW-LIST (`=== true`/`=== false`), never
    // truthiness — `simulated: undefined`/`fromApp: "yes"`/`insideBuffer:
    // "true"` (a string) all used to pass a deny-list check (`!x`/bare
    // `x`) and no longer do.
    fix.fromApp === true &&
    fix.simulated === false &&
    fix.foreground === true &&
    // `challenge` is allow-listed to the two REAL challenge kinds — not
    // merely "not none" (which let `challenge: undefined`, or any other
    // non-`"none"` garbage string, through as if it were a real challenge).
    (fix.challenge === "live" || fix.challenge === "prefetched") &&
    finiteInRange(fix.accuracyMeters, 0, ACCURACY_METERS_MAX) &&
    fix.geometryKind === "polygon" &&
    fix.verificationTier === "play-verified" &&
    fix.insideBuffer === true &&
    resolveFixGrade(fix.token) !== "failed"
  );
}

export function windowMs(aMs: number, bMs: number, ms: number): boolean {
  // NaN-safe: Math.abs(NaN) is NaN, and `NaN <= ms` is false, so a NaN
  // timestamp never satisfies a window.
  return Math.abs(aMs - bMs) <= ms;
}

/**
 * Re-gate finding 1/2: staff_presence's ±10 min hard-window, as ONE shared
 * predicate — used identically by `classifyEvidenceRow` (the row's own
 * inline fix) AND `score-play.ts`'s `resolveGroups` (a fix absorbed from
 * elsewhere in the same derived group), so the two can never drift apart
 * the way they did before (the gate that found this duplication was
 * itself evidence of the risk). Requires the fix's OWN date to match
 * `ctx.playLocalDate` — NOT merely that it falls within ±10 min of
 * `scanAt` — because a scan and a fix that are both mis-dated (or a scan
 * whose own `scanAt` epoch happens to be close to a fix on a genuinely
 * different calendar day, e.g. a malformed or adversarial input) must not
 * resolve hard just because the millisecond delta between two absolute
 * timestamps happens to be small.
 */
export function staffFixSatisfiesHardWindow(fix: AppFix, scanAt: number, ctx: ScorePlayContext): boolean {
  return (
    isQualityCoSignalFix(fix, ctx.playFacilityId) &&
    fix.localDate === ctx.playLocalDate &&
    windowMs(fix.capturedAt, scanAt, STAFF_HARD_WINDOW_MS)
  );
}

/** Same idea for `booking`'s same-day-presence hard-window (a whole-day
 * window, not a minute delta — so this needs no `scanAt`-analogue). */
export function bookingFixSatisfiesHardWindow(fix: AppFix, ctx: ScorePlayContext): boolean {
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
   * correlation from the data itself and ignores this field entirely when
   * deciding how rows combine. */
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
      /** Eighth gate, item 1: WHY a `status: "void"` row is void — only
       * meaningful when `status === "void"`, ignored otherwise. `"duplicate"`
       * = intake's own dedup determined this is a re-upload of an
       * already-present receipt (a re-photographed copy, a client retry) —
       * this row is simply IGNORED for fingerprint-group voiding, never
       * poisons the group. `"reviewer"` / `"fraud"` = a human reviewer or a
       * fraud check flagged the CLAIM itself (the booking/payment this
       * fingerprint represents) — either POISONS the whole fingerprint
       * group (`voidDuplicateFingerprints`, `score-play.ts`). Omitted on a
       * void row defaults to `"reviewer"` (fail-safe: an unlabeled void is
       * treated as the MORE cautious case, not the more lenient one). */
      voidReason?: "duplicate" | "reviewer" | "fraud";
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
  /** H3 (fifth gate): the play's own COURSE anchor, for a multi-course
   * (e.g. 36-hole) facility. A row that carries a `courseId` of its own
   * (§4.4's `courseDisambiguatedBy`-adjacent field — set when the source
   * itself is course-specific, e.g. a staff scan at a particular course's
   * booth) contributes NOTHING when that `courseId` disagrees with
   * `playCourseId` — the SAME facility, SAME date, but the OTHER course's
   * evidence must never count for this play. A row with NO `courseId` at
   * all (most sources: booking, receipt, most device-GPS rows — the plan
   * has no course-level granularity for them) stays allowed regardless,
   * exactly as `undefined` means "facility-level, not course-scoped."
   * `undefined` here (the field omitted entirely) disables the check —
   * every row is course-unanchored — for a single-course facility or a
   * caller that hasn't wired course resolution yet. The DB's
   * `play_evidence UNIQUE(evidence_id)` constraint (preventing the SAME
   * evidence row from being attributed to two plays) is a separate,
   * P3a-scope guarantee — this is the money-path-visible half: even
   * absent that DB constraint, a WRONG-course row must never contribute.
   *
   * **Seventh gate, item 8: REQUIRED at the type level, not just the
   * parser's `ScorePlayContextSchema`.** Every REAL caller goes through
   * `scorePlay`'s parser, which has enforced this since H3/H3-residual —
   * the type now says so too, so a caller building a `ScorePlayContext`
   * directly (bypassing the parser — a direct `classifyEvidenceRow` test,
   * the same "tests reach it directly" path this file's own doc
   * describes elsewhere) gets a compile error instead of silently
   * constructing an under-specified context. `courseOk`'s own `undefined`
   * -disables-the-check branch (below) is UNCHANGED — it is now reachable
   * only via an explicit type-system bypass (`as any`/`as
   * ScorePlayContext`), the same category as this module's other
   * defence-in-depth checks (a null token, a malformed fix, …), which all
   * stay safe against a caller that ignores the type contract entirely. */
  playCourseId: string;
  purchases?: PurchaseCorroboration[];
  /** H2 (fifth gate): the play's facility's IANA timezone, used ONLY by
   * `parseScorePlayInput`'s (`../parse-evidence.js`) capturedAt/localDate
   * cross-check — never read by `classifyEvidenceRow`/`scorePlay`
   * themselves, which trust each fix's own pre-validated `localDate`
   * string throughout (this module's own doc: "every date check is
   * anchored to ctx.playLocalDate, never re-derived from an epoch").
   * **Seventh gate, item 8: REQUIRED at the type level** — see
   * `playCourseId`'s own doc just above for why; F1 (sixth gate) already
   * made it required at the parser/schema level, closing the "defaults to
   * UTC" exploit — this closes the matching type-level gap. */
  facilityTz: string;
}

/* ------------------------------------------------------------------ */
/* Weights (§4.5's class table, verbatim)                               */
/* ------------------------------------------------------------------ */

export const WEIGHT: Record<EvidenceClassId, number> = {
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

export const GROUP: Record<EvidenceClassId, EvidenceGroup> = {
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
  // Fifth gate, M4: a `null`/non-object `fix` (a malformed or missing
  // `checkinFix`/`checkoutFix`/`fix`) fails the gate rather than throwing
  // on the property reads below.
  if (fix === null || typeof fix !== "object") return false;
  if (fix.facilityId !== playFacilityId) return false;
  // Re-gate finding 1: the fix's own date must match the play's date — a
  // check-in/dwell fix from another day is not evidence for THIS play,
  // however good its other attributes are.
  if (fix.localDate !== playLocalDate) return false;
  // Should-fix: fail closed on an unverified facility — rewritten as an
  // ALLOW-LIST (fifth gate, H1): only the two REAL verified tiers pass,
  // rather than merely excluding the one known-bad value (`"unverified"`),
  // which let any OTHER garbage `verificationTier` string through.
  if (fix.verificationTier !== "listed-verified" && fix.verificationTier !== "play-verified") return false;
  // Every boolean below is an allow-list (fifth gate, H1).
  if (fix.fromApp !== true) return false;
  if (fix.foreground !== true) return false;
  if (!finiteInRange(fix.accuracyMeters, 0, ACCURACY_METERS_MAX)) return false;
  if (fix.insideBuffer !== true) return false;
  // `challenge` allow-listed to the two real kinds when required — not
  // merely "not none" (`undefined`/a bogus string previously passed).
  if (requireChallenge && fix.challenge !== "live" && fix.challenge !== "prefetched") return false;
  if (resolveFixGrade(fix.token) === "failed") return false;
  return true;
}

/** The `simulated`×0.3 and `unattestable`/no-challenge×0.6 penalties,
 * applied only AFTER `deviceRowFixGateOk` has already passed.
 *
 * Fifth gate, H1: both penalties are now fail-SAFE, not merely fail-open
 * deny-lists. `simulated !== false` (rather than bare `simulated`) means
 * anything that isn't STRICTLY `false` — `undefined`, a truthy string,
 * `true` — is treated as "possibly simulated" and gets the reduction,
 * never the opposite mistake of treating an ambiguous value as "safe."
 * `challenge` is allow-listed to the two real kinds — `challenge:
 * undefined` (H1's own exploit case) no longer skips the penalty by
 * failing to equal the single denied literal `"none"`. */
function deviceFixMultiplier(fix: Pick<AppFix, "simulated" | "token" | "challenge">): number {
  let m = 1;
  if (fix.simulated !== false) m *= SIMULATED_PENALTY_MULTIPLIER;
  const grade = resolveFixGrade(fix.token);
  if (grade === "unattestable" || (fix.challenge !== "live" && fix.challenge !== "prefetched")) m *= UNATTESTABLE_OR_NO_CHALLENGE_PENALTY_MULTIPLIER;
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
 */
function deviceRowMoneyEligible(fix: AppFix): boolean {
  // Fifth gate, H1: strict equality, not truthiness — `simulated:
  // undefined` no longer counts as "not simulated."
  return fix.simulated === false && fix.verificationTier === "play-verified";
}

/** §4.5's radius-fallback cap. */
export const RADIUS_CAP = 0.5;
/** §4.3/A2-01's user-pick cap. Kept as its own named constant even though
 * it currently shares `RADIUS_CAP`'s value — they are conceptually
 * distinct caps, and M5's policy hash (`score-play.ts`) pins them
 * separately so either one drifting is caught on its own. */
export const USER_PICK_CAP = 0.5;
/** M4 (fifth gate) / item 9 (seventh gate): the row-count ceiling
 * `parseScorePlayInput` enforces on rows that survive the loose
 * facility/date/course filter — i.e. rows that actually belong to THIS
 * play (`scorePlay`'s own contract is "one play per call"; see that
 * function's module doc). Raised from 200 (fifth gate) to 1000 (seventh
 * gate, item 9: "apply the 1000-row absolute cap only to rows that pass
 * the loose on-play filter") — 200 was closer to the RAW, unfiltered
 * ceiling's old value than to a real per-play bound, and a legitimately
 * evidence-heavy single play (many corroborating device-GPS rows across a
 * long round) should not be squeezed by the SAME number that also used to
 * bound "how many other plays' rows can ride along before we even start
 * filtering." `parse-evidence.ts`'s `ABSOLUTE_ROW_CAP` (raised in the same
 * gate to 10,000) is now the ONLY cap on the raw, unfiltered array — this
 * one is the real per-play bound. Kept here, beside the other policy
 * constants, so `SCORE_PLAY_POLICY_VERSION`'s hash pin covers it too. */
export const EVIDENCE_ROW_CAP = 1000;
/** M2 (fifth gate): a `foreground_dwell` whose two fixes are more than 12h
 * apart (or, via a signed rather than absolute delta, apart in the WRONG
 * direction — checkout before checkin) is ineligible outright, never
 * merely a large multiplier input. */
export const MAX_DWELL_MINUTES = 12 * 60;
/** `combine`'s (`score-play.ts`) device-GPS noisy-OR subtotal cap. */
export const DEVICE_GPS_SUBTOTAL_CAP = 0.8;
/** `combine`'s overall noisy-OR cap (both pipelines) and the
 * purchase-corroboration combination's own cap (`scorePlay`). */
export const OVERALL_SCORE_CAP = 0.99;
/** `scorePlay`'s purchase-corroboration eligibility floor (badge score). */
export const CORROBORATION_ELIGIBLE_THRESHOLD = 0.5;

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
    w = Math.min(w, RADIUS_CAP);
    money = false;
  }
  if (courseDisambiguatedBy === "user") {
    w = Math.min(w, USER_PICK_CAP);
    money = false;
  }
  return { badgeWeight: w, moneyEligible: money };
}

/** Runtime object-shape guard for an `AppFix`-typed field that may, at
 * runtime, be `null`/non-object despite the type saying otherwise (fifth
 * gate, M4: "a null or undefined token/coSignalFix/fix contributes 0 and
 * never throws"). Deliberately permissive on the fix's OWN internal
 * shape — every field-level check downstream (`isQualityCoSignalFix`,
 * `deviceRowFixGateOk`, `resolveFixGrade`) is itself an allow-list that
 * fails closed on a missing/malformed field, so this only needs to stop a
 * `null`/`undefined`/primitive from reaching a `.property` read. */
function hasFix(x: unknown): x is AppFix {
  return x !== null && x !== undefined && typeof x === "object";
}

/** Every `AppFix` embedded in one evidence row (any source) — shared by
 * `score-play.ts`'s own correlation logic (`fixesOfRow`, re-exported from
 * there under that name for backward compatibility within this package)
 * and `parse-evidence.ts`'s capturedAt/localDate cross-check (H2, fifth
 * gate), so the two enumerations can never drift apart. */
export function fixesOfEvidenceRow(row: Evidence): AppFix[] {
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
  /** Blocking finding 4 (third re-gate): the attestation grade of the
   * SPECIFIC fix that backs this contribution's hard/money status (the
   * staff scan's or booking's winning co-signal, a check-in's own fix, a
   * dwell's worse-of-two-fixes grade, a receipt's co-signal when
   * money-eligible). `undefined` for a class with no single governing fix
   * (vendor, ghin, health_route, connect_iq, file_import, self/
   * health_workout, a `booking_alone`/soft `staff_presence` with no
   * qualifying fix). Used by `computeHeldReview` (`score-play.ts`) —
   * scoped to ONLY the fix(es) that actually established the winning
   * result, never any unrelated fix elsewhere in the same evidence set. */
  governingGrade?: FixGrade;
}

export function finish(
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
    // Blocking finding 3 (second re-gate): `hard` is a MONEY-path signal
    // only (it never affects `score_badge`, which is driven by
    // `badgeWeight` alone) — so a user-picked course, which
    // `applyCourseCaps` already strips of money-eligibility, must ALSO
    // lose its `hard` flag. Leaving `hard: true` here let `hardSignal`
    // bypass the money-eligibility cap entirely (`money = presence &&
    // (hardSignal || score >= MONEY_MIN)`), so a user-picked staff-scan/
    // booking could still reach `money: true` through the `hardSignal`
    // branch even though its OWN contribution was correctly excluded from
    // `score_monetary`.
    hard: fields.hard && capped.moneyEligible,
    moneyEligible: capped.moneyEligible,
    moneyWeight: capped.moneyEligible ? capped.badgeWeight : 0,
  };
}

/**
 * The evidence-class classifier (§4.5's class table). NOT part of
 * `@golfraven/rules`'s public surface (see this module's own doc) —
 * `score-play.ts` imports it under this name for `scorePlay`'s own
 * internal use, and never re-exports the name; tests that need to reach
 * it directly (defence-in-depth unit tests, bypassing `scorePlay`'s
 * top-level filter) import it from `../src/internal/classify.js` — the
 * SAME path `score-play.ts` itself uses, not a re-export.
 *
 * Defence in depth (fourth re-gate, blocking finding 1): every branch
 * below checks the ROW's own `facilityId`/`localDate` against
 * `ctx.playFacilityId`/`ctx.playLocalDate` DIRECTLY (`rowOk`), not merely
 * via whatever facility/date its embedded fix happens to carry — a
 * malformed or adversarial row (wrong facility/date, but an otherwise
 * "clean" embedded fix, e.g. because the fix was copy-pasted from a
 * different, legitimate row) must never classify as if it belonged to
 * this play. `scorePlay`'s own top-level filter (`score-play.ts`) already
 * guarantees `rowOk` for any row reaching this function through it — these
 * checks matter only when this function is called some OTHER way, which is
 * now a real, supported (if narrow) path: direct unit tests.
 */
export function classifyEvidenceRow(row: Evidence, ctx: ScorePlayContext): ScorePlayContribution {
  // H3 (fifth gate): the course anchor — a row that names its OWN
  // `courseId` contributes nothing when it disagrees with
  // `ctx.playCourseId` (a same-facility, same-date, WRONG-course row at a
  // multi-course facility); a row with no `courseId` at all is
  // facility-level and stays allowed regardless (`ctx.playCourseId`
  // undefined disables the check entirely, for a single-course facility).
  const courseOk =
    row.courseId === undefined || ctx.playCourseId === undefined || row.courseId === ctx.playCourseId;
  const rowOk = row.facilityId === ctx.playFacilityId && row.localDate === ctx.playLocalDate && courseOk;
  switch (row.source) {
    case "staff_presence": {
      // §4.5 line 990: "a co-signal within ±10 min", now including the
      // fix's OWN date matching `ctx.playLocalDate` (finding 1/re-gate) —
      // see `staffFixSatisfiesHardWindow`, shared with `resolveGroups`.
      const hasCoSignal =
        rowOk &&
        Number.isFinite(row.scanAt) &&
        hasFix(row.coSignalFix) &&
        staffFixSatisfiesHardWindow(row.coSignalFix, row.scanAt, ctx);
      const classId: EvidenceClassId = hasCoSignal ? "staff_presence_hard" : "staff_presence_soft";
      const badgeWeight = rowOk ? WEIGHT[classId] : 0;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId) && rowOk,
        badgeWeight,
        moneyEligible: hasCoSignal,
        ...(hasCoSignal ? { governingGrade: resolveFixGrade(row.coSignalFix!.token) } : {}),
      });
    }
    case "arccos":
    case "garmin": {
      const isSensorVendor = rowOk && row.vendorCourseMapped && row.sensorProvenance;
      const classId: EvidenceClassId = isSensorVendor ? "vendor_sensor" : "self_posted";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: rowOk ? WEIGHT[classId] : 0,
        moneyEligible: isSensorVendor,
      });
    }
    case "ghin": {
      const classId: EvidenceClassId = "self_posted";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: rowOk ? WEIGHT[classId] : 0,
        moneyEligible: false,
      });
    }
    case "booking": {
      // Finding 4: anchored to `ctx.playLocalDate`, never to `row.localDate`
      // compared against the fix — see `bookingFixSatisfiesHardWindow`,
      // shared with `resolveGroups`.
      const hasPresence = rowOk && hasFix(row.presenceFix) && bookingFixSatisfiesHardWindow(row.presenceFix, ctx);
      const classId: EvidenceClassId = hasPresence ? "booking_hard" : "booking_alone";
      const badgeWeight = rowOk ? WEIGHT[classId] : 0;
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: HARD.has(classId) && rowOk,
        badgeWeight,
        moneyEligible: rowOk, // both booking classes count in score_monetary (line 947) — but only on-date/on-facility
        ...(hasPresence ? { governingGrade: resolveFixGrade(row.presenceFix!.token) } : {}),
      });
    }
    case "receipt_green_fee": {
      const classId: EvidenceClassId = "receipt_green_fee";
      const badgeWeight = rowOk ? (row.status === "approved" ? WEIGHT[classId] : row.status === "pending" ? RECEIPT_PENDING_WEIGHT : 0) : 0;
      // Finding 4: anchored to `ctx.playLocalDate`.
      const moneyEligible =
        rowOk &&
        row.status !== "void" &&
        hasFix(row.coSignalFix) &&
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
      if (!rowOk || !Number.isFinite(row.insideRatio) || row.insideRatio < HEALTH_ROUTE_MIN_INSIDE_RATIO) {
        return finish(row, {
          classId,
          group: GROUP[classId],
          hard: false,
          badgeWeight: 0,
          moneyEligible: false,
        });
      }
      // H1 (fifth gate): `sourceAllowListed`/`simulated` are allow-listed
      // (`=== true`/`!== false`), not deny-listed — an ambiguous value
      // (e.g. `simulated: undefined`) must never be read as "definitely
      // not simulated."
      const base = row.sourceAllowListed !== true ? HEALTH_ROUTE_LOW_WEIGHT : row.insideRatio >= HEALTH_ROUTE_HIGH_INSIDE_RATIO ? HEALTH_ROUTE_HIGH_WEIGHT : HEALTH_ROUTE_MID_WEIGHT;
      const badgeWeight0 = row.simulated !== false ? base * SIMULATED_PENALTY_MULTIPLIER : base;
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
      if (!rowOk) {
        return finish(row, { classId, group: GROUP[classId], hard: false, badgeWeight: 0, moneyEligible: false });
      }
      let badgeWeight: number;
      if (row.variant === "route") {
        // H1 (fifth gate): allow-listed booleans.
        badgeWeight =
          row.k4bPassed === true &&
          row.insidePolygon === true &&
          Number.isFinite(row.durationMinutes) &&
          row.durationMinutes >= CONNECT_IQ_ROUTE_MIN_DURATION_MINUTES
            ? WEIGHT[classId]
            : 0;
      } else {
        badgeWeight = WEIGHT[classId];
      }
      if (row.simulated !== false) badgeWeight *= SIMULATED_PENALTY_MULTIPLIER;
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
      // M4: a null/undefined `checkinFix`/`checkoutFix` (violating the
      // required type at runtime) must not throw on the `.capturedAt`
      // reads below.
      if (!hasFix(row.checkinFix) || !hasFix(row.checkoutFix)) {
        return finish(row, { classId, group: GROUP[classId], hard: false, badgeWeight: 0, moneyEligible: false });
      }
      const threshold = row.holes === 9 ? DWELL_THRESHOLD_9_HOLES_MINUTES : DWELL_THRESHOLD_18_HOLES_MINUTES; // line 1000
      // Should-fix: derive `apartMinutes` from the two fixes' OWN
      // `capturedAt` rather than trusting the stored field — if they
      // disagree, the derived value wins (both are always present on a
      // `foreground_dwell` row, so this is unconditional, not a fallback:
      // a client-computed `apartMinutes` that doesn't match the fixes it
      // was supposedly computed from is exactly the kind of stored-value
      // drift this guards against).
      //
      // M2 (fifth gate): SIGNED, not `Math.abs` — a checkout that comes
      // BEFORE checkin (a negative delta) is a physically impossible/
      // fabricated ordering and must be REJECTED, not silently folded
      // into "apart enough" by the absolute value. Also capped at
      // `MAX_DWELL_MINUTES` (12h): the probe's `capturedAt: Infinity`/
      // `1e300` cases derive an astronomically large (or non-finite)
      // delta that must never be treated as a valid, eligible dwell.
      const derivedApart = (row.checkoutFix.capturedAt - row.checkinFix.capturedAt) / 60_000;
      const durationOk = Number.isFinite(derivedApart) && derivedApart >= threshold && derivedApart <= MAX_DWELL_MINUTES;
      const openOk = deviceRowFixGateOk(row.checkinFix, ctx.playFacilityId, ctx.playLocalDate, true);
      const closeOk = deviceRowFixGateOk(row.checkoutFix, ctx.playFacilityId, ctx.playLocalDate, true);
      if (!rowOk || !durationOk || !openOk || !closeOk) {
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
        MONEY_ELIGIBLE_BASE.has(classId) &&
        deviceRowMoneyEligible(row.checkinFix) &&
        deviceRowMoneyEligible(row.checkoutFix);
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
      const group: EvidenceGroup = row.matchedRoute ? "device-gps" : "self";
      if (!rowOk) {
        return finish(row, { classId, group, hard: false, badgeWeight: 0, moneyEligible: false });
      }
      const badgeWeight0 = row.matchedRoute ? FILE_IMPORT_MATCHED_WEIGHT : FILE_IMPORT_UNMATCHED_WEIGHT;
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
      // M4: `deviceRowFixGateOk` already fails closed on a null/undefined
      // `row.fix` (violating the required type at runtime) — `hasFix` here
      // is belt-and-suspenders so the intent reads the same as every other
      // branch's guard.
      const gateOk = rowOk && hasFix(row.fix) && deviceRowFixGateOk(row.fix, ctx.playFacilityId, ctx.playLocalDate, false);
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
        badgeWeight: rowOk ? WEIGHT[classId] : 0,
        moneyEligible: false,
      });
    }
    case "self_report": {
      const classId: EvidenceClassId = "self_report";
      return finish(row, {
        classId,
        group: GROUP[classId],
        hard: false,
        badgeWeight: rowOk ? WEIGHT[classId] : 0,
        moneyEligible: false,
      });
    }
    default: {
      // M4 (fifth gate): defence in depth. `Evidence["source"]` is a
      // closed, exhaustive union at the type level — this branch is
      // unreachable through any well-typed caller (`row` narrows to
      // `never` here) — but `parseScorePlayInput`/`parseEvidence`
      // (`../parse-evidence.js`) are meant to reject an unrecognized
      // `source` LONG before it ever reaches this function; this is the
      // second, independent layer for the case those are bypassed
      // entirely (a direct `classifyEvidenceRow` call — the same "tests
      // reach it directly" path this module's own doc describes — or a
      // future schema/version drift). An unknown source contributes
      // NOTHING and, critically, never throws.
      const raw = row as unknown as { id?: unknown };
      return {
        evidenceId: typeof raw.id === "string" ? raw.id : "unknown",
        classId: "self_report",
        group: "self",
        hard: false,
        badgeWeight: 0,
        moneyEligible: false,
        moneyWeight: 0,
      };
    }
  }
}
