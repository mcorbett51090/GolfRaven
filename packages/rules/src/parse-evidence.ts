/**
 * `parseEvidence` / `parseScorePlayInput` — the fifth gate's H2 finding:
 * "There is no input validator." Every field `scorePlay` (`score-play.ts`)
 * or `classifyEvidenceRow` (`internal/classify.ts`) reads is, before this
 * module existed, an UNCHECKED cast from whatever the caller passed in —
 * strict shape, enum membership, finiteness and non-empty-string invariants
 * were only ever enforced (if at all) ad hoc, deep inside the scoring logic
 * itself, and several were not enforced at all (H1's own deny-list findings
 * are downstream consequences of this). This module is the FIRST gate:
 * `scorePlay` runs it before anything else (`score-play.ts`'s own doc), and
 * a parse failure returns a fail-closed `{money: false, reasons: [...]}}`
 * result rather than ever reaching the scoring logic with untrusted data —
 * see that file's module doc for the full TRUST TABLE this closes out.
 *
 * Every object schema below is `z.strictObject` (rejects an unrecognized
 * extra key outright, rather than silently ignoring it) and every enum is
 * an allow-list (`z.enum`/`z.literal`), mirroring `@golfraven/catalog`'s own
 * schema conventions (`schema.ts`) so a reader familiar with one recognizes
 * the other.
 */
import { z } from "zod";
import {
  EVIDENCE_ROW_CAP,
  fixesOfEvidenceRow,
  type Evidence,
  type ScorePlayContext,
} from "./internal/classify.js";

/* ------------------------------------------------------------------ */
/* Shared leaf schemas                                                  */
/* ------------------------------------------------------------------ */

const LOCAL_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/** F6 (sixth gate): "localDate must be a real calendar date... so
 * '2026-02-31' is rejected." `Date.UTC`'s own round-trip (construct from
 * the components, read them back) is what catches this — `Date.parse`/
 * `new Date(...)` silently ROLL an invalid date over instead of rejecting
 * it (`2026-02-31` parses cleanly as March 3rd) — same technique as
 * `@golfraven/import`'s `timestamps.ts#isRealCalendarDate`, duplicated
 * here for the same "stay scoped to packages/rules" reason as
 * `localDateForTz` below. */
function isRealCalendarDate(year: number, month: number, day: number): boolean {
  const dt = new Date(Date.UTC(year, month - 1, day));
  return dt.getUTCFullYear() === year && dt.getUTCMonth() === month - 1 && dt.getUTCDate() === day;
}

const LocalDateSchema = z
  .string()
  .regex(LOCAL_DATE_RE, "must be a YYYY-MM-DD calendar date")
  .refine(
    (s) => {
      const [y, m, d] = s.split("-").map(Number);
      return isRealCalendarDate(y!, m!, d!);
    },
    { message: "must be a REAL calendar date (e.g. not 2026-02-31)" },
  );

/** M1 (fifth gate): `fixId`/`paymentRef` "must be non-empty strings; reject
 * objects and other shapes." `z.string().min(1)` does both — Zod's
 * `z.string()` already rejects any non-string type (an object, a number, an
 * array), and `.min(1)` rejects the empty string. */
const NonEmptyStringSchema = z.string().min(1);

const ChallengeKindSchema = z.enum(["live", "prefetched", "none"]);
const GeometryKindSchema = z.enum(["polygon", "radius"]);
const VerificationTierSchema = z.enum(["unverified", "listed-verified", "play-verified"]);
const CourseDisambiguatedBySchema = z.enum(["geometry", "staff", "user"]);

/** `FixGrade`'s three literals are all accepted here (H1's own resolution
 * treats `"failed"` as the correct catch-all for anything ELSE — this
 * schema's job is only to reject something that isn't even one of the
 * three known strings; `resolveFixGrade` still separately treats a
 * malformed/absent `grade` under `present: true` as `"failed"`, as defence
 * in depth for a caller that bypasses this parser entirely). */
const TokenStateSchema = z.union([
  z.strictObject({ present: z.literal(true), grade: z.enum(["attested", "unattestable", "failed"]) }),
  z.strictObject({ present: z.literal(false), hardwareSupportsAttestation: z.boolean() }),
]);

const AppFixSchema = z.strictObject({
  fixId: NonEmptyStringSchema,
  facilityId: NonEmptyStringSchema,
  fromApp: z.boolean(),
  simulated: z.boolean(),
  foreground: z.boolean(),
  challenge: ChallengeKindSchema,
  token: TokenStateSchema,
  verificationTier: VerificationTierSchema,
  geometryKind: GeometryKindSchema,
  insideBuffer: z.boolean(),
  // M2 (fifth gate): `Number.isFinite` on every timestamp/measurement —
  // `.finite()` rejects `Infinity`/`-Infinity`/`NaN` (zod's bare
  // `z.number()` accepts `Infinity`, since it IS a JS `number`).
  accuracyMeters: z.number().finite(),
  capturedAt: z.number().finite(),
  localDate: LocalDateSchema,
});

const EvidenceCommonShape = {
  id: NonEmptyStringSchema,
  facilityId: NonEmptyStringSchema,
  courseId: NonEmptyStringSchema.optional(),
  localDate: LocalDateSchema,
  courseDisambiguatedBy: CourseDisambiguatedBySchema.optional(),
  correlationId: z.string().optional(),
};

/* ------------------------------------------------------------------ */
/* The Evidence discriminated union — mirrors internal/classify.ts's own  */
/* Evidence type EXACTLY, field for field, so a structurally-valid typed  */
/* caller never trips this parser.                                       */
/* ------------------------------------------------------------------ */

const EvidenceSchema = z.discriminatedUnion("source", [
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("staff_presence"),
    scanAt: z.number().finite(),
    coSignalFix: AppFixSchema.optional(),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("arccos"),
    vendorCourseMapped: z.boolean(),
    sensorProvenance: z.boolean(),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("garmin"),
    vendorCourseMapped: z.boolean(),
    sensorProvenance: z.boolean(),
  }),
  z.strictObject({ ...EvidenceCommonShape, source: z.literal("ghin") }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("booking"),
    presenceFix: AppFixSchema.optional(),
    paymentRef: NonEmptyStringSchema.optional(),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("receipt_green_fee"),
    status: z.enum(["approved", "pending", "void"]),
    coSignalFix: AppFixSchema.optional(),
    paymentRef: NonEmptyStringSchema.optional(),
    fingerprint: z.string().optional(),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("health_route"),
    sourceAllowListed: z.boolean(),
    insideRatio: z.number().finite(),
    simulated: z.boolean(),
    geometryKind: GeometryKindSchema,
    startedAt: z.number().finite().optional(),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("connect_iq"),
    variant: z.enum(["route", "checkin"]),
    k4bPassed: z.boolean(),
    insidePolygon: z.boolean(),
    durationMinutes: z.number().finite(),
    simulated: z.boolean(),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("foreground_dwell"),
    checkinFix: AppFixSchema,
    checkoutFix: AppFixSchema,
    apartMinutes: z.number().finite(),
    holes: z.union([z.literal(9), z.literal(18)]),
  }),
  z.strictObject({
    ...EvidenceCommonShape,
    source: z.literal("file_import"),
    matchedRoute: z.boolean(),
    geometryKind: GeometryKindSchema.optional(),
    startedAt: z.number().finite().optional(),
  }),
  z.strictObject({ ...EvidenceCommonShape, source: z.literal("foreground_checkin"), fix: AppFixSchema }),
  z.strictObject({ ...EvidenceCommonShape, source: z.literal("health_workout") }),
  z.strictObject({ ...EvidenceCommonShape, source: z.literal("self_report") }),
]);

const PurchaseCorroborationSchema = z.strictObject({
  facilityId: NonEmptyStringSchema,
  localDate: LocalDateSchema,
});

const ScorePlayContextSchema = z.strictObject({
  playFacilityId: NonEmptyStringSchema,
  playLocalDate: LocalDateSchema,
  playCourseId: NonEmptyStringSchema.optional(),
  purchases: z.array(PurchaseCorroborationSchema).optional(),
  facilityTz: NonEmptyStringSchema.optional(),
});

/* ------------------------------------------------------------------ */
/* H2's localDate/capturedAt cross-check                                */
/* ------------------------------------------------------------------ */

/** Converts an epoch-millisecond instant into an IANA timezone's local
 * calendar date. Mirrors `@golfraven/import`'s `timestamps.ts#localDateForTz`
 * (same `Intl.DateTimeFormat("en-CA", ...)` trick — that locale formats as
 * `YYYY-MM-DD` directly) — duplicated here in ~10 lines rather than taken as
 * a cross-package dependency, since this task's own rules keep changes
 * scoped to `packages/rules`. */
function localDateForTz(ms: number, tz: string): string | undefined {
  try {
    const formatted = new Intl.DateTimeFormat("en-CA", {
      timeZone: tz,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
    }).format(new Date(ms));
    return LOCAL_DATE_RE.test(formatted) ? formatted : undefined;
  } catch {
    return undefined;
  }
}

/** H2's third bullet: "Cross-check `localDate` against `capturedAt` in the
 * facility tz... Reject a mismatch." Applied to EVERY `AppFix` embedded in
 * a row (`fixesOfEvidenceRow`), not merely a top-level field — the probe
 * case is a `coSignalFix.capturedAt` three days after its own
 * `coSignalFix.localDate`. `tz` defaults to `"UTC"` when the caller's `ctx`
 * doesn't carry one (`ScorePlayContext.facilityTz`'s own doc). */
function tzCrossCheckIssues(row: Evidence, tz: string): string[] {
  const issues: string[] = [];
  for (const fix of fixesOfEvidenceRow(row)) {
    const derived = localDateForTz(fix.capturedAt, tz);
    if (derived === undefined) {
      issues.push(`fix ${fix.fixId}: facilityTz "${tz}" is not a timezone Intl recognizes`);
    } else if (derived !== fix.localDate) {
      issues.push(
        `fix ${fix.fixId}: capturedAt resolves to ${derived} in tz "${tz}", but localDate says ${fix.localDate}`,
      );
    }
  }
  return issues;
}

/* ------------------------------------------------------------------ */
/* Public API                                                           */
/* ------------------------------------------------------------------ */

export interface EvidenceParseSuccess {
  success: true;
  data: Evidence;
}
export interface EvidenceParseFailure {
  success: false;
  reasons: string[];
}
export type EvidenceParseResult = EvidenceParseSuccess | EvidenceParseFailure;

function zodIssuesToReasons(issues: readonly { path: PropertyKey[]; message: string }[]): string[] {
  return issues.map((i) => `${i.path.length > 0 ? i.path.join(".") : "(root)"}: ${i.message}`);
}

/**
 * Parses ONE not-yet-typed `app.evidence` row. `tz` (the facility's IANA
 * timezone, `ScorePlayContext.facilityTz`) is optional and defaults to
 * `"UTC"` — pass it to also run H2's capturedAt/localDate cross-check;
 * omit it only when the caller genuinely has no timezone context (the
 * cross-check still runs, against UTC, since skipping it silently would
 * defeat the point).
 */
export function parseEvidence(raw: unknown, tz = "UTC"): EvidenceParseResult {
  const parsed = EvidenceSchema.safeParse(raw);
  if (!parsed.success) {
    return { success: false, reasons: zodIssuesToReasons(parsed.error.issues) };
  }
  const row = parsed.data as Evidence;
  const tzIssues = tzCrossCheckIssues(row, tz);
  if (tzIssues.length > 0) {
    return { success: false, reasons: tzIssues };
  }
  return { success: true, data: row };
}

export interface ScorePlayInputParseSuccess {
  success: true;
  evidence: Evidence[];
  ctx: ScorePlayContext;
}
export interface ScorePlayInputParseFailure {
  success: false;
  reasons: string[];
}
export type ScorePlayInputParseResult = ScorePlayInputParseSuccess | ScorePlayInputParseFailure;

/**
 * Parses `scorePlay`'s whole raw input — `{evidence, ctx}` — as ONE call:
 * the `ctx` shape (H3's `playCourseId`, H2's `facilityTz`, …), the
 * `evidence` array's own row cap (M4: 200 rows), and every row via
 * `parseEvidence` (including the tz cross-check, using `ctx.facilityTz`).
 * `scorePlay` (`score-play.ts`) calls this FIRST, always — see that
 * module's doc.
 */
export function parseScorePlayInput(raw: unknown): ScorePlayInputParseResult {
  if (raw === null || typeof raw !== "object") {
    return { success: false, reasons: ["input must be an object shaped { evidence, ctx }"] };
  }
  const { evidence, ctx } = raw as { evidence?: unknown; ctx?: unknown };

  const ctxParsed = ScorePlayContextSchema.safeParse(ctx);
  if (!ctxParsed.success) {
    return { success: false, reasons: zodIssuesToReasons(ctxParsed.error.issues).map((r) => `ctx.${r}`) };
  }
  const parsedCtx = ctxParsed.data as ScorePlayContext;

  if (!Array.isArray(evidence)) {
    return { success: false, reasons: ["evidence must be an array"] };
  }
  // M4: the row cap is checked BEFORE any per-row parsing — a >200-row
  // payload is rejected outright, never partially processed (the whole
  // point of a DoS cap is to bound the work done on an oversized input).
  if (evidence.length > EVIDENCE_ROW_CAP) {
    return {
      success: false,
      reasons: [`evidence has ${evidence.length} rows, exceeding the ${EVIDENCE_ROW_CAP}-row cap`],
    };
  }

  const tz = parsedCtx.facilityTz ?? "UTC";
  const reasons: string[] = [];
  const parsedEvidence: Evidence[] = [];
  evidence.forEach((rawRow, i) => {
    const result = parseEvidence(rawRow, tz);
    if (result.success) {
      parsedEvidence.push(result.data);
    } else {
      reasons.push(...result.reasons.map((r) => `evidence[${i}]: ${r}`));
    }
  });
  if (reasons.length > 0) return { success: false, reasons };
  return { success: true, evidence: parsedEvidence, ctx: parsedCtx };
}
