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
import { canonicalizeTimeZone, isValidIanaTimeZoneName } from "@golfraven/catalog";
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

/** Seventh gate, item 1 (HIGH — a correctness regression in the sixth
 * gate's own fix): `Intl.supportedValuesOf('timeZone')` was WRONG for
 * this job — it returns CLDR's canonical-id list, which excludes several
 * genuine, still-current IANA names it merely prefers an alias for
 * (`America/Indiana/Indianapolis`, `America/Kentucky/Louisville`,
 * `America/Argentina/Buenos_Aires`, `Europe/Kyiv`, `America/Nuuk`) — so
 * every play at a facility in one of THOSE zones failed outright, even
 * though `@golfraven/catalog`'s own `tz-lookup`-derived value (this
 * package's actual server-side source of `facilityTz`) can BE
 * `America/Indiana/Indianapolis`. `packages/catalog/src/common.ts:62-74`
 * already worked this out (`isValidIanaTimeZoneName`'s own doc: "that API
 * is a fairly recent addition... and its populated list is an ICU
 * implementation detail that can vary... a name it doesn't happen to
 * enumerate could be wrongly rejected") — this reuses that exact
 * function, imported from `@golfraven/catalog` (an existing dependency;
 * no import cycle — `@golfraven/catalog` does not depend on
 * `@golfraven/rules`).
 *
 * `isValidIanaTimeZoneName` alone is not enough, though: `Intl` in this
 * environment is FAR more permissive than "is this a real zone" — `new
 * Intl.DateTimeFormat('en-US', {timeZone: tz})` does NOT throw for
 * `"-07:00"` (a literal fixed offset), `"EST"` (resolves to
 * `America/Panama` — numerically correct, semantically the wrong zone),
 * `"US/Pacific"`/`"Canada/Eastern"` (legacy Area-prefix links) or
 * `"PST8PDT"` (a POSIX-style zone spec) — confirmed directly, `node -e`,
 * against this exact runtime, not assumed. `hasAreaLocationShape` below
 * is the SECOND, independent gate this fix adds: a genuine canonical IANA
 * name is always `Area/Location[/Location...]`, each segment built from
 * letters/underscores/hyphens ONLY, with at least one segment containing
 * an uppercase letter (rules out an all-lowercase `"america/los_angeles"`
 * — canonical names are capitalized) — and the Area itself is never one
 * of the three DENIED legacy-link prefixes this gate names (`Etc`, `US`,
 * `Canada`). BOTH gates must pass. */
const AREA_LOCATION_SEGMENT_RE = /^[A-Za-z_]+(?:-[A-Za-z_]+)*$/;
const DENIED_TZ_AREA_PREFIXES = new Set(["Etc", "US", "Canada"]);

function hasAreaLocationShape(tz: string): boolean {
  const segments = tz.split("/");
  if (segments.length < 2) return false; // must be Area/Location — at least one "/"
  for (const segment of segments) {
    if (segment.length === 0) return false;
    if (!AREA_LOCATION_SEGMENT_RE.test(segment)) return false;
    if (!/[A-Z]/.test(segment)) return false; // rejects an all-lowercase segment
  }
  return !DENIED_TZ_AREA_PREFIXES.has(segments[0]!);
}

/** Never throws — not even when `Intl` itself is missing entirely (item
 * 1's own requirement, and the probe's `NO-INTL` case): `isValidIanaTimeZoneName`
 * already try/catches its own `Intl` reference internally, and this
 * wraps the call again anyway, as defence in depth, so a caller can never
 * observe an uncaught exception out of this function regardless of what
 * changes inside it later. */
function isValidFacilityTimeZone(tz: string): boolean {
  try {
    return hasAreaLocationShape(tz) && isValidIanaTimeZoneName(tz);
  } catch {
    return false;
  }
}

/** Canonicalizes an accepted tz through the catalog's vendored tzdb
 * backward-links table (item 1: "canonicalise using the catalog's
 * vendored tzdb-backward-links.json... importable without a cycle" — it
 * is; see the import above) — e.g. a legacy alias some upstream step
 * still emits resolves to its modern canonical name before this value is
 * used further or stored back into the parsed `ctx`/`inputDigest`. Falls
 * back to the ORIGINAL string (never throws) if canonicalization itself
 * somehow fails — a canonicalization failure is not evidence the ALREADY
 * -validated tz is invalid. */
function canonicalizeFacilityTimeZone(tz: string): string {
  try {
    return canonicalizeTimeZone(tz);
  } catch {
    return tz;
  }
}

const FacilityTzSchema = NonEmptyStringSchema.refine(isValidFacilityTimeZone, {
  message:
    "must be a real IANA Area/Location timezone name (not a fixed offset, abbreviation, or Etc/US/Canada-style legacy link)",
}).transform(canonicalizeFacilityTimeZone);

const ScorePlayContextSchema = z.strictObject({
  playFacilityId: NonEmptyStringSchema,
  playLocalDate: LocalDateSchema,
  // H3 residual (sixth gate): REQUIRED — see this schema's own callers
  // for the "a row without its own courseId is facility-level and stays
  // allowed" rule this does NOT disable (`internal/classify.ts`'s
  // `courseOk`).
  playCourseId: NonEmptyStringSchema,
  purchases: z.array(PurchaseCorroborationSchema).optional(),
  facilityTz: FacilityTzSchema,
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
 * `coSignalFix.localDate`. `tz` is `ctx.facilityTz` (F1, sixth gate: now
 * REQUIRED, no silent UTC default — see `ScorePlayContextSchema`'s own
 * doc for the exploit that closed). */
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
 * timezone, `ScorePlayContext.facilityTz`) is now REQUIRED (F1, sixth
 * gate) — there is no default, silent or otherwise; `parseScorePlayInput`
 * always supplies its already-validated `ctx.facilityTz`, and a caller
 * using `parseEvidence` standalone must supply a real one too. `tz` is
 * re-validated here (not just trusted from the caller) so this function is
 * safe even when called directly, bypassing `parseScorePlayInput`'s own
 * `ScorePlayContextSchema` check.
 */
export function parseEvidence(raw: unknown, tz: string): EvidenceParseResult {
  if (!isValidFacilityTimeZone(tz)) {
    return { success: false, reasons: [`facilityTz "${tz}" is not a real IANA Area/Location timezone name`] };
  }
  const canonicalTz = canonicalizeFacilityTimeZone(tz);
  const parsed = EvidenceSchema.safeParse(raw);
  if (!parsed.success) {
    return { success: false, reasons: zodIssuesToReasons(parsed.error.issues) };
  }
  const row = parsed.data as Evidence;
  const tzIssues = tzCrossCheckIssues(row, canonicalTz);
  if (tzIssues.length > 0) {
    return { success: false, reasons: tzIssues };
  }
  return { success: true, data: row };
}

/** F3 (sixth gate): one row that didn't make it into the scored evidence
 * set — either because it plainly belongs to a DIFFERENT play (facility/
 * date/course mismatch: not malformed, just not this play's evidence), or
 * because it matched this play's facility/date/course but then failed the
 * strict per-row parse (genuinely malformed). Either way it is EXCLUDED
 * from scoring, never counted, and never fails the whole play by itself —
 * `index` is its position in the ORIGINAL, unfiltered `evidence` array, so
 * a caller can find it again. */
export interface ExcludedRow {
  index: number;
  reasons: string[];
}

export interface ScorePlayInputParseSuccess {
  success: true;
  evidence: Evidence[];
  ctx: ScorePlayContext;
  /** Every row that did not make it into `evidence` above — off-play rows
   * and quarantined (malformed but on-play) rows alike. Empty when every
   * raw row either matched and parsed cleanly. */
  excludedRows: ExcludedRow[];
}
export interface ScorePlayInputParseFailure {
  success: false;
  reasons: string[];
}
export type ScorePlayInputParseResult = ScorePlayInputParseSuccess | ScorePlayInputParseFailure;

/** F3: the ABSOLUTE ceiling on the RAW `evidence` array length, checked
 * BEFORE any filtering — a pure DoS guard, independent of how many rows
 * actually belong to this play (a real `app.evidence` query can
 * legitimately return many OTHER plays' rows alongside this one's; this
 * cap exists only to bound the work done reading the raw array at all). */
export const ABSOLUTE_ROW_CAP = 1000;

/** F3: a LOOSE, tolerant read of a not-yet-validated row's `facilityId`/
 * `localDate`/`courseId` — deliberately NOT the strict `EvidenceSchema`.
 * This is what decides whether a row is even a CANDIDATE for this play
 * (and therefore eligible for quarantine-on-malformed, rather than being
 * silently excluded as someone else's evidence) — H3's residual rule
 * applies here too: a row with no `courseId` at all is facility-level and
 * always a candidate; a row whose `courseId` disagrees with
 * `ctx.playCourseId` is not. */
function looseRowMatchesPlay(raw: unknown, ctx: ScorePlayContext): boolean {
  if (raw === null || typeof raw !== "object") return false;
  const r = raw as Record<string, unknown>;
  if (r.facilityId !== ctx.playFacilityId) return false;
  if (r.localDate !== ctx.playLocalDate) return false;
  if (r.courseId !== undefined && r.courseId !== ctx.playCourseId) return false;
  return true;
}

/**
 * Parses `scorePlay`'s whole raw input — `{evidence, ctx}`.
 *
 * **F3 (sixth gate): one bad row no longer fails the whole play.** The
 * `ctx` shape, a non-array `evidence`, and the `evidence` array's own row
 * counts are STRUCTURAL problems — those still fail the whole input
 * (`success: false`), because there is no sound "which play is this for"
 * to even filter against. Once `ctx` is valid, every raw row is first
 * LOOSELY matched against `ctx.playFacilityId`/`playLocalDate`/
 * `playCourseId` (`looseRowMatchesPlay`) — a row that plainly belongs to a
 * DIFFERENT play is simply excluded, not an error. Only THEN does a
 * matching row go through the full strict `parseEvidence` — if THAT
 * fails, the row is QUARANTINED (excluded, with a reason) rather than
 * failing the whole play: a single malformed row for this play must not
 * zero out every OTHER, perfectly good row alongside it.
 *
 * Two independent row-count caps, checked in order: `ABSOLUTE_ROW_CAP`
 * (1000) bounds the RAW array before any filtering (pure DoS guard);
 * `EVIDENCE_ROW_CAP` (200, M4) bounds the count of rows that survived the
 * LOOSE filter — i.e. rows that actually belong to this play — so a table
 * scan returning many other plays' rows can never fail this one on count
 * alone.
 *
 * `scorePlay` (`score-play.ts`) calls this FIRST, always — see that
 * module's doc for the TRUST TABLE.
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
  if (evidence.length > ABSOLUTE_ROW_CAP) {
    return {
      success: false,
      reasons: [`evidence has ${evidence.length} raw rows, exceeding the absolute ${ABSOLUTE_ROW_CAP}-row DoS cap`],
    };
  }

  const excludedRows: ExcludedRow[] = [];
  const matchingIndices: number[] = [];
  evidence.forEach((rawRow, i) => {
    if (looseRowMatchesPlay(rawRow, parsedCtx)) {
      matchingIndices.push(i);
    } else {
      excludedRows.push({ index: i, reasons: ["different facility, date, or course than this play"] });
    }
  });

  // M4 / F3: the 200-row cap counts only rows that survived the loose
  // facility/date/course filter — a genuinely oversized evidence set FOR
  // THIS PLAY is still a structural failure (the whole point of the cap:
  // bound the classification/combination work below), but noise from
  // OTHER plays never counts against it.
  if (matchingIndices.length > EVIDENCE_ROW_CAP) {
    return {
      success: false,
      reasons: [
        `${matchingIndices.length} rows match this play's facility/date/course, exceeding the ${EVIDENCE_ROW_CAP}-row cap`,
      ],
    };
  }

  const tz: string = ctxParsed.data.facilityTz;
  const parsedEvidence: Evidence[] = [];
  for (const i of matchingIndices) {
    const result = parseEvidence(evidence[i], tz);
    if (result.success) {
      parsedEvidence.push(result.data);
    } else {
      // F3: QUARANTINED, not a whole-input failure — this row matched the
      // play's own facility/date/course but failed strict validation for
      // some other reason (bad shape, tz-cross-check mismatch, …).
      excludedRows.push({ index: i, reasons: result.reasons });
    }
  }

  // Seventh gate, item 4: duplicate evidence `id`s are a STRUCTURAL
  // problem, not a per-row quarantine — two rows sharing the same `id`
  // would silently confuse BOTH `voidDuplicateFingerprints`'s winner
  // lookup (F2, `score-play.ts`: `row.id === winnerId` could match either
  // copy) AND `computeInputDigest`'s sort-by-id (F4: a tied `id` falls
  // back to original array order, reintroducing exactly the
  // order-dependence F4 closed). Checked over `parsedEvidence` — a row
  // that shared an id but was ITSELF quarantined for some other reason
  // never reaches this array, so it can't spuriously trip this check;
  // only a genuine duplicate among rows that would otherwise BOTH score
  // does.
  const idCounts = new Map<string, number>();
  for (const row of parsedEvidence) idCounts.set(row.id, (idCounts.get(row.id) ?? 0) + 1);
  const duplicateIds = [...idCounts.entries()].filter(([, count]) => count > 1).map(([id]) => id);
  if (duplicateIds.length > 0) {
    return {
      success: false,
      reasons: [`duplicate evidence id(s) within this play's evidence: ${duplicateIds.map((id) => safeQuote(id)).join(", ")}`],
    };
  }

  return { success: true, evidence: parsedEvidence, ctx: parsedCtx, excludedRows };
}
