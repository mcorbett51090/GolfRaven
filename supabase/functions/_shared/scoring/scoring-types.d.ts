// supabase/functions/_shared/scoring/scoring-types.d.ts
//
// Hand-maintained type surface for scoring/vendor/score-play.js (the
// vendored copy of packages/rules/dist/score-play.js — see
// generate-bundle.sh's own header). NOT auto-generated: the vendored .js
// files have no matching .d.ts of their own (packages/rules/dist DOES
// ship one, but referencing it here would itself be a lint-scanned
// import reaching outside supabase/functions — the same reason
// generate-bundle.sh vendors the .js in the first place). This is
// therefore a DELIBERATE, minimal, hand-written mirror of exactly the
// public surface supabase/functions/_shared/evidence/handler.ts needs
// from packages/rules/src/score-play.ts / parse-evidence.ts — kept
// narrow on purpose so there is less to drift. A mismatch here shows up
// immediately as a `deno check`/`tsc` type error in handler.ts (or a
// test failure), never silently: this is a type-only declaration, erased
// at runtime, so it cannot itself misbehave — only mis-describe.

export type ChallengeKind = "live" | "prefetched" | "none";
export type GeometryKind = "polygon" | "radius";
export type VerificationTier = "unverified" | "listed-verified" | "play-verified";
export type CourseDisambiguatedBy = "geometry" | "staff" | "user";
export type FixGrade = "attested" | "unattestable" | "failed";

export interface ScorePlayContext {
  playFacilityId: string;
  playLocalDate: string;
  playCourseId: string;
  facilityTz: string;
  purchases?: { facilityId: string; localDate: string }[];
}

export interface ScorePlayContribution {
  evidenceId: string;
  classId: string;
  group: string;
  hard: boolean;
  badgeWeight: number;
  moneyEligible: boolean;
  governingGrade?: FixGrade;
  moneyWeight?: number;
}

export interface ExcludedRow {
  index: number;
  kind: "off_play" | "quarantined" | string;
  reasons: string[];
}

export interface ScorePlayResult {
  score_badge: number;
  score_monetary: number;
  presence_signal: boolean;
  money: boolean;
  heldReview: boolean;
  heldReviewReasons: string[];
  policyVersion: number;
  contributions: ScorePlayContribution[];
  inputDigest: string;
  excludedRows: ExcludedRow[];
}

export type ScorePlaySuccess = { ok: true } & ScorePlayResult;
export interface ScorePlayFailure {
  ok: false;
  reasons: string[];
}
export type ScorePlayOutcome = ScorePlaySuccess | ScorePlayFailure;

export interface EvidenceParseSuccess {
  ok: true;
  value: unknown;
}
export interface EvidenceParseFailure {
  ok: false;
  reasons: string[];
}
export type EvidenceParseResult = EvidenceParseSuccess | EvidenceParseFailure;

export interface ScorePlayInputParseSuccess {
  ok: true;
  evidence: unknown[];
  ctx: ScorePlayContext;
  excludedRows: ExcludedRow[];
}
export interface ScorePlayInputParseFailure {
  ok: false;
  reasons: string[];
}
export type ScorePlayInputParseResult = ScorePlayInputParseSuccess | ScorePlayInputParseFailure;

/** `evidenceIn`'s element shape mirrors packages/rules' own discriminated
 * `Evidence` union (parse-evidence.ts) field-for-field — kept as
 * `Record<string, unknown>[]` here (rather than re-declaring all ~13
 * source-specific shapes) since this vendored copy's own runtime parser
 * (parseScorePlayInput, invoked first inside scorePlay) is what actually
 * enforces the shape; this declaration only needs to be accurate enough
 * that handler.ts's caller-side construction type-checks sensibly. */
export function scorePlay(evidenceIn: Record<string, unknown>[], ctx: ScorePlayContext): ScorePlayOutcome;
export function parseScorePlayInput(raw: unknown): ScorePlayInputParseResult;
export function parseEvidence(raw: unknown, tz: string): EvidenceParseResult;

export const MONEY_MIN: number;
export const SCORE_PLAY_POLICY_VERSION: number;
export const ROUND_CORRELATION_WINDOW_MS: number;
export const CORROBORATION_WINDOW_DAYS: number;
export const ABSOLUTE_ROW_CAP: number;
