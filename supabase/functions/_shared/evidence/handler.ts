// supabase/functions/_shared/evidence/handler.ts
//
// The pure, dependency-injected core of POST /v1/evidence and POST
// /v1/evidence/batch (build plan P3/§10 AT 3, AT 8, AT 15; docs/security/
// p3-money-path-requirements.md). Every I/O dependency comes through
// `Repo` (types.ts) or the small extra functions below, so this is
// unit-testable (supabase/tests/unit/evidence-handler.test.ts) with a
// fake in-memory Repo, and now ALSO integration-tested for real
// (supabase/tests/integration/*.deno.test.ts) against the real
// `privileged.ts` and a real Postgres cluster — the P3c gate round 2's
// own item 0.
//
// P3c gate round 2 (dbe1aaa) fixes, file:line pointers in the report:
//   1. Day-2 evidence: `Repo#evidence.listForPlay` now filters on a REAL
//      `local_date` column (privileged.ts + 0019's own ALTER), capped at
//      ABSOLUTE_ROW_CAP; only CONTRIBUTING evidence ids get linked to the
//      play (`contributedEvidenceIds` below), never every candidate row.
//   2. Transactions: entirely `privileged.ts#withOwnership`'s concern now
//      — this file no longer knows or cares that it runs inside one.
//      Facility/course existence is asserted via a REAL catalog row
//      (`assertRealCatalogRow` below), not merely a ledger entry.
//   3. Forged facility/course pairing: `assertCourseBelongsToFacility`.
//   4. Challenge window/device/single-use-per-fix:
//      `Repo#checkinToken.consumeForFix` (privileged.ts) — one atomic
//      statement, called from `deriveEvidenceFix` below.
//   5. Actor scoping: every `Repo` call below takes no user id at all.
//   6. connect_iq/health_route/file_import rejected at request-shape.ts;
//      `holes` derived from `Repo#catalog.courseHoleCount`, never the
//      client.
//   9. Replay-with-changed-payload: superseded by P3c gate round 3's
//      `findExisting`/`input_hash` design below — see that section.
//  11. Tombstoned-id rewrite: `reconstructEvidenceForScoring` now uses the
//      RESOLVED (survivor) ids, never the raw submitted ones.
//  should-fix: quarantine fraud_signal includes `play_id`; scorer
//      `reasons` are logged server-side only, never returned to the
//      client.
//
// P3c gate round 3 (b7c41cc) fixes, blocking HIGH 1+2 ("replay
// handling" — one fix covers both a changed-replay bypass and an AT 3
// regression) and blocking MEDIUM 5 ("local_date comes from the client
// label, not the server"):
//
//   HIGH 1 (changed-replay bypass) + HIGH 2 (AT 3 regression, one fix):
//   the OLD replay check (round 2's item 9, `assertReplayPayloadUnchanged`
//   -shaped logic inlined at the bottom of the pipeline) only ran when
//   the stored row showed up in `listForPlay`'s OWN (facility, course,
//   localDate) window — change `localDate` on a replay and the check was
//   skipped entirely, letting new, unstored content score under the old
//   evidence id (Bug 1). Separately, `consumeTokenForFix` ran BEFORE
//   that check, so an IDENTICAL retry of a token-bearing check-in saw its
//   own token already consumed and produced a false `challenge:none` /
//   422 `evidence_conflict` (Bug 2 — every outbox retry broke). Both are
//   closed the same way: `repo.evidence.findExisting(source, sourceRef)`
//   is now the FIRST repo call this function makes, before rate-limiting,
//   device resolution, token consumption, or any fraud signal. A match
//   whose `input_hash` (a canonical SHA-256 of the ENTIRE parsed
//   submission — `computeInputHash` below) equals this call's own hash is
//   an idempotent replay: `buildReplayResult` re-derives the response
//   PURELY from already-persisted rows, with zero new side effects (no
//   token consumption, no rate-limit hit, no fresh insert). A mismatch is
//   `Errors.conflict` (409 `evidence_conflict`) — rejected before
//   anything about the NEW, different content is ever acted on. Only a
//   genuinely new (user, source, source_ref) proceeds into the
//   side-effecting pipeline below.
//
//   MEDIUM 5 (local_date from the client): for a fix-bearing source
//   (foreground_checkin/foreground_dwell), `localDate` is now derived
//   server-side from the ANCHOR fix's own `capturedAt` resolved into the
//   facility's real IANA tz (`localDateInTz`, `anchorCapturedAtMs`) — a
//   mismatching client label is rejected with 422 `local_date_mismatch`,
//   never silently overridden. For a date-only source (self_report/
//   health_workout, which carry no client-controlled capturedAt to
//   derive a date from at all), the client's own label is accepted only
//   inside a facility-local-today window (`assertSelfReportDateWindow`).
//
// P3c gate round 4 fixes, blocking HIGH ("5 concurrent requests deadlock
// the pool") and blocking MEDIUM ("replays skip every rate limit"):
//
//   Blocking HIGH's own fix moved EVERY rate-limit hit for evidence
//   intake OUT of this file's own pipeline entirely — `handleEvidenceIntake`
//   no longer calls anything rate-limit-shaped at all. The reviewer's own
//   diagnosis: `Repo#rateLimit.hit` (round 3) opened a SECOND pooled
//   connection from inside a `buildRepo` callback that already holds ONE
//   (the request's own transaction) — under real concurrency (5+
//   simultaneous requests against a `max: 5` pool), every one of them
//   blocked forever waiting for a connection that would never free up.
//   `planEvidenceRateLimitChecks` below is the new seam: it parses the
//   submission and returns the bucket checks that must be hit —
//   UNCONDITIONALLY, replay or not — with NO transaction open at all.
//   The caller (evidence/index.ts, evidence-batch/index.ts) hits each
//   one via `privileged.ts#hitRateLimitForActor` BEFORE ever calling
//   `withOwnership`/`withOwnershipBatch`, closing both findings at once:
//   no request ever holds two pooled connections (blocking HIGH), and
//   every attempt — replay included — counts against its bucket, since
//   the hit now happens before `findExisting` is even reachable
//   (blocking MEDIUM).
//
//   Blocking MEDIUM's OTHER fix item ("make the replay path read-only")
//   rewrote `buildReplayResult`: it no longer re-runs `scorePlay` or
//   `upsertFromScore` at all for a course-anchored replay — it reads the
//   ALREADY-STORED `app.play` row back via the new `Repo#play.getForDate`
//   (a plain SELECT, no scoring, no write) and returns exactly that. The
//   original, genuinely-new submission that created the evidence row
//   already scored and upserted its play row, atomically, in the SAME
//   transaction (P3c gate round 2, item 2) — a replay of that SAME
//   content has nothing new to contribute, so this is not merely
//   cheaper, it is the literal "no re-score beyond what's idempotent"
//   contract, made unconditional instead of merely idempotent-in-practice.

// @deno-types="../scoring/scoring-types.d.ts"
import { scorePlay } from "../scoring/vendor/score-play.js";
import type { Repo, StoredEvidenceRow, ExistingEvidenceRow } from "../types.ts";
import { HttpError, Errors } from "../http.ts";
import { parseEvidenceSubmission, type EvidenceSubmission, type FixSubmission } from "./request-shape.ts";
import { deriveSourceRef } from "./source-ref.ts";
import { deriveFix, type DerivedFix } from "./derive-fix.ts";
import { classifyCatalogSubmission, type ManifestSigClaim } from "../catalog/classify-version.ts";
import { verifyManifestSignature } from "../catalog/signature.ts";

const MAX_OPEN_QUEUED_PER_USER = 20; // build plan §4.7 item 8 / AT 8, item 15
const CLOCK_SKEW_MAX_MS = 24 * 60 * 60 * 1000; // security doc §3
const RATE_LIMIT_EVIDENCE_PER_USER_HOUR = 60; // build plan §4.7 item 8
const RATE_LIMIT_EVIDENCE_PER_DEVICE_DAY = 200;
const MAX_DEVICES_PER_USER = 20; // P3c gate round 2, item 7 (should-fix cap, no plan-stated number)
// P3c gate round 3, blocking MEDIUM 5: a date-only source (self_report/
// health_workout) carries no server-verifiable capturedAt to derive a
// date from at all, so its client-submitted `localDate` label is bounded
// by a window instead of cross-checked exactly. docs/golf-trails/
// 02-build-plan.md is not present in this checkout to verify a
// plan-stated number against (confirmed via grep/find, same as
// MAX_DEVICES_PER_USER's own identical footnote above) — 30 days back /
// 1 day forward is this round's own documented, conservative default:
// generous enough for a round played off-app and logged from memory a
// few weeks later, tight enough that it can't backdate into a wildly
// different scoring period or postdate past "tomorrow" (a device's own
// clock can be a day ahead across a timezone boundary at local midnight).
const SELF_REPORT_WINDOW_DAYS_BACK = 30;
const SELF_REPORT_WINDOW_DAYS_FORWARD = 1;

export interface EvidenceIntakeSuccess {
  status: "accepted";
  evidenceId: string;
  replay: boolean;
  play: {
    id: string;
    scoreBadge: number;
    scoreMonetary: number;
    presenceSignal: boolean;
    money: boolean;
    heldReview: boolean;
  };
}

export interface EvidenceIntakeQueued {
  status: "queued_catalog";
  evidenceId: string;
}

export type EvidenceIntakeResult = EvidenceIntakeSuccess | EvidenceIntakeQueued;

function fixesOf(submission: EvidenceSubmission): FixSubmission[] {
  switch (submission.source) {
    case "foreground_checkin":
      return [submission.fix];
    case "foreground_dwell":
      return [submission.checkinFix, submission.checkoutFix];
    default:
      return [];
  }
}

/** P3c gate round 2, item 4: atomically consumes the fix's checkin-token
 * (ownership + single-use + device match + challenge-window clamp, ALL
 * in one statement — see `Repo#checkinToken.consumeForFix`'s own doc). A
 * fix with no token reference, or whose consume call is rejected for ANY
 * reason, simply isn't a co-signal — never a structural error on its
 * own (a stale/expired token is a normal, scoreable shape, not an
 * attack). */
async function consumeTokenForFix(repo: Repo, submittingDeviceId: string, fix: FixSubmission) {
  if (!fix.checkinTokenJti) return null;
  return repo.checkinToken.consumeForFix(fix.checkinTokenJti, submittingDeviceId, fix.capturedAt);
}

/** Clamps every fix's `capturedAt` against server time — security doc §3:
 * "clock skew over 24h raises a fraud_signal". Returns the offending
 * fixIds (empty when every fix is within tolerance) so the caller can
 * raise ONE fraud_signal naming all of them, rather than one per fix. */
function findClockSkewedFixIds(fixes: FixSubmission[], now: Date): string[] {
  const nowMs = now.getTime();
  return fixes.filter((f) => Math.abs(nowMs - f.capturedAt) > CLOCK_SKEW_MAX_MS).map((f) => f.fixId);
}

async function resolveCourseAnchor(repo: Repo, courseId: string | undefined): Promise<
  | { kind: "none" }
  | { kind: "resolved"; id: string }
  | { kind: "unknown" }
> {
  if (courseId === undefined) return { kind: "none" };
  const resolved = await repo.catalog.resolveLedgerId(courseId);
  if (!resolved) return { kind: "unknown" };
  // G3-01: a stub OR verified course id is accepted (stub-course
  // promotion) — status alone never blocks the submission.
  return { kind: "resolved", id: resolved.id };
}

/** Canonical JSON (sorted keys, recursively) — used by `computeInputHash`
 * below (P3c gate round 3) and by `source-ref.ts`'s own content-hash
 * fallback. Order-independent so the SAME logical content always hashes
 * the same regardless of client key ordering. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalize((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function toHex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export type DigestFn = (algorithm: "SHA-256", data: BufferSource) => Promise<ArrayBuffer>;

/** P3c gate round 3, blocking HIGH 1+2: a canonical SHA-256 hash (hex) of
 * the ENTIRE parsed, validated client submission — stored once at insert
 * (`app.evidence.input_hash`, 0019) and compared against every later
 * request that resolves to the SAME (user, source, source_ref), BEFORE
 * any side effect. Unlike `source-ref.ts#deriveSourceRef` (which, for a
 * fix-bearing source, derives a NATURAL ref from just the fixId(s) — so
 * two submissions with the SAME fixId but different localDate/course
 * collide on `source_ref` even though their CONTENT differs), this hash
 * covers the WHOLE submission, so any content difference is caught even
 * when `source_ref` alone could not distinguish the two calls. Same
 * canonicalization discipline as `deriveSourceRef` (sorted keys,
 * recursively) so the SAME logical payload always hashes to the SAME
 * bytes regardless of client key ordering. */
export async function computeInputHash(submission: EvidenceSubmission, digestHex: DigestFn = crypto.subtle.digest.bind(crypto.subtle)): Promise<string> {
  const canonical = JSON.stringify(canonicalize(submission));
  const bytes = new TextEncoder().encode(canonical);
  const digest = await digestHex("SHA-256", bytes.slice());
  return toHex(digest);
}

/** IANA-tz calendar date (YYYY-MM-DD) for an epoch-ms instant (P3c gate
 * round 3, blocking MEDIUM 5) — the same derivation `app.evidence.
 * local_date`'s own column comment (0019/0020) documents as the source
 * of truth for a fix-bearing row. `Intl.DateTimeFormat`'s "en-CA" locale
 * already formats as YYYY-MM-DD, so no extra dependency (beyond
 * `tz-lookup`, already used elsewhere in this tree to resolve a
 * facility's own tz in the first place) is needed here. */
export function localDateInTz(epochMs: number, tz: string): string {
  const fmt = new Intl.DateTimeFormat("en-CA", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit" });
  return fmt.format(new Date(epochMs));
}

/** Which fix's `capturedAt` anchors a fix-bearing submission's own
 * facility-local date (P3c gate round 3, blocking MEDIUM 5) — server
 * -derived, never the client's own `localDate` label. `foreground_dwell`
 * anchors on the CHECK-IN fix (the round begins there, before the
 * checkout fix's own, later, capturedAt); `foreground_checkin` has only
 * the one fix. Returns `null` for a date-only source (self_report/
 * health_workout), which has no client-controlled capturedAt to derive a
 * date from at all — `assertSelfReportDateWindow` validates that case
 * instead. */
function anchorCapturedAtMs(submission: EvidenceSubmission): number | null {
  switch (submission.source) {
    case "foreground_checkin":
      return submission.fix.capturedAt;
    case "foreground_dwell":
      return submission.checkinFix.capturedAt;
    default:
      return null;
  }
}

/** P3c gate round 3, blocking MEDIUM 5: a date-only source's own
 * client-submitted `localDate` is accepted only within a bounded window
 * of the facility-local "today" (`repo.now()` resolved into the
 * facility's own tz, the same way a fix-bearing source's date is
 * derived) — see `SELF_REPORT_WINDOW_DAYS_BACK`/`_FORWARD`'s own doc for
 * why 30/1. Throws 422 `local_date_out_of_window` outside it. */
function assertSelfReportDateWindow(localDate: string, facilityTz: string, now: Date): void {
  const today = localDateInTz(now.getTime(), facilityTz);
  const todayMs = Date.parse(`${today}T00:00:00Z`);
  const claimedMs = Date.parse(`${localDate}T00:00:00Z`);
  const daysDiff = Math.round((claimedMs - todayMs) / 86_400_000);
  if (daysDiff < -SELF_REPORT_WINDOW_DAYS_BACK || daysDiff > SELF_REPORT_WINDOW_DAYS_FORWARD) {
    throw Errors.unprocessable(
      "local_date_out_of_window",
      `localDate "${localDate}" is outside the accepted window (facility-local today -${SELF_REPORT_WINDOW_DAYS_BACK}..+${SELF_REPORT_WINDOW_DAYS_FORWARD} days)`,
    );
  }
}

/** P3c gate round 3, blocking MEDIUM 5: for a fix-bearing submission,
 * `localDate` must equal the server-derived facility-local date of its
 * own anchor fix — a mismatch is rejected (422 `local_date_mismatch`),
 * never silently overridden (the OLD behaviour this replaces stored
 * whatever the client sent, unverified). For a date-only submission, the
 * client's own label is accepted only inside a bounded window of
 * "today" (`assertSelfReportDateWindow`). Called AFTER facility
 * resolution (needs the facility's real tz) and BEFORE any of this
 * request's writes (token consumption, the evidence insert, a fraud
 * signal) — a genuinely new submission never reaches those with an
 * unverified date. */
function assertServerDerivableLocalDate(submission: EvidenceSubmission, facilityTz: string, now: Date): void {
  const anchorMs = anchorCapturedAtMs(submission);
  if (anchorMs === null) {
    assertSelfReportDateWindow(submission.localDate, facilityTz, now);
    return;
  }
  const serverLocalDate = localDateInTz(anchorMs, facilityTz);
  if (serverLocalDate !== submission.localDate) {
    throw Errors.unprocessable(
      "local_date_mismatch",
      `localDate "${submission.localDate}" does not match the server-derived facility-local date "${serverLocalDate}" for this submission's own capturedAt`,
    );
  }
}

export interface RateLimitCheck {
  bucketKey: string;
  windowSeconds: number;
  max: number;
}

/** P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock the
 * pool") + blocking MEDIUM ("replays skip every rate limit"): parses the
 * submission and returns the rate-limit checks that MUST be hit —
 * unconditionally, replay or not — before this submission's own
 * transaction (`findExisting` onward) ever opens. Pure: needs no DB
 * access of its own. `actor.uid` is the caller's own concern (not
 * threaded through here at all); the device-scoped bucket key uses the
 * CLIENT-SUPPLIED `deviceId` directly — always present, request-shape.ts's
 * `CommonFields` — never the DB-resolved device row's own id, so this
 * needs no DB round trip either (the two are guaranteed equal:
 * `Repo#device.ensureOwn` always stores the id it's given, P3c gate
 * round 2's own device-identity fix). The caller hits each check via
 * `privileged.ts#hitRateLimitForActor` BEFORE calling `withOwnership`,
 * so no request ever holds the request transaction's own pooled
 * connection AND a rate-limit connection at the same time, and every
 * attempt (replay included) counts, since this runs before
 * `handleEvidenceIntake`'s own `findExisting` is even reachable. */
export function planEvidenceRateLimitChecks(rawBody: unknown, options: { skipLiveRateLimit?: boolean } = {}): { submission: EvidenceSubmission; checks: RateLimitCheck[] } {
  const parsed = parseEvidenceSubmission(rawBody);
  if (!parsed.ok) {
    throw Errors.badRequest("invalid evidence submission", { issues: parsed.issues });
  }
  const submission = parsed.value;
  const checks: RateLimitCheck[] = [];
  // should-fix (P3c gate round 2): "batch items must not consume the
  // live 60/h limit." evidence-batch/index.ts sets this true — its OWN
  // per-item call into the 2,000/day batch bucket is what gates a batch
  // submission instead (see that file).
  if (!options.skipLiveRateLimit) {
    checks.push({ bucketKey: "evidence:user", windowSeconds: 3600, max: RATE_LIMIT_EVIDENCE_PER_USER_HOUR });
  }
  checks.push({ bucketKey: `evidence:device:${submission.deviceId}`, windowSeconds: 86400, max: RATE_LIMIT_EVIDENCE_PER_DEVICE_DAY });
  return { submission, checks };
}

/** P3c gate round 3, blocking HIGH 1+2: rebuilds this function's own
 * response PURELY from already-persisted rows — zero new side effects
 * (no token consumption, no rate-limit hit, no fresh insert, no fraud
 * signal). Handles both `status` shapes this handler ever actually
 * persists: `queued_catalog` (nothing further to score at all) and
 * `accepted` (facility-level rows short-circuit the same way a fresh
 * facility-level submission already does).
 *
 * ⛔ FIX (P3c gate round 4, blocking MEDIUM's own fix item: "make the
 * replay path read-only... If a re-score is genuinely needed for
 * correctness, say why"). A course-anchored replay used to re-run
 * `scorePlay` against `listForPlay`'s own already-stored set and then
 * `upsertFromScore` the result — a REAL re-score and a REAL write, on
 * every single replay, which is how 150 replays in 757ms each still did
 * real work even though the rate-limit bucket (this file's OTHER round-4
 * fix) now also catches the volume. Genuinely not needed: the ORIGINAL,
 * new submission that created this evidence row already scored and
 * upserted its play row, atomically, in the SAME transaction (P3c gate
 * round 2, item 2) — nothing about a byte-for-byte-identical replay
 * (guaranteed by the caller's own `input_hash` match, the only way this
 * function is ever reached) could produce a DIFFERENT score from the
 * SAME already-persisted inputs. `Repo#play.getForDate` is a plain
 * SELECT of that already-computed row — no scoring, no advisory lock, no
 * write of any kind. */
async function buildReplayResult(repo: Repo, existing: ExistingEvidenceRow): Promise<EvidenceIntakeResult> {
  if (existing.status === "queued_catalog") {
    return { status: "queued_catalog", evidenceId: existing.id };
  }
  if (existing.courseId === null) {
    return {
      status: "accepted",
      evidenceId: existing.id,
      replay: true,
      play: { id: "", scoreBadge: 0, scoreMonetary: 0, presenceSignal: false, money: false, heldReview: false },
    };
  }
  const play = await repo.play.getForDate(existing.courseId, existing.localDate);
  if (!play) {
    // Should be unreachable: the original submission that created this
    // evidence row always upserts its play row in the SAME atomic
    // transaction (P3c gate round 2, item 2), so a course-anchored
    // evidence row and its play row either both exist or neither does.
    // Reaching here means a genuine data inconsistency, not a normal
    // race — fail closed rather than fabricate a play outcome.
    console.error(`buildReplayResult: no app.play row found for an existing, course-anchored evidence row (evidenceId=${existing.id}, courseId=${existing.courseId}, localDate=${existing.localDate})`);
    throw Errors.internal();
  }
  return {
    status: "accepted",
    evidenceId: existing.id,
    replay: true,
    play: { id: play.id, scoreBadge: play.scoreBadge, scoreMonetary: play.scoreMonetary, presenceSignal: play.presenceSignal, money: play.money, heldReview: play.heldReview },
  };
}

export async function handleEvidenceIntake(rawBody: unknown, repo: Repo): Promise<EvidenceIntakeResult> {
  const parsed = parseEvidenceSubmission(rawBody);
  if (!parsed.ok) {
    throw Errors.badRequest("invalid evidence submission", { issues: parsed.issues });
  }
  const submission = parsed.value;

  // ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
  // the pool"): rate-limiting used to happen HERE, via
  // `repo.rateLimit.hit` — removed entirely. The caller (evidence/
  // index.ts, evidence-batch/index.ts) already hit every check
  // `planEvidenceRateLimitChecks` returned, via `hitRateLimitForActor`,
  // BEFORE `withOwnership` was even called — see this file's own header
  // for the full reasoning. By the time `repo` exists at all (this
  // function's own second parameter), rate-limiting for this request has
  // already happened, unconditionally, replay or not.

  // Computed ONCE, reused everywhere below this point — both are pure
  // functions of `submission` alone.
  const sourceRef = await deriveSourceRef(submission);
  const inputHash = await computeInputHash(submission);

  // ⛔ P3c gate round 3, blocking HIGH 1+2 ("replay handling"): looked up
  // BEFORE ANY side effect — token consumption, a fraud signal, a
  // rate-limit hit, a device row — verbatim per the gate's own fix list.
  // A match here means this (user, source, source_ref) already has a
  // row on file; the ONLY question left is whether this call's content
  // is the SAME as what's stored (an idempotent replay, handled with
  // zero new side effects by `buildReplayResult`) or DIFFERENT (a
  // genuine conflict, rejected outright before any of the new content is
  // ever acted on).
  const existing = await repo.evidence.findExisting(submission.source, sourceRef);
  if (existing) {
    if (existing.inputHash === inputHash) {
      return buildReplayResult(repo, existing);
    }
    throw Errors.conflict("evidence_conflict", "a replay of this evidence id was submitted with different content than what is already on file");
  }

  // ---- Everything below only ever runs for a GENUINELY NEW submission
  // (no existing row for this (user, source, source_ref) at all). ----

  // ⛔ FIX (P3c gate round 2, item 7): device cap checked BEFORE anything
  // is written. `findOwn` never creates a row — only a genuinely NEW
  // device (not already this actor's own) is subject to the cap, and a
  // request that would exceed it is rejected BEFORE `ensureOwn` (which
  // DOES write) is ever called, so a rejected request never creates a
  // device row at all.
  const knownDevice = await repo.device.findOwn(submission.deviceId);
  if (!knownDevice) {
    const existingDeviceCount = await repo.device.countForUser();
    if (existingDeviceCount >= MAX_DEVICES_PER_USER) {
      throw Errors.unprocessable("device_limit_exceeded", `this account already has ${MAX_DEVICES_PER_USER} devices on record`);
    }
  }
  const device = knownDevice ?? (await repo.device.ensureOwn(submission.deviceId, null));

  // ---- Catalog skew (AT 8 / AT 15 / G3-10) — BEFORE any id lookup. ----
  const currentVersion = await repo.catalog.currentVersion();
  const declaredVersionRow = await repo.catalog.versionRow(submission.catalogVersion);
  // AT 15: "a revoked-kid version gets 422 catalog_stale" — looked up
  // from the SAME signing-key table manifestSig verification uses.
  let declaredVersionKidRevoked = false;
  if (declaredVersionRow) {
    const declaredKey = await repo.catalog.signingKey(declaredVersionRow.kid);
    declaredVersionKidRevoked = Boolean(declaredKey?.revokedAt);
  }
  const manifestSig: ManifestSigClaim | undefined = submission.manifestSig
    ? {
        kid: submission.manifestSig.kid,
        signatureB64Url: submission.manifestSig.signatureB64Url,
        // should-fix (P3c gate round 2): "sign a domain-tagged payload
        // that binds the version and the manifest sha256" — a bare
        // integer signature could be replayed against a DIFFERENT
        // future release that happens to share a version number; this
        // binds the signature to the SPECIFIC content the client claims
        // that version's manifest hashes to.
        payload: `golfraven-catalog-manifest-v1:${submission.catalogVersion}:${submission.manifestSig.manifestSha256}`,
      }
    : undefined;
  const versionOutcome = await classifyCatalogSubmission(
    {
      declaredVersion: submission.catalogVersion,
      currentVersion: currentVersion?.version ?? null,
      declaredVersionRow: declaredVersionRow ? { publishedAt: declaredVersionRow.publishedAt, kidRevoked: declaredVersionKidRevoked } : null,
      now: repo.now(),
      manifestSig,
    },
    async (claim) => {
      const key = await repo.catalog.signingKey(claim.kid);
      if (!key || key.revokedAt) return false;
      return verifyManifestSignature({ publicKeyB64Url: key.publicKeyB64Url, signatureB64Url: claim.signatureB64Url, payload: claim.payload });
    },
  );
  if (versionOutcome.kind === "stale") throw Errors.unprocessable("catalog_stale", "submitted catalogVersion is outside the accepted skew window, or its signing kid is revoked");
  if (versionOutcome.kind === "forged") throw Errors.unprocessable("catalog_forged", "submitted catalogVersion is newer than the server's import with no verifying manifestSig, or far in the future");

  // "an id newer than the server's import returns 202" (AT 8) — reachable
  // when the (verified, per above) declared version is itself newer than
  // what the server has imported: by definition the ledger cannot have
  // this id yet. See classify-version.ts's own header for why, absent
  // any registered signing key, this path never actually verifies in
  // this environment (documented deferral).
  if (currentVersion !== null && versionOutcome.resolvedVersion > currentVersion.version) {
    // ⛔ FIX (P3c gate round 2, item 8): count-then-insert race — the
    // 20-open-queued cap is now checked and reserved under the SAME
    // advisory lock `evidence.countOpenQueued` itself takes (see
    // privileged.ts), so two concurrent submissions can't both read
    // "19 open" and both proceed.
    const openCount = await repo.evidence.countOpenQueued();
    if (openCount >= MAX_OPEN_QUEUED_PER_USER) {
      throw Errors.tooManyRequests(`this account already has ${MAX_OPEN_QUEUED_PER_USER} open queued_catalog evidence rows`);
    }
    const inserted = await repo.evidence.insertIdempotent({
      sourceRef,
      inputHash,
      source: submission.source,
      facilityId: submission.facilityId,
      courseId: submission.courseId ?? null,
      startedAt: null,
      endedAt: null,
      localDate: submission.localDate,
      summary: { queuedForCatalogVersion: submission.catalogVersion },
      integrity: {},
      cosignal: {},
      attestationGrade: "unattestable",
      matcherVersion: null,
      catalogVersion: submission.catalogVersion,
      status: "queued_catalog",
      deviceId: device.id,
    });
    // ⛔ P3c gate round 3, blocking HIGH 1+2's own race-safety note:
    // `findExisting` above already confirmed no row existed moments ago
    // — reaching `!wasNew` here means a CONCURRENT request for the SAME
    // (user, source, source_ref) won a narrow race against THIS one.
    // Resolve it exactly like the top-of-function check would have: an
    // exact hash match is the other request's own row, safe to report as
    // this call's own (idempotent) outcome; a mismatch is a genuine
    // conflict.
    if (!inserted.wasNew) {
      if (inserted.inputHash !== inputHash) {
        throw Errors.conflict("evidence_conflict", "a concurrent replay of this evidence id was submitted with different content than what is already on file");
      }
      return buildReplayResult(repo, { id: inserted.id, status: inserted.status, inputHash: inserted.inputHash, facilityId: submission.facilityId, courseId: submission.courseId ?? null, localDate: submission.localDate });
    }
    return { status: "queued_catalog", evidenceId: inserted.id };
  }

  // ---- Facility + course id resolution against the ledger, THEN
  // against the REAL catalog row (P3c gate round 2, item 2: "resolveLedgerId
  // callers must assert the id kind and require a real catalog_facility /
  // catalog_course row"). ----
  const facilityLedger = await repo.catalog.resolveLedgerId(submission.facilityId);
  if (!facilityLedger || facilityLedger.kind !== "facility") {
    throw Errors.unprocessable("unknown_id", `facilityId "${submission.facilityId}" is not a known catalog facility id`);
  }
  const resolvedFacilityId = facilityLedger.id;
  const facilityTz = await repo.catalog.facilityTz(resolvedFacilityId);
  if (!facilityTz) {
    // The ledger says this id exists, but no app.catalog_facility row
    // backs it — a half-imported/inconsistent catalog state. Fail
    // closed rather than silently scoring against a facility that
    // doesn't really have a tz on record.
    throw Errors.unprocessable("unknown_id", `facilityId "${resolvedFacilityId}" has a ledger entry but no catalog_facility row`);
  }

  const courseAnchor = await resolveCourseAnchor(repo, submission.courseId);
  if (courseAnchor.kind === "unknown") {
    throw Errors.unprocessable("unknown_id", `courseId "${submission.courseId}" is not a known catalog id`);
  }
  let resolvedCourseId: string | null = null;
  if (courseAnchor.kind === "resolved") {
    const ledgerRow = await repo.catalog.resolveLedgerId(courseAnchor.id);
    if (!ledgerRow || ledgerRow.kind !== "course") {
      throw Errors.unprocessable("unknown_id", `courseId "${submission.courseId}" is not a known catalog course id`);
    }
    // ⛔ FIX (P3c gate round 2, item 3): "forged facility/course
    // pairing." A course id that resolves fine on its OWN, but belongs
    // to a DIFFERENT facility than the one this submission claims, is
    // rejected outright — never silently re-anchored to whichever
    // facility the course actually belongs to.
    const courseFacilityId = await repo.catalog.courseFacilityId(ledgerRow.id);
    if (!courseFacilityId) {
      throw Errors.unprocessable("unknown_id", `courseId "${submission.courseId}" has a ledger entry but no catalog_course row`);
    }
    if (courseFacilityId !== resolvedFacilityId) {
      throw Errors.unprocessable("facility_course_mismatch", `courseId "${submission.courseId}" belongs to a different facility than facilityId "${submission.facilityId}"`);
    }
    resolvedCourseId = ledgerRow.id;
  }

  // ⛔ FIX (P3c gate round 3, blocking MEDIUM 5): "local_date comes from
  // the client label, not the server." Runs the moment `facilityTz` is
  // known and BEFORE any of this request's own writes (clock-skew's own
  // fraud signal, token consumption, the evidence insert) — a genuinely
  // new submission with an unverified/out-of-window date never reaches
  // any of those.
  assertServerDerivableLocalDate(submission, facilityTz, repo.now());

  // ---- Clock skew (security doc §3). ----
  const fixes = fixesOf(submission);
  const skewedFixIds = findClockSkewedFixIds(fixes, repo.now());
  if (skewedFixIds.length > 0) {
    await repo.fraudSignal.insert("clock_skew", { fixIds: skewedFixIds, evidenceSource: submission.source });
  }

  // ---- Consume any referenced checkin-token, THEN derive server-owned
  // AppFix fields for every fix (P3c gate round 2, item 4). ----
  const derivedFixesByFixId = new Map<string, DerivedFix>();
  for (const fix of fixes) {
    const perFixMatch = resolvedCourseId ? await repo.catalog.matchFix(resolvedCourseId, fix.lat, fix.lng) : null;
    const consumedToken = await consumeTokenForFix(repo, device.id, fix);
    derivedFixesByFixId.set(
      fix.fixId,
      deriveFix({ fix, resolvedFacilityId, localDate: submission.localDate, match: perFixMatch, consumedToken }),
    );
  }

  // ---- Assemble the app.evidence row's summary/integrity/cosignal jsonb
  // exactly as `scorePlay`'s Evidence union (rules.generated.js) expects
  // it to be reconstructed on read — see listForPlay's mirror of this in
  // privileged.ts. ----
  const anyFailedGrade = [...derivedFixesByFixId.values()].some((f) => f.token.present && f.token.grade === "failed");
  if (anyFailedGrade) {
    // security doc §3: "A fix that grades failed MUST raise
    // fraud_signal(attestation_failed) AT INTAKE."
    await repo.fraudSignal.insert("attestation_failed", { evidenceSource: submission.source, facilityId: resolvedFacilityId });
  }

  const worstGrade: "attested" | "unattestable" | "failed" = anyFailedGrade
    ? "failed"
    : [...derivedFixesByFixId.values()].every((f) => f.token.present && f.token.grade === "attested")
      ? "attested"
      : "unattestable";

  // ⛔ FIX (P3c gate round 2, item 6): `holes` is derived from the
  // catalog, never the client. Only reachable for foreground_dwell,
  // which always carries a courseId (request-shape.ts requires it
  // implicitly via COMMON_KEYS — a facility-level dwell has no course to
  // derive hole data from, so it falls back to 18 as the conservative
  // (stricter apart-minutes bar) default).
  let holes: 9 | 18 = 18;
  if (submission.source === "foreground_dwell" && resolvedCourseId) {
    const holeCount = await repo.catalog.courseHoleCount(resolvedCourseId);
    if (holeCount > 0) holes = holeCount >= 18 ? 18 : 9;
  }

  const summary: Record<string, unknown> = { localDate: submission.localDate };
  let fixPayload: Record<string, unknown> = {};

  switch (submission.source) {
    case "foreground_checkin": {
      const f = derivedFixesByFixId.get(submission.fix.fixId)!;
      fixPayload = { fix: f };
      break;
    }
    case "foreground_dwell": {
      const a = derivedFixesByFixId.get(submission.checkinFix.fixId)!;
      const b = derivedFixesByFixId.get(submission.checkoutFix.fixId)!;
      fixPayload = { checkinFix: a, checkoutFix: b, apartMinutes: submission.apartMinutes, holes };
      break;
    }
    default:
      fixPayload = {};
  }
  Object.assign(summary, fixPayload);

  const inserted = await repo.evidence.insertIdempotent({
    sourceRef,
    inputHash,
    source: submission.source,
    facilityId: resolvedFacilityId,
    courseId: resolvedCourseId,
    startedAt: null,
    endedAt: null,
    localDate: submission.localDate,
    summary,
    integrity: {},
    cosignal: {},
    attestationGrade: worstGrade,
    matcherVersion: null,
    catalogVersion: currentVersion?.version ?? submission.catalogVersion,
    status: "accepted",
    deviceId: device.id,
  });

  // ⛔ P3c gate round 3, blocking HIGH 1+2's own race-safety note: same
  // reasoning as the queued_catalog branch above — `findExisting`
  // already confirmed no row existed moments ago, so `!wasNew` here
  // means a concurrent request for the SAME (user, source, source_ref)
  // won a narrow race. This call's own token consumption / fraud signals
  // above ALREADY happened by this point (they are this call's own,
  // legitimate side effects for what it believed was a new submission,
  // not something to undo) — what matters now is which response this
  // call itself returns: the winner's stored outcome on a hash match, or
  // a conflict on a mismatch.
  if (!inserted.wasNew) {
    if (inserted.inputHash !== inputHash) {
      throw Errors.conflict("evidence_conflict", "a concurrent replay of this evidence id was submitted with different content than what is already on file");
    }
    return buildReplayResult(repo, { id: inserted.id, status: inserted.status, inputHash: inserted.inputHash, facilityId: resolvedFacilityId, courseId: resolvedCourseId, localDate: submission.localDate });
  }

  // ---- Score the play: gather every OTHER accepted row for this
  // (user, facility, date) too, so a play already backed by prior
  // evidence gets re-scored with the new row folded in. ----
  if (resolvedCourseId === null) {
    // Facility-level evidence (H3 residual: no course anchor) never
    // anchors a `play` row on its own (app.play requires course_id NOT
    // NULL) — it is scoreable badge-only evidence that a play anchored
    // by a DIFFERENT, course-anchored row can later fold in. Nothing
    // further to persist this call.
    return {
      status: "accepted",
      evidenceId: inserted.id,
      replay: false,
      play: { id: "", scoreBadge: 0, scoreMonetary: 0, presenceSignal: false, money: false, heldReview: false },
    };
  }

  const priorRows = await repo.evidence.listForPlay(resolvedFacilityId, resolvedCourseId, submission.localDate);
  const evidenceForScoring = reconstructEvidenceForScoring(priorRows, inserted.id, submission, derivedFixesByFixId, resolvedFacilityId, resolvedCourseId, holes);

  const outcome = scorePlay(evidenceForScoring, {
    playFacilityId: resolvedFacilityId,
    playLocalDate: submission.localDate,
    playCourseId: resolvedCourseId,
    facilityTz,
  });

  if (!outcome.ok) {
    // A structural scorePlay failure here means OUR OWN row assembly is
    // malformed (every field is server-derived above) — a bug in this
    // handler, not a client attack. Fail closed (500) rather than
    // silently persisting a zero/garbage play. should-fix (P3c gate
    // round 2): "scorer reasons: never return them to the client" —
    // logged server-side only; the client gets a generic message.
    console.error(`scorePlay rejected server-assembled input: ${outcome.reasons.join("; ")}`);
    throw Errors.internal();
  }

  // ⛔ FIX (P3c gate round 2, item 1): link only CONTRIBUTING evidence —
  // never every row that merely matched the candidate query.
  const contributedIds = new Set(outcome.contributions.map((c) => c.evidenceId));
  const evidenceIdsToLink = [inserted.id, ...priorRows.map((r) => r.id)].filter((id) => contributedIds.has(id) || id === inserted.id);

  const play = await repo.play.upsertFromScore({
    courseId: resolvedCourseId,
    facilityId: resolvedFacilityId,
    playDate: submission.localDate,
    courseDisambiguatedBy: null,
    scoreBadge: outcome.score_badge,
    scoreMonetary: outcome.score_monetary,
    hardSignal: outcome.contributions.some((c) => c.hard),
    presenceSignal: outcome.presence_signal,
    money: outcome.money,
    heldReview: outcome.heldReview,
    policyVersion: String(outcome.policyVersion),
    inputDigest: outcome.inputDigest,
    evidenceIds: evidenceIdsToLink,
  });

  if (outcome.excludedRows.some((r) => r.kind === "quarantined")) {
    // security doc §3: "Every ON-PLAY quarantine... must raise a
    // fraud_signal or create a review_item." should-fix (P3c gate round
    // 2): include play_id.
    await repo.fraudSignal.insert("quarantined_evidence_row", {
      playId: play.id,
      facilityId: resolvedFacilityId,
      courseId: resolvedCourseId,
      localDate: submission.localDate,
      excludedRows: outcome.excludedRows.filter((r) => r.kind === "quarantined"),
    });
  }

  return {
    status: "accepted",
    evidenceId: inserted.id,
    replay: false,
    play: { id: play.id, scoreBadge: outcome.score_badge, scoreMonetary: outcome.score_monetary, presenceSignal: outcome.presence_signal, money: outcome.money, heldReview: outcome.heldReview },
  };
}

/** Rebuilds one `scorePlay` `Evidence[]` ROW from an already-stored
 * `StoredEvidenceRow` — the shared shape both `reconstructEvidenceForScoring`
 * (a NEW submission's prior rows) and `buildReplayResult` (a replay's
 * ENTIRE row set, including what was originally "this" row) use. */
function reconstructOneStoredRow(row: StoredEvidenceRow): Record<string, unknown> {
  return {
    id: row.id,
    facilityId: row.facilityId,
    courseId: row.courseId ?? undefined,
    localDate: row.localDate,
    source: row.source,
    ...row.summary,
  };
}

/** P3c gate round 3: the replay path's own scoring input — EVERY row
 * comes from `listForPlay` (already persisted), unlike
 * `reconstructEvidenceForScoring` below, which also assembles one FRESH
 * (not-yet-persisted) row for a genuinely new submission. */
function reconstructEvidenceFromStoredRows(rows: StoredEvidenceRow[]): Record<string, unknown>[] {
  return rows.map(reconstructOneStoredRow);
}

/** Rebuilds the `scorePlay` `Evidence[]` input from: every PRIOR stored
 * row for this play (as persisted — already server-derived, since only
 * this handler ever writes them) plus the row THIS call just inserted
 * (built fresh from `submission`/`derivedFixesByFixId` — a genuinely NEW
 * submission's own row is never yet in `priorRows`, since `listForPlay`
 * only runs AFTER this call's own insert already committed, and
 * P3c gate round 3's own `findExisting` guard means this function is
 * only ever reached for a submission that had no prior row at all).
 *
 * ⛔ FIX (P3c gate round 2, item 11): the fresh row's own `facilityId`/
 * `courseId` are the RESOLVED (survivor) ids passed in, never
 * `submission.facilityId`/`submission.courseId` directly — a tombstoned
 * id the caller already rewrote to its survivor MUST use that survivor
 * id here too, or `scorePlay`'s strict `courseId === ctx.playCourseId`
 * check (internal/classify.js) mismatches the tombstoned id against the
 * survivor `ctx.playCourseId` and scores the row 0 (excluded as
 * off-play) even though it plainly belongs to this play. */
function reconstructEvidenceForScoring(
  priorRows: StoredEvidenceRow[],
  insertedId: string,
  submission: EvidenceSubmission,
  derivedFixesByFixId: Map<string, DerivedFix>,
  resolvedFacilityId: string,
  resolvedCourseId: string,
  holes: 9 | 18,
): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = priorRows.filter((row) => row.id !== insertedId).map(reconstructOneStoredRow);
  const fresh: Record<string, unknown> = {
    id: insertedId,
    facilityId: resolvedFacilityId,
    courseId: resolvedCourseId,
    localDate: submission.localDate,
    source: submission.source,
  };
  switch (submission.source) {
    case "foreground_checkin":
      fresh.fix = derivedFixesByFixId.get(submission.fix.fixId);
      break;
    case "foreground_dwell":
      fresh.checkinFix = derivedFixesByFixId.get(submission.checkinFix.fixId);
      fresh.checkoutFix = derivedFixesByFixId.get(submission.checkoutFix.fixId);
      fresh.apartMinutes = submission.apartMinutes;
      fresh.holes = holes;
      break;
    default:
      break;
  }
  rows.push(fresh);
  return rows;
}

export { HttpError };
