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
//   9. Replay-with-changed-payload: `assertReplayPayloadUnchanged` below.
//  11. Tombstoned-id rewrite: `reconstructEvidenceForScoring` now uses the
//      RESOLVED (survivor) ids, never the raw submitted ones.
//  should-fix: quarantine fraud_signal includes `play_id`; scorer
//      `reasons` are logged server-side only, never returned to the
//      client.

// @deno-types="../scoring/scoring-types.d.ts"
import { scorePlay } from "../scoring/vendor/score-play.js";
import type { Repo, StoredEvidenceRow } from "../types.ts";
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

/** Canonical JSON (sorted keys, recursively) — used both by
 * source-ref.ts's content-hash fallback and here, to compare a REPLAYED
 * submission's derived content against what's already persisted (item
 * 9). Order-independent so the SAME logical content always compares
 * equal regardless of client key ordering. */
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

function stableStringify(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

export interface HandleEvidenceIntakeOptions {
  /** should-fix (P3c gate round 2): "batch items must not consume the
   * live 60/h limit." evidence-batch/index.ts sets this true — its OWN
   * per-item call into the 2,000/day batch bucket is what gates a batch
   * submission instead (see that file). */
  skipLiveRateLimit?: boolean;
}

export async function handleEvidenceIntake(rawBody: unknown, repo: Repo, options: HandleEvidenceIntakeOptions = {}): Promise<EvidenceIntakeResult> {
  const parsed = parseEvidenceSubmission(rawBody);
  if (!parsed.ok) {
    throw Errors.badRequest("invalid evidence submission", { issues: parsed.issues });
  }
  const submission = parsed.value;

  // ⛔ FIX (P3c gate round 2, item 7): rate-limit BEFORE any write —
  // including BEFORE ensureOwn, which otherwise creates a device row
  // even for a request this same call is about to reject.
  if (!options.skipLiveRateLimit) {
    const rateLimitUser = await repo.rateLimit.hit(`evidence:user`, 3600, RATE_LIMIT_EVIDENCE_PER_USER_HOUR);
    if (!rateLimitUser.ok) throw Errors.tooManyRequests("evidence rate limit exceeded for this account", rateLimitUser.retryAfterSeconds);
  }

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

  const rateLimitDevice = await repo.rateLimit.hit(`evidence:device:${device.id}`, 86400, RATE_LIMIT_EVIDENCE_PER_DEVICE_DAY);
  if (!rateLimitDevice.ok) throw Errors.tooManyRequests("evidence rate limit exceeded for this device", rateLimitDevice.retryAfterSeconds);

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
    const sourceRef = await deriveSourceRef(submission);
    const inserted = await repo.evidence.insertIdempotent({
      sourceRef,
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

  const sourceRef = await deriveSourceRef(submission);
  const inserted = await repo.evidence.insertIdempotent({
    sourceRef,
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
      replay: !inserted.wasNew,
      play: { id: "", scoreBadge: 0, scoreMonetary: 0, presenceSignal: false, money: false, heldReview: false },
    };
  }

  const priorRows = await repo.evidence.listForPlay(resolvedFacilityId, resolvedCourseId, submission.localDate);

  // ⛔ FIX (P3c gate round 2, item 9): "replay with a changed payload."
  // If this call's own row was NOT new (a replay of an existing
  // source_ref), the row on file might have been derived from a
  // DIFFERENT payload than this call's own submission would produce
  // (e.g. the client retried with different accuracy/lat/lng under the
  // same fixId) — 409, rather than silently re-scoring from the new
  // (unpersisted) content while the stored row itself never changed.
  if (!inserted.wasNew) {
    const storedRow = priorRows.find((r) => r.id === inserted.id);
    if (storedRow) {
      const freshComparable = stableStringify(summary);
      const storedComparable = stableStringify(storedRow.summary);
      if (freshComparable !== storedComparable) {
        throw Errors.unprocessable("evidence_conflict", "a replay of this evidence id was submitted with different content than what is already on file");
      }
    }
  }

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
    replay: !inserted.wasNew,
    play: { id: play.id, scoreBadge: outcome.score_badge, scoreMonetary: outcome.score_monetary, presenceSignal: outcome.presence_signal, money: outcome.money, heldReview: outcome.heldReview },
  };
}

/** Rebuilds the `scorePlay` `Evidence[]` input from: every PRIOR stored
 * row for this play (as persisted — already server-derived, since only
 * this handler ever writes them) plus the row THIS call just inserted
 * (built fresh from `submission`/`derivedFixesByFixId`, since a replay's
 * `priorRows` read already includes the row from ITS OWN earlier
 * insert — reconstructing it again here would double count it; dedup by
 * id).
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
  const rows: Record<string, unknown>[] = [];
  for (const row of priorRows) {
    if (row.id === insertedId) continue; // this call's own row — added fresh below
    rows.push({
      id: row.id,
      facilityId: row.facilityId,
      courseId: row.courseId ?? undefined,
      localDate: row.localDate,
      source: row.source,
      ...row.summary,
    });
  }
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
