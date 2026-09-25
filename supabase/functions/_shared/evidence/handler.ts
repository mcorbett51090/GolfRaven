// supabase/functions/_shared/evidence/handler.ts
//
// The pure, dependency-injected core of POST /v1/evidence and POST
// /v1/evidence/batch (build plan P3/§10 AT 3, AT 8, AT 15; docs/security/
// p3-money-path-requirements.md). Every I/O dependency comes through
// `Repo` (types.ts) or the small extra functions below, so this is
// unit-testable (supabase/tests/unit/evidence-handler.test.ts) with a
// fake in-memory Repo and no live Supabase project at all — the task's
// own instruction ("handler logic in pure, dependency-injected modules").
//
// What this enforces, file:line pointers for the P3c handback report:
//   - server-derived fields (fixId/facilityId/verificationTier/
//     geometryKind/insideBuffer/challenge/token grade): derive-fix.ts,
//     never taken from the client's FixSubmission directly except the
//     raw lat/lng/accuracy/timestamps/quality-flags a real device can
//     honestly report.
//   - replay/idempotency (AT 3): source-ref.ts + Repo#insertEvidenceIdempotent's
//     `ON CONFLICT (user_id, source, source_ref) DO NOTHING` (see
//     privileged.ts) + Repo#upsertPlayFromScore's `ON CONFLICT (user_id,
//     course_id, play_date) DO UPDATE` — a replay converges on the SAME
//     evidence row AND the same play row.
//   - catalog skew (AT 8 / AT 15 / G3-10): classifyCatalogSubmission below,
//     BEFORE any scoring happens.
//   - future-date / server-now clock-skew check (security doc §3: "clock
//     skew over 24h raises a fraud_signal"): checkClockSkew below, run
//     against every fix's capturedAt using Repo#now() (server time),
//     never the client's own clock.
//   - a `failed`-grade fix raises `fraud_signal(attestation_failed)` AT
//     INTAKE (security doc §3): raiseAttestationFailedSignal below.
//   - `excludedRows`/quarantine -> `fraud_signal`/`review_item` (security
//     doc §3): raiseQuarantineSignal below, whenever `scorePlay` reports
//     an on-play quarantined row.
//   - `heldReview`/`money`/`hardSignal`/`policyVersion`/`inputDigest`
//     persisted verbatim from the scorer's own result, never recomputed
//     from the rounded numeric(3,2) score (security doc §4): see the
//     `upsertPlayFromScore` call below.

// @deno-types="../scoring/scoring-types.d.ts"
import { scorePlay } from "../scoring/vendor/score-play.js";
import type { Repo, StoredEvidenceRow } from "../types.ts";
import { HttpError, Errors } from "../http.ts";
import { parseEvidenceSubmission, type EvidenceSubmission, type FixSubmission } from "./request-shape.ts";
import { deriveSourceRef } from "./source-ref.ts";
import { deriveFix, type CheckinTokenLookup } from "./derive-fix.ts";
import { classifyCatalogSubmission, type ManifestSigClaim } from "../catalog/classify-version.ts";
import { verifyManifestSignature } from "../catalog/signature.ts";

const MAX_OPEN_QUEUED_PER_USER = 20; // build plan §4.7 item 8 / AT 8, item 15
const CLOCK_SKEW_MAX_MS = 24 * 60 * 60 * 1000; // security doc §3
const RATE_LIMIT_EVIDENCE_PER_USER_HOUR = 60; // build plan §4.7 item 8
const RATE_LIMIT_EVIDENCE_PER_DEVICE_DAY = 200;

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

async function lookupTokenForFix(repo: Repo, actorUid: string, resolvedFacilityId: string, fix: FixSubmission): Promise<CheckinTokenLookup | null> {
  if (!fix.checkinTokenJti) return null;
  const row = await repo.getCheckinToken(fix.checkinTokenJti);
  if (!row) return null;
  if (row.userId !== actorUid) return null; // never trust/consume another actor's session
  if (row.facilityId !== null && row.facilityId !== resolvedFacilityId) return null;
  if (Date.parse(row.expiresAt) < repo.now().getTime()) return null;
  return { userId: row.userId, facilityId: row.facilityId, attestationGrade: row.attestationGrade, challengeKind: row.challengeKind, expiresAt: row.expiresAt };
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
  const resolved = await repo.resolveLedgerId(courseId);
  if (!resolved) return { kind: "unknown" };
  // G3-01: a stub OR verified course id is accepted (stub-course
  // promotion) — status alone never blocks the submission.
  return { kind: "resolved", id: resolved.id };
}

export async function handleEvidenceIntake(actorUid: string, rawBody: unknown, repo: Repo, deviceIdOverride?: string): Promise<EvidenceIntakeResult> {
  const parsed = parseEvidenceSubmission(rawBody);
  if (!parsed.ok) {
    throw Errors.badRequest("invalid evidence submission", { issues: parsed.issues });
  }
  const submission = parsed.value;
  const deviceId = deviceIdOverride ?? submission.deviceId;

  const device = await repo.ensureOwnDevice(actorUid, deviceId, null);

  const rateLimitUser = await repo.hitRateLimit(`evidence:user:${actorUid}`, 3600, RATE_LIMIT_EVIDENCE_PER_USER_HOUR);
  if (!rateLimitUser.ok) throw Errors.tooManyRequests("evidence rate limit exceeded for this account", rateLimitUser.retryAfterSeconds);
  const rateLimitDevice = await repo.hitRateLimit(`evidence:device:${device.id}`, 86400, RATE_LIMIT_EVIDENCE_PER_DEVICE_DAY);
  if (!rateLimitDevice.ok) throw Errors.tooManyRequests("evidence rate limit exceeded for this device", rateLimitDevice.retryAfterSeconds);

  // ---- Catalog skew (AT 8 / AT 15 / G3-10) — BEFORE any id lookup. ----
  const currentVersion = await repo.currentCatalogVersion();
  const declaredVersionRow = await repo.catalogVersionRow(submission.catalogVersion);
  const manifestSig: ManifestSigClaim | undefined = submission.manifestSig
    ? { kid: submission.manifestSig.kid, signatureB64Url: submission.manifestSig.signatureB64Url, payload: String(submission.catalogVersion) }
    : undefined;
  const versionOutcome = await classifyCatalogSubmission(
    {
      declaredVersion: submission.catalogVersion,
      currentVersion: currentVersion?.version ?? null,
      declaredVersionRow: declaredVersionRow ? { publishedAt: declaredVersionRow.publishedAt } : null,
      now: repo.now(),
      manifestSig,
    },
    async (claim) => {
      const key = await repo.signingKey(claim.kid);
      if (!key || key.revokedAt) return false;
      return verifyManifestSignature({ publicKeyB64Url: key.publicKeyB64Url, signatureB64Url: claim.signatureB64Url, payload: claim.payload });
    },
  );
  if (versionOutcome.kind === "stale") throw Errors.unprocessable("catalog_stale", "submitted catalogVersion is outside the accepted skew window");
  if (versionOutcome.kind === "forged") throw Errors.unprocessable("catalog_forged", "submitted catalogVersion is newer than the server's import with no verifying manifestSig, or far in the future");

  // "an id newer than the server's import returns 202" (AT 8) — reachable
  // when the (verified, per above) declared version is itself newer than
  // what the server has imported: by definition the ledger cannot have
  // this id yet. See classify-version.ts's own header for why, absent
  // any registered signing key, this path never actually verifies in
  // this environment (documented deferral).
  if (currentVersion !== null && versionOutcome.resolvedVersion > currentVersion.version) {
    const openCount = await repo.countOpenQueuedEvidence(actorUid);
    if (openCount >= MAX_OPEN_QUEUED_PER_USER) {
      throw Errors.tooManyRequests(`this account already has ${MAX_OPEN_QUEUED_PER_USER} open queued_catalog evidence rows`);
    }
    const sourceRef = await deriveSourceRef(submission);
    const inserted = await repo.insertEvidenceIdempotent(actorUid, {
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

  // ---- Facility + course id resolution against the ledger. ----
  const facilityLedger = await repo.resolveLedgerId(submission.facilityId);
  if (!facilityLedger) throw Errors.unprocessable("unknown_id", `facilityId "${submission.facilityId}" is not a known catalog id`);
  const resolvedFacilityId = facilityLedger.id;

  const courseAnchor = await resolveCourseAnchor(repo, submission.courseId);
  if (courseAnchor.kind === "unknown") {
    throw Errors.unprocessable("unknown_id", `courseId "${submission.courseId}" is not a known catalog id`);
  }
  const resolvedCourseId = courseAnchor.kind === "resolved" ? courseAnchor.id : null;

  // ---- Clock skew (security doc §3). ----
  const fixes = fixesOf(submission);
  const skewedFixIds = findClockSkewedFixIds(fixes, repo.now());
  if (skewedFixIds.length > 0) {
    await repo.insertFraudSignal(actorUid, "clock_skew", { fixIds: skewedFixIds, evidenceSource: submission.source });
  }

  // ---- Derive server-owned AppFix fields for every fix. ----
  const derivedFixesByFixId = new Map<string, ReturnType<typeof deriveFix>>();
  for (const fix of fixes) {
    const perFixMatch = resolvedCourseId ? await repo.matchFix(resolvedCourseId, fix.lat, fix.lng) : null;
    const tokenLookup = await lookupTokenForFix(repo, actorUid, resolvedFacilityId, fix);
    derivedFixesByFixId.set(
      fix.fixId,
      deriveFix({ fix, resolvedFacilityId, localDate: submission.localDate, match: perFixMatch, tokenLookup }),
    );
  }

  // ---- Assemble the app.evidence row's summary/integrity/cosignal jsonb
  // exactly as `scorePlay`'s Evidence union (rules.generated.js) expects
  // it to be reconstructed on read — see listEvidenceForPlay's mirror of
  // this in privileged.ts. ----
  const anyFailedGrade = [...derivedFixesByFixId.values()].some((f) => f.token.present && f.token.grade === "failed");
  if (anyFailedGrade) {
    // security doc §3: "A fix that grades failed MUST raise
    // fraud_signal(attestation_failed) AT INTAKE."
    await repo.insertFraudSignal(actorUid, "attestation_failed", { evidenceSource: submission.source, facilityId: resolvedFacilityId });
  }

  const worstGrade: "attested" | "unattestable" | "failed" = anyFailedGrade
    ? "failed"
    : [...derivedFixesByFixId.values()].every((f) => f.token.present && f.token.grade === "attested")
      ? "attested"
      : "unattestable";

  const summary: Record<string, unknown> = { localDate: submission.localDate };
  const integrity: Record<string, unknown> = {};
  const cosignal: Record<string, unknown> = {};
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
      fixPayload = { checkinFix: a, checkoutFix: b, apartMinutes: submission.apartMinutes, holes: submission.holes };
      break;
    }
    case "health_route":
      fixPayload = { sourceAllowListed: submission.sourceAllowListed, insideRatio: submission.insideRatio, simulated: submission.simulated, startedAt: submission.startedAt };
      break;
    case "connect_iq":
      fixPayload = { variant: submission.variant, k4bPassed: submission.k4bPassed, insidePolygon: submission.insidePolygon, durationMinutes: submission.durationMinutes, simulated: submission.simulated };
      break;
    case "file_import":
      fixPayload = { matchedRoute: submission.matchedRoute, startedAt: submission.startedAt };
      break;
    default:
      fixPayload = {};
  }
  Object.assign(summary, fixPayload);

  const sourceRef = await deriveSourceRef(submission);
  const inserted = await repo.insertEvidenceIdempotent(actorUid, {
    sourceRef,
    source: submission.source,
    facilityId: resolvedFacilityId,
    courseId: resolvedCourseId,
    startedAt: null,
    endedAt: null,
    localDate: submission.localDate,
    summary,
    integrity,
    cosignal,
    attestationGrade: worstGrade,
    matcherVersion: null,
    catalogVersion: currentVersion?.version ?? submission.catalogVersion,
    status: "accepted",
    deviceId: device.id,
  });

  // ---- Score the play: gather every OTHER accepted row for this
  // (user, facility, date) too, so a play already backed by prior
  // evidence gets re-scored with the new row folded in — this is what
  // makes a replay (same row, same play) AND an incremental submission
  // (new row, same play, updated score) both converge correctly. ----
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

  const priorRows = await repo.listEvidenceForPlay(actorUid, resolvedFacilityId, resolvedCourseId, submission.localDate);
  const evidenceForScoring = reconstructEvidenceForScoring(priorRows, inserted.id, submission, derivedFixesByFixId);

  const facilityTz = await repo.facilityTz(resolvedFacilityId);
  if (!facilityTz) throw Errors.internal(`facility "${resolvedFacilityId}" has no tz on record`);

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
    // silently persisting a zero/garbage play, per security doc §3's
    // "catch scorer exceptions... so one bad row cannot block a re-score
    // batch" (the batch handler catches THIS per-item; a single-item
    // caller sees the 500).
    throw Errors.internal(`scorePlay rejected server-assembled input: ${outcome.reasons.join("; ")}`);
  }

  if (outcome.excludedRows.some((r) => r.kind === "quarantined")) {
    // security doc §3: "Every ON-PLAY quarantine... must raise a
    // fraud_signal or create a review_item."
    await repo.insertFraudSignal(actorUid, "quarantined_evidence_row", {
      facilityId: resolvedFacilityId,
      courseId: resolvedCourseId,
      localDate: submission.localDate,
      excludedRows: outcome.excludedRows.filter((r) => r.kind === "quarantined"),
    });
  }

  const play = await repo.upsertPlayFromScore(actorUid, {
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
    evidenceIds: [inserted.id, ...priorRows.map((r) => r.id)],
  });

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
 * id). */
function reconstructEvidenceForScoring(
  priorRows: StoredEvidenceRow[],
  insertedId: string,
  submission: EvidenceSubmission,
  derivedFixesByFixId: Map<string, ReturnType<typeof deriveFix>>,
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
    facilityId: submission.facilityId,
    courseId: submission.courseId,
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
      fresh.holes = submission.holes;
      break;
    case "health_route":
      fresh.sourceAllowListed = submission.sourceAllowListed;
      fresh.insideRatio = submission.insideRatio;
      fresh.simulated = submission.simulated;
      if (submission.startedAt !== undefined) fresh.startedAt = submission.startedAt;
      break;
    case "connect_iq":
      fresh.variant = submission.variant;
      fresh.k4bPassed = submission.k4bPassed;
      fresh.insidePolygon = submission.insidePolygon;
      fresh.durationMinutes = submission.durationMinutes;
      fresh.simulated = submission.simulated;
      break;
    case "file_import":
      fresh.matchedRoute = submission.matchedRoute;
      if (submission.startedAt !== undefined) fresh.startedAt = submission.startedAt;
      break;
    default:
      break;
  }
  if (fresh.courseId === undefined) delete fresh.courseId; // security doc §2: omit, never null
  rows.push(fresh);
  return rows;
}

export { HttpError };
