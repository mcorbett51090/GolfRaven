// supabase/functions/_shared/checkin/token-handler.ts
//
// Pure, DI'd core of the `checkin-token` Edge Function (build plan §4.7.1a:
// "checkin-token issues the QR session and the rotating JWT. It moved out
// of the RPC allowlist because it must verify attestation, sign, and
// record a jti"). Consumes a single-use `app.checkin_challenge` row
// (atomically, via `Repo#consumeChallenge`) and issues an
// `app.checkin_token` row — the session token later `POST /v1/evidence`
// fixes reference via `checkinTokenJti` (evidence/derive-fix.ts).
//
// ⛔ STUB, clearly marked (task instruction: attestation is explicitly
// OUT OF SCOPE this round): real App Attest / Play Integrity verification
// does not exist in this environment. §4.5 G3-08's own rule is applied
// EXACTLY as written for "no token": "on hardware that supports
// attestation it is failed, and otherwise unattestable" — since this
// round has no way to verify ANY presented attestation token as genuine,
// every call is treated as the "no token" case, using the caller's own
// `hardwareSupportsAttestation` claim (the one part of this that a real
// client CAN honestly self-report even before real attestation
// verification exists — the platform capability check itself, not a
// signed assertion). This can never produce `grade: "attested"` — the
// money-path's own hard-class weight (0.95, staff_presence-with-co-signal)
// and the `unattestable`-routes-to-held_review rule are exactly the
// SAFE side of that: nothing this round can OVER-grant, only under-grant
// relative to a build with real attestation wired in.

import type { Repo } from "../types.ts";
import { Errors } from "../http.ts";

const TOKEN_TTL_SECONDS = 15 * 60; // generous enough to cover a full round's checkin/evidence flow within one QR session

export interface TokenRequest {
  challengeId: string;
  hardwareSupportsAttestation: boolean;
}

export interface IssuedToken {
  jti: string;
  expiresAt: string;
  attestationGrade: "attested" | "unattestable" | "failed";
}

export async function handleTokenRequest(actorUid: string, body: TokenRequest, repo: Repo): Promise<IssuedToken> {
  const challenge = await repo.getOwnChallenge(body.challengeId, actorUid);
  if (!challenge) throw Errors.notFound("no such challenge for this account");
  if (challenge.usedAt !== null) throw Errors.unprocessable("challenge_used", "this challenge has already been consumed");
  if (Date.parse(challenge.expiresAt) < repo.now().getTime()) throw Errors.unprocessable("challenge_expired", "this challenge has expired");

  const consumed = await repo.consumeChallenge(body.challengeId);
  if (!consumed) {
    // Lost the race against a concurrent consumer of the SAME challenge —
    // single-use, so this is a 409, not a 422 (the challenge was valid;
    // it just isn't available to consume any more).
    throw Errors.unprocessable("challenge_already_consumed", "this challenge was consumed by a concurrent request");
  }

  // G3-08's "no token" rule, applied deliberately (see this module's own
  // header): every submission this round IS the "no token" case.
  const attestationGrade: "attested" | "unattestable" | "failed" = body.hardwareSupportsAttestation ? "failed" : "unattestable";
  if (attestationGrade === "failed") {
    await repo.insertFraudSignal(actorUid, "attestation_failed", { challengeId: body.challengeId, reason: "hardware_supports_attestation_but_no_verified_token" });
  }

  // Live-vs-prefetched: derived from the challenge's own TTL width (this
  // repo's checkin_challenge has no separate "kind" column — see
  // types.ts's own doc on this simplification). A short-TTL challenge
  // (issued by handleChallengeRequest's live branch) maps to "live"; a
  // long-TTL one (the prefetch branch) maps to "prefetched".
  const ttlMs = Date.parse(challenge.expiresAt) - repo.now().getTime();
  const challengeKind: "live" | "prefetched" = ttlMs > 60 * 60 * 1000 ? "prefetched" : "live";

  const expiresAt = new Date(repo.now().getTime() + TOKEN_TTL_SECONDS * 1000).toISOString();
  const issued = await repo.insertCheckinToken({
    challengeId: body.challengeId,
    userId: actorUid,
    deviceId: challenge.deviceId,
    facilityId: challenge.facilityId,
    attestationGrade,
    challengeKind,
    expiresAt,
  });
  return { jti: issued.jti, expiresAt: issued.expiresAt, attestationGrade };
}
