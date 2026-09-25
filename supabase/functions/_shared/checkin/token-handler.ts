// supabase/functions/_shared/checkin/token-handler.ts
//
// Pure, DI'd core of the `checkin-token` Edge Function (build plan §4.7.1a:
// "checkin-token issues the QR session and the rotating JWT. It moved out
// of the RPC allowlist because it must verify attestation, sign, and
// record a jti"). Consumes a single-use `app.checkin_challenge` row
// (atomically, via `Repo#challenge.consume`) and issues an
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
// relative to a build with real attestation wired in. Recorded again in
// "Accepted follow-ups" (P3c gate round 2): this is a genuine, standing
// gap, not merely a one-time note.
//
// P3c gate round 2 fixes:
//   - should-fix "nonce": the caller must now present the RAW nonce
//     (from POST /v1/checkin/challenge's own response) and
//     `Repo#challenge.consume` requires its hash to match the stored one
//     — a challenge id alone is no longer sufficient to consume it.
//   - should-fix "challenge kind": pulled straight from
//     `app.checkin_challenge.kind` (a real column, 0019) rather than
//     inferred from TTL width.
//   - should-fix "rate limit": a per-user hourly limit, same shape as
//     every other write endpoint this round.

import type { Repo } from "../types.ts";
import { Errors } from "../http.ts";

const TOKEN_TTL_SECONDS = 15 * 60; // generous enough to cover a full round's checkin/evidence flow within one QR session
const RATE_LIMIT_PER_USER_HOUR = 60; // should-fix (P3c gate round 2): "add one on checkin-token"

export interface TokenRequest {
  challengeId: string;
  /** The RAW nonce POST /v1/checkin/challenge returned — proves
   * possession of that specific challenge, not just knowledge of its id
   * (should-fix, P3c gate round 2). */
  nonce: string;
  hardwareSupportsAttestation: boolean;
}

export interface IssuedToken {
  jti: string;
  expiresAt: string;
  attestationGrade: "attested" | "unattestable" | "failed";
}

export interface DigestHexFn {
  (bytes: Uint8Array): Promise<string>;
}

function fromBase64Url(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export async function handleTokenRequest(body: TokenRequest, repo: Repo, digestHex: DigestHexFn): Promise<IssuedToken> {
  const rateLimit = await repo.rateLimit.hit(`checkin-token:user`, 3600, RATE_LIMIT_PER_USER_HOUR);
  if (!rateLimit.ok) throw Errors.tooManyRequests("checkin-token rate limit exceeded", rateLimit.retryAfterSeconds);

  const challenge = await repo.challenge.getOwn(body.challengeId);
  if (!challenge) throw Errors.notFound("no such challenge for this account");
  if (challenge.usedAt !== null) throw Errors.unprocessable("challenge_used", "this challenge has already been consumed");
  if (Date.parse(challenge.expiresAt) < repo.now().getTime()) throw Errors.unprocessable("challenge_expired", "this challenge has expired");

  let nonceBytes: Uint8Array;
  try {
    nonceBytes = fromBase64Url(body.nonce);
  } catch {
    throw Errors.badRequest("nonce must be unpadded base64url");
  }
  const nonceHash = await digestHex(nonceBytes);

  const consumed = await repo.challenge.consume(body.challengeId, nonceHash);
  if (!consumed) {
    // Either lost the race against a concurrent consumer of the SAME
    // challenge (single-use), or the presented nonce didn't hash-match —
    // both collapse to the same outer signal on purpose (an attacker
    // guessing challenge ids should not be able to distinguish "wrong
    // nonce" from "already consumed" from the response).
    throw Errors.unprocessable("challenge_not_consumable", "this challenge could not be consumed (already used, expired, or the nonce did not match)");
  }

  // G3-08's "no token" rule, applied deliberately (see this module's own
  // header): every submission this round IS the "no token" case.
  const attestationGrade: "attested" | "unattestable" | "failed" = body.hardwareSupportsAttestation ? "failed" : "unattestable";
  if (attestationGrade === "failed") {
    await repo.fraudSignal.insert("attestation_failed", { challengeId: body.challengeId, reason: "hardware_supports_attestation_but_no_verified_token" });
  }

  const expiresAt = new Date(repo.now().getTime() + TOKEN_TTL_SECONDS * 1000).toISOString();
  const issued = await repo.checkinToken.insert({
    challengeId: body.challengeId,
    deviceId: challenge.deviceId,
    facilityId: challenge.facilityId,
    attestationGrade,
    challengeKind: challenge.kind,
    expiresAt,
  });
  return { jti: issued.jti, expiresAt: issued.expiresAt, attestationGrade };
}
