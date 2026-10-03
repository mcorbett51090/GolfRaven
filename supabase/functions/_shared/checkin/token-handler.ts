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
// ATTESTATION (build plan §4.5 G3-08, §7.5): the request may carry an App Attest assertion (iOS) or a Play Integrity token
// (Android), verified here with the SAME verifiers `rewards-activate` uses (rewards/app-attest.ts, rewards/play-integrity.ts) but over
// a DIFFERENT binding — the check-in binding (rewards/binding.ts#CHECKIN_TOKEN_PURPOSE, `computeCheckinAndroidBinding`,
// rewards/string-binding.ts#computeIosCheckinBinding): purpose "golfraven/checkin-token/v1", the challenge id, the device the challenge was
// issued to, the account, and the raw nonce. An activation or key-registration attestation therefore cannot verify as a check-in, nor the reverse.
//
// GRADING, exactly as §4.5 G3-08 reads:
//   - a VALID attestation over the binding -> `attested`. iOS means: the key is the one registered (0034) on THIS user's device, the
//     signature verifies, `rpIdHash` is the app's, the counter is strictly greater than the stored one, and the stored counter is advanced
//     atomically by `Repo#rewards.advanceAttestCounter` (the activation path's own mechanism: `UPDATE ... WHERE attest_key_id = $key AND
//     attest_counter < $new`; zero rows is a replay, a lost race, or a replaced key, and grades `failed`, never `attested`). Android means:
//     Play Integrity's decoded verdict carries our `requestHash`, our package, an allowed certificate digest, `MEETS_DEVICE_INTEGRITY`, a
//     recognised app and a fresh timestamp.
//   - an attestation PRESENTED but not valid -> `failed`, and `fraud_signal(attestation_failed)` is opened the way activation opens it
//     (`Repo#rewards.raiseAttestationFailedIfNone`: one OPEN signal per account, serialised, detail = reasons, no key material or token).
//     The challenge is consumed first and the failure is RETURNED as a graded token (never thrown), so the transaction commits and a failed
//     attempt spends its challenge: there is no free second guess on one nonce. A device with NO registered key (iOS) answers `unattestable`
//     (`key_not_registered`), as activation does — a missing key is never `attested`, and never reads as tampering.
//   - NO attestation -> `failed` when `hardwareSupportsAttestation`, otherwise `unattestable` (unchanged; the standing self-report gap of
//     docs/security/p3-money-path-requirements.md follow-up 9 is closed only for clients that send an attestation).
//   - VENDOR / TRANSPORT errors NEVER grade `failed`. Play Integrity unreachable, rate-limited or answering 5xx, or a deployment with no
//     Play/App Attest configuration, throws a 503 (`attestation_unavailable` / `attestation_not_configured`) — the activation path's own
//     choice (activate-handler.ts#mapVendorError): the transaction rolls back, so the challenge is NOT consumed, no token is issued and no
//     signal is raised, and a retry is safe. (Grading `unattestable` instead would have let an outage mint tokens that count as co-signals
//     and route money to review; refusing is the conservative reading and the only one that cannot misgrade an honest device.) Only an
//     explicit rejection by the vendor of the token itself (Google's 400 "cannot decode") is `failed`.
//
// A token is ALWAYS issued once the challenge is consumed (graded `attested`, `unattestable` or `failed`): `failed` is not a refusal, it is
// the grade (§4.5: a `failed` fix is never a co-signal). The only non-2xx outcomes are the 4xx for a bad challenge/nonce/shape, the 429, and
// the two 503s above.
//
// ⚠ LIVE VERIFICATION IS NOT EXERCISED against Apple or Google (no device, credentials or route in the build environment); the verifiers are
// proven against assertions and verdicts this repo's tests construct (see rewards/app-attest.ts, play-integrity.ts for what is `[unverified]`).
//
// IDEMPOTENT REDEMPTION. A client whose response was lost retries the same request and must not lose its co-signal to `challenge_used`.
// A repeat redemption of an ALREADY-CONSUMED challenge, by the same account (every Repo method is actor-scoped), presenting the same nonce
// (its SHA-256 equals the stored hash; the device is the challenge's own, so "same device" is implied), while the token that redemption
// issued is still valid (unexpired and not yet consumed by a fix), returns THAT token: the original jti, expiry and grade, with the same
// success status. Nothing is re-verified, re-graded, re-counted or re-signalled (so an iOS assertion with a repeat counter is NOT a counter
// failure here: the replay never reaches the verifier), and a stronger attestation in the repeat can never upgrade a `failed` or
// `unattestable` first grade (nor a weaker one downgrade an `attested`). Anything else about a used challenge — another account, a different
// nonce, no token, a token that expired or was consumed — stays `422 challenge_used`. The concurrent case is covered too: a request that
// loses the atomic consume to an identical one answers with the winner's token.
//
// THE NO-ATTESTATION RULE (the capability claim NARROWED for honest clients, not closed). `hardwareSupportsAttestation` is a self-report, so
// "I cannot attest" proves nothing about a device that HAS attested. A request with no attestation grades `failed`, whatever it claims, when this
// account's device row has shown it can attest: iOS = a REGISTERED App Attest key (`Repo#rewards.deviceAttestState` returns a key only for a
// verified registration, 0034); either platform = a token previously issued on the device graded `attested` (`Repo#checkinToken.hasAttestedOnDevice`)
// or an activation verdict of `attested` recorded on it (`Repo#rewards.hasAttestedVerdictOnDevice`, 0043). The rule is ONE function shared with
// rewards-activate (rewards/attestation-evidence.ts#gradeNoAttestation). Otherwise the claim decides, as before.
// ⚠ The evidence is bound to the DEVICE ID, which the client chooses (up to 20 per account): an attacker claims "incapable" on a device id that
// has never attested and gets `unattestable` instead of `failed`. That is not closed (see docs/security/p3-money-path-requirements.md,
// "Attestation follow-ups", where the account-level variant is evaluated and left as an owner decision). Cost to an honest client: once a device
// has shown it can attest, a check-in that omits the attestation is `failed` (and raises the signal); the client must send one, or accept that.
// The signal is opened the same way as for a presented attestation (`raiseAttestationFailedIfNone`: one OPEN signal per account, serialised).
//
// STALE-KEY RECOVERY (the `rekey` hint). The grade is all the client used to learn, so an honest device whose local App Attest key is not the one the server
// holds (a database restore, an admin key reset, a lost registration write) was graded `failed` on every check-in, forever, and could not tell that
// from a replay. When an iOS assertion is refused for a KEY-IDENTITY reason only (`key_id_mismatch`: the key it names is not the one registered for this
// user's device; `key_not_registered`: none is registered), the answer carries `rekey: true`. It is absent on every other answer: counter replay or
// out of order, a bad signature, a wrong rpId, a binding that does not hash, a malformed assertion, a key replaced mid-flight, `attested`, and the
// no-attestation `unattestable` / `failed`. The grade, the spent challenge and the fraud signal are exactly as before (`failed` still raises
// `attestation_failed`, reasons `["key_id_mismatch"]`, so a reviewer sees it; `key_not_registered` stays `unattestable`, no signal). The recovery is
// `POST /v1/devices/attest-key` with a freshly generated key (replacement, counter restarts at 0). Why the hint leaks nothing, and what it does not
// recover: docs/security/p3-money-path-requirements.md, "Stale App Attest key recovery (the `rekey` hint)".
//
// OUT-OF-ORDER ASSERTIONS. The App Attest counter is shared by `checkin-token` and `rewards-activate` and is strictly monotonic. Two assertions of
// one key in flight at once can commit out of order; the lower one then grades `failed` (never `attested`, strictness is unchanged) with the reason
// `counter_out_of_order` rather than `counter_replay`, so a reviewer can tell an honest client's race from a replay. The mobile client's contract is
// one assertion in flight per key across BOTH endpoints (docs/security/p3-money-path-requirements.md, "Attestation follow-ups").
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
import { Errors, HttpError } from "../http.ts";
import { computeCheckinAndroidBinding, fromBase64UrlStrict, toBase64Url, type Sha256Fn } from "../rewards/binding.ts";
import { computeIosCheckinBinding } from "../rewards/string-binding.ts";
import { VendorForbiddenError, VendorNotConfiguredError, VendorUnavailableError, type Grade } from "../rewards/types.ts";
import { logVendorFault } from "../rewards/vendor-log.ts";
import type { VerificationPorts } from "../rewards/verification-ports.ts";
import { gradeNoAttestation, isKeyIdentityReason, lostAdvanceReason, noAttestationReasons } from "../rewards/attestation-evidence.ts";
import type { CheckinAttestation, TokenRequest } from "./token-request-shape.ts";

export type { CheckinAttestation, TokenRequest } from "./token-request-shape.ts";

const TOKEN_TTL_SECONDS = 15 * 60; // generous enough to cover a full round's checkin/evidence flow within one QR session
// P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock the
// pool"): exported so checkin-token/index.ts can hit this bucket via
// `privileged.ts#hitRateLimitForActor` BEFORE calling `withOwnership` —
// see this file's own `handleTokenRequest` for why the hit no longer
// happens in here.
export const RATE_LIMIT_PER_USER_HOUR = 60; // should-fix (P3c gate round 2): "add one on checkin-token"

export interface IssuedToken {
  jti: string;
  expiresAt: string;
  attestationGrade: "attested" | "unattestable" | "failed";
  /** Present (and always `true`) ONLY on the answer to an iOS check-in whose presented assertion named a key that is not the one registered for this
   * (user, device), or when no key is registered at all: the client's local App Attest key is stale, and registering a fresh one
   * (`POST /v1/devices/attest-key`) is what recovers. Absent on every other answer, including every other `failed` one. It is never persisted:
   * a repeat redemption of the same challenge (idempotent redemption) answers the original token WITHOUT it. */
  rekey?: true;
}

export interface DigestHexFn {
  (bytes: Uint8Array): Promise<string>;
}

/** What verifying a presented attestation needs, injected (production: checkin-token/index.ts from privileged.ts's configuration; tests:
 * scripted ports). Absent, or a `null` port for the presented platform, means "not configured": a request that carries an attestation then
 * fails closed (503) before the challenge is touched; a request that carries none is unaffected. */
export interface CheckinAttestationDeps {
  /** The authenticated account's id (the JWT `sub`), bound into what the attestation commits to. It is NOT used to address any row (every
   * Repo method is already scoped to the actor), so a wrong value can only make a verification fail, never reach another account's data. */
  userId: string;
  ports: VerificationPorts;
  sha256: Sha256Fn;
}

function fromBase64Url(b64url: string): Uint8Array {
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

const fail503 = (code: "attestation_not_configured" | "attestation_unavailable", message: string) => new HttpError(503, code, message);

/** Vendor error -> the HTTP error the handler throws (activate-handler.ts#mapVendorError's twin). NotConfigured and Unavailable are both 503:
 * fail closed, the transaction rolls back (the challenge is not consumed, nothing is written), safe to retry. Anything else is not ours to
 * interpret and propagates. NEITHER is ever graded `failed`. */
function mapVendorError(e: unknown): unknown {
  if (e instanceof VendorForbiddenError) {
    // Google's 403 on the decode: ours or the caller's (a token from another app) `[unverified]`. Same 503 and the same non-grading as NotConfigured
    // (a subtype), but logged at warn level and rate-limited, never as "our credentials are wrong": any account can send such a token.
    logVendorFault("checkin-token", "decode_forbidden", e.message);
    return fail503("attestation_not_configured", "device attestation is not available on this deployment; no check-in token was issued");
  }
  if (e instanceof VendorNotConfiguredError) {
    console.error("checkin-token: attestation vendor is not configured:", e.message);
    return fail503("attestation_not_configured", "device attestation is not available on this deployment; no check-in token was issued");
  }
  if (e instanceof VendorUnavailableError) {
    console.error("checkin-token: attestation vendor unavailable:", e.message);
    return fail503("attestation_unavailable", "device attestation is temporarily unavailable; no check-in token was issued — retry");
  }
  return e;
}

interface AttestationVerdict {
  grade: Grade;
  reasons: string[];
  /** The refusal was a key-identity one (attestation-evidence.ts#isKeyIdentityReason). Only the iOS verifier-refusal path can set it. */
  rekey: boolean;
}

/** Verifies a PRESENTED attestation over the check-in binding. Runs after the challenge was consumed, inside the transaction. */
async function gradePresentedAttestation(
  att: CheckinAttestation,
  challenge: { id: string; deviceId: string },
  nonce: { text: string; bytes: Uint8Array },
  repo: Repo,
  deps: CheckinAttestationDeps,
): Promise<AttestationVerdict> {
  const bound = { challengeId: challenge.id, deviceId: challenge.deviceId, userId: deps.userId };

  if (att.platform === "ios") {
    const port = deps.ports.ios;
    if (!port) throw fail503("attestation_not_configured", "iOS device attestation is not configured on this deployment; no check-in token was issued");
    // The device the challenge was issued to, read through the actor-scoped Repo: another account's device (and its key) is not visible here.
    const device = await repo.rewards.deviceAttestState(challenge.deviceId);
    if (!device) throw Errors.internal();
    const clientDataHash = await computeIosCheckinBinding(deps.sha256, { ...bound, nonce: nonce.text });
    const verdict = await port.verifyAssertion({ assertionB64: att.assertion, keyId: att.keyId, clientDataHash, device });
    if (!verdict.ok) return { grade: verdict.grade, reasons: [verdict.reason], rekey: isKeyIdentityReason(verdict.reason) };
    // Atomic, monotonic and key-bound (the activation path's own statement): a replayed or racing counter does not advance, and neither does an
    // assertion whose key was replaced after `deviceAttestState` read it. Zero rows is `failed`, never `attested`.
    if (device.attestKeyId !== null && (await repo.rewards.advanceAttestCounter(challenge.deviceId, device.attestKeyId, verdict.counter))) {
      return { grade: "attested", reasons: [], rekey: false };
    }
    // A lost advance (counter replay / out of order / key replaced mid-flight) is about THIS assertion: never a rekey hint.
    return { grade: "failed", reasons: [await lostAdvanceReason(challenge.deviceId, device.attestKeyId, verdict.counter, repo)], rekey: false };
  }

  const port = deps.ports.android;
  if (!port) throw fail503("attestation_not_configured", "Android device attestation is not configured on this deployment; no check-in token was issued");
  const binding = await computeCheckinAndroidBinding(deps.sha256, bound, nonce.bytes);
  const verdict = await port.verifyIntegrity({ integrityToken: att.integrityToken, expectedRequestHash: toBase64Url(binding), nowMs: repo.now().getTime() });
  return { grade: verdict.grade, reasons: verdict.grade === "failed" ? verdict.reasons : [], rekey: false };
}

/** The idempotent-redemption lookup (see the header). `null` unless EVERY condition holds: the presented nonce hashes to the challenge's
 * stored hash (a different nonce never learns anything), a token exists for the challenge, it is not consumed, and it has not expired.
 * Pure read: it writes nothing, verifies nothing, and raises nothing. */
async function originalTokenForRepeat(
  challenge: { id: string; nonceHash: string },
  presentedNonce: string,
  repo: Repo,
  digestHex: DigestHexFn,
): Promise<IssuedToken | null> {
  let presentedHash: string;
  try {
    presentedHash = await digestHex(fromBase64Url(presentedNonce));
  } catch {
    return null; // an undecodable nonce is not a repeat of anything
  }
  if (presentedHash !== challenge.nonceHash) return null;
  const token = await repo.checkinToken.findByChallenge(challenge.id);
  if (!token || token.consumedAt !== null || !(Date.parse(token.expiresAt) > repo.now().getTime())) return null;
  return { jti: token.jti, expiresAt: token.expiresAt, attestationGrade: token.attestationGrade };
}

export async function handleTokenRequest(body: TokenRequest, repo: Repo, digestHex: DigestHexFn, attest?: CheckinAttestationDeps): Promise<IssuedToken> {
  // ⛔ P3c gate round 4, blocking HIGH ("5 concurrent requests deadlock
  // the pool"): the rate-limit hit used to happen HERE, via
  // `repo.rateLimit.hit` — removed. `Repo` no longer has a `rateLimit`
  // member at all (types.ts). checkin-token/index.ts now hits
  // `checkin-token:user` via `hitRateLimitForActor` BEFORE calling
  // `withOwnership`, so this function is only ever reached once that has
  // already succeeded.
  const challenge = await repo.challenge.getOwn(body.challengeId);
  if (!challenge) throw Errors.notFound("no such challenge for this account");
  if (challenge.usedAt !== null) {
    const original = await originalTokenForRepeat(challenge, body.nonce, repo, digestHex);
    if (original) return original;
    throw Errors.unprocessable("challenge_used", "this challenge has already been consumed");
  }
  if (Date.parse(challenge.expiresAt) < repo.now().getTime()) throw Errors.unprocessable("challenge_expired", "this challenge has expired");

  const att = body.attestation;
  let nonceBytes: Uint8Array;
  if (att) {
    // The nonce is bound into the iOS string `S` as TEXT and into the Android hash as BYTES, so several spellings of one consumed nonce would
    // be several different bindings of it: an attestation requires the one canonical spelling (rewards/binding.ts#fromBase64UrlStrict).
    const strict = fromBase64UrlStrict(body.nonce);
    if (!strict) throw Errors.badRequest("nonce must be unpadded, canonical base64url");
    nonceBytes = strict;
    // Fail closed BEFORE the challenge is touched when this platform cannot be verified here at all.
    if (!(att.platform === "ios" ? attest?.ports.ios : attest?.ports.android)) {
      throw fail503("attestation_not_configured", "device attestation is not available on this deployment; no check-in token was issued");
    }
  } else {
    try {
      nonceBytes = fromBase64Url(body.nonce);
    } catch {
      throw Errors.badRequest("nonce must be unpadded base64url");
    }
  }
  const nonceHash = await digestHex(nonceBytes);

  const consumed = await repo.challenge.consume(body.challengeId, nonceHash);
  if (!consumed) {
    // Lost the atomic consume to an IDENTICAL request (same nonce): answer with the winner's token, exactly as a later repeat would.
    const original = await originalTokenForRepeat(challenge, body.nonce, repo, digestHex);
    if (original) return original;
    // Either lost the race against a concurrent consumer of the SAME
    // challenge (single-use), or the presented nonce didn't hash-match —
    // both collapse to the same outer signal on purpose (an attacker
    // guessing challenge ids should not be able to distinguish "wrong
    // nonce" from "already consumed" from the response).
    throw Errors.unprocessable("challenge_not_consumable", "this challenge could not be consumed (already used, expired, or the nonce did not match)");
  }

  let attestationGrade: Grade;
  let rekey = false;
  if (att) {
    let verdict: AttestationVerdict;
    try {
      verdict = await gradePresentedAttestation(att, challenge, { text: body.nonce, bytes: nonceBytes }, repo, attest!);
    } catch (e) {
      throw mapVendorError(e);
    }
    attestationGrade = verdict.grade;
    rekey = verdict.rekey;
    // 0042: a VERIFIED attestation is a platform-bearing use: it labels a device whose platform is still unknown (a device first seen by
    // checkin-challenge or evidence). First wins; an already-set platform is left as it is and nothing is refused here (the attestation block
    // names its own platform, and the token does not depend on the column). An unverified block labels nothing.
    if (verdict.grade === "attested") await repo.device.claimPlatform(challenge.deviceId, att.platform);
    if (verdict.grade === "failed") {
      // Opened the way activation opens it, in the same transaction that records the attempt (security doc §3). Reasons are fixed
      // vocabulary words (never key material or the token).
      await repo.rewards.raiseAttestationFailedIfNone({ challengeId: challenge.id, deviceId: challenge.deviceId, platform: att.platform, reasons: verdict.reasons, source: "checkin-token" });
    }
  } else {
    // G3-08's "no token" rule (rewards/attestation-evidence.ts#gradeNoAttestation, shared with rewards-activate): `failed` on hardware that
    // supports attestation, otherwise `unattestable`; the claim counts only when the server has no evidence to the contrary for this device.
    const verdict = await gradeNoAttestation(body.hardwareSupportsAttestation, challenge.deviceId, repo);
    attestationGrade = verdict.grade;
    if (verdict.grade === "failed") {
      // Deduplicated like the presented-attestation path (one OPEN signal per account, serialised), and in the same vocabulary as activation.
      // `platform` is null: no attestation block names one.
      await repo.rewards.raiseAttestationFailedIfNone({
        challengeId: challenge.id,
        deviceId: challenge.deviceId,
        platform: null,
        reasons: noAttestationReasons(verdict),
        source: "checkin-token",
      });
    }
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
  // The key-identity hint rides on the answer only, never on the stored token (no schema change): see `IssuedToken#rekey`.
  return rekey ? { jti: issued.jti, expiresAt: issued.expiresAt, attestationGrade, rekey: true } : { jti: issued.jti, expiresAt: issued.expiresAt, attestationGrade };
}
