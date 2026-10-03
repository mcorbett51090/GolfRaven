// supabase/functions/_shared/rewards/attest-key-handler.ts
//
// Pure, DI'd core of `POST /v1/devices/attest-key` (Edge Function `devices-attest-key`; build plan §7.5;
// follow-up F2 of the P3f section of docs/security/p3-money-path-requirements.md): App Attest KEY
// REGISTRATION. The app calls `DCAppAttestService.generateKey()`, then `attestKey(keyId, clientDataHash)`
// with a hash that binds a server challenge, and sends the resulting attestation object here. This
// handler verifies it (app-attest-registration.ts: Apple's chain, nonce, key id, app id, counter, aaguid)
// and records the key on the caller's OWN device (`app.register_attest_key`, 0034). From then on
// rewards-activate can verify that device's assertions, and an iOS activation can grade `attested`.
//
// Everything is injected: the `Repo` (already scoped to the actor — no method takes a user id), the
// verifier (production: built in index.ts from privileged.ts's configuration, with the trust anchor pinned
// in code; tests: a throw-away root) and SHA-256. So it runs identically under vitest (fake repo), under
// Deno against a real Postgres (the integration suite), and in production.
//
// ORDER (each step fails closed, and nothing is written before the device is proven the caller's own):
//   0. unconfigured (no Apple team/bundle/environment) -> 503 before anything is read or written;
//   1. the device must be the caller's own iOS device (a foreign or unknown id is the same 422 as a bad
//      challenge: there is no existence oracle) and must not already hold THIS key (409, nothing consumed);
//   2. the challenge is consumed: live, single-use, bound to this device and this user, 120 s — the SAME
//      check rewards-activate uses (activate-handler.ts#consumeLiveChallenge);
//   3. the attestation is verified against clientDataHash = SHA-256(UTF-8(S)), S a canonical JSON string carrying the nonce as text;
//   4. on success the key is registered (a first registration, or the replacement a reinstall needs).
//
// A VERIFICATION FAILURE IS NOT AN EXCEPTION: it is returned as `{ ok: false }` AFTER the challenge was
// consumed, so the request still commits — a challenge is spent by a failed attempt, never reusable to
// probe the verifier with a second guess. (A thrown error rolls the transaction back, which would give an
// attacker free retries on one challenge.) The reason goes to the server log only; the client sees one
// generic 422 `attestation_rejected`. A failed registration deliberately raises NO fraud signal: an honest
// build/configuration mismatch (a development build against a production deployment: a wrong aaguid) is the
// likeliest cause, and an account-wide `attestation_failed` signal would hold every reward the account has;
// the device simply stays `unattestable` and held, as it is today.

import { Errors, HttpError } from "../http.ts";
import type { Repo } from "../types.ts";
import { consumeLiveChallenge } from "./activate-handler.ts";
import { type AttestationRegistrationVerifier, computeAttestKeyBinding } from "./app-attest-registration.ts";
import type { Sha256Fn } from "./binding.ts";
import type { AttestKeyRequest } from "./attest-key-request.ts";

/** Build plan §4.7 item 8 has no row for key registration; these follow the activation endpoint's shape
 * (`[no plan-stated number]`). A reinstall registers once; the budget leaves room for honest retries. */
export const RATE_LIMIT_PER_USER_HOUR = 10;
export const RATE_LIMIT_PER_DEVICE_DAY = 10;

export interface RateLimitFn {
  (bucketKey: string, windowSeconds: number, max: number): Promise<{ ok: boolean; retryAfterSeconds?: number }>;
}

/** Called by the entrypoint BEFORE `withOwnership` opens (privileged.ts#hitRateLimitForActor must never run
 * from inside a transaction — P3c gate round 4). The user bucket is hit first and short-circuits. */
export async function enforceAttestKeyRateLimits(hit: RateLimitFn, deviceId: string): Promise<{ ok: true } | { ok: false; retryAfterSeconds?: number }> {
  const user = await hit("devices-attest-key:user", 3_600, RATE_LIMIT_PER_USER_HOUR);
  if (!user.ok) return { ok: false, retryAfterSeconds: user.retryAfterSeconds };
  const device = await hit(`devices-attest-key:device:${deviceId}`, 86_400, RATE_LIMIT_PER_DEVICE_DAY);
  if (!device.ok) return { ok: false, retryAfterSeconds: device.retryAfterSeconds };
  return { ok: true };
}

export type AttestKeyHandlerRepo = Pick<Repo, "now" | "challenge" | "attestKey" | "device">;

export interface AttestKeyDeps {
  /** `null` = App Attest registration is not configured on this deployment (503). */
  verifier: AttestationRegistrationVerifier | null;
  sha256: Sha256Fn;
}

export type AttestKeyOutcome =
  | { ok: true; status: 200 | 201; body: { deviceId: string; keyId: string; replaced: boolean } }
  | { ok: false; status: 422; code: "attestation_rejected"; message: string };

export async function handleAttestKey(req: AttestKeyRequest, repo: AttestKeyHandlerRepo, deps: AttestKeyDeps): Promise<AttestKeyOutcome> {
  // 0. Fail closed when unconfigured: before any read or write.
  if (!deps.verifier) {
    throw new HttpError(503, "attestation_not_configured", "App Attest key registration is not available on this deployment");
  }

  // 1. The caller's own iOS device.
  const device = await repo.attestKey.deviceKey(req.deviceId);
  if (!device) {
    // The same answer as an unusable challenge: a foreign device id and a nonexistent one look alike.
    throw Errors.unprocessable("challenge_not_consumable", "this challenge could not be used (already used, expired, or not issued to this device)");
  }
  // A device with an unknown platform (0042: first seen by checkin-challenge or evidence) may register a key: its platform becomes iOS below,
  // once the attestation has VERIFIED. An Android device is refused, as before.
  if (device.platform !== null && device.platform !== "ios") throw Errors.unprocessable("platform_mismatch", "App Attest is available on iOS devices only");
  if (device.keyId === req.keyId) {
    throw Errors.conflict("key_already_registered", "this key is already registered on this device");
  }

  // 2. The challenge: live, single-use, bound to this device and user.
  await consumeLiveChallenge({ challengeId: req.challengeId, nonce: req.nonce }, req.deviceId, repo, deps.sha256);

  // 3. The attestation, over the hash the SERVER computes from ITS challenge: SHA-256 of a canonical STRING that carries
  //    the nonce as text (string-binding.ts: a React Native client can only hash a string). The nonce string was just
  //    consumed against the stored hash of its decoded bytes, so it is the one this server issued.
  const clientDataHash = await computeAttestKeyBinding(deps.sha256, { challengeId: req.challengeId, deviceId: req.deviceId, keyId: req.keyId, nonce: req.nonce });
  const verdict = await deps.verifier.verify({ attestationB64: req.attestation, keyId: req.keyId, clientDataHash, nowMs: repo.now().getTime() });
  if (!verdict.ok) {
    // Server-side diagnostic only (never echoed): which check refused, for which device. No key material.
    console.error(`devices-attest-key: attestation rejected (${verdict.reason}) for device ${req.deviceId}`);
    return { ok: false, status: 422, code: "attestation_rejected", message: "the attestation could not be verified" };
  }

  // 3b. Only a VERIFIED attestation labels an unknown device iOS (first platform-bearing use wins; app.register_attest_key itself refuses a non-iOS
  //     row). A device that was claimed as Android between the read above and this write is refused, not relabelled.
  if ((await repo.device.claimPlatform(req.deviceId, "ios")) !== "ios") {
    throw Errors.unprocessable("platform_mismatch", "App Attest is available on iOS devices only");
  }

  // 4. Record the key it attested.
  const result = await repo.attestKey.register({ deviceId: req.deviceId, keyId: verdict.keyId, publicKey: verdict.publicKeyRaw });
  return {
    ok: true,
    status: result === "registered" ? 201 : 200,
    body: { deviceId: req.deviceId, keyId: verdict.keyId, replaced: result === "replaced" },
  };
}
