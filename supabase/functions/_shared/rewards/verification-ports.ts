// supabase/functions/_shared/rewards/verification-ports.ts
//
// The VERIFICATION-ONLY half of the production attestation ports: App Attest assertion verification (local
// cryptography, no vendor call) and Play Integrity token verification (one Google decode call). Nothing here can
// read or write a DeviceCheck persistent bit, and nothing here names one: that is what lets the EARNING side (the
// `checkin-token` Edge Function) verify an attestation without importing the module that holds the bit-reading
// adapter (production-ports.ts imports devicecheck-client.ts). `rewards-isolation.test.ts` pins that boundary: the
// earning side may import only the modules on its verification-only allow-list, of which this is one, and every one
// of them is checked for the absence of any bit-reading name.
//
// `production-ports.ts` (rewards-activate) builds its Android port from `buildAndroidPort` below and re-exports it, so
// both entrypoints grade a Play Integrity token with exactly one implementation.
//
// Pure, DI'd: no environment, no secret, no global. Configuration arrives as an argument (privileged.ts reads it).

import { type AppAttestCrypto, verifyAppAttestAssertion } from "./app-attest.ts";
import { type PlayIntegrityConfig, createIntegrityDecoder, isCompletePlayIntegrityConfig } from "./play-integrity-client.ts";
import { evaluateIntegrityPayload } from "./play-integrity.ts";
import { type AndroidPort, type IosPort, VendorRejectedError } from "./types.ts";
import type { VendorHttp } from "./vendor-http.ts";

/** A verdict older than this, or in the future by more than the skew, is not
 * a verdict for this request (the challenge itself lives 120 s). */
export const INTEGRITY_MAX_AGE_MS = 5 * 60_000;
export const INTEGRITY_MAX_FUTURE_SKEW_MS = 60_000;

export function buildAndroidPort(google: PlayIntegrityConfig, http: VendorHttp): AndroidPort {
  const decoder = createIntegrityDecoder(google, http);
  return {
    async verifyIntegrity(input) {
      let payload: unknown;
      try {
        payload = await decoder.decode(input.integrityToken);
      } catch (e) {
        // Google understood the request and could not decode the token: that is
        // a failed attestation. Unavailable / not-configured propagate.
        if (e instanceof VendorRejectedError) return { grade: "failed", reasons: ["token_rejected_by_google"] };
        throw e;
      }
      const evaluation = evaluateIntegrityPayload(payload, {
        packageName: google.packageName,
        certificateSha256Digests: google.certificateSha256Digests,
        expectedRequestHash: input.expectedRequestHash,
        nowMs: input.nowMs,
        maxAgeMs: INTEGRITY_MAX_AGE_MS,
        maxFutureSkewMs: INTEGRITY_MAX_FUTURE_SKEW_MS,
      });
      return evaluation;
    },
  };
}

/** The iOS half a verification-only caller needs: assertion verification and nothing else. */
export type IosAssertionPort = Pick<IosPort, "verifyAssertion">;

export function buildIosAssertionPort(appId: string, appAttestCrypto: AppAttestCrypto): IosAssertionPort {
  return { verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId }, appAttestCrypto) };
}

/** `null` = that platform is not configured: a request carrying that platform's attestation material fails closed (503). */
export interface VerificationPorts {
  ios: IosAssertionPort | null;
  android: AndroidPort | null;
}

export interface VerificationConfig {
  /** `<TeamID>.<BundleID>` (the App Attest `rpId`), or `null` when either half is unset. */
  appId: string | null;
  google: PlayIntegrityConfig | null;
}

export function buildVerificationPorts(config: VerificationConfig, http: VendorHttp, appAttestCrypto: AppAttestCrypto): VerificationPorts {
  return {
    ios: config.appId !== null && config.appId.length > 0 ? buildIosAssertionPort(config.appId, appAttestCrypto) : null,
    android: config.google !== null && isCompletePlayIntegrityConfig(config.google) ? buildAndroidPort(config.google, http) : null,
  };
}
