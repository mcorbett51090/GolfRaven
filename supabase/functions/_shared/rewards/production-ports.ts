// supabase/functions/_shared/rewards/production-ports.ts
//
// Assembles the production `AttestationPorts` from an already-parsed
// configuration object. THE ONLY place that decides what "configured" means:
//
//   - `config.apple === null`  -> `ports.ios === null`   -> any request carrying
//     iOS attestation material fails closed (503), never "clean";
//   - `config.google === null` -> `ports.android === null` -> likewise.
//
// A port that exists is built from a COMPLETE config only (every field
// non-empty); the vendor clients re-check at call time and throw
// `VendorNotConfiguredError` on anything they cannot use.
//
// ⚠ LIVE VENDOR VERIFICATION IS NOT EXERCISED (see devicecheck-client.ts /
// play-integrity-client.ts). The Android port has NO persistent-bit methods at
// all: whether Play Integrity device recall exists, and under what field/
// endpoint, is spike A20 `[unverified]`, and a port that could read bits it
// cannot write would be half a mechanism. Android's two bits are the §7.5
// server-side substitute instead, computed by the handler from the `device`
// rows (`RewardsRepo#androidInstallSignals`) — read and written (the install
// link is recorded on every Android activation) by the server itself.

import { type AppAttestCrypto, verifyAppAttestAssertion } from "./app-attest.ts";
import { type DeviceCheckClient, type DeviceCheckConfig, createDeviceCheckClient, isCompleteDeviceCheckConfig } from "./devicecheck-client.ts";
import { type PlayIntegrityConfig, createIntegrityDecoder, isCompletePlayIntegrityConfig } from "./play-integrity-client.ts";
import { evaluateIntegrityPayload } from "./play-integrity.ts";
import { type AttestationPorts, type AndroidPort, type IosPort, VendorRejectedError } from "./types.ts";
import type { VendorHttp } from "./vendor-http.ts";

export interface AppleConfig extends DeviceCheckConfig {
  bundleId: string;
}

export interface RewardsAttestationConfig {
  apple: AppleConfig | null;
  google: PlayIntegrityConfig | null;
}

/** A verdict older than this, or in the future by more than the skew, is not
 * a verdict for this request (the challenge itself lives 120 s). */
export const INTEGRITY_MAX_AGE_MS = 5 * 60_000;
export const INTEGRITY_MAX_FUTURE_SKEW_MS = 60_000;

export function buildIosPort(apple: AppleConfig, http: VendorHttp, appAttestCrypto: AppAttestCrypto, client?: DeviceCheckClient): IosPort {
  const deviceCheck = client ?? createDeviceCheckClient(apple, http);
  const appId = `${apple.teamId}.${apple.bundleId}`;
  return {
    verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId }, appAttestCrypto),
    readBits: (token) => deviceCheck.queryTwoBits(token),
    async setBit0(token, known) {
      // update_two_bits writes BOTH bits, so bit1 is written back as the table
      // just read it: this must never clear a bit1 an admin set. (A bit1 set
      // between that reading and this write would still be lost — a vendor API
      // limitation, recorded in the security doc. Re-reading here would only
      // narrow that window by a few ms while adding a network round trip to a
      // request that holds a database transaction open.)
      await deviceCheck.updateTwoBits(token, { bit0: true, bit1: known.bit1 });
    },
  };
}

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

export function buildAttestationPorts(config: RewardsAttestationConfig, http: VendorHttp, appAttestCrypto: AppAttestCrypto): AttestationPorts {
  return {
    ios: config.apple !== null && isCompleteDeviceCheckConfig(config.apple) && config.apple.bundleId.length > 0 ? buildIosPort(config.apple, http, appAttestCrypto) : null,
    android: config.google !== null && isCompletePlayIntegrityConfig(config.google) ? buildAndroidPort(config.google, http) : null,
  };
}
