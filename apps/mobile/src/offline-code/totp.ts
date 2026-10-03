/**
 * The offline staff code: RFC 6238 TOTP over RFC 4226 HOTP, HMAC-SHA-256, 6 digits, a 600 s step, computed on the device from the seed the server provisioned. The server's
 * own implementation is `supabase/functions/_shared/offline-code/totp.ts`; `test/offline-code-totp.test.ts` imports it and compares this one with it on random seeds and times,
 * and recomputes the RFC 6238 Appendix B SHA-256 vectors at the 600 s step.
 *
 *   counter = floor(t / 600)                       (t in unix seconds)
 *   h       = HMAC-SHA256(seed, counter as 8 bytes, BIG-endian)
 *   offset  = h[31] & 0x0f
 *   bin     = ((h[offset] & 0x7f) << 24) | (h[offset+1] << 16) | (h[offset+2] << 8) | h[offset+3]
 *   code    = (bin mod 10^6), left-padded with zeros to 6 digits        (leading zeros are significant)
 *
 * Pure: `@noble/hashes` (already a dependency; pure JS), no clock of its own (the caller passes the time), no BigInt (the counter is written as two 32-bit halves, so Hermes
 * needs nothing beyond what the rest of the app already uses).
 */
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { OFFLINE_CODE_DIGITS, OFFLINE_CODE_STEP_SECONDS, OFFLINE_SEED_BYTES } from "./params";

/** The TOTP counter for a unix time in seconds. */
export function stepOf(unixSeconds: number): number {
  return Math.floor(unixSeconds / OFFLINE_CODE_STEP_SECONDS);
}

/** HOTP(seed, counter) with HMAC-SHA-256, `digits` digits, as a zero-padded decimal string. `counter` is a non-negative safe integer. */
export function hotp(seed: Uint8Array, counter: number, digits: number = OFFLINE_CODE_DIGITS): string {
  if (!(seed instanceof Uint8Array) || seed.length !== OFFLINE_SEED_BYTES) throw new Error(`offline code: the seed must be exactly ${OFFLINE_SEED_BYTES} bytes`);
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error("offline code: the counter must be a non-negative safe integer");
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000), false); // high half, big-endian
  view.setUint32(4, counter % 0x1_0000_0000, false); // low half, big-endian
  const h = hmac(sha256, seed, msg);
  const offset = h[h.length - 1]! & 0x0f; // RFC 4226 dynamic truncation
  const bin = (((h[offset]! & 0x7f) << 24) | (h[offset + 1]! << 16) | (h[offset + 2]! << 8) | h[offset + 3]!) >>> 0;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/** The code the device shows at a unix time in seconds. */
export function codeAtSeconds(seed: Uint8Array, unixSeconds: number): string {
  return hotp(seed, stepOf(unixSeconds));
}

/** The code the device shows at an epoch time in MILLISECONDS (`Date.now()`). */
export function codeAt(seed: Uint8Array, nowMs: number): string {
  return codeAtSeconds(seed, Math.floor(nowMs / 1000));
}

/** Whole seconds until the displayed code changes (1 to 600): the boundary second itself already shows the NEW code, so exactly on a boundary there are 600 left. */
export function secondsToNextStep(nowMs: number): number {
  const s = Math.floor(nowMs / 1000);
  return OFFLINE_CODE_STEP_SECONDS - (s % OFFLINE_CODE_STEP_SECONDS);
}
