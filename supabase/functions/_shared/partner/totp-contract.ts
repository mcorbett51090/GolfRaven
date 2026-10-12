// supabase/functions/_shared/partner/totp-contract.ts
//
// THE TOTP CONTRACT of the partner operator/admin factor (docs/security/partner-auth-design.md 6.4, PA-20, S1.4). Pure: Web Crypto only (plus the shared base32 encoder), no environment, no
// database, no logging. The same file runs in Deno (the Edge builds the otpauth URI from the seed the database returns once), in Node (vitest RFC vectors) and, later, in the S7 PWA.
//
//   HOTP     RFC 4226 over HMAC-SHA-1, 6 digits, 30 s step (authenticator-app defaults; N6)
//   seed     derived in Postgres (Vault partner_totp_key); shown ONCE as unpadded RFC 4648 base32
//   otpauth  `otpauth://totp/{issuer}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30`
//
// The SQL HOTP (`private.hotp`, migration 0053) and this module's `hotpSha1` must agree on RFC 6238 Appendix B SHA-1 vectors (PA-20). Offline codes use a different parameter set (SHA-256 / 600 s) in
// `_shared/offline-code/totp.ts`; do not mix them.

import { base32Encode } from "../offline-code/totp.ts";

export const PARTNER_TOTP = Object.freeze({
  /** The contract version: bump it with the label in migration 0053's `partner_totp_seed_derive`. */
  version: 1,
  issuer: "GolfRaven",
  periodSeconds: 30,
  digits: 6,
  algo: "SHA1",
  /** HMAC-SHA-256 of the Vault-derived seed is 32 bytes. */
  seedBytes: 32,
});

export interface OtpauthParams {
  readonly seed: Uint8Array;
  readonly issuer: string;
  readonly period: number;
  readonly digits: number;
  readonly algo: string;
}

/** Unpadded upper-case RFC 4648 base32 of the seed bytes (what authenticator apps take as `secret=`). */
export function encodeTotpSeed(seed: Uint8Array): string {
  return base32Encode(seed);
}

/**
 * The provisioning URI the PWA turns into a QR. Label is the issuer alone (the Edge has no mailbox on this path); query carries issuer again so apps that ignore the label still show "GolfRaven".
 * `algo` is upper-case without a hyphen (`SHA1`), matching what `partner_totp_enrol_for_partner` returns.
 */
export function buildOtpauthUrl(p: OtpauthParams): string {
  const secret = encodeTotpSeed(p.seed);
  const label = encodeURIComponent(p.issuer);
  const q = new URLSearchParams({
    secret,
    issuer: p.issuer,
    algorithm: p.algo,
    digits: String(p.digits),
    period: String(p.period),
  });
  return `otpauth://totp/${label}?${q.toString()}`;
}

/** RFC 4226 HOTP(K, C) with HMAC-SHA-1 and `digits` digits, as a zero-padded decimal string. `counter` is a non-negative safe integer encoded as 8 big-endian bytes. */
export async function hotpSha1(seed: Uint8Array, counter: number, digits: number = PARTNER_TOTP.digits): Promise<string> {
  if (!(seed instanceof Uint8Array) || seed.length < 1) throw new Error("partner-totp: the seed must be a non-empty byte array");
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error("partner-totp: the counter must be a non-negative safe integer");
  if (!Number.isInteger(digits) || digits < 6 || digits > 8) throw new Error("partner-totp: digits must be 6, 7 or 8");
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter), false);
  const key = await crypto.subtle.importKey("raw", seed as BufferSource, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
  const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg as BufferSource));
  const offset = h[h.length - 1]! & 0x0f;
  const bin = new DataView(h.buffer, h.byteOffset, h.byteLength).getUint32(offset, false) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/** The TOTP counter (RFC 6238 `T`) for a unix time in seconds at the partner 30 s step. */
export function partnerTotpStep(unixSeconds: number): number {
  return Math.floor(unixSeconds / PARTNER_TOTP.periodSeconds);
}

export { base32Encode };
