// supabase/functions/_shared/offline-code/totp.ts
//
// RFC 6238 TOTP over RFC 4226 HOTP, HMAC-SHA-256, 6 digits, a 600 s step (params.ts). Pure: WebCrypto only, no I/O, no environment, no database; the
// same file runs under Deno (the Edge runtime) and Node (the vitest suite). It computes a code from a SEED; it never sees the server key K (the
// seed is derived inside Postgres, migration 0045).

import { OFFLINE_CODE_DIGITS, OFFLINE_CODE_STEP_SECONDS, OFFLINE_SEED_BYTES } from "./params.ts";

/** The TOTP counter (RFC 6238 `T`) for a unix time in seconds: floor(t / step). */
export function stepOf(unixSeconds: number): number {
  return Math.floor(unixSeconds / OFFLINE_CODE_STEP_SECONDS);
}

async function hmacSha256(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, message as BufferSource));
}

/** RFC 4226 HOTP(K, C) with HMAC-SHA-256 and `digits` digits, as a zero-padded decimal string. `counter` is a non-negative safe integer (a step
 * number); it is encoded as 8 big-endian bytes. */
export async function hotp(seed: Uint8Array, counter: number, digits: number = OFFLINE_CODE_DIGITS): Promise<string> {
  if (!(seed instanceof Uint8Array) || seed.length !== OFFLINE_SEED_BYTES) {
    throw new Error(`offline-code: the seed must be exactly ${OFFLINE_SEED_BYTES} bytes`);
  }
  if (!Number.isSafeInteger(counter) || counter < 0) throw new Error("offline-code: the counter must be a non-negative safe integer");
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter), false);
  const h = await hmacSha256(seed, msg);
  // RFC 4226 dynamic truncation: the low nibble of the last byte picks a 4-byte window; its top bit is masked so the value is a 31-bit integer.
  const offset = h[h.length - 1]! & 0x0f;
  const bin = new DataView(h.buffer, h.byteOffset, h.byteLength).getUint32(offset, false) & 0x7fffffff;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/** The code the device shows at a unix time (seconds). */
export function totpAt(seed: Uint8Array, unixSeconds: number): Promise<string> {
  return hotp(seed, stepOf(unixSeconds));
}

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** RFC 4648 base32, upper-case, NO padding: the encoding of the `seed` the provisioning endpoint returns (the encoding every TOTP library takes). */
export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

/** The inverse of `base32Encode` (strict: upper-case alphabet, no padding, no whitespace; throws on anything else). Provided for the tests and for
 * the P5 side; the mobile client carries its own decoder. */
export function base32Decode(text: string): Uint8Array {
  if (!/^[A-Z2-7]+$/.test(text)) throw new Error("offline-code: not an unpadded upper-case RFC 4648 base32 string");
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of text) {
    acc = (acc << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((acc >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    acc &= (1 << bits) - 1;
  }
  return new Uint8Array(out);
}
