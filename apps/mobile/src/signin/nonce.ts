/**
 * The Apple (and Google) nonce, built the way the server verifies it (`supabase/functions/_shared/signin/apple-id-token.ts`, security gate F1):
 *
 *  - the RAW nonce is 32 CSPRNG bytes, base64url (43 characters; the server accepts 16-256 of `[A-Za-z0-9._~+/=-]`);
 *  - the provider gets ONLY `SHA-256(raw)` as lowercase hex (Apple echoes it unchanged into the id token's `nonce` claim);
 *  - the server (and Supabase Auth) gets the RAW value and re-hashes it. The claim must equal the hash; the claim itself is never accepted
 *    as a raw nonce, so a token holder cannot "prove" the nonce by replaying the claim.
 *
 * Swapping the two (raw to Apple, or the hash to the server) makes every sign-in fail the server's check, so the flow tests assert which
 * value went where (`test/signin-flow.test.ts`).
 * The CSPRNG is injected (`expo-crypto`'s `getRandomBytes` in the app, `signin/expo-random.ts`); `expo-crypto` throws rather than
 * falling back to `Math.random` in a release build.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, utf8Encode } from "../catalog/bytes";

export type RandomBytes = (byteCount: number) => Uint8Array;

export interface Nonce {
  /** Goes to OUR server and to Supabase Auth. Never to Apple/Google. */
  raw: string;
  /** Goes to Apple/Google. Never to our server. */
  hashed: string;
}

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function bytesToBase64Url(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += B64URL[(acc >> bits) & 63];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += B64URL[(acc << (6 - bits)) & 63];
  return out;
}

export function sha256Hex(text: string): string {
  return bytesToHex(sha256(utf8Encode(text)));
}

export function createNonce(random: RandomBytes): Nonce {
  const bytes = random(32);
  if (bytes.length !== 32) throw new Error("nonce: the random source returned the wrong number of bytes");
  if (bytes.every((b) => b === 0)) throw new Error("nonce: the random source returned all zeros");
  const raw = bytesToBase64Url(bytes);
  return { raw, hashed: sha256Hex(raw) };
}

/** A random RFC 4122 version-4 UUID (lowercase), from the same injected CSPRNG. */
export function randomUuid(random: RandomBytes): string {
  const b = random(16);
  if (b.length !== 16) throw new Error("uuid: the random source returned the wrong number of bytes");
  const v = Uint8Array.from(b);
  v[6] = ((v[6] ?? 0) & 0x0f) | 0x40;
  v[8] = ((v[8] ?? 0) & 0x3f) | 0x80;
  const h = bytesToHex(v);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
