// supabase/functions/_shared/partner/pin-contract.ts
//
// THE BROWSER-DERIVATION CONTRACT of the partner step-up PIN (docs/security/partner-auth-design.md 6.3, decisions D8 and N1, S1.3). Pure: Web Crypto only, no environment, no database, no logging, no import but
// `./token.ts` (which is itself Web Crypto only), so the SAME file runs in the browser (the S7 PWA imports it by relative path), in Deno (the Edge's request validation and the integration suite) and in Node
// (vitest). The PIN is a four-digit secret; PBKDF2-HMAC-SHA256 runs IN THE BROWSER and only the DERIVED bytes are ever sent, so the PIN itself never reaches the Edge or the database.
//
//   derived  = PBKDF2-HMAC-SHA256( password = the 4 PIN characters as ASCII bytes, salt = the 16 stored salt bytes, iterations = the stored count, dkLen = 32 bytes )
//   on the wire   `derived` is canonical UNPADDED base64url of those 32 bytes (43 characters); `salt` is canonical unpadded base64url of 16 bytes (22 characters); `iterations` is an integer
//   in the database  verifier = HMAC-SHA256( Vault pepper, "golfraven/partner-pin/v1" || 0x00 || user id (16 bytes) || derived (32 bytes) )   (migration 0052, partner_pin_core)
//
// WHO CHOOSES WHAT. The browser picks a fresh 16-byte salt from its CSPRNG at SET and CHANGE time (`newPinSalt`) and sends it with the derived bytes; the iteration count is the browser's too, inside
// [MIN_ITERATIONS, MAX_ITERATIONS] (the floor is the OWASP-style minimum this repository measured at 115 ms on a server core; the default is 600,000, the design's figure; both `[unverified - training knowledge]`
// until S0 measures a low-end iPad). `GET pin` returns the stored salt and iteration count so the browser derives the SAME bytes at VERIFY time. A salt is not a secret (the verifier is peppered in the database),
// it only makes two members' derived bytes differ; a salt the browser chose badly weakens only that member's own verifier.
//
// WHAT THE EDGE CHECKS (`parseDerivedKey`, `parsePinSalt`, `parseIterations`): length and encoding, nothing else: it cannot see the PIN, so it cannot enforce the PIN's SHAPE or the deny-list. The
// shape rules and the deny-list (`pin-deny-list.ts`) are enforced where the PIN is typed: in this module's callers, which is the browser. A custom client can therefore set any four digits; the lockout
// (5 consecutive failures, 20 a day) and the email-proof requirement are what bound that, not the deny-list (design 11, R-P2; the S1.3 departure note).
//
// The test vectors (`PIN_DERIVATION_VECTORS`) were computed OUTSIDE this code (Python `hashlib.pbkdf2_hmac`) and are asserted by vitest (Node), by a pure Deno test and, for S7, by the PWA's own tests:
// a browser that derives anything else than these bytes for these inputs cannot verify against a stored verifier.

import { fromB64u, toB64u } from "./token.ts";

export const PIN_DERIVATION = Object.freeze({
  /** The contract version: bump it (and the label in migration 0052's `partner_pin_core`) together. */
  version: 1,
  kdf: "PBKDF2-HMAC-SHA256",
  /** The PIN is exactly this many ASCII digits. */
  pinLength: 4,
  saltBytes: 16,
  derivedBytes: 32,
  minIterations: 210_000,
  maxIterations: 1_000_000,
  defaultIterations: 600_000,
});

export const MIN_ITERATIONS = PIN_DERIVATION.minIterations;
export const MAX_ITERATIONS = PIN_DERIVATION.maxIterations;
export const DEFAULT_ITERATIONS = PIN_DERIVATION.defaultIterations;

const PIN_RE = /^[0-9]{4}$/;

/** Exactly four ASCII digits. */
export function isWellFormedPin(pin: unknown): pin is string {
  return typeof pin === "string" && PIN_RE.test(pin);
}

/** 16 random bytes from the platform CSPRNG: the salt a browser chooses at set and change time. */
export function newPinSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(PIN_DERIVATION.saltBytes));
}

/** An integer iteration count inside the contract's range, or null. */
export function parseIterations(n: unknown): number | null {
  return typeof n === "number" && Number.isSafeInteger(n) && n >= MIN_ITERATIONS && n <= MAX_ITERATIONS ? n : null;
}

/** A canonical unpadded base64url string of exactly 32 bytes (43 characters): the derived key as it travels. null for anything else. */
export function parseDerivedKey(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || s.length !== 43) return null;
  const b = fromB64u(s);
  return b !== null && b.length === PIN_DERIVATION.derivedBytes ? b : null;
}

/** A canonical unpadded base64url string of exactly 16 bytes (22 characters): the salt as it travels. null for anything else. */
export function parsePinSalt(s: unknown): Uint8Array | null {
  if (typeof s !== "string" || s.length !== 22) return null;
  const b = fromB64u(s);
  return b !== null && b.length === PIN_DERIVATION.saltBytes ? b : null;
}

/**
 * The derived bytes of a PIN: PBKDF2-HMAC-SHA256(PIN as ASCII, salt, iterations, 32 bytes). Throws (a programming error, never a user-facing answer) for a PIN that is not four digits, a salt that is not 16
 * bytes or an iteration count outside the contract.
 */
export async function derivePinKey(pin: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  if (!isWellFormedPin(pin)) throw new Error("derivePinKey: the PIN must be exactly four digits");
  if (salt.length !== PIN_DERIVATION.saltBytes) throw new Error("derivePinKey: the salt must be 16 bytes");
  if (parseIterations(iterations) === null) throw new Error("derivePinKey: the iteration count is outside the contract");
  const password = new TextEncoder().encode(pin);
  const base = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: new Uint8Array(salt), iterations }, base, PIN_DERIVATION.derivedBytes * 8);
  return new Uint8Array(bits);
}

/** `derivePinKey`, encoded as the request bodies carry it (canonical unpadded base64url, 43 characters). */
export async function derivePinKeyB64u(pin: string, salt: Uint8Array, iterations: number): Promise<string> {
  return toB64u(await derivePinKey(pin, salt, iterations));
}
