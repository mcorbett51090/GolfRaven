// supabase/functions/_shared/rewards/vendor-http.ts
//
// What the production vendor adapters need from the outside world, injected so
// every adapter is unit-testable against a scripted `fetch` with no network:
// the HTTP client, a clock, a UUID source, a per-request timeout, and the two
// Web Crypto signing helpers the vendors' auth schemes need (ES256 JWTs for
// Apple, RS256 JWTs for Google).
//
// Nothing in this file reads configuration or the environment — the adapters
// receive an already-parsed config object or `null` (unconfigured), and
// `null`/incomplete config makes every call throw `VendorNotConfiguredError`
// rather than reaching for a default.

import { toBase64Url } from "./binding.ts";
import { pkcs8PemToDer } from "../pem.ts";

export interface VendorHttp {
  /** `redirect: "error"` makes the platform `fetch` reject a redirect instead of following it (a redirect would be a way to leave a host
   * allow-list after the check). Optional only so the Play Integrity adapter, which does not set it, still type-checks. */
  fetch(url: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal; redirect?: "error" }): Promise<Response>;
  nowMs(): number;
  randomUuid(): string;
  /** Per-vendor-call wall-clock bound; see `VENDOR_CALL_TIMEOUT_MS`. */
  timeoutMs: number;
}

/** THE TIMING BUDGET (F6). `withOwnership` runs the whole activation in ONE
 * transaction with `lock_timeout = 5 s` and `transaction_timeout = 12 s`
 * (privileged.ts). The first thing the handler does is lock the reward row, which
 * may wait up to the full 5 s behind another request on the SAME reward. After
 * that, the only slow steps are the vendor calls, and there are at most
 * `MAX_VENDOR_CALLS_PER_REQUEST` of them per request:
 *   iOS     DeviceCheck query_two_bits, then (row 6 only) update_two_bits
 *   Android Google OAuth token exchange, then decodeIntegrityToken
 * Worst case: 5 s + 2 x 2.5 s = 10 s, leaving 2 s for every other statement and
 * for signing. (The later advisory-lock waits cannot add to this: no vendor call
 * happens after one is taken — a held outcome ends the request, and row 6 raises
 * no signal.) With the earlier 4 s default the worst case was 13 s: a
 * transaction_timeout kill (FATAL, connection dropped, outcome unknown) that a
 * slow-but-working vendor could have triggered on a contended reward.
 * `activate-handler`'s unit test pins this inequality against the real
 * constants in privileged.ts. */
export const VENDOR_CALL_TIMEOUT_MS = 2_500;
export const MAX_VENDOR_CALLS_PER_REQUEST = 2;

/** The default `VendorHttp` over the platform's `fetch` / `crypto`. */
export function platformVendorHttp(timeoutMs = VENDOR_CALL_TIMEOUT_MS): VendorHttp {
  return {
    fetch: (url, init) => fetch(url, init),
    nowMs: () => Date.now(),
    randomUuid: () => crypto.randomUUID(),
    timeoutMs,
  };
}

/** PEM (PKCS#8, "BEGIN PRIVATE KEY") -> DER bytes. `null` if it is not a single well-formed PEM block. The parser is the shared one
 * (../pem.ts), so a key is accepted in exactly the forms the Sign in with Apple key is: real line breaks, or a one-line value with a literal
 * backslash-n for each line break (how a single-line environment variable carries a PEM). */
export function pemToDer(pem: string): Uint8Array | null {
  return pkcs8PemToDer(pem);
}

function b64urlJson(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

/** Signs a compact JWS with ES256 (ECDSA P-256 / SHA-256, raw r‖s as JWS
 * requires — Web Crypto already returns that form). */
export async function signJwtEs256(privateKeyPkcs8: Uint8Array, header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", privateKeyPkcs8.slice().buffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signingInput = `${b64urlJson({ ...header, alg: "ES256" })}.${b64urlJson(claims)}`;
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${toBase64Url(new Uint8Array(sig))}`;
}

/** Signs a compact JWS with RS256. */
export async function signJwtRs256(privateKeyPkcs8: Uint8Array, header: Record<string, unknown>, claims: Record<string, unknown>): Promise<string> {
  const key = await crypto.subtle.importKey("pkcs8", privateKeyPkcs8.slice().buffer, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const signingInput = `${b64urlJson({ ...header, alg: "RS256" })}.${b64urlJson(claims)}`;
  const sig = await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${toBase64Url(new Uint8Array(sig))}`;
}
