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

export interface VendorHttp {
  fetch(url: string, init: { method: string; headers: Record<string, string>; body: string; signal: AbortSignal }): Promise<Response>;
  nowMs(): number;
  randomUuid(): string;
  /** Per-vendor-call wall-clock bound. The handler makes at most two calls per
   * request (query + update), so 2 x this stays well under privileged.ts's
   * 12 s `transaction_timeout`. */
  timeoutMs: number;
}

/** The default `VendorHttp` over the platform's `fetch` / `crypto`. */
export function platformVendorHttp(timeoutMs = 4_000): VendorHttp {
  return {
    fetch: (url, init) => fetch(url, init),
    nowMs: () => Date.now(),
    randomUuid: () => crypto.randomUUID(),
    timeoutMs,
  };
}

/** PEM (PKCS#8, "BEGIN PRIVATE KEY") -> DER bytes. `null` if it is not a
 * single well-formed PEM block. */
export function pemToDer(pem: string): Uint8Array | null {
  const m = /^\s*-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----\s*$/.exec(pem);
  if (!m) return null;
  const b64 = m[1]!.replace(/\s+/g, "");
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.length > 0 ? out : null;
  } catch {
    return null;
  }
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
