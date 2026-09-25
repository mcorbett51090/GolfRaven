// supabase/functions/_shared/catalog/signature.ts
//
// Real Ed25519 (RFC 8032) verification of a catalog manifest signature
// (build plan §4.8: "Catalog signing key (Ed25519)... kid keyset of at
// least 2 keys in the app"), using only the standard Web Crypto API
// (`crypto.subtle`) — available in both Deno (the real runtime) and
// modern Node (>=20, this repo's vitest run), so this module needs no
// import at all, Deno- or Node-specific.
//
// This is the MECHANISM, genuinely implemented and unit-tested (a real
// keypair, a real signature, a real verify) — not a stub of the crypto
// itself. What IS deferred (see catalog/classify-version.ts's own header,
// and docs/security/p3-money-path-requirements.md) is the §4.8 key
// -rotation/registration OPERATIONAL workflow and the import pipeline
// that would ever produce a real signed manifest in the first place —
// neither exists yet, so `app.catalog_signing_key` (0019 migration) ships
// empty, and every real submission's signature verification legitimately
// fails closed (no registered key to check it against) until that
// workflow lands.
//
// [unverified — training knowledge]: Deno's `crypto.subtle` has supported
// the "Ed25519" algorithm identifier since Deno 1.43ish; this has not
// been confirmed against the pinned Deno 2.5.2 in THIS session (Deno
// tests, if runnable at all here, would confirm it directly — see the
// P3c handback report for whether that check ran). Node >=20's WebCrypto
// implementation supports Ed25519, confirmed by this session's own vitest
// run of signature.test.ts.

const BASE64URL_UNPADDED_RE = /^[A-Za-z0-9_-]*$/;

export function base64UrlToBytes(b64url: string): Uint8Array {
  if (!BASE64URL_UNPADDED_RE.test(b64url)) {
    throw new Error("base64UrlToBytes: not unpadded base64url");
  }
  const padded = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(padded);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface VerifyManifestSigInput {
  /** The raw, unpadded-base64url-encoded Ed25519 public key bytes for
   * this kid — looked up by the caller from `app.catalog_signing_key`
   * (never trust a client-supplied key). */
  publicKeyB64Url: string;
  signatureB64Url: string;
  payload: string;
}

/** Never throws on malformed input (a forged/garbled signature claim is
 * exactly the case this function exists to reject) — every failure path
 * (bad base64, wrong-length key, `subtle.verify` throwing, or a clean
 * cryptographic "no") resolves to `false`. */
export async function verifyManifestSignature(input: VerifyManifestSigInput): Promise<boolean> {
  try {
    const keyBytes = base64UrlToBytes(input.publicKeyB64Url);
    const sigBytes = base64UrlToBytes(input.signatureB64Url);
    if (keyBytes.length !== 32 || sigBytes.length === 0) return false;
    const key = await crypto.subtle.importKey("raw", keyBytes.slice().buffer, { name: "Ed25519" }, false, ["verify"]);
    const payloadBytes = new TextEncoder().encode(input.payload);
    return await crypto.subtle.verify("Ed25519", key, sigBytes.slice().buffer, payloadBytes.slice().buffer);
  } catch {
    return false;
  }
}
