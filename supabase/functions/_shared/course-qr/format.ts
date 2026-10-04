// supabase/functions/_shared/course-qr/format.ts
//
// P5.1a S2a: the wire FORMATS of the course QR and their VERIFICATION (build plan §9.2 "Course-QR design and anti-replay (O5)", §4.8). The staff lane (S2b) SIGNS; this
// module is the player lane's read side, written so S2b can implement the signing side against exactly these definitions. docs/security/partner-auth-design.md,
// "Course QR token format", states the same in prose.
//
// ONE rule for both formats: Ed25519 (RFC 8032) through WebCrypto, verified against a PUBLIC key looked up by `kid` from app.course_qr_key (never a key the client sends),
// with NOTHING trusted before the signature verifies: the signed bytes are the bytes received, claims are parsed only after, and a malformed value is refused without a
// distinction a caller could probe.
//
// Q1, THE ROTATING TOKEN (a compact JWS, RFC 7515, `alg` EdDSA):
//     token     = b64url(header) "." b64url(payload) "." b64url(signature)          (unpadded base64url, RFC 4648 §5)
//     header    = {"alg":"EdDSA","kid":"<kid>","typ":"golfraven-course-qr+jwt"}      exactly these three members
//     payload   = {"exp":<int>,"fac":"<facility id>","iat":<int>,"kid":"<kid>","nonce":"<b64url of 16 random bytes>"}   exactly these five members; seconds since the epoch;
//                 exp = iat + 120; kid equals the header's
//     signature = Ed25519 over the ASCII bytes  b64url(header) "." b64url(payload)    (the JWS signing input, as received)
//     the NONCE's HASH is  hex(SHA-256(the 16 raw nonce bytes)), lower case: that is `app.course_qr_token.nonce_hash` (single use) and what the scan hands the database.
//     The universal link is  https://golfraven.<tld>/q/m#<token>  (the fragment, so no server or CDN log sees it).
//     `typ` makes a token unusable as any other JWS (and the S2b hand-over token, plan §9.4, a different one); the key PURPOSE `rotating_token` keeps its keys apart from the printed QR's.
//
// Q2, THE PRINTED FACILITY QR:
//     link      = https://golfraven.<tld>/q/f/<facility-slug>#<qr_kid> "." <sig>      (the fragment carries the kid so the verifier knows which key)
//     sig       = b64url(Ed25519 over the UTF-8 bytes  "golfraven/printed-qr/v1" 0x00 <facility id> 0x00 <qr_kid>)     64 bytes, 86 characters
//     The facility id is the CATALOG id (the app resolves the slug to it from its catalog); binding it into the signed bytes is what makes the QR of facility X useless for Y
//     ("a forged printed QR for another facility", plan §9.2). It carries no authority on its own: the PIN and a presence fix are still needed.
//
// Nothing in this file reads a clock, a key store or the environment: pure, and unit-tested (supabase/tests/unit/course-qr-format.test.ts) with tokens minted by test-only code
// (supabase/tests/unit/course-qr-test-keys.ts) under keys generated at run time.

import { ROTATING_TOKEN_WINDOW_SECONDS } from "./params.ts";

export const ROTATING_TOKEN_TYP = "golfraven-course-qr+jwt";
export const PRINTED_QR_LABEL = "golfraven/printed-qr/v1";

const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const KID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const FACILITY_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;
/** 16 bytes, unpadded base64url: 22 characters. */
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
/** Ed25519 signatures are 64 bytes: 86 base64url characters. */
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
const MAX_TOKEN_CHARS = 640;

/** Strict unpadded base64url -> bytes. `null` for anything else (never throws): an empty string, a character outside the alphabet, padding, or a length no byte string has. */
export function base64UrlDecode(s: string): Uint8Array | null {
  if (typeof s !== "string" || s.length === 0 || !B64URL_RE.test(s) || s.length % 4 === 1) return null;
  try {
    const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const textEncoder = new TextEncoder();

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function exactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const have = Object.keys(o);
  return have.length === keys.length && keys.every((k) => Object.prototype.hasOwnProperty.call(o, k));
}

function parseJsonObject(bytes: Uint8Array): Record<string, unknown> | null {
  try {
    const v: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return isPlainObject(v) ? v : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/** Ed25519 verification of `message` under a raw 32-byte public key (unpadded base64url). Never throws: every failure (a bad key, a bad length, a clean cryptographic "no") is `false`. */
export async function verifyEd25519(publicKeyB64Url: string, message: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    const keyBytes = base64UrlDecode(publicKeyB64Url);
    if (keyBytes === null || keyBytes.length !== 32 || signature.length !== 64) return false;
    const key = await crypto.subtle.importKey("raw", keyBytes.slice().buffer, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature.slice().buffer, message.slice().buffer);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Q1: the rotating token
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

export interface RotatingTokenClaims {
  /** The facility the token was minted for (the catalog id). */
  fac: string;
  /** The 16 raw nonce bytes. */
  nonce: Uint8Array;
  /** Seconds since the epoch. */
  iat: number;
  exp: number;
  kid: string;
}

export interface ParsedRotatingToken {
  claims: RotatingTokenClaims;
  /** The JWS signing input exactly as received (`header.payload`, ASCII). */
  signingInput: Uint8Array;
  signature: Uint8Array;
}

/** Structural parse of a rotating token. The CLAIMS are not trustworthy until `verifyRotatingToken` says so: this only refuses what is not even shaped like a token (and
 * checks the header's `alg` and `typ` and that the payload's `kid` equals the header's, so a verifier never selects a key from an unauthenticated, inconsistent pair). `null`
 * for any malformation: the caller answers one `invalid_qr` for all of them. */
export function parseRotatingToken(token: string): ParsedRotatingToken | null {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_CHARS) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  const headerBytes = base64UrlDecode(h);
  const payloadBytes = base64UrlDecode(p);
  const signature = base64UrlDecode(s);
  if (headerBytes === null || payloadBytes === null || signature === null || !SIG_RE.test(s)) return null;
  const header = parseJsonObject(headerBytes);
  const payload = parseJsonObject(payloadBytes);
  if (header === null || payload === null) return null;
  if (!exactKeys(header, ["alg", "kid", "typ"]) || header.alg !== "EdDSA" || header.typ !== ROTATING_TOKEN_TYP || typeof header.kid !== "string" || !KID_RE.test(header.kid)) return null;
  if (!exactKeys(payload, ["exp", "fac", "iat", "kid", "nonce"])) return null;
  const { exp, fac, iat, kid, nonce } = payload;
  if (typeof fac !== "string" || !FACILITY_ID_RE.test(fac)) return null;
  if (typeof kid !== "string" || kid !== header.kid) return null;
  if (typeof nonce !== "string" || !NONCE_RE.test(nonce)) return null;
  if (typeof iat !== "number" || !Number.isInteger(iat) || iat < 0 || typeof exp !== "number" || !Number.isInteger(exp) || exp !== iat + ROTATING_TOKEN_WINDOW_SECONDS) return null;
  const nonceBytes = base64UrlDecode(nonce);
  if (nonceBytes === null || nonceBytes.length !== 16) return null;
  return { claims: { fac, nonce: nonceBytes, iat, exp, kid }, signingInput: textEncoder.encode(`${h}.${p}`), signature };
}

/** The signature check of a parsed token under the PUBLIC key of its kid. */
export function verifyRotatingToken(parsed: ParsedRotatingToken, publicKeyB64Url: string): Promise<boolean> {
  return verifyEd25519(publicKeyB64Url, parsed.signingInput, parsed.signature);
}

/** `app.course_qr_token.nonce_hash`: lower-case hex SHA-256 of the 16 raw nonce bytes. */
export async function nonceHashHex(nonce: Uint8Array, sha256Hex: (bytes: Uint8Array) => Promise<string>): Promise<string> {
  return sha256Hex(nonce);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------------
// Q2: the printed facility QR
// ---------------------------------------------------------------------------------------------------------------------------------------------------------------

/** The bytes the printed QR's signature covers: label, 0x00, the facility id, 0x00, the kid (all UTF-8; neither id can contain NUL, so the encoding is unambiguous). */
export function printedQrMessage(facilityId: string, qrKid: string): Uint8Array {
  return textEncoder.encode(`${PRINTED_QR_LABEL}\u0000${facilityId}\u0000${qrKid}`);
}

export interface ParsedPrintedQr {
  kid: string;
  signature: Uint8Array;
}

/** Structural parse of the printed QR's `kid` and `sig` (as the app extracts them from the fragment). `null` for any malformation. */
export function parsePrintedQr(kid: string, sig: string): ParsedPrintedQr | null {
  if (typeof kid !== "string" || !KID_RE.test(kid) || typeof sig !== "string" || !SIG_RE.test(sig)) return null;
  const signature = base64UrlDecode(sig);
  if (signature === null || signature.length !== 64) return null;
  return { kid, signature };
}

export function verifyPrintedQr(parsed: ParsedPrintedQr, facilityId: string, publicKeyB64Url: string): Promise<boolean> {
  return verifyEd25519(publicKeyB64Url, printedQrMessage(facilityId, parsed.kid), parsed.signature);
}
