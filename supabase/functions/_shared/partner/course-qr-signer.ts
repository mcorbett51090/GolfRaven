// supabase/functions/_shared/partner/course-qr-signer.ts
//
// The SIGNING side of the course QR (P5.1a S2b; docs/security/partner-auth-design.md "Course QR token format"; the definitions are `_shared/course-qr/format.ts`, which the player lane VERIFIES with). Ed25519
// through WebCrypto, from a 32-byte SEED that the database released from Vault for exactly one authorized call (private.course_qr_mint_for_partner, private.course_qr_print_key_for_partner). Pure: no
// environment, no database, no clock, no logging, and nothing here keeps a key: a seed is imported, used once and dropped. The seed is never put in an Error message (a failure says "could not sign").
//
//   * `signRotatingToken`: the Q1 compact JWS, header and payload with their members in alphabetical order (the canonical form the test minter also emits), signature over `b64url(header) "." b64url(payload)`.
//   * `signPrintedQr`: the Q2 `sig`, Ed25519 over `printedQrMessage(facility, kid)` (label, NUL, facility, NUL, kid).
//   * `publicKeyOfSeed`: the raw 32-byte public key as 43 base64url characters (what app.course_qr_key holds).
//   * EVERY signature is verified under the PUBLIC key the database holds for the kid before it is returned (`selfVerify*`): a Vault seed that does not belong to the registered public key would mint tokens no
//     player can verify, so that is a deploy fault (`CourseQrKeyMismatch`, a bare 503), found at the first mint rather than at the first player.

import { base64UrlDecode, base64UrlEncode, parseRotatingToken, printedQrMessage, ROTATING_TOKEN_TYP, verifyEd25519, verifyRotatingToken } from "../course-qr/format.ts";
import { ROTATING_TOKEN_WINDOW_SECONDS } from "../course-qr/params.ts";

/** The seed does not belong to the registered public key, or is not a seed at all: a deploy fault, never a client error. */
export class CourseQrKeyMismatch extends Error {
  constructor() {
    super("course_qr_key_mismatch");
    this.name = "CourseQrKeyMismatch";
  }
}

/** RFC 8410 PKCS#8 prefix of an Ed25519 private key: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING (32) } }. The 32 seed bytes follow. */
const PKCS8_ED25519_PREFIX = Uint8Array.of(0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20);

const enc = new TextEncoder();

function seedBytes(seedB64u: string): Uint8Array {
  const raw = typeof seedB64u === "string" && seedB64u.length === 43 ? base64UrlDecode(seedB64u) : null;
  if (raw === null || raw.length !== 32) throw new CourseQrKeyMismatch();
  return raw;
}

async function importSeed(seedB64u: string, extractable: boolean): Promise<CryptoKey> {
  const raw = seedBytes(seedB64u);
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + raw.length);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(raw, PKCS8_ED25519_PREFIX.length);
  try {
    return await crypto.subtle.importKey("pkcs8", pkcs8.buffer, { name: "Ed25519" }, extractable, ["sign"]);
  } catch {
    throw new CourseQrKeyMismatch();
  }
}

async function sign(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  try {
    return new Uint8Array(await crypto.subtle.sign("Ed25519", key, message.slice().buffer));
  } catch {
    throw new CourseQrKeyMismatch();
  }
}

/** The raw public key of a seed, unpadded base64url (43 characters): what app.course_qr_key.public_key_b64url holds. */
export async function publicKeyOfSeed(seedB64u: string): Promise<string> {
  const key = await importSeed(seedB64u, true);
  try {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    if (typeof jwk.x !== "string" || jwk.x.length !== 43) throw new CourseQrKeyMismatch();
    return jwk.x;
  } catch (err) {
    if (err instanceof CourseQrKeyMismatch) throw err;
    throw new CourseQrKeyMismatch();
  }
}

export interface RotatingTokenInput {
  readonly kid: string;
  readonly facilityId: string;
  /** Seconds since the epoch: the database row's issued_at, the SAME instant the row holds (the player lane judges the 120 s rule against the row). */
  readonly iat: number;
  /** The 16 raw nonce bytes. */
  readonly nonce: Uint8Array;
  readonly seed: string;
  /** The PUBLIC key the database holds for `kid`: the signature is verified under it before the token is returned. */
  readonly publicKey: string;
}

/** A Q1 rotating token, signed and self-verified. */
export async function signRotatingToken(i: RotatingTokenInput): Promise<string> {
  if (i.nonce.length !== 16 || !Number.isInteger(i.iat) || i.iat < 0) throw new CourseQrKeyMismatch();
  const header = { alg: "EdDSA", kid: i.kid, typ: ROTATING_TOKEN_TYP };
  const payload = { exp: i.iat + ROTATING_TOKEN_WINDOW_SECONDS, fac: i.facilityId, iat: i.iat, kid: i.kid, nonce: base64UrlEncode(i.nonce) };
  const signingInput = `${base64UrlEncode(enc.encode(JSON.stringify(header)))}.${base64UrlEncode(enc.encode(JSON.stringify(payload)))}`;
  const key = await importSeed(i.seed, false);
  const token = `${signingInput}.${base64UrlEncode(await sign(key, enc.encode(signingInput)))}`;
  const parsed = parseRotatingToken(token);
  if (parsed === null || parsed.claims.fac !== i.facilityId || parsed.claims.iat !== i.iat || parsed.claims.kid !== i.kid || !(await verifyRotatingToken(parsed, i.publicKey))) throw new CourseQrKeyMismatch();
  return token;
}

export interface PrintedQrInput {
  readonly facilityId: string;
  readonly qrKid: string;
  readonly seed: string;
}

/** A Q2 printed-QR `sig` (86 base64url characters) and the public key of the seed that made it, verified against each other. Ed25519 is deterministic: the same inputs give the same `sig`. */
export async function signPrintedQr(i: PrintedQrInput): Promise<{ readonly sig: string; readonly publicKey: string }> {
  const publicKey = await publicKeyOfSeed(i.seed);
  const key = await importSeed(i.seed, false);
  const message = printedQrMessage(i.facilityId, i.qrKid);
  const signature = await sign(key, message);
  if (signature.length !== 64 || !(await verifyEd25519(publicKey, message, signature))) throw new CourseQrKeyMismatch();
  return { sig: base64UrlEncode(signature), publicKey };
}
