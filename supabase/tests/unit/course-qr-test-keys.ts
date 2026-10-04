// supabase/tests/unit/course-qr-test-keys.ts
//
// TEST-ONLY minting of course-QR artifacts (P5.1a S2a). The SIGNING side of the course QR is S2b's (the staff lane: `course-qr` on "Marker sold", `qr-print`), behind a passkey session
// and a Vault key. S2a still has to DEFINE and VERIFY both formats, so the tests mint their own: this module, under Ed25519 keys generated AT RUN TIME (never a key literal), producing
// exactly what `_shared/course-qr/format.ts` documents. Nothing under supabase/functions imports this file (a unit test checks that), and it holds no production signing path.
//
// It is also what S2b should be proven against: a token minted here verifies in format.ts, and a token S2b mints must verify there too.

import { PRINTED_QR_LABEL, ROTATING_TOKEN_TYP, base64UrlEncode, printedQrMessage } from "../../functions/_shared/course-qr/format.ts";
import { ROTATING_TOKEN_WINDOW_SECONDS } from "../../functions/_shared/course-qr/params.ts";

export interface TestSigningKey {
  /** The raw 32-byte public key, unpadded base64url: what `app.course_qr_key.public_key_b64url` holds. */
  publicKeyB64Url: string;
  privateKey: CryptoKey;
}

export async function generateTestSigningKey(): Promise<TestSigningKey> {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  return { publicKeyB64Url: base64UrlEncode(raw), privateKey: pair.privateKey };
}

const enc = new TextEncoder();

async function sign(key: CryptoKey, message: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.sign("Ed25519", key, message.slice().buffer));
}

export interface MintRotatingOptions {
  key: TestSigningKey;
  kid: string;
  facilityId: string;
  /** Seconds since the epoch. */
  iat: number;
  /** 16 raw bytes; random when absent. */
  nonce?: Uint8Array;
  /** Overrides for malformed-token tests. */
  header?: Record<string, unknown>;
  payload?: Record<string, unknown>;
}

export interface MintedRotatingToken {
  token: string;
  nonce: Uint8Array;
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
}

/** A compact JWS exactly as format.ts documents it (header and payload members in alphabetical order, like the canonical form S2b should emit). */
export async function mintRotatingToken(o: MintRotatingOptions): Promise<MintedRotatingToken> {
  const nonce = o.nonce ?? crypto.getRandomValues(new Uint8Array(16));
  const header = o.header ?? { alg: "EdDSA", kid: o.kid, typ: ROTATING_TOKEN_TYP };
  const payload = o.payload ?? { exp: o.iat + ROTATING_TOKEN_WINDOW_SECONDS, fac: o.facilityId, iat: o.iat, kid: o.kid, nonce: base64UrlEncode(nonce) };
  const h = base64UrlEncode(enc.encode(JSON.stringify(header)));
  const p = base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const signature = await sign(o.key.privateKey, enc.encode(`${h}.${p}`));
  return { token: `${h}.${p}.${base64UrlEncode(signature)}`, nonce, header, payload };
}

/** The printed QR's `sig` for (facility, qr_kid): Ed25519 over `golfraven/printed-qr/v1 NUL facility NUL kid`. */
export async function mintPrintedQrSig(key: TestSigningKey, facilityId: string, qrKid: string): Promise<string> {
  return base64UrlEncode(await sign(key.privateKey, printedQrMessage(facilityId, qrKid)));
}

export { PRINTED_QR_LABEL };
