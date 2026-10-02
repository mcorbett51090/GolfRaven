// supabase/functions/_shared/rewards/app-attest.ts
//
// App Attest ASSERTION verification (build plan §7.5): "The server verifies the
// signature, the `rpIdHash`, and that the counter is monotonic per key", with
// `clientDataHash = SHA-256(canonical_body ‖ server_challenge)` (binding.ts).
//
// This is local cryptography — no Apple network call — over the public key the
// server stored when the key was registered (`app.device.attest_public_key`).
// Key REGISTRATION (verifying the attestation object against Apple's root CA and
// extracting that public key) is NOT built in P3f: until it is, a device has no
// key on record and this verifier answers `unattestable` ("key_not_registered"),
// which routes the reward to `held_review`. It never answers "verified" for a
// key it does not hold.
//
// ⚠ `[unverified — training knowledge of Apple's App Attest assertion format]`.
// No iOS device, Apple account or network is available in this environment, so
// the format below is exercised only against assertions this repo's own tests
// construct (an ECDSA P-256 key pair generated with Web Crypto, an
// authenticatorData built to the layout below, a CBOR map built by a test-only
// encoder). What is assumed:
//   - the assertion is a CBOR map {"signature": bstr (DER ECDSA),
//     "authenticatorData": bstr};
//   - authenticatorData = rpIdHash (32) ‖ flags (1) ‖ signCount (4, big-endian);
//   - nonce = SHA-256(authenticatorData ‖ clientDataHash), and the signature is
//     ECDSA-SHA256 over `nonce` (i.e. SHA-256 is applied to the nonce once more
//     by the signing primitive);
//   - rpIdHash = SHA-256(`<TeamID>.<BundleID>`).
// A real-device conformance run must confirm each before this ships to players.
// Everything fails CLOSED on a shape it does not recognise (`failed`).

import { bytesEqual, concatBytes, fromBase64Lenient, type Sha256Fn } from "./binding.ts";
import type { AppAttestAssertionInput, AssertionResult } from "./types.ts";

// ---------------------------------------------------------------------------
// Minimal strict CBOR decoder — only what an assertion needs: unsigned ints,
// byte strings, text strings, definite-length maps. Anything else (tags,
// floats, arrays, indefinite lengths, negative ints, trailing bytes) throws.
// ---------------------------------------------------------------------------
export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

interface Cursor {
  bytes: Uint8Array;
  pos: number;
}

function readLength(c: Cursor, info: number): number {
  if (info < 24) return info;
  const need = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : 0;
  if (need === 0) throw new CborError(`unsupported additional info ${info}`);
  if (c.pos + need > c.bytes.length) throw new CborError("truncated length");
  let v = 0;
  for (const b of c.bytes.subarray(c.pos, c.pos + need)) v = v * 256 + b;
  c.pos += need;
  return v;
}

function readItem(c: Cursor, depth: number): unknown {
  if (depth > 4) throw new CborError("nesting too deep");
  if (c.pos >= c.bytes.length) throw new CborError("truncated");
  const head = c.bytes[c.pos++]!;
  const major = head >> 5;
  const info = head & 0x1f;
  switch (major) {
    case 0:
      return readLength(c, info);
    case 2: {
      const n = readLength(c, info);
      if (c.pos + n > c.bytes.length) throw new CborError("truncated byte string");
      const out = c.bytes.slice(c.pos, c.pos + n);
      c.pos += n;
      return out;
    }
    case 3: {
      const n = readLength(c, info);
      if (c.pos + n > c.bytes.length) throw new CborError("truncated text string");
      const slice = c.bytes.slice(c.pos, c.pos + n);
      c.pos += n;
      try {
        return new TextDecoder("utf-8", { fatal: true }).decode(slice);
      } catch {
        throw new CborError("invalid utf-8 text string");
      }
    }
    case 5: {
      const n = readLength(c, info);
      if (n > 16) throw new CborError("map too large for an assertion");
      const map = new Map<string, unknown>();
      for (let i = 0; i < n; i++) {
        const key = readItem(c, depth + 1);
        if (typeof key !== "string") throw new CborError("non-text map key");
        if (map.has(key)) throw new CborError("duplicate map key");
        map.set(key, readItem(c, depth + 1));
      }
      return map;
    }
    default:
      throw new CborError(`unsupported CBOR major type ${major}`);
  }
}

export function decodeCbor(bytes: Uint8Array): unknown {
  const c: Cursor = { bytes, pos: 0 };
  const v = readItem(c, 0);
  if (c.pos !== bytes.length) throw new CborError("trailing bytes after the CBOR item");
  return v;
}

export interface ParsedAssertion {
  signature: Uint8Array;
  authenticatorData: Uint8Array;
}

export function parseAssertion(bytes: Uint8Array): ParsedAssertion {
  const v = decodeCbor(bytes);
  if (!(v instanceof Map) || v.size !== 2) throw new CborError("assertion must be a map of exactly two entries");
  const signature = v.get("signature");
  const authenticatorData = v.get("authenticatorData");
  if (!(signature instanceof Uint8Array) || !(authenticatorData instanceof Uint8Array)) {
    throw new CborError("assertion needs byte-string signature and authenticatorData");
  }
  return { signature, authenticatorData };
}

export interface ParsedAuthenticatorData {
  rpIdHash: Uint8Array;
  flags: number;
  counter: number;
}

export function parseAuthenticatorData(data: Uint8Array): ParsedAuthenticatorData {
  // An assertion's authenticatorData carries no attested-credential data:
  // exactly 32 + 1 + 4 bytes.
  if (data.byteLength !== 37) throw new CborError(`authenticatorData must be 37 bytes (got ${data.byteLength})`);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  return { rpIdHash: data.slice(0, 32), flags: data[32]!, counter: view.getUint32(33, false) };
}

/** DER ECDSA signature -> the raw r‖s (64 bytes) Web Crypto wants. `null` on
 * any malformed DER. */
export function derSignatureToRaw(der: Uint8Array): Uint8Array | null {
  // A P-256 ECDSA signature is at most 72 bytes of DER, so every length below
  // uses the one-byte short form; the long form is rejected.
  //
  // STRICT DER: each INTEGER must be the MINIMAL encoding of a non-negative
  // value. A leading 0x00 is legal only in front of a byte with the high bit set
  // (it is what keeps that value positive); a leading 0x00 in front of anything
  // else is a non-minimal encoding, and a high-bit first byte with no leading
  // 0x00 is a negative number. Both are rejected, not "repaired": accepting a
  // malleable encoding means one signature has several accepted byte strings.
  let p = 0;
  if (der[p++] !== 0x30) return null;
  const seqLen = der[p++];
  if (seqLen === undefined || seqLen >= 0x80 || p + seqLen !== der.length) return null;
  const out = new Uint8Array(64);
  for (let half = 0; half < 2; half++) {
    if (der[p++] !== 0x02) return null;
    let len = der[p++];
    if (len === undefined || len === 0 || len >= 0x80 || p + len > der.length) return null;
    let start = p;
    p += len;
    const first = der[start]!;
    if (first & 0x80) return null; // negative
    if (len > 1 && first === 0x00) {
      if (((der.at(start + 1) ?? 0) & 0x80) === 0) return null; // non-minimal: the zero is not needed
      start++;
      len--;
    }
    if (len > 32) return null;
    out.set(der.slice(start, start + len), half * 32 + (32 - len));
  }
  if (p !== der.length) return null;
  return out;
}

export interface AppAttestVerifierConfig {
  /** `<TeamID>.<BundleID>`. */
  appId: string;
}

export interface AppAttestCrypto {
  sha256: Sha256Fn;
  /** ECDSA P-256 / SHA-256 verify: raw 65-byte public key, raw 64-byte r‖s
   * signature, message. */
  verifyP256(publicKeyRaw: Uint8Array, signatureRaw: Uint8Array, message: Uint8Array): Promise<boolean>;
}

/** Web Crypto implementation of `AppAttestCrypto.verifyP256`. */
export async function verifyP256WebCrypto(publicKeyRaw: Uint8Array, signatureRaw: Uint8Array, message: Uint8Array): Promise<boolean> {
  const key = await crypto.subtle.importKey("raw", publicKeyRaw.slice().buffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signatureRaw.slice().buffer, message.slice().buffer);
}

/** Verifies one App Attest assertion. Returns the new counter on success.
 * Every failure names its class so the handler can grade it: a missing key is
 * `unattestable`; everything else is `failed` (§4.5: "a tampering verdict, a
 * replayed counter, a wrong requestHash"). */
export async function verifyAppAttestAssertion(
  input: AppAttestAssertionInput,
  config: AppAttestVerifierConfig,
  deps: AppAttestCrypto,
): Promise<AssertionResult> {
  const { device } = input;
  if (!device.attestPublicKey || !device.attestKeyId) {
    return { ok: false, grade: "unattestable", reason: "key_not_registered" };
  }
  // The key id the client names must be the one on record for this install.
  const claimedKeyId = fromBase64Lenient(input.keyId);
  const recordedKeyId = fromBase64Lenient(device.attestKeyId);
  if (!claimedKeyId || !recordedKeyId || !bytesEqual(claimedKeyId, recordedKeyId)) {
    return { ok: false, grade: "failed", reason: "key_id_mismatch" };
  }

  const raw = fromBase64Lenient(input.assertionB64);
  if (!raw) return { ok: false, grade: "failed", reason: "malformed_assertion" };
  let parsed: ParsedAssertion;
  let auth: ParsedAuthenticatorData;
  try {
    parsed = parseAssertion(raw);
    auth = parseAuthenticatorData(parsed.authenticatorData);
  } catch {
    return { ok: false, grade: "failed", reason: "malformed_assertion" };
  }

  const expectedRpIdHash = await deps.sha256(new TextEncoder().encode(config.appId));
  if (!bytesEqual(auth.rpIdHash, expectedRpIdHash)) return { ok: false, grade: "failed", reason: "rp_id_mismatch" };

  const sigRaw = derSignatureToRaw(parsed.signature);
  if (!sigRaw) return { ok: false, grade: "failed", reason: "malformed_signature" };
  const nonce = await deps.sha256(concatBytes(parsed.authenticatorData, input.clientDataHash));
  let valid = false;
  try {
    valid = await deps.verifyP256(device.attestPublicKey, sigRaw, nonce);
  } catch {
    return { ok: false, grade: "failed", reason: "bad_public_key" };
  }
  // A signature over a different clientDataHash (a different reward, device,
  // platform, challenge — or a tampered body) lands here.
  if (!valid) return { ok: false, grade: "failed", reason: "bad_signature_or_request_hash" };

  if (auth.counter <= device.attestCounter) return { ok: false, grade: "failed", reason: "counter_not_monotonic" };
  return { ok: true, counter: auth.counter };
}
