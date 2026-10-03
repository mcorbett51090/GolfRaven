/**
 * The request bindings the SERVER verifies, byte for byte (`supabase/functions/_shared/rewards/binding.ts`, `string-binding.ts`,
 * `app-attest-registration.ts`). Cross-checked against the server's own output for fixed inputs (`test/fixtures/edge-contract.json`
 * `vectors.binding`, recorded from the real functions by `scripts/record-edge-contract.rec.ts`).
 *
 * Plan vs server (the server wins): build plan §7.5 says both platforms bind `SHA-256(canonical_body || server_challenge)`. The server keeps that
 * RAW-bytes form for Android only. For iOS it hashes a UTF-8 STRING, a canonical JSON object that carries the nonce as base64url TEXT, because a
 * React Native client can hash only strings through the App Attest module. So:
 *   - Android `requestHash`  = SHA-256( UTF-8(canonical_body JSON) || raw challenge bytes )        -> `androidRequestBinding`
 *   - iOS `clientDataHash`   = SHA-256( UTF-8(canonical JSON string S) )                            -> `iosActivationBinding`, `attestKeyBinding`
 * `canonical JSON` = keys sorted recursively, no whitespace, `JSON.stringify` escaping; an `undefined` / non-finite value is an error, an absent
 * optional field is ABSENT (never null). UUIDs are lowercase (Swift's `UUID.uuidString` is uppercase: lowercase it first, done here).
 *
 * What there is NOT: a binding for the evidence / `checkin-token` request. The server's `checkin-token` handler does not read any attestation
 * material today (it grades every call "no token", `token-handler.ts`), so there is nothing to bind to; P4.2b-2 needs the server to define it
 * (`README.md`, "What P4.2b-2 must plug in").
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { base64UrlToBytes, bytesToHex, utf8Encode } from "../catalog/bytes";
import { bytesToBase64Url } from "../signin/nonce";

// The repo's own unpadded base64url encoder (pure, Node-checked in signin-flow.test.ts): no global `btoa` is needed. Re-exported: callers import it from here.
export { bytesToBase64Url };

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalize(value));
}

function canonicalize(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalJson: non-finite number");
    return value;
  }
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v === undefined) throw new Error(`canonicalJson: undefined value at key "${key}"`);
      out[key] = canonicalize(v);
    }
    return out;
  }
  throw new Error(`canonicalJson: unsupported value of type ${typeof value}`);
}

/** Strict unpadded base64url -> bytes (the server's `fromBase64UrlStrict`): `null` unless the text is canonical (re-encoding gives the same text). */
export function nonceBytesStrict(nonce: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(nonce) || nonce.length % 4 === 1) return null;
  try {
    const bytes = base64UrlToBytes(nonce);
    return bytesToBase64Url(bytes) === nonce ? bytes : null;
  } catch {
    return null;
  }
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.byteLength, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

const lower = (s: string): string => s.toLowerCase();

// ---- Android ------------------------------------------------------------------------------------------------------------------------------------

/** What an Android activation request binds (`BoundBody`, binding.ts). `installLinkId` is bound only when the request carries one. */
export interface AndroidBoundBody {
  rewardId: string;
  deviceId: string;
  challengeId: string;
  installLinkId?: string;
}

/** The canonical body bytes (UTF-8 of the canonical JSON). */
export function androidBoundBodyBytes(b: AndroidBoundBody): Uint8Array {
  return utf8Encode(
    canonicalJson({
      rewardId: lower(b.rewardId),
      deviceId: lower(b.deviceId),
      platform: "android",
      challengeId: lower(b.challengeId),
      ...(b.installLinkId !== undefined ? { installLinkId: b.installLinkId } : {}),
    }),
  );
}

/** Play Integrity `requestHash` = SHA-256(canonical_body || RAW challenge bytes). `nonce` is the base64url text the challenge endpoint returned;
 * it is decoded strictly (a non-canonical spelling is refused, as on the server). */
export function androidRequestBinding(body: AndroidBoundBody, nonce: string): Uint8Array {
  const challenge = nonceBytesStrict(nonce);
  if (challenge === null) throw new Error("androidRequestBinding: the nonce is not canonical unpadded base64url");
  return sha256(concatBytes(androidBoundBodyBytes(body), challenge));
}

// ---- iOS ----------------------------------------------------------------------------------------------------------------------------------------

export interface IosActivationBoundBody {
  rewardId: string;
  deviceId: string;
  challengeId: string;
  /** Lowercase hex SHA-256 of the DeviceCheck token the request carries. */
  deviceCheckTokenSha256: string;
  /** The nonce STRING exactly as the challenge endpoint returned it. */
  nonce: string;
}

/** `S` for `generateAssertion` of a reward activation. */
export function iosActivationChallengeString(b: IosActivationBoundBody): string {
  return canonicalJson({
    challengeId: lower(b.challengeId),
    deviceCheckTokenSha256: b.deviceCheckTokenSha256,
    deviceId: lower(b.deviceId),
    nonce: b.nonce,
    platform: "ios",
    purpose: "reward_activation",
    rewardId: lower(b.rewardId),
  });
}

export function iosActivationBinding(b: IosActivationBoundBody): Uint8Array {
  return sha256(utf8Encode(iosActivationChallengeString(b)));
}

export interface AttestKeyBoundBody {
  challengeId: string;
  deviceId: string;
  /** Exactly the string `generateKey` returned (44 characters, standard base64, one `=`). */
  keyId: string;
  nonce: string;
}

/** `S` for `attestKey` (App Attest key registration). */
export function attestKeyChallengeString(b: AttestKeyBoundBody): string {
  return canonicalJson({
    challengeId: lower(b.challengeId),
    deviceId: lower(b.deviceId),
    keyId: b.keyId,
    nonce: b.nonce,
    platform: "ios",
    purpose: "attest_key_registration",
  });
}

export function attestKeyBinding(b: AttestKeyBoundBody): Uint8Array {
  return sha256(utf8Encode(attestKeyChallengeString(b)));
}

export { bytesToHex };
