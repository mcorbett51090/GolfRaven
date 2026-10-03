// supabase/functions/_shared/rewards/binding.ts
//
// Binding an attestation to the request payload (build plan §7.5):
//   iOS     clientDataHash = SHA-256(canonical_body ‖ server_challenge)
//   Android requestHash    = SHA-256(canonical_body ‖ challenge)
// where `canonical_body` is the activation request's own fields, serialised
// canonically, and the challenge is the RAW nonce POST /v1/checkin/challenge
// returned. An assertion made for a different reward, device, platform or
// challenge therefore cannot verify against this request: a "mismatched body
// hash" (AT 5) is a hash that does not match, nothing more subtle.
//
// UPDATE (iOS): the iOS clientDataHash no longer uses this raw-bytes form. A React Native client can only hash a
// STRING, so iOS (activation assertions and key registration) uses string-binding.ts
// (`SHA-256(UTF-8(canonical JSON string carrying the nonce as text))`). This module's raw-bytes construction remains
// the Android Play Integrity `requestHash`, which the app computes itself, and its building blocks.
//
// Pure, Web-Crypto-only (the SHA-256 itself is injected as `Sha256Fn`, so unit
// tests and the Deno runtime share one code path and nothing here imports a
// platform global).

export interface Sha256Fn {
  (bytes: Uint8Array): Promise<Uint8Array>;
}

/** What the client binds. The request's identity fields, plus the two request
 * fields that feed the persistent-bit lookup:
 *   - iOS: `deviceCheckTokenSha256` (lowercase hex SHA-256 of the DeviceCheck
 *     token the request carries). The assertion cannot cover the token itself
 *     (the token is not part of what an App Attest key signs), but it CAN cover
 *     the token's hash — and must, otherwise the DeviceCheck token is the one
 *     request field a man-in-the-middle or a second device can swap freely:
 *     present a valid assertion from a device whose bits are bad, next to a
 *     token from a device whose bits are clean (H1).
 *   - Android: `installLinkId` (the opaque install identifier the A20 substitute
 *     links on), when the request carries one.
 * The attestation material itself (assertion, integrity token) cannot be part
 * of what it signs, and `hardwareSupportsAttestation` is a self-report, not a
 * bound fact. A field that is absent is absent from the canonical bytes — it is
 * never serialised as null — so an Android body and an iOS body can never be
 * confused for one another. */
export interface BoundBody {
  rewardId: string;
  deviceId: string;
  platform: "ios" | "android";
  challengeId: string;
  deviceCheckTokenSha256?: string;
  installLinkId?: string;
}

/** Canonical JSON: object keys sorted (recursively), no whitespace, strings
 * escaped by JSON.stringify, UTF-8 on the wire. Rejects anything JSON cannot
 * represent faithfully (undefined, NaN/Infinity, functions, bigint) so two
 * parties can never disagree on bytes because one dropped a field. */
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

export function boundBodyBytes(body: BoundBody): Uint8Array {
  return new TextEncoder().encode(
    canonicalJson({
      rewardId: body.rewardId,
      deviceId: body.deviceId,
      platform: body.platform,
      challengeId: body.challengeId,
      ...(body.deviceCheckTokenSha256 !== undefined ? { deviceCheckTokenSha256: body.deviceCheckTokenSha256 } : {}),
      ...(body.installLinkId !== undefined ? { installLinkId: body.installLinkId } : {}),
    }),
  );
}

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.byteLength;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.byteLength;
  }
  return out;
}

/** SHA-256(canonical_body ‖ server_challenge). */
export async function computeRequestBinding(sha256: Sha256Fn, body: BoundBody, challengeBytes: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(boundBodyBytes(body), challengeBytes));
}

// ---- the check-in token binding (checkin-token, build plan §4.5 G3-08 / §4.7.1a) ----------------------------------
//
// `POST /v1/checkin/token` may carry an App Attest assertion (iOS) or a Play Integrity token (Android) that
// proves THIS device, for THIS server challenge, on behalf of THIS account. What the attestation commits to is
// the check-in binding below. It is deliberately a different message from the reward-activation binding and the
// key-registration binding, so an attestation made for one purpose can never verify as another:
//   - the purpose string `golfraven/checkin-token/v1` is part of every check-in binding (a domain separator;
//     activation uses "reward_activation", key registration "attest_key_registration");
//   - the field SET differs too: activation binds a `rewardId`, a check-in binds a `userId`;
//   - the challenge id, the device the challenge was issued to, and the account are bound, so a challenge or an
//     assertion cannot be moved between devices or accounts; the raw nonce is bound, so the assertion proves
//     possession of the nonce the server issued.
//
//   iOS      clientDataHash = SHA-256(UTF-8(S)),  S = canonical JSON string (string-binding.ts#iosCheckinChallengeString)
//            {"challengeId","deviceId","nonce","platform":"ios","purpose":"golfraven/checkin-token/v1","userId"}
//   Android  requestHash    = base64url(SHA-256(canonical_body ‖ RAW nonce bytes)),  canonical_body below
//            {"challengeId","deviceId","platform":"android","purpose":"golfraven/checkin-token/v1","userId"}
//
// The device id is the one the challenge was ISSUED to (the server reads it from the challenge row; the client
// sent it to POST /v1/checkin/challenge), so the token request does not need to repeat it.

/** Domain separator for the check-in token attestation, both platforms. Distinct from activation and key registration. */
export const CHECKIN_TOKEN_PURPOSE = "golfraven/checkin-token/v1";

/** What a check-in attestation binds, apart from the nonce. UUIDs lowercase. */
export interface CheckinBoundBody {
  challengeId: string;
  /** The device the challenge was issued to. */
  deviceId: string;
  /** The authenticated account (the JWT `sub`). */
  userId: string;
}

/** The Android canonical body (UTF-8 JSON, keys sorted, no whitespace). The raw nonce bytes follow it in the hash input. */
export function checkinAndroidBoundBodyBytes(body: CheckinBoundBody): Uint8Array {
  return new TextEncoder().encode(
    canonicalJson({
      challengeId: body.challengeId,
      deviceId: body.deviceId,
      platform: "android",
      purpose: CHECKIN_TOKEN_PURPOSE,
      userId: body.userId,
    }),
  );
}

/** Android check-in `requestHash` (before base64url): SHA-256(canonical_body ‖ raw nonce bytes). Same layout as
 * `computeRequestBinding`, over the check-in body. */
export async function computeCheckinAndroidBinding(sha256: Sha256Fn, body: CheckinBoundBody, nonceBytes: Uint8Array): Promise<Uint8Array> {
  return sha256(concatBytes(checkinAndroidBoundBodyBytes(body), nonceBytes));
}

// ---- base64 / base64url ----------------------------------------------------

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict UNPADDED base64url (RFC 4648 §5). `null` on anything else — never a
 * silent partial decode, and never a NON-CANONICAL spelling: when the length is not a multiple of 4 the last
 * character carries unused trailing bits, which `atob` ignores, so `AA`, `AB` and `AP` all decode to the one byte
 * 0x00. A nonce is bound as TEXT into the iOS string `S` (string-binding.ts) as well as decoded to bytes for the
 * challenge hash, so several spellings of one challenge would be several different bindings of the same consumed
 * nonce. The decode therefore must round-trip: `toBase64Url(bytes) === s`. */
export function fromBase64UrlStrict(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) return null;
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return toBase64Url(out) === s ? out : null;
  } catch {
    return null;
  }
}

/** Standard OR url-safe base64, padded or not (App Attest key ids and the
 * CBOR assertion arrive as plain base64 from the iOS SDK). `null` on junk. */
export function fromBase64Lenient(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
  const unpadded = s.replace(/=+$/, "").replace(/-/g, "+").replace(/_/g, "/");
  if (unpadded.length % 4 === 1) return null;
  try {
    const bin = atob(unpadded + "===".slice((unpadded.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Length-independent-of-content equality (no early exit on the first
 * differing byte). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export function stringsEqualConstantTime(a: string, b: string): boolean {
  const enc = new TextEncoder();
  return bytesEqual(enc.encode(a), enc.encode(b));
}
