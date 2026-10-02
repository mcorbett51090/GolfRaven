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

// ---- base64 / base64url ----------------------------------------------------

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Strict UNPADDED base64url (RFC 4648 §5). `null` on anything else — never a
 * silent partial decode. */
export function fromBase64UrlStrict(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) return null;
  const padded = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
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
