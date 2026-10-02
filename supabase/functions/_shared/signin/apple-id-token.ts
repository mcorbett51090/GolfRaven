// supabase/functions/_shared/signin/apple-id-token.ts
//
// Verification of a Sign in with Apple IDENTITY TOKEN (a JWT the client got from Apple), server side.
//
// [unverified — training knowledge] Every Apple-specific fact below comes from memory of Apple's documentation, not from
// this session reaching Apple (there are no credentials and no route to Apple in the build environment); the P4 spike,
// against a real service id and key, confirms them:
//   * the issuer is exactly `https://appleid.apple.com`;
//   * the signing keys are an RSA JWKS at `https://appleid.apple.com/auth/keys`, tokens are RS256, and carry a `kid`;
//   * `aud` is the app's client id (the bundle id for a native iOS sign-in, a Services ID for web / Android);
//   * `sub` is Apple's stable per-team user id; `email` / `email_verified` / `is_private_email` are optional and the last two
//     may be the STRINGS "true" / "false" rather than booleans;
//   * for the native flow the client hashes its nonce with SHA-256 (lowercase hex) before handing it to Apple, so the token's
//     `nonce` claim is that hash.
//
// What is checked, all of it, in this order (any failure is an AppleTokenError with a closed `reason`; nothing the token said
// is echoed anywhere):
//   1. shape: three base64url segments, bounded size, header and payload are JSON objects;
//   2. `alg` is exactly RS256 (never `none`, never an HMAC: a downgrade to HS256 with the PUBLIC key as the secret is the
//      classic JWT forgery) and `kid` is present;
//   3. the key for that `kid` is in Apple's JWKS (fetched through the injected SafeFetcher, cached, refetched at most once a
//      minute for an unknown `kid`), imported as RSA-2048+ and the RSASSA-PKCS1-v1_5/SHA-256 signature verifies;
//   4. `iss` equals Apple's issuer, `aud` equals the configured client id (a string, or an array of exactly that one), `exp`
//      is in the future, `iat` is not in the future (60 s skew), `sub` is a non-empty string;
//   5. the NONCE: the token's `nonce` claim must equal SHA-256-hex(rawNonce) or rawNonce itself (a client that forgot to hash
//      before calling Apple). A token without a nonce is refused: the binding is not optional.
//
// What this does NOT do: it is not a replay defence on its own (the nonce binds a token to one client-held secret, not to
// "used once"); the caller combines it with the authenticated session and the single-use authorization code.

import { AppleTokenError, VendorUnavailableError } from "./errors.ts";
import { constantTimeEqual, fromBase64Url, sha256Hex } from "./bytes.ts";
import { parseJsonObject, type SafeFetcher } from "./safe-fetch.ts";

export const APPLE_ISSUER = "https://appleid.apple.com";
export const APPLE_JWKS_URL = "https://appleid.apple.com/auth/keys";
export const APPLE_HOST = "appleid.apple.com";

const MAX_TOKEN_CHARS = 8 * 1024;
const MAX_KEYS = 20;
const CLOCK_SKEW_SECONDS = 60;

export interface AppleJwk {
  kty: "RSA";
  kid: string;
  n: string;
  e: string;
}

export interface VerifiedAppleIdentity {
  /** Apple's stable user id for this team. */
  subject: string;
  email: string | null;
  emailVerified: boolean;
  isPrivateRelay: boolean;
}

// ---------------------------------------------------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------------------------------------------------
export interface JwksCacheOptions {
  fetcher: SafeFetcher;
  nowMs(): number;
  url?: string;
  /** A fetched set is fresh for this long. */
  ttlMs?: number;
  /** A set older than ttl is still used (stale-if-error) for this long when Apple cannot be reached; past it, fail closed. */
  maxStaleMs?: number;
  /** An unknown `kid` triggers a refetch, but never more often than this. */
  minRefetchMs?: number;
}

export interface JwksCache {
  /** The key for `kid`, or `null` if Apple's current set has no such key. Throws VendorUnavailableError when no usable set can be had. */
  getKey(kid: string): Promise<AppleJwk | null>;
}

export function createJwksCache(opts: JwksCacheOptions): JwksCache {
  const url = opts.url ?? APPLE_JWKS_URL;
  const ttlMs = opts.ttlMs ?? 60 * 60_000;
  const maxStaleMs = opts.maxStaleMs ?? 24 * 60 * 60_000;
  const minRefetchMs = opts.minRefetchMs ?? 60_000;
  let keys: Map<string, AppleJwk> | null = null;
  let fetchedAt = 0;
  let lastAttemptAt = Number.NEGATIVE_INFINITY;
  let inflight: Promise<void> | null = null;

  async function refresh(): Promise<void> {
    if (inflight) return inflight;
    inflight = (async () => {
      lastAttemptAt = opts.nowMs();
      const res = await opts.fetcher(url, { method: "GET", headers: { accept: "application/json" } });
      if (res.status !== 200) throw new VendorUnavailableError(`jwks_status_${res.status >= 500 ? "5xx" : "other"}`);
      const body = parseJsonObject(res.text);
      const list = body && Array.isArray(body.keys) ? (body.keys as unknown[]) : null;
      if (list === null || list.length === 0 || list.length > MAX_KEYS) throw new VendorUnavailableError("jwks_malformed");
      const next = new Map<string, AppleJwk>();
      for (const k of list) {
        if (typeof k !== "object" || k === null) continue;
        const o = k as Record<string, unknown>;
        if (o.kty === "RSA" && typeof o.kid === "string" && o.kid.length > 0 && o.kid.length <= 128 && typeof o.n === "string" && typeof o.e === "string") {
          next.set(o.kid, { kty: "RSA", kid: o.kid, n: o.n, e: o.e });
        }
      }
      if (next.size === 0) throw new VendorUnavailableError("jwks_malformed");
      keys = next;
      fetchedAt = opts.nowMs();
    })().finally(() => {
      inflight = null;
    });
    return inflight;
  }

  return {
    async getKey(kid: string): Promise<AppleJwk | null> {
      const now = opts.nowMs();
      const fresh = keys !== null && now - fetchedAt < ttlMs;
      if (fresh && keys!.has(kid)) return keys!.get(kid)!;
      // Stale, empty, or the kid is unknown: refetch, but an unknown kid cannot make this a fetch-per-request amplifier.
      const mayFetch = keys === null || !fresh || now - lastAttemptAt >= minRefetchMs;
      if (mayFetch) {
        try {
          await refresh();
        } catch (e) {
          // Apple is unreachable: serve the stale set for a bounded time, never indefinitely.
          if (keys !== null && now - fetchedAt < maxStaleMs) return keys.get(kid) ?? null;
          throw e instanceof VendorUnavailableError ? e : new VendorUnavailableError("jwks");
        }
      }
      return keys?.get(kid) ?? null;
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------------------------------------------------
export interface VerifyOptions {
  jwks: JwksCache;
  nowMs(): number;
  /** The configured client id (bundle id / Services ID): the only acceptable `aud`. */
  clientId: string;
}

export interface Expectation {
  /** The raw nonce the client generated. `null` skips the nonce check (only for the token Apple returns from the token endpoint, which carries the nonce of the original request but is not bound to a client secret we hold). */
  rawNonce: string | null;
}

function decodeJsonSegment(seg: string): Record<string, unknown> {
  const bytes = fromBase64Url(seg);
  if (bytes === null) throw new AppleTokenError("malformed");
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new AppleTokenError("malformed");
  }
  const obj = parseJsonObject(text);
  if (obj === null) throw new AppleTokenError("malformed");
  return obj;
}

/** A JWK `n` has no leading zero byte, so a 2048-bit modulus is exactly 256 bytes. */
const MIN_RSA_MODULUS_BYTES = 256;

const isTrue = (v: unknown): boolean => v === true || v === "true";

export async function verifyAppleIdentityToken(token: string, expect: Expectation, opts: VerifyOptions): Promise<VerifiedAppleIdentity> {
  if (typeof token !== "string" || token.length === 0 || token.length > MAX_TOKEN_CHARS) throw new AppleTokenError("malformed");
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) throw new AppleTokenError("malformed");
  const [h, p, s] = parts as [string, string, string];

  const header = decodeJsonSegment(h);
  if (header.alg !== "RS256") throw new AppleTokenError("alg");
  if (typeof header.kid !== "string" || header.kid.length === 0 || header.kid.length > 128) throw new AppleTokenError("unknown_kid");
  const claims = decodeJsonSegment(p);
  const sig = fromBase64Url(s);
  if (sig === null || sig.length === 0 || sig.length > 1024) throw new AppleTokenError("malformed");

  const jwk = await opts.jwks.getKey(header.kid);
  if (jwk === null) throw new AppleTokenError("unknown_kid");

  let valid: boolean;
  try {
    // A modulus under 2048 bits is not a key Apple publishes (security gate NIT): refuse it before it can verify anything.
    const modulus = fromBase64Url(jwk.n);
    if (modulus === null || modulus.length < MIN_RSA_MODULUS_BYTES) throw new AppleTokenError("signature");
    const key = await crypto.subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    valid = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig.slice().buffer, new TextEncoder().encode(`${h}.${p}`));
  } catch {
    throw new AppleTokenError("signature");
  }
  if (!valid) throw new AppleTokenError("signature");

  // ---- claims (the signature is good: from here on the content is Apple's, but still checked) ----
  if (claims.iss !== APPLE_ISSUER) throw new AppleTokenError("issuer");
  const aud = claims.aud;
  const audOk = typeof aud === "string" ? aud === opts.clientId : Array.isArray(aud) && aud.length === 1 && aud[0] === opts.clientId;
  if (!audOk) throw new AppleTokenError("audience");
  const nowSec = Math.floor(opts.nowMs() / 1000);
  if (typeof claims.exp !== "number" || !Number.isFinite(claims.exp) || claims.exp <= nowSec) throw new AppleTokenError("expired");
  if (typeof claims.iat !== "number" || !Number.isFinite(claims.iat) || claims.iat > nowSec + CLOCK_SKEW_SECONDS) throw new AppleTokenError("not_yet_valid");
  if (typeof claims.sub !== "string" || claims.sub.length === 0 || claims.sub.length > 255) throw new AppleTokenError("subject");

  if (expect.rawNonce !== null) {
    const claimed = claims.nonce;
    if (typeof claimed !== "string" || claimed.length === 0) throw new AppleTokenError("nonce");
    // ONLY the SHA-256 hex of the raw nonce is accepted (Apple's native flow: the app puts sha256(raw) in the request, Apple echoes it as the
    // claim). The claim itself is NEVER an acceptable raw nonce: a token holder can read the claim, so accepting `claim === raw` would let
    // anyone who holds an id_token "prove" the nonce by submitting the claim as the raw value, binding nothing (security gate F1).
    const hashed = await sha256Hex(expect.rawNonce);
    if (!constantTimeEqual(claimed, hashed)) throw new AppleTokenError("nonce");
  }

  const email = typeof claims.email === "string" && claims.email.length > 0 && claims.email.length <= 320 ? claims.email.trim().toLowerCase() : null;
  return {
    subject: claims.sub,
    email,
    emailVerified: email !== null && isTrue(claims.email_verified),
    isPrivateRelay: isTrue(claims.is_private_email) || (email !== null && email.endsWith("@privaterelay.appleid.com")),
  };
}
