// supabase/functions/_shared/partner/token.ts
//
// The opaque partner session token (docs/security/partner-auth-design.md 4.2, 4.6): `gr_ps_` + 43 base64url characters (256 random bits), generated HERE, hashed with SHA-256 HERE, and only the hash
// ever reaches the database. Pure (Web Crypto only): no environment, no database, no logging. The token is returned to the client exactly once, in the body of a successful sign-in, and is never
// stored, logged or sent anywhere else.

/** The prefix of a partner session token (greppable by a secret scanner, and what `getActorFromRequest` refuses to forward to GoTrue). */
export const PARTNER_SESSION_PREFIX = "gr_ps_";
/** `gr_ps_` followed by exactly 43 base64url characters. */
export const PARTNER_SESSION_TOKEN_RE = /^gr_ps_[A-Za-z0-9_-]{43}$/;

/** Unpadded base64url. */
export function toB64u(bytes: Uint8Array): string {
  const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join("");
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Strict, canonical unpadded base64url to bytes, or null: the characters must be base64url, the length must be possible, and re-encoding must give the same string (no stray trailing bits). */
export function fromB64u(s: string): Uint8Array | null {
  if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) return null;
  const padded = s.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (s.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return toB64u(bytes) === s ? bytes : null;
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** sha256 of a string's UTF-8 bytes, lower-case hex (64 characters): what `private.bind_partner_session` and `partner_session_mint` take. */
export async function sha256Hex(text: string): Promise<string> {
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

/** The invite token (6.1): `gr_inv_` + 43 base64url characters (32 random bytes), carried in the link's fragment and never sent as a bearer. */
export const PARTNER_INVITE_PREFIX = "gr_inv_";
/** The enrolment token (recovery 6.5, admin 6.4): `gr_enr_` + 43 base64url characters, handed by a manager or an admin to the person it belongs to. */
export const PARTNER_ENROLMENT_PREFIX = "gr_enr_";
/** The hand-over token (S5): `gr_ho_` + 43 base64url characters (32 random bytes), shown to the player once, typed or scanned by staff within 15 minutes; only its SHA-256 reaches the database. */
export const PARTNER_HANDOVER_PREFIX = "gr_ho_";
export const PARTNER_HANDOVER_TOKEN_RE = /^gr_ho_[A-Za-z0-9_-]{43}$/;
export const PARTNER_INVITE_TOKEN_RE = /^gr_inv_[A-Za-z0-9_-]{43}$/;
export const PARTNER_ENROLMENT_TOKEN_RE = /^gr_enr_[A-Za-z0-9_-]{43}$/;

export interface NewSessionToken {
  /** The raw token the client receives, once. */
  readonly token: string;
  /** sha256 hex of `token`: the only form the database ever sees. */
  readonly hash: string;
}

async function newOpaqueToken(prefix: string): Promise<NewSessionToken> {
  const token = prefix + toB64u(crypto.getRandomValues(new Uint8Array(32)));
  return { token, hash: await sha256Hex(token) };
}

export function newPartnerSessionToken(): Promise<NewSessionToken> {
  return newOpaqueToken(PARTNER_SESSION_PREFIX);
}

export function newPartnerInviteToken(): Promise<NewSessionToken> {
  return newOpaqueToken(PARTNER_INVITE_PREFIX);
}

export function newPartnerEnrolmentToken(): Promise<NewSessionToken> {
  return newOpaqueToken(PARTNER_ENROLMENT_PREFIX);
}

export function newPartnerHandoverToken(): Promise<NewSessionToken> {
  return newOpaqueToken(PARTNER_HANDOVER_PREFIX);
}

/** The token of an `Authorization: Bearer gr_ps_...` header, or null for anything else (a Supabase JWT, another scheme, a malformed token, no header). Never throws, never inspects another shape of token. */
export function partnerTokenFromHeader(authorization: string | null): string | null {
  if (authorization === null) return null;
  const m = /^Bearer ([^\s]+)$/i.exec(authorization);
  if (m === null) return null;
  return PARTNER_SESSION_TOKEN_RE.test(m[1]!) ? m[1]! : null;
}
