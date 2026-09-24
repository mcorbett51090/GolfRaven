/**
 * Single-use token generation + hashing (confirm links, unsubscribe links,
 * and the rate-limit IP key). Raw tokens are only ever returned to the
 * caller (to put in an email link or KV key) — everything durable stores
 * only `sha256(pepper + ":" + raw)`, never the raw value (gate-review S6 /
 * "store token hashes, never raw tokens").
 */

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** A 256-bit random, URL-safe token — used for confirm and unsubscribe links. */
export function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

/** SHA-256 hex digest of `pepper + ":" + value`. */
export async function hashWithPepper(
  pepper: string,
  value: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${pepper}:${value}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The unsubscribe token, unlike the confirm token, is deliberately
 * DETERMINISTIC and STABLE per address rather than random-and-rotated
 * (gate-round3 finding A-2): `base64url(HMAC-SHA256(key = pepper,
 * message = "golfraven-unsubscribe-v1:" + email_lc))`.
 *
 * Why: RFC 8058 one-click unsubscribe must keep working from EVERY
 * confirmation email ever sent to an address, not just the most recent
 * resend — a mailbox can hold several confirmation emails (initial send
 * plus resends) at once, and each one's `List-Unsubscribe` link has to
 * resolve. Deriving the token from the address (instead of drawing a
 * fresh random value per send, as the confirm token does) makes every
 * email's unsubscribe link identical, so an old email's link 400ing after
 * a later resend — the exact regression this closes — becomes
 * structurally impossible: there is only ever one value to compute.
 *
 * It stays unguessable without the pepper: this is a keyed HMAC over
 * public data (the address), not a hash of public data alone, so nothing
 * short of TOKEN_PEPPER lets an attacker compute another address's
 * unsubscribe token. The corollary: rotating TOKEN_PEPPER changes every
 * derived unsubscribe token at once and invalidates every previously
 * emailed unsubscribe link — see config.ts's `Env.TOKEN_PEPPER_PREVIOUS`
 * and README.md "Rotating TOKEN_PEPPER" for the transition path (accept
 * either pepper for a lookup window) before rotating it in production.
 */
export async function deriveUnsubscribeToken(
  pepper: string,
  emailLc: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pepper),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(`golfraven-unsubscribe-v1:${emailLc}`),
  );
  return toBase64Url(new Uint8Array(signature));
}

/** ISO-8601 timestamp `secondsFromNow` seconds in the future, for `confirm_expires_at`. */
export function isoTimeFromNow(secondsFromNow: number): string {
  return new Date(Date.now() + secondsFromNow * 1000).toISOString();
}

export function isExpired(isoExpiry: string, now: Date = new Date()): boolean {
  const expiry = new Date(isoExpiry);
  if (Number.isNaN(expiry.getTime())) return true;
  return expiry.getTime() <= now.getTime();
}
