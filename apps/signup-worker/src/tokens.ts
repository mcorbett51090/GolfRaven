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
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A 256-bit random, URL-safe token — used for confirm and unsubscribe links. */
export function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

/** SHA-256 hex digest of `pepper + ":" + value`. */
export async function hashWithPepper(pepper: string, value: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(`${pepper}:${value}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
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
