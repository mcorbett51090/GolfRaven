import { base64UrlToBytes, utf8DecodeStrict } from "../catalog/bytes";

/**
 * The address inside an Apple identity token, READ BUT NOT TRUSTED: the server verifies the token's signature, issuer, audience, expiry and
 * nonce. The client reads it only to know where to send the one-time code when the server says an account with that address already exists
 * (`409 email_proof_required` carries no address). `null` when the token has no usable address (e.g. an unshared / relay-less token) or
 * the claim is not marked verified.
 */
export function emailFromIdentityToken(token: string): string | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const claims = JSON.parse(utf8DecodeStrict(base64UrlToBytes(payload))) as { email?: unknown; email_verified?: unknown };
    const verified = claims.email_verified === true || claims.email_verified === "true";
    return typeof claims.email === "string" && verified && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(claims.email) ? claims.email : null;
  } catch {
    return null;
  }
}

export const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
