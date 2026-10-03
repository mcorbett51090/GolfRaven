import { base64UrlToBytes, utf8DecodeStrict } from "../catalog/bytes";

/** The `sub` claim of a JWT access token, or `null` when it cannot be read. NOT a verification (the server verifies the token): the check-in binding names the
 * account by the same `sub` the server reads from the same token, so the client reads it the same way. */
export function jwtSubject(token: string): string | null {
  const parts = token.split(".");
  const payload = parts[1];
  if (parts.length !== 3 || !payload || !/^[A-Za-z0-9_-]+$/.test(payload)) return null;
  try {
    const sub = (JSON.parse(utf8DecodeStrict(base64UrlToBytes(payload))) as { sub?: unknown }).sub;
    return typeof sub === "string" && sub.length > 0 && sub.length <= 128 ? sub : null;
  } catch {
    return null;
  }
}
