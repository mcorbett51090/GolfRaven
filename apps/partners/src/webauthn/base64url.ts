/**
 * Unpadded base64url <-> bytes, the encoding of every binary WebAuthn field on the wire
 * (docs/security/partner-auth-design.md 18.1; the server's `fromB64u` is canonical and strict).
 *
 * `decodeBase64Url` is just as strict: only the base64url alphabet, no padding, a possible length, and
 * re-encoding must give the same string. A server value that is not canonical is a server fault, not
 * something to repair silently.
 */

const ALPHABET = /^[A-Za-z0-9_-]*$/;

export function encodeBase64Url(input: ArrayBuffer | ArrayBufferView): string {
  const bytes = input instanceof ArrayBuffer ? new Uint8Array(input) : new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** The bytes of a canonical unpadded base64url string, as an `ArrayBuffer` (what `PublicKeyCredentialRequestOptions` takes). Throws `RangeError` for anything else. */
export function decodeBase64Url(text: string): ArrayBuffer {
  if (typeof text !== "string" || !ALPHABET.test(text) || text.length % 4 === 1) throw new RangeError("not canonical base64url");
  const padded = text.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - (text.length % 4)) % 4);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    throw new RangeError("not canonical base64url");
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  if (encodeBase64Url(bytes) !== text) throw new RangeError("not canonical base64url");
  return bytes.buffer;
}
