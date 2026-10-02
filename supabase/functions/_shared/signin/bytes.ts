// supabase/functions/_shared/signin/bytes.ts
//
// Tiny, dependency-free byte/text helpers for the sign-in modules (base64, base64url, hex, SHA-256, constant-time
// compare). Web Crypto + atob/btoa only, so the same code runs under Deno (the Edge runtime) and Node (vitest).

export function utf8(s: string): Uint8Array<ArrayBuffer> {
  // Copied into a fresh ArrayBuffer-backed array so it is accepted as a Web Crypto BufferSource without a cast.
  return new Uint8Array(new TextEncoder().encode(s));
}

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decodes unpadded or padded base64url (or standard base64). `null` for anything else — never throws. */
export function fromBase64Url(s: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_+/-]*={0,2}$/.test(s)) return null;
  const std = s.replace(/-/g, "+").replace(/_/g, "/").replace(/=+$/, "");
  if (std.length % 4 === 1) return null; // no base64 string has a length of 1 mod 4
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  try {
    const bin = atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}

export async function sha256Bytes(input: Uint8Array | string): Promise<Uint8Array> {
  const data = typeof input === "string" ? utf8(input) : input;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data.slice().buffer));
}

export async function sha256Hex(input: Uint8Array | string): Promise<string> {
  return toHex(await sha256Bytes(input));
}

/** Compares two strings in time that depends only on their lengths, not on where they first differ. */
export function constantTimeEqual(a: string, b: string): boolean {
  const x = utf8(a);
  const y = utf8(b);
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}
