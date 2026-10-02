/**
 * Byte/text helpers for the catalog verifier. Hand-written (no `Buffer`,
 * no `TextEncoder`/`TextDecoder`, no `atob`) because the verifier must be
 * byte-exact and must not depend on which of those a given Hermes build
 * ships `[unverified — training knowledge on Hermes global availability]`.
 * Pure and platform-neutral; unit-tested in `test/catalog-bytes.test.ts`.
 */

/** UTF-8 encode, with lone surrogates REJECTED (a signed string never
 * legitimately contains one; `parseStrictJson` rejects them too). */
export function utf8Encode(s: string): Uint8Array {
  const out: number[] = [];
  for (let i = 0; i < s.length; i += 1) {
    let cp = s.charCodeAt(i);
    if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error("utf8Encode: lone high surrogate");
      cp = 0x10000 + ((cp - 0xd800) << 10) + (next - 0xdc00);
      i += 1;
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      throw new Error("utf8Encode: lone low surrogate");
    }
    if (cp < 0x80) out.push(cp);
    else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
  }
  return Uint8Array.from(out);
}

/**
 * Strict UTF-8 decode: throws on a truncated sequence, an overlong
 * encoding, a surrogate code point, or a code point above U+10FFFF. (Node's
 * `Buffer#toString("utf8")`, which the signing side uses, silently
 * substitutes U+FFFD; for every VALID input the two agree, and an invalid
 * artifact is rejected here rather than half-read.) A leading BOM is NOT
 * stripped — the strict JSON parser then rejects it, as it does in Node.
 */
export function utf8DecodeStrict(bytes: Uint8Array): string {
  let out = "";
  const chunk: number[] = [];
  const flush = (): void => {
    if (chunk.length > 0) {
      out += String.fromCharCode(...chunk);
      chunk.length = 0;
    }
  };
  let i = 0;
  while (i < bytes.length) {
    const b0 = bytes[i]!;
    let cp: number;
    let need: number;
    let min: number;
    if (b0 < 0x80) {
      cp = b0;
      need = 0;
      min = 0;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      cp = b0 & 0x1f;
      need = 1;
      min = 0x80;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      cp = b0 & 0x0f;
      need = 2;
      min = 0x800;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      cp = b0 & 0x07;
      need = 3;
      min = 0x10000;
    } else {
      throw new Error(`utf8DecodeStrict: invalid lead byte at offset ${i}`);
    }
    for (let k = 1; k <= need; k += 1) {
      const b = bytes[i + k];
      if (b === undefined) throw new Error(`utf8DecodeStrict: truncated sequence at offset ${i}`);
      if ((b & 0xc0) !== 0x80) {
        throw new Error(`utf8DecodeStrict: bad continuation byte at offset ${i + k}`);
      }
      cp = (cp << 6) | (b & 0x3f);
    }
    if (cp < min) throw new Error(`utf8DecodeStrict: overlong encoding at offset ${i}`);
    if (cp > 0x10ffff) throw new Error(`utf8DecodeStrict: code point above U+10FFFF at offset ${i}`);
    if (cp >= 0xd800 && cp <= 0xdfff) throw new Error(`utf8DecodeStrict: surrogate code point at offset ${i}`);
    if (cp >= 0x10000) {
      const v = cp - 0x10000;
      chunk.push(0xd800 + (v >> 10), 0xdc00 + (v & 0x3ff));
    } else {
      chunk.push(cp);
    }
    if (chunk.length >= 4096) flush();
    i += need + 1;
  }
  flush();
  return out;
}

const B64_STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64_URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

function decodeBase64(s: string, alphabet: string, padded: boolean): Uint8Array {
  let body = s;
  if (padded) {
    if (s.length % 4 !== 0) throw new Error("base64: length is not a multiple of 4");
    const m = /=*$/.exec(s);
    const pad = m ? m[0].length : 0;
    if (pad > 2) throw new Error("base64: too much padding");
    body = s.slice(0, s.length - pad);
  } else if (s.length % 4 === 1) {
    throw new Error("base64url: impossible length");
  }
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < body.length; i += 1) {
    const v = alphabet.indexOf(body[i]!);
    if (v < 0) throw new Error(`base64: invalid character at offset ${i}`);
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
      acc &= (1 << bits) - 1;
    }
  }
  // Canonical form: leftover bits must be zero (rejects non-canonical padding bits).
  if (acc !== 0) throw new Error("base64: non-zero trailing bits");
  return Uint8Array.from(out);
}

/** Standard, PADDED base64 — the encoding `tools/catalog`'s `signBytes`
 * emits for `manifest.sig.json` / `versions.sig.json` signatures. */
export function base64ToBytes(s: string): Uint8Array {
  return decodeBase64(s, B64_STD, true);
}

/** Unpadded base64url — the encoding used for raw public keys (the same
 * convention as `app.catalog_signing_key.public_key_b64url` server-side). */
export function base64UrlToBytes(s: string): Uint8Array {
  return decodeBase64(s, B64_URL, false);
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += (b < 16 ? "0" : "") + b.toString(16);
  return out;
}
