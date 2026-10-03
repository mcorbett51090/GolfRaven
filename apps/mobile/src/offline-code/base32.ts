/**
 * RFC 4648 base32, upper case, NO padding: the encoding of the `seed` the provisioning endpoint returns (`base32Encode` in the server's `offline-code/totp.ts`). The decoder
 * is strict (upper-case alphabet `A-Z2-7`, no padding, no whitespace, canonical trailing bits) so a seed that is not exactly what the server sends is refused rather than
 * half-read. Pure.
 */
const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(bytes: Uint8Array): string {
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(acc << (5 - bits)) & 31];
  return out;
}

/** The bytes of an unpadded upper-case base32 string, or `null` for anything else (a wrong character, padding, a non-canonical last character). */
export function base32Decode(text: string): Uint8Array | null {
  if (!/^[A-Z2-7]+$/.test(text)) return null;
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of text) {
    acc = (acc << 5) | ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((acc >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
    acc &= (1 << bits) - 1;
  }
  // The leftover bits (fewer than 8) must be zero: a spelling that sets them is a different string for the same bytes.
  if (acc !== 0) return null;
  return Uint8Array.from(out);
}
