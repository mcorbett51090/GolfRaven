// supabase/functions/_shared/rewards/der.ts
//
// A minimal, STRICT ASN.1 DER reader — exactly what x509-lite.ts needs to read an Apple
// App Attest certificate chain and nothing more. It is a reader only (no encoder).
//
// "Strict" here means the encoding has exactly one accepted spelling, so a certificate or
// signature cannot be re-encoded into a different byte string that still parses:
//   - definite lengths only; the minimal length form (a long form that fits the short form,
//     or one with a leading zero length byte, is refused);
//   - single-byte tags only (the high-tag-number form is refused);
//   - INTEGERs are minimal (no redundant leading 0x00 / 0xFF) and, where a caller asks for an
//     unsigned value, non-negative;
//   - OIDs have minimal base-128 arcs; BOOLEAN is exactly 0x00 or 0xFF; BIT STRING carries 0
//     unused bits where the caller says so; times are the exact UTCTime / GeneralizedTime shapes.
// Anything else throws `DerError`; the callers turn that into a refusal, never a partial read.
//
// ⚠ `[unverified — training knowledge of Apple's certificate encodings]`: nothing here has met a
// real Apple certificate except the pinned root (which a unit test parses). It is exercised
// against certificates this repo's tests build with the same rules.

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DerError";
  }
}

export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OID: 0x06,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  SEQUENCE: 0x30,
} as const;

export interface Tlv {
  tag: number;
  /** Offset of the tag byte. */
  hdr: number;
  /** Offset of the first content byte. */
  start: number;
  /** One past the last content byte (also the offset of the next sibling). */
  end: number;
}

/** Reads one TLV that starts at `pos` and must end at or before `limit`. */
export function readTlv(buf: Uint8Array, pos: number, limit: number = buf.length): Tlv {
  if (limit > buf.length) throw new DerError("limit beyond buffer");
  if (pos + 2 > limit) throw new DerError("truncated TLV header");
  const tag = buf[pos]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("high-tag-number form is not supported");
  const first = buf.at(pos + 1)!;
  let len: number;
  let hdrLen = 2;
  if (first < 0x80) {
    len = first;
  } else if (first === 0x80) {
    throw new DerError("indefinite length is not DER");
  } else {
    const n = first & 0x7f;
    // Everything this module reads is far below 16 MiB; refuse longer length-of-length outright.
    if (n > 3) throw new DerError("length too large");
    if (pos + 2 + n > limit) throw new DerError("truncated length");
    if (buf.at(pos + 2) === 0) throw new DerError("non-minimal length (leading zero)");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf.at(pos + 2 + i)!;
    if (len < 0x80) throw new DerError("non-minimal length (fits the short form)");
    hdrLen = 2 + n;
  }
  const start = pos + hdrLen;
  const end = start + len;
  if (end > limit) throw new DerError("TLV overruns its container");
  return { tag, hdr: pos, start, end };
}

/** The full encoded bytes (header + content) of a TLV. */
export function tlvBytes(buf: Uint8Array, t: Tlv): Uint8Array {
  return buf.subarray(t.hdr, t.end);
}

export function tlvContent(buf: Uint8Array, t: Tlv): Uint8Array {
  return buf.subarray(t.start, t.end);
}

/** Reads the TLV at `pos`, requiring `tag`. */
export function expectTlv(buf: Uint8Array, pos: number, limit: number, tag: number, what: string): Tlv {
  const t = readTlv(buf, pos, limit);
  if (t.tag !== tag) throw new DerError(`${what}: expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
  return t;
}

/** The direct children of a constructed TLV, in order. The content must be consumed exactly. */
export function children(buf: Uint8Array, parent: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let p = parent.start;
  while (p < parent.end) {
    const t = readTlv(buf, p, parent.end);
    out.push(t);
    p = t.end;
  }
  if (p !== parent.end) throw new DerError("constructed content not consumed exactly");
  return out;
}

/** An OID as dotted decimal. */
export function oidToString(content: Uint8Array): string {
  if (content.length === 0) throw new DerError("empty OID");
  const arcs: number[] = [];
  let v = 0;
  let inArc = false;
  for (let i = 0; i < content.length; i++) {
    const b = content[i]!;
    if (!inArc && b === 0x80) throw new DerError("non-minimal OID arc");
    inArc = true;
    if (v > 0x1fffff) throw new DerError("OID arc too large");
    v = v * 128 + (b & 0x7f);
    if ((b & 0x80) === 0) {
      if (arcs.length === 0) {
        const first = v < 40 ? 0 : v < 80 ? 1 : 2;
        arcs.push(first, v - first * 40);
      } else {
        arcs.push(v);
      }
      v = 0;
      inArc = false;
    }
  }
  if (inArc) throw new DerError("truncated OID arc");
  return arcs.join(".");
}

export function readOid(buf: Uint8Array, t: Tlv, what: string): string {
  if (t.tag !== TAG.OID) throw new DerError(`${what}: not an OID`);
  return oidToString(tlvContent(buf, t));
}

/** BOOLEAN: DER allows exactly 0x00 and 0xFF. */
export function readBoolean(buf: Uint8Array, t: Tlv): boolean {
  if (t.tag !== TAG.BOOLEAN || t.end - t.start !== 1) throw new DerError("malformed BOOLEAN");
  const v = buf[t.start]!;
  if (v !== 0x00 && v !== 0xff) throw new DerError("non-DER BOOLEAN");
  return v === 0xff;
}

/** A non-negative INTEGER with its minimal magnitude bytes (no leading zero), at most `maxBytes` long.
 * Negative and non-minimal encodings are refused. Zero is the single byte 0x00. */
export function readUnsignedInteger(buf: Uint8Array, t: Tlv, maxBytes: number, what: string): Uint8Array {
  if (t.tag !== TAG.INTEGER) throw new DerError(`${what}: not an INTEGER`);
  const n = t.end - t.start;
  if (n === 0) throw new DerError(`${what}: empty INTEGER`);
  const first = buf[t.start]!;
  if (first & 0x80) throw new DerError(`${what}: negative INTEGER`);
  if (n > 1 && first === 0x00 && (buf.at(t.start + 1)! & 0x80) === 0) throw new DerError(`${what}: non-minimal INTEGER`);
  const mag = first === 0x00 && n > 1 ? buf.subarray(t.start + 1, t.end) : buf.subarray(t.start, t.end);
  if (mag.length > maxBytes) throw new DerError(`${what}: INTEGER too long`);
  return mag;
}

/** A small non-negative INTEGER as a number (path length, version). */
export function readSmallInteger(buf: Uint8Array, t: Tlv, what: string): number {
  const mag = readUnsignedInteger(buf, t, 4, what);
  let v = 0;
  for (const b of mag) v = v * 256 + b;
  return v;
}

/** BIT STRING content with the leading "unused bits" byte checked to be 0 and removed. */
export function readBitStringBytes(buf: Uint8Array, t: Tlv, what: string): Uint8Array {
  if (t.tag !== TAG.BIT_STRING) throw new DerError(`${what}: not a BIT STRING`);
  if (t.end - t.start < 1) throw new DerError(`${what}: empty BIT STRING`);
  if (buf[t.start] !== 0) throw new DerError(`${what}: BIT STRING with unused bits`);
  return buf.subarray(t.start + 1, t.end);
}

function digits(s: string, from: number, n: number): number {
  const part = s.slice(from, from + n);
  if (!/^[0-9]+$/.test(part) || part.length !== n) throw new DerError("non-digit in time");
  return Number(part);
}

/** UTCTime `YYMMDDHHMMSSZ` (RFC 5280: YY >= 50 is 19YY, else 20YY) or GeneralizedTime
 * `YYYYMMDDHHMMSSZ`, in milliseconds since the epoch. Anything else (no seconds, an offset,
 * fractional seconds) is refused, as RFC 5280 requires. */
export function readTime(buf: Uint8Array, t: Tlv): number {
  const s = new TextDecoder("ascii", { fatal: true }).decode(tlvContent(buf, t));
  let year: number;
  let o: number;
  if (t.tag === TAG.UTC_TIME) {
    if (s.length !== 13 || s[12] !== "Z") throw new DerError("malformed UTCTime");
    const yy = digits(s, 0, 2);
    year = yy >= 50 ? 1900 + yy : 2000 + yy;
    o = 2;
  } else if (t.tag === TAG.GENERALIZED_TIME) {
    if (s.length !== 15 || s[14] !== "Z") throw new DerError("malformed GeneralizedTime");
    year = digits(s, 0, 4);
    o = 4;
  } else {
    throw new DerError("not a time");
  }
  const month = digits(s, o, 2);
  const day = digits(s, o + 2, 2);
  const hour = digits(s, o + 4, 2);
  const minute = digits(s, o + 6, 2);
  const second = digits(s, o + 8, 2);
  const ms = Date.UTC(year, month - 1, day, hour, minute, second);
  const d = new Date(ms);
  // Date.UTC wraps an out-of-range field (month 13, day 31 in a 30-day month); a round trip catches it.
  if (d.getUTCFullYear() !== year || d.getUTCMonth() !== month - 1 || d.getUTCDate() !== day || hour > 23 || minute > 59 || second > 59) {
    throw new DerError("time field out of range");
  }
  return ms;
}

/** An ECDSA-Sig-Value (`SEQUENCE { INTEGER r, INTEGER s }`) as the fixed-width raw `r ‖ s` Web Crypto
 * wants, for a curve whose scalars are `size` bytes (32 for P-256, 48 for P-384). Strict DER: each
 * INTEGER minimal and non-negative; no trailing bytes. `null` on anything else. */
export function ecdsaSignatureDerToRaw(der: Uint8Array, size: number): Uint8Array | null {
  try {
    const seq = readTlv(der, 0, der.length);
    if (seq.tag !== TAG.SEQUENCE || seq.end !== der.length) return null;
    const kids = children(der, seq);
    if (kids.length !== 2) return null;
    const out = new Uint8Array(size * 2);
    for (let i = 0; i < 2; i++) {
      const mag = readUnsignedInteger(der, kids[i]!, size, "signature scalar");
      out.set(mag, i * size + (size - mag.length));
    }
    return out;
  } catch {
    return null;
  }
}
