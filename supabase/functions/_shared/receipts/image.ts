import { sha256 } from "@noble/hashes/sha2.js";

export type ReceiptImageKind = "jpeg" | "png" | "heic";

function startsWithJpeg(bytes: Uint8Array): boolean {
  if (bytes.length < 2) return false;
  let i = 0;
  const b0 = bytes[i];
  i += 1;
  const b1 = bytes[i];
  return b0 === 0xff && b1 === 0xd8;
}

function startsWithPng(bytes: Uint8Array): boolean {
  if (bytes.length < 8) return false;
  let i = 0;
  const a0 = bytes[i]; i += 1;
  const a1 = bytes[i]; i += 1;
  const a2 = bytes[i]; i += 1;
  const a3 = bytes[i]; i += 1;
  const a4 = bytes[i]; i += 1;
  const a5 = bytes[i]; i += 1;
  const a6 = bytes[i]; i += 1;
  const a7 = bytes[i];
  return a0 === 0x89 && a1 === 0x50 && a2 === 0x4e && a3 === 0x47 && a4 === 0x0d && a5 === 0x0a && a6 === 0x1a && a7 === 0x0a;
}

function brandIsHeifFamily(b0: number, b1: number, b2: number, b3: number): boolean {
  if (b0 === 0x68 && b1 === 0x65 && b2 === 0x69 && (b3 === 0x63 || b3 === 0x78)) return true; // heic/heix
  if (b0 === 0x68 && b1 === 0x65 && b2 === 0x76 && (b3 === 0x63 || b3 === 0x78)) return true; // hevc/hevx
  if (b0 === 0x6d && b1 === 0x69 && b2 === 0x66 && b3 === 0x31) return true; // mif1
  if (b0 === 0x6d && b1 === 0x73 && b2 === 0x66 && b3 === 0x31) return true; // msf1
  return false;
}

function isHeic(bytes: Uint8Array): boolean {
  if (bytes.length < 12) return false;
  let i = 4;
  const f0 = bytes[i]; i += 1;
  const f1 = bytes[i]; i += 1;
  const f2 = bytes[i]; i += 1;
  const f3 = bytes[i]; i += 1;
  if (!(f0 === 0x66 && f1 === 0x74 && f2 === 0x79 && f3 === 0x70)) return false;
  const b0 = bytes[i]; i += 1;
  const b1 = bytes[i]; i += 1;
  const b2 = bytes[i]; i += 1;
  const b3 = bytes[i];
  return brandIsHeifFamily(b0!, b1!, b2!, b3!);
}

export function sniffReceiptImageKind(bytes: Uint8Array): ReceiptImageKind | null {
  if (startsWithJpeg(bytes)) return "jpeg";
  if (startsWithPng(bytes)) return "png";
  if (isHeic(bytes)) return "heic";
  return null;
}

/** Strip JPEG APP1 (EXIF) segments; return a new buffer. */
export function stripJpegExif(bytes: Uint8Array): Uint8Array {
  if (!startsWithJpeg(bytes)) return bytes.slice();
  const out: number[] = [0xff, 0xd8];
  let i = 2;
  while (i + 4 < bytes.length) {
    const marker0 = bytes[i];
    if (marker0 !== 0xff) break;
    i += 1;
    const marker = bytes[i];
    i += 1;
    if (marker === 0xd9 || marker === 0xda) {
      // Push marker start and remainder.
      out.push(0xff);
      out.push(marker!);
      while (i < bytes.length) {
        out.push(bytes[i]!);
        i += 1;
      }
      return Uint8Array.from(out);
    }
    const lenHi = bytes[i]!;
    i += 1;
    const lenLo = bytes[i]!;
    i += 1;
    const segLen = (lenHi << 8) | lenLo;
    // segLen includes the two length bytes already consumed; payload is segLen - 2.
    const payload = segLen - 2;
    if (marker === 0xe1) {
      i += payload;
      continue;
    }
    out.push(0xff);
    out.push(marker!);
    out.push(lenHi);
    out.push(lenLo);
    let left = payload;
    while (left > 0 && i < bytes.length) {
      out.push(bytes[i]!);
      i += 1;
      left -= 1;
    }
  }
  while (i < bytes.length) {
    out.push(bytes[i]!);
    i += 1;
  }
  return Uint8Array.from(out);
}

/** Remove eXIf ancillary chunks from PNG. */
export function stripPngExif(bytes: Uint8Array): Uint8Array {
  if (!startsWithPng(bytes)) return bytes.slice();
  const out: number[] = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  let i = 8;
  while (i + 12 <= bytes.length) {
    const l0 = bytes[i]!; i += 1;
    const l1 = bytes[i]!; i += 1;
    const l2 = bytes[i]!; i += 1;
    const l3 = bytes[i]!; i += 1;
    const t0 = bytes[i]!; i += 1;
    const t1 = bytes[i]!; i += 1;
    const t2 = bytes[i]!; i += 1;
    const t3 = bytes[i]!; i += 1;
    const length = (l0 << 24) | (l1 << 16) | (l2 << 8) | l3;
    const isExif = t0 === 0x65 && t1 === 0x58 && t2 === 0x49 && t3 === 0x66;
    const isIend = t0 === 0x49 && t1 === 0x45 && t2 === 0x4e && t3 === 0x44;
    // CRC is 4 bytes after the payload.
    const rest = length + 4;
    if (!isExif) {
      out.push(l0, l1, l2, l3, t0, t1, t2, t3);
      let left = rest;
      while (left > 0 && i < bytes.length) {
        out.push(bytes[i]!);
        i += 1;
        left -= 1;
      }
    } else {
      i += rest;
    }
    if (isIend) break;
  }
  return Uint8Array.from(out);
}

export function sha256Hex(bytes: Uint8Array): string {
  const dig = sha256(bytes);
  let hex = "";
  let i = 0;
  while (i < dig.length) {
    const b = dig[i]!;
    hex += (b >>> 4).toString(16);
    hex += (b & 0xf).toString(16);
    i += 1;
  }
  return hex;
}

/**
 * Strip EXIF where we can, then fingerprint the stored bytes.
 * Perceptual aHash needs a pixel decoder; jpeg-js/pngjs trip the Edge import
 * lint. Exact sha256 of the stripped object is the §40 phash until a reviewed
 * decoder lands.
 */
export function prepareReceiptImage(bytes: Uint8Array, kind: ReceiptImageKind): { stripped: Uint8Array; phash: string } {
  if (kind === "heic") {
    const stripped = bytes.slice();
    return { stripped, phash: sha256Hex(stripped) };
  }
  if (kind === "jpeg") {
    const stripped = stripJpegExif(bytes);
    if (stripped.length < 4) throw new Error("invalid jpeg");
    return { stripped, phash: sha256Hex(stripped) };
  }
  const stripped = stripPngExif(bytes);
  if (stripped.length < 8) throw new Error("invalid png");
  return { stripped, phash: sha256Hex(stripped) };
}

export function extensionForKind(kind: ReceiptImageKind): string {
  if (kind === "jpeg") return "jpg";
  if (kind === "png") return "png";
  return "heic";
}

export function contentTypeForKind(kind: ReceiptImageKind): string {
  if (kind === "jpeg") return "image/jpeg";
  if (kind === "png") return "image/png";
  return "image/heic";
}
