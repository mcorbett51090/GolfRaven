import { decode as decodeJpeg } from "jpeg-js";
import { PNG } from "pngjs";
import { Buffer } from "node:buffer";
import { sha256 } from "@noble/hashes/sha2.js";

export type ReceiptImageKind = "jpeg" | "png" | "heic";

const JPEG_SOI = [0xff, 0xd8];
const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const HEIC_FTYP = [0x66, 0x74, 0x79, 0x70]; // 'ftyp' at offset 4 in ISO BMFF

function startsWith(bytes: Uint8Array, sig: number[]): boolean {
  if (bytes.length < sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[i] !== sig[i]) return false;
  return true;
}

function isHeic(bytes: Uint8Array): boolean {
  // ISO BMFF: size(4) + 'ftyp'(4) + major_brand(4). Size may be any 32-bit value;
  // only require the ftyp fourcc at offset 4 and a HEIF/HEIC-family brand.
  if (bytes.length < 12) return false;
  if (!(bytes[4] === HEIC_FTYP[0] && bytes[5] === HEIC_FTYP[1] && bytes[6] === HEIC_FTYP[2] && bytes[7] === HEIC_FTYP[3])) {
    return false;
  }
  const brand = String.fromCharCode(bytes[8]!, bytes[9]!, bytes[10]!, bytes[11]!);
  return brand === "heic" || brand === "heix" || brand === "hevc" || brand === "hevx" || brand === "mif1" || brand === "msf1";
}

export function sniffReceiptImageKind(bytes: Uint8Array): ReceiptImageKind | null {
  if (startsWith(bytes, JPEG_SOI)) return "jpeg";
  if (startsWith(bytes, PNG_SIG)) return "png";
  if (isHeic(bytes)) return "heic";
  return null;
}

/** Strip JPEG APP1 (EXIF) segments; return a new buffer. */
export function stripJpegExif(bytes: Uint8Array): Uint8Array {
  if (!startsWith(bytes, JPEG_SOI)) return bytes.slice();
  const out: number[] = [0xff, 0xd8];
  let i = 2;
  while (i + 4 < bytes.length) {
    if (bytes[i] !== 0xff) break;
    const marker = bytes[i + 1]!;
    if (marker === 0xd9 || marker === 0xda) {
      out.push(...bytes.slice(i));
      return Uint8Array.from(out);
    }
    const len = (bytes[i + 2]! << 8) | bytes[i + 3]!;
    const segEnd = i + 2 + len;
    if (marker === 0xe1) {
      i = segEnd;
      continue;
    }
    out.push(...bytes.slice(i, segEnd));
    i = segEnd;
  }
  out.push(...bytes.slice(i));
  return Uint8Array.from(out);
}

/** Remove eXIf ancillary chunks from PNG. */
export function stripPngExif(bytes: Uint8Array): Uint8Array {
  if (!startsWith(bytes, PNG_SIG)) return bytes.slice();
  const out: number[] = [...PNG_SIG];
  let i = 8;
  while (i + 12 <= bytes.length) {
    const length = (bytes[i]! << 24) | (bytes[i + 1]! << 16) | (bytes[i + 2]! << 8) | bytes[i + 3]!;
    const type = String.fromCharCode(bytes[i + 4]!, bytes[i + 5]!, bytes[i + 6]!, bytes[i + 7]!);
    const chunkEnd = i + 12 + length;
    if (type === "eXIf") {
      i = chunkEnd;
      continue;
    }
    out.push(...bytes.slice(i, chunkEnd));
    i = chunkEnd;
    if (type === "IEND") break;
  }
  return Uint8Array.from(out);
}

function averageHashHex(rgba: Uint8Array, width: number, height: number): string {
  const size = 8;
  const gray: number[] = [];
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const sx = Math.min(width - 1, Math.floor((x + 0.5) * width / size));
      const sy = Math.min(height - 1, Math.floor((y + 0.5) * height / size));
      const idx = (sy * width + sx) * 4;
      const r = rgba[idx]!;
      const g = rgba[idx + 1]!;
      const b = rgba[idx + 2]!;
      gray.push(0.299 * r + 0.587 * g + 0.114 * b);
    }
  }
  const avg = gray.reduce((a, b) => a + b, 0) / gray.length;
  let bits = "";
  for (const v of gray) bits += v >= avg ? "1" : "0";
  let hex = "";
  for (let i = 0; i < 64; i += 4) {
    hex += parseInt(bits.slice(i, i + 4), 2).toString(16);
  }
  return hex;
}

export function sha256Hex(bytes: Uint8Array): string {
  return [...sha256(bytes)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function prepareReceiptImage(bytes: Uint8Array, kind: ReceiptImageKind): { stripped: Uint8Array; phash: string } {
  if (kind === "heic") {
    return { stripped: bytes.slice(), phash: sha256Hex(bytes) };
  }
  if (kind === "jpeg") {
    const stripped = stripJpegExif(bytes);
    const decoded = decodeJpeg(stripped, { useTArray: true });
    if (!decoded.data || decoded.width <= 0 || decoded.height <= 0) throw new Error("invalid jpeg");
    const phash = averageHashHex(decoded.data, decoded.width, decoded.height);
    return { stripped, phash };
  }
  const stripped = stripPngExif(bytes);
  const png = PNG.sync.read(Buffer.from(stripped));
  const phash = averageHashHex(png.data, png.width, png.height);
  return { stripped, phash };
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
