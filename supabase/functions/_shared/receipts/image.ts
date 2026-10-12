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

/** FourCC as big-endian u32 — compared numerically so we never build strings from bytes (service-role-lint). */
const FOURCC_UUID = 0x75756964; // 'uuid'
const FOURCC_META = 0x6d657461; // 'meta'
const FOURCC_IINF = 0x69696e66; // 'iinf'
const FOURCC_ILOC = 0x696c6f63; // 'iloc'
const FOURCC_INFE = 0x696e6665; // 'infe'
const FOURCC_EXIF = 0x45786966; // 'Exif'
const FOURCC_MIME = 0x6d696d65; // 'mime'

/** `application/rdf+xml` as bytes (XMP content_type on a mime item). */
const XMP_CONTENT_TYPE = [0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x72, 0x64, 0x66, 0x2b, 0x78, 0x6d, 0x6c];

function readU16At(bytes: Uint8Array, i: number): number {
  let p = i;
  const hi = bytes[p]!;
  p += 1;
  const lo = bytes[p]!;
  return ((hi << 8) | lo) >>> 0;
}

function readU32At(bytes: Uint8Array, i: number): number {
  let p = i;
  const b0 = bytes[p]!;
  p += 1;
  const b1 = bytes[p]!;
  p += 1;
  const b2 = bytes[p]!;
  p += 1;
  const b3 = bytes[p]!;
  return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) >>> 0;
}

/** Standard XMP UUID in HEIF/HEIC uuid boxes (BE7ACFCB-97A9-42E8-9C71-999491E3AFAC). */
function isXmpUuidBox(bytes: Uint8Array, contentStart: number): boolean {
  if (contentStart + 16 > bytes.length) return false;
  const xmp = [0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac];
  let p = contentStart;
  let i = 0;
  while (i < 16) {
    if (bytes[p] !== xmp[i]) return false;
    p += 1;
    i += 1;
  }
  return true;
}

function bytesEqualAt(bytes: Uint8Array, start: number, end: number, expected: number[]): boolean {
  if (end - start !== expected.length) return false;
  let p = start;
  let i = 0;
  while (i < expected.length) {
    if (bytes[p] !== expected[i]) return false;
    p += 1;
    i += 1;
  }
  return true;
}

type BmffBox = { start: number; end: number; type: number; headerSize: number; contentStart: number };

/** Read one ISO BMFF box header at `start`; null if truncated / unreadable. */
function readBmffBox(bytes: Uint8Array, start: number, limit: number): BmffBox | null {
  if (start + 8 > limit) return null;
  let size = readU32At(bytes, start);
  const type = readU32At(bytes, start + 4);
  let headerSize = 8;
  let end: number;
  if (size === 1) {
    if (start + 16 > limit) return null;
    // 64-bit size; we only accept values that fit in JS safe integer range for this walk.
    const hi = readU32At(bytes, start + 8);
    const lo = readU32At(bytes, start + 12);
    if (hi !== 0) return null;
    size = lo;
    headerSize = 16;
    end = start + size;
  } else if (size === 0) {
    end = limit;
  } else {
    end = start + size;
  }
  if (end > limit || end < start + headerSize) return null;
  return { start, end, type, headerSize, contentStart: start + headerSize };
}

/**
 * HEIC/HEIF privacy strip (pure BMFF walk, no decoder):
 *  - drop top-level `uuid` boxes that carry the standard XMP UUID;
 *  - inside `meta`, find `iinf` items of type `Exif` (or XMP mime) and zero their
 *    `iloc` extents in a copy (offsets stay valid; GPS/camera bytes are gone).
 * Residual metadata in non-item forms is accepted (same honesty as JPEG APP13).
 */
export function stripHeicExif(bytes: Uint8Array): Uint8Array {
  if (!isHeic(bytes)) return bytes.slice();
  const out = bytes.slice();
  const topParts: Uint8Array[] = [];
  let i = 0;
  while (i < out.length) {
    const box = readBmffBox(out, i, out.length);
    if (!box) {
      topParts.push(out.subarray(i));
      break;
    }
    if (box.type === FOURCC_UUID && isXmpUuidBox(out, box.contentStart)) {
      i = box.end;
      continue;
    }
    if (box.type === FOURCC_META) {
      zeroHeicMetaExifItems(out, box);
    }
    topParts.push(out.subarray(box.start, box.end));
    i = box.end;
  }
  let total = 0;
  for (const p of topParts) total += p.length;
  const rebuilt = new Uint8Array(total);
  let o = 0;
  for (const p of topParts) {
    rebuilt.set(p, o);
    o += p.length;
  }
  return rebuilt;
}

function zeroHeicMetaExifItems(bytes: Uint8Array, meta: BmffBox): void {
  // meta is a FullBox: version (1) + flags (3) then children.
  let p = meta.contentStart + 4;
  if (p > meta.end) return;
  const exifItemIds = new Set<number>();
  // First pass: collect Exif / XMP item ids from iinf.
  let q = p;
  while (q < meta.end) {
    const child = readBmffBox(bytes, q, meta.end);
    if (!child) break;
    if (child.type === FOURCC_IINF) collectExifItemIds(bytes, child, exifItemIds);
    q = child.end;
  }
  if (exifItemIds.size === 0) return;
  // Second pass: zero iloc extents for those ids (file-absolute offsets).
  q = p;
  while (q < meta.end) {
    const child = readBmffBox(bytes, q, meta.end);
    if (!child) break;
    if (child.type === FOURCC_ILOC) zeroIlocExtents(bytes, child, exifItemIds);
    q = child.end;
  }
}

function collectExifItemIds(bytes: Uint8Array, iinf: BmffBox, out: Set<number>): void {
  // iinf FullBox: version/flags, then entry_count, then infe boxes.
  let p = iinf.contentStart;
  if (p + 4 > iinf.end) return;
  const version = bytes[p]!;
  p += 4;
  let entryCount: number;
  if (version === 0) {
    if (p + 2 > iinf.end) return;
    entryCount = readU16At(bytes, p);
    p += 2;
  } else {
    if (p + 4 > iinf.end) return;
    entryCount = readU32At(bytes, p);
    p += 4;
  }
  let n = 0;
  while (n < entryCount && p < iinf.end) {
    const infe = readBmffBox(bytes, p, iinf.end);
    if (!infe || infe.type !== FOURCC_INFE) break;
    const itemId = parseInfeItem(bytes, infe);
    if (itemId !== null) out.add(itemId);
    p = infe.end;
    n += 1;
  }
}

function parseInfeItem(bytes: Uint8Array, infe: BmffBox): number | null {
  // infe FullBox. v2/v3: item_ID, item_protection_index, item_type (4cc), then name / content_type.
  let p = infe.contentStart;
  if (p + 4 > infe.end) return null;
  const version = bytes[p]!;
  p += 4;
  let itemId: number;
  if (version >= 2) {
    if (version === 2) {
      if (p + 2 > infe.end) return null;
      itemId = readU16At(bytes, p);
      p += 2;
    } else {
      if (p + 4 > infe.end) return null;
      itemId = readU32At(bytes, p);
      p += 4;
    }
    if (p + 2 + 4 > infe.end) return null;
    p += 2; // item_protection_index
    const itemType = readU32At(bytes, p);
    p += 4;
    if (itemType === FOURCC_EXIF) return itemId;
    if (itemType === FOURCC_MIME) {
      // item_name (nul), content_type (nul) — look for application/rdf+xml (XMP).
      let nameEnd = p;
      while (nameEnd < infe.end && bytes[nameEnd] !== 0) nameEnd += 1;
      let ct = nameEnd + 1;
      let ctEnd = ct;
      while (ctEnd < infe.end && bytes[ctEnd] !== 0) ctEnd += 1;
      if (bytesEqualAt(bytes, ct, ctEnd, XMP_CONTENT_TYPE)) return itemId;
    }
    return null;
  }
  // v0/v1: item_ID (16), protection (16), name — no item_type; treat as non-Exif.
  return null;
}

function zeroIlocExtents(bytes: Uint8Array, iloc: BmffBox, itemIds: Set<number>): void {
  let p = iloc.contentStart;
  if (p + 6 > iloc.end) return;
  const version = bytes[p]!;
  p += 4; // FullBox version + flags
  const offsetSize = (bytes[p]! >> 4) & 0xf;
  const lengthSize = bytes[p]! & 0xf;
  p += 1;
  const baseOffsetSize = (bytes[p]! >> 4) & 0xf;
  const indexSize = version === 1 || version === 2 ? bytes[p]! & 0xf : 0;
  p += 1;
  let itemCount: number;
  if (version < 2) {
    if (p + 2 > iloc.end) return;
    itemCount = readU16At(bytes, p);
    p += 2;
  } else {
    if (p + 4 > iloc.end) return;
    itemCount = readU32At(bytes, p);
    p += 4;
  }
  const readSized = (size: number): number | null => {
    if (size === 0) return 0;
    if (size === 4) {
      if (p + 4 > iloc.end) return null;
      const v = readU32At(bytes, p);
      p += 4;
      return v;
    }
    if (size === 8) {
      if (p + 8 > iloc.end) return null;
      const hi = readU32At(bytes, p);
      p += 4;
      const lo = readU32At(bytes, p);
      p += 4;
      if (hi !== 0) return null;
      return lo;
    }
    if (size === 2) {
      if (p + 2 > iloc.end) return null;
      const v = readU16At(bytes, p);
      p += 2;
      return v;
    }
    return null;
  };
  let n = 0;
  while (n < itemCount && p < iloc.end) {
    let itemId: number;
    if (version < 2) {
      if (p + 2 > iloc.end) return;
      itemId = readU16At(bytes, p);
      p += 2;
    } else {
      if (p + 4 > iloc.end) return;
      itemId = readU32At(bytes, p);
      p += 4;
    }
    if (version === 1 || version === 2) {
      if (p + 2 > iloc.end) return;
      p += 2; // construction_method
    }
    if (p + 2 > iloc.end) return;
    p += 2; // data_reference_index
    const baseOffset = readSized(baseOffsetSize);
    if (baseOffset === null) return;
    if (p + 2 > iloc.end) return;
    const extentCount = readU16At(bytes, p);
    p += 2;
    let e = 0;
    while (e < extentCount) {
      if (indexSize > 0) {
        if (readSized(indexSize) === null) return;
      }
      const extentOffset = readSized(offsetSize);
      const extentLength = readSized(lengthSize);
      if (extentOffset === null || extentLength === null) return;
      if (itemIds.has(itemId) && extentLength > 0) {
        let z = baseOffset + extentOffset;
        const zEnd = z + extentLength;
        while (z < zEnd && z < bytes.length) {
          bytes[z] = 0;
          z += 1;
        }
      }
      e += 1;
    }
    n += 1;
  }
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
    const stripped = stripHeicExif(bytes);
    if (stripped.length < 12) throw new Error("invalid heic");
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
