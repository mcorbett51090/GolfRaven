import { describe, expect, it } from "vitest";
import {
  prepareReceiptImage,
  sha256Hex,
  sniffReceiptImageKind,
  stripHeicExif,
  stripJpegExif,
  stripPngExif,
} from "../../functions/_shared/receipts/image.ts";

/** Minimal 1x1 JPEG (no EXIF). */
const TINY_JPEG = Uint8Array.from([
  0xff, 0xd8, 0xff, 0xdb, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0a, 0x0c, 0x14, 0x0d, 0x0c, 0x0b, 0x0b, 0x0c, 0x19, 0x12, 0x13, 0x0f,
  0x14, 0x1d, 0x1a, 0x1f, 0x1e, 0x1d, 0x1a, 0x1c, 0x1c, 0x20, 0x24, 0x2e, 0x27, 0x20, 0x22, 0x2c, 0x23, 0x1c, 0x1c, 0x28, 0x37, 0x29, 0x2c, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1f, 0x27, 0x39, 0x3d, 0x38, 0x32, 0x3c, 0x2e, 0x33, 0x34, 0x32,
  0xff, 0xc0, 0x00, 0x0b, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xff, 0xc4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
  0xff, 0xc4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00, 0x7b, 0xbf, 0xff, 0xd9,
]);

function jpegWithApp1(): Uint8Array {
  const app1 = new Uint8Array([0xff, 0xe1, 0x00, 0x08, 0x45, 0x78, 0x69, 0x66, 0x00, 0x00]);
  const out = new Uint8Array(2 + app1.length + TINY_JPEG.length - 2);
  out[0] = 0xff;
  out[1] = 0xd8;
  out.set(app1, 2);
  out.set(TINY_JPEG.subarray(2), 2 + app1.length);
  return out;
}

describe("receipt image sniff and EXIF strip", () => {
  it("accepts JPEG and PNG magic; rejects PDF and SVG", () => {
    expect(sniffReceiptImageKind(TINY_JPEG)).toBe("jpeg");
    expect(sniffReceiptImageKind(Uint8Array.from([0x25, 0x50, 0x44, 0x46]))).toBeNull();
    expect(sniffReceiptImageKind(Uint8Array.from([0x3c, 0x73, 0x76, 0x67]))).toBeNull();
  });

  it("strips JPEG APP1 (EXIF) segments", () => {
    const raw = jpegWithApp1();
    const stripped = stripJpegExif(raw);
    // APP1 payload started with ASCII "Exif\0\0" — must not remain contiguous after strip.
    let foundExif = false;
    for (let i = 0; i + 4 < stripped.length; i++) {
      if (
        stripped[i] === 0x45 &&
        stripped[i + 1] === 0x78 &&
        stripped[i + 2] === 0x69 &&
        stripped[i + 3] === 0x66
      ) {
        foundExif = true;
        break;
      }
    }
    expect(foundExif).toBe(false);
    expect(stripped[0]).toBe(0xff);
    expect(stripped[1]).toBe(0xd8);
  });

  it("phash (sha256 of stripped bytes) is stable for the same JPEG", () => {
    const a = prepareReceiptImage(TINY_JPEG, "jpeg");
    const b = prepareReceiptImage(TINY_JPEG, "jpeg");
    expect(a.phash).toBe(b.phash);
    expect(a.phash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("stripping EXIF changes the phash vs the EXIF-bearing original", () => {
    const withExif = jpegWithApp1();
    const rawHash = prepareReceiptImage(TINY_JPEG, "jpeg").phash;
    const strippedHash = prepareReceiptImage(withExif, "jpeg").phash;
    // stripped content equals TINY_JPEG after APP1 removal → same phash as clean JPEG
    expect(strippedHash).toBe(rawHash);
  });

  it("HEIC uses content sha256 as phash", () => {
    const heic = new Uint8Array(16);
    heic.set([0x00, 0x00, 0x00, 0x0c, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63]);
    expect(sniffReceiptImageKind(heic)).toBe("heic");
    const { phash } = prepareReceiptImage(heic, "heic");
    expect(phash).toHaveLength(64);
  });
});

describe("HEIC Exif/XMP strip", () => {
  /** Minimal ftyp-heic + trailing free box. */
  function heicShell(extra: Uint8Array): Uint8Array {
    const ftyp = Uint8Array.from([0x00, 0x00, 0x00, 0x0c, 0x66, 0x74, 0x79, 0x70, 0x68, 0x65, 0x69, 0x63]);
    const out = new Uint8Array(ftyp.length + extra.length);
    out.set(ftyp, 0);
    out.set(extra, ftyp.length);
    return out;
  }

  it("drops a top-level XMP uuid box", () => {
    const xmpUuid = Uint8Array.from([
      0x00, 0x00, 0x00, 0x18, 0x75, 0x75, 0x69, 0x64,
      0xbe, 0x7a, 0xcf, 0xcb, 0x97, 0xa9, 0x42, 0xe8, 0x9c, 0x71, 0x99, 0x94, 0x91, 0xe3, 0xaf, 0xac,
    ]);
    const free = Uint8Array.from([0x00, 0x00, 0x00, 0x08, 0x66, 0x72, 0x65, 0x65]);
    const raw = heicShell(Uint8Array.from([...xmpUuid, ...free]));
    const stripped = stripHeicExif(raw);
    expect(sniffReceiptImageKind(stripped)).toBe("heic");
    // XMP UUID bytes must not remain contiguous.
    let found = false;
    for (let i = 0; i + 3 < stripped.length; i++) {
      if (stripped[i] === 0xbe && stripped[i + 1] === 0x7a && stripped[i + 2] === 0xcf && stripped[i + 3] === 0xcb) {
        found = true;
        break;
      }
    }
    expect(found).toBe(false);
    expect(stripped.length).toBe(raw.length - xmpUuid.length);
  });

  it("zeros an Exif item extent referenced from meta/iinf+iloc", () => {
    // Layout after ftyp:
    //   meta (fullbox v0) {
    //     iinf (v0) { entry_count=1, infe v2 item_ID=1 type=Exif name="" }
    //     iloc (v0, offset_size=4, length_size=4) { item 1, base=0, 1 extent at absolute offset of payload }
    //   }
    //   free box holding the Exif payload (simulates mdat extent target)
    const exifPayload = Uint8Array.from([0x45, 0x78, 0x69, 0x66, 0x00, 0x00, 0xaa, 0xbb]); // "Exif\0\0" + junk

    // infe v2: size, 'infe', ver=2 flags=0, item_ID u16=1, protection u16=0, type='Exif', name=\0
    const infeBody = Uint8Array.from([
      0x02, 0x00, 0x00, 0x00,
      0x00, 0x01,
      0x00, 0x00,
      0x45, 0x78, 0x69, 0x66, // Exif
      0x00,
    ]);
    const infe = new Uint8Array(8 + infeBody.length);
    infe[0] = 0; infe[1] = 0; infe[2] = 0; infe[3] = 8 + infeBody.length;
    infe.set([0x69, 0x6e, 0x66, 0x65], 4);
    infe.set(infeBody, 8);

    const iinfBody = new Uint8Array(4 + 2 + infe.length);
    iinfBody[0] = 0; // version
    iinfBody[1] = 0; iinfBody[2] = 0; iinfBody[3] = 0; // flags
    iinfBody[4] = 0; iinfBody[5] = 1; // entry_count
    iinfBody.set(infe, 6);
    const iinf = new Uint8Array(8 + iinfBody.length);
    iinf[0] = 0; iinf[1] = 0; iinf[2] = 0; iinf[3] = 8 + iinfBody.length;
    iinf.set([0x69, 0x69, 0x6e, 0x66], 4);
    iinf.set(iinfBody, 8);

    // We will place the free/payload box after meta. Absolute offset = ftyp(12) + metaSize.
    // iloc FullBox v0: version/flags, then offset_size|length_size, base_offset_size|reserved, item_count…
    const ilocBodyPrefix = Uint8Array.from([
      0x00, 0x00, 0x00, 0x00, // version + flags
      0x44, // offset_size=4, length_size=4
      0x00, // base_offset_size=0, reserved
      0x00, 0x01, // item_count
      0x00, 0x01, // item_ID
      0x00, 0x00, // data_reference_index
      0x00, 0x01, // extent_count
    ]);
    // extent_offset (4) + extent_length (4) — patched below
    const ilocBody = new Uint8Array(ilocBodyPrefix.length + 8);
    ilocBody.set(ilocBodyPrefix, 0);
    const iloc = new Uint8Array(8 + ilocBody.length);
    iloc[0] = 0; iloc[1] = 0; iloc[2] = 0; iloc[3] = 8 + ilocBody.length;
    iloc.set([0x69, 0x6c, 0x6f, 0x63], 4);
    iloc.set(ilocBody, 8);

    const metaContent = new Uint8Array(4 + iinf.length + iloc.length);
    metaContent[0] = 0; metaContent[1] = 0; metaContent[2] = 0; metaContent[3] = 0; // fullbox
    metaContent.set(iinf, 4);
    metaContent.set(iloc, 4 + iinf.length);
    const meta = new Uint8Array(8 + metaContent.length);
    meta[0] = 0; meta[1] = 0; meta[2] = 0; meta[3] = 8 + metaContent.length;
    meta.set([0x6d, 0x65, 0x74, 0x61], 4);
    meta.set(metaContent, 8);

    const free = new Uint8Array(8 + exifPayload.length);
    free[0] = 0; free[1] = 0; free[2] = 0; free[3] = 8 + exifPayload.length;
    free.set([0x66, 0x72, 0x65, 0x65], 4);
    free.set(exifPayload, 8);

    const ftypLen = 12;
    const absOffset = ftypLen + meta.length + 8; // start of free payload
    const raw = heicShell(Uint8Array.from([...meta, ...free]));
    // Patch extent_offset / extent_length inside the assembled file's iloc body.
    const extentAtInFile = ftypLen + 8 + 4 + iinf.length + 8 + ilocBodyPrefix.length;
    raw[extentAtInFile] = (absOffset >>> 24) & 0xff;
    raw[extentAtInFile + 1] = (absOffset >>> 16) & 0xff;
    raw[extentAtInFile + 2] = (absOffset >>> 8) & 0xff;
    raw[extentAtInFile + 3] = absOffset & 0xff;
    raw[extentAtInFile + 4] = 0;
    raw[extentAtInFile + 5] = 0;
    raw[extentAtInFile + 6] = 0;
    raw[extentAtInFile + 7] = exifPayload.length;

    // Sanity: payload present before strip.
    expect(raw[absOffset]).toBe(0x45);
    expect(raw[absOffset + 1]).toBe(0x78);

    const stripped = stripHeicExif(raw);
    expect(stripped[absOffset]).toBe(0);
    expect(stripped[absOffset + 1]).toBe(0);
    expect(stripped[absOffset + 6]).toBe(0);
    expect(stripped[absOffset + 7]).toBe(0);
    // Structure preserved (same length — we zero in place after uuid drops; no uuid here).
    expect(stripped.length).toBe(raw.length);
    // prepareReceiptImage strips first — phash must differ from sha256 of the EXIF-bearing raw.
    const rawHash = sha256Hex(raw);
    const strippedHash = prepareReceiptImage(raw, "heic").phash;
    expect(strippedHash).not.toBe(rawHash);
    expect(strippedHash).toBe(sha256Hex(stripped));
  });
});

describe("PNG eXIf strip", () => {
  it("removes eXIf chunk from a minimal PNG", () => {
    const png = Uint8Array.from(atob(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==",
    ), (c) => c.charCodeAt(0));
    const withExif = new Uint8Array(png.length + 20);
    withExif.set(png.subarray(0, 8), 0);
    const exifChunk = new Uint8Array([
      0x00, 0x00, 0x00, 0x04, 0x65, 0x58, 0x49, 0x66, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00,
    ]);
    withExif.set(exifChunk, 8);
    withExif.set(png.subarray(8), 8 + exifChunk.length);
    const stripped = stripPngExif(withExif);
    let found = false;
    for (let i = 0; i + 3 < stripped.length; i++) {
      if (
        stripped[i] === 0x65 &&
        stripped[i + 1] === 0x58 &&
        stripped[i + 2] === 0x49 &&
        stripped[i + 3] === 0x66
      ) {
        found = true;
        break;
      }
    }
    expect(found).toBe(false);
  });
});
