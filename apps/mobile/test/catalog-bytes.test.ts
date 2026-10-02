import { describe, expect, it } from "vitest";
import { base64ToBytes, base64UrlToBytes, bytesToHex, utf8DecodeStrict, utf8Encode } from "../src/catalog/bytes";

const SAMPLES = ["", "a", "golfraven", "é à ç — fr-CA", "日本語", "😀 emoji 🏌️‍♂️", "\u0000\u007f\u0080߿ࠀ￿", "mixed 😀 é"];

describe("utf8", () => {
  it.each(SAMPLES)("round-trips and matches Node's encoder: %j", (s) => {
    const mine = utf8Encode(s);
    expect(Buffer.from(mine).equals(Buffer.from(s, "utf8"))).toBe(true);
    expect(utf8DecodeStrict(mine)).toBe(s);
  });

  it("decodes a large buffer (chunk flush path)", () => {
    const s = "é😀a".repeat(5000);
    expect(utf8DecodeStrict(utf8Encode(s))).toBe(s);
  });

  it("encoding refuses lone surrogates", () => {
    expect(() => utf8Encode("\ud800")).toThrow();
    expect(() => utf8Encode("\udc00x")).toThrow();
  });

  it.each([
    ["overlong NUL (C0 80)", [0xc0, 0x80]],
    ["overlong slash (E0 80 AF)", [0xe0, 0x80, 0xaf]],
    ["lone continuation byte", [0x80]],
    ["truncated 2-byte", [0xc3]],
    ["truncated 3-byte", [0xe2, 0x82]],
    ["truncated 4-byte", [0xf0, 0x9f, 0x98]],
    ["UTF-16 surrogate (ED A0 80)", [0xed, 0xa0, 0x80]],
    ["above U+10FFFF (F4 90 80 80)", [0xf4, 0x90, 0x80, 0x80]],
    ["invalid lead F5", [0xf5, 0x80, 0x80, 0x80]],
    ["bad continuation", [0xc3, 0x28]],
  ])("strict decode rejects %s", (_name, bytes) => {
    expect(() => utf8DecodeStrict(Uint8Array.from(bytes))).toThrow();
  });

  it("does not strip a BOM", () => {
    expect(utf8DecodeStrict(Uint8Array.from([0xef, 0xbb, 0xbf, 0x41]))).toBe("﻿A");
  });
});

describe("base64", () => {
  const raw = Uint8Array.from({ length: 64 }, (_, i) => (i * 37 + 11) & 0xff);

  it("standard padded matches Node for every length 0..64", () => {
    for (let n = 0; n <= raw.length; n += 1) {
      const slice = raw.slice(0, n);
      const enc = Buffer.from(slice).toString("base64");
      expect(Buffer.from(base64ToBytes(enc)).equals(Buffer.from(slice))).toBe(true);
    }
  });

  it("base64url unpadded matches Node for every length 0..64", () => {
    for (let n = 0; n <= raw.length; n += 1) {
      const slice = raw.slice(0, n);
      const enc = Buffer.from(slice).toString("base64url");
      expect(Buffer.from(base64UrlToBytes(enc)).equals(Buffer.from(slice))).toBe(true);
    }
  });

  it.each(["abc", "ab=c", "a===", "abc*", "ab c", "YQ="])("standard decoder rejects malformed %j", (s) => {
    expect(() => base64ToBytes(s)).toThrow();
  });

  it("rejects the wrong alphabet for each variant", () => {
    expect(() => base64ToBytes("-_-_")).toThrow();
    expect(() => base64UrlToBytes("+/+/")).toThrow();
    expect(() => base64UrlToBytes("YQ==")).toThrow(); // padding is not url-safe-unpadded
  });

  it("rejects non-canonical trailing bits", () => {
    expect(() => base64ToBytes("YR==")).toThrow(); // 'a' is "YQ=="; YR== has stray bits
    expect(() => base64UrlToBytes("YR")).toThrow();
  });

  it("bytesToHex", () => {
    expect(bytesToHex(Uint8Array.from([0, 1, 15, 16, 255]))).toBe("00010f10ff");
  });
});
