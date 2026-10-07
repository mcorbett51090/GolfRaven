import { describe, expect, it } from "vitest";
import { decodeBase64Url, encodeBase64Url } from "../src/webauthn/base64url";

const bytes = (...n: number[]) => new Uint8Array(n);

describe("base64url <-> ArrayBuffer", () => {
  it("encodes with the URL alphabet and no padding", () => {
    expect(encodeBase64Url(bytes())).toBe("");
    expect(encodeBase64Url(bytes(0xfb, 0xff))).toBe("-_8");
    expect(encodeBase64Url(bytes(0xfb, 0xef, 0xbe))).toBe("--++".replaceAll("+", "-"));
    expect(encodeBase64Url(bytes(1))).toBe("AQ");
    expect(encodeBase64Url(bytes(1, 2))).toBe("AQI");
    expect(encodeBase64Url(bytes(1, 2, 3))).toBe("AQID");
  });

  it("accepts an ArrayBuffer, a typed array and a view onto part of a buffer", () => {
    const whole = bytes(9, 9, 1, 2, 3, 9);
    expect(encodeBase64Url(whole.buffer)).toBe(encodeBase64Url(whole));
    expect(encodeBase64Url(whole.subarray(2, 5))).toBe("AQID");
    expect(encodeBase64Url(new DataView(whole.buffer, 2, 3))).toBe("AQID");
  });

  it("round-trips every length 0..70 and every byte value", () => {
    for (let n = 0; n <= 70; n += 1) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) % 256);
      expect(new Uint8Array(decodeBase64Url(encodeBase64Url(b)))).toEqual(b);
    }
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    expect(new Uint8Array(decodeBase64Url(encodeBase64Url(all)))).toEqual(all);
  });

  it("decodes to a standalone ArrayBuffer of exactly the right length", () => {
    const ab = decodeBase64Url("AQID");
    expect(ab).toBeInstanceOf(ArrayBuffer);
    expect(ab.byteLength).toBe(3);
  });

  it("refuses everything that is not canonical unpadded base64url", () => {
    for (const bad of ["AQ==", "AQI=", "A", "AQIDB", "+/8", "a b", "AQ\n", "AR", "AQJ", "%41%41", "éééé"]) {
      expect(() => decodeBase64Url(bad), JSON.stringify(bad)).toThrow(RangeError);
    }
    expect(() => decodeBase64Url(undefined as unknown as string)).toThrow(RangeError);
  });

  it("matches the server's WebAuthn challenge vector (32 bytes of 0x07)", () => {
    expect(encodeBase64Url(new Uint8Array(32).fill(7))).toBe("BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc");
  });
});
