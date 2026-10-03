/**
 * P4.2b-3b: the offline staff code. The mobile TOTP is compared with (1) the SERVER's own `totp.ts`, imported here, on random seeds and times; (2) the codes the server's module computed for the
 * recorded seed (`vectors.offlineCode` in the fixture); (3) RFC 6238 Appendix B (the SHA-256 vectors, at the RFC's 30 s step and 8 digits, and recomputed at the 600 s step against an independent
 * `node:crypto` HMAC); (4) the properties the spec states: 8 big-endian counter bytes, dynamic truncation with `h[31] & 0x0f`, zero-padded digits, the step boundary.
 */
import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { base32Decode as serverBase32Decode, base32Encode as serverBase32Encode, hotp as serverHotp, stepOf as serverStepOf, totpAt as serverTotpAt } from "../../../supabase/functions/_shared/offline-code/totp.ts";
import * as serverParams from "../../../supabase/functions/_shared/offline-code/params.ts";
import { base32Decode, base32Encode, codeAt, codeAtSeconds, hotp, secondsToNextStep, stepOf } from "../src/offline-code";
import * as params from "../src/offline-code/params";
import { RECORDED, VECTORS } from "./support/edge-fixtures";

/** A deterministic PRNG (mulberry32): the "random" vectors are the same on every run. */
function prng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const bytes = (rnd: () => number, n: number): Uint8Array => Uint8Array.from({ length: n }, () => Math.floor(rnd() * 256));

/** An independent implementation on `node:crypto`: the counter written byte by byte, big-endian. */
function referenceCode(seed: Uint8Array, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i -= 1) {
    msg[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  const h = createHmac("sha256", seed).update(msg).digest();
  const o = h[31]! & 0x0f;
  const bin = ((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

describe("the parameters are the server's", () => {
  it("step, digits, algorithm and seed length equal `offline-code/params.ts` of the server", () => {
    expect(params.OFFLINE_CODE_STEP_SECONDS).toBe(serverParams.OFFLINE_CODE_STEP_SECONDS);
    expect(params.OFFLINE_CODE_DIGITS).toBe(serverParams.OFFLINE_CODE_DIGITS);
    expect(params.OFFLINE_CODE_ALGORITHM).toBe(serverParams.OFFLINE_CODE_ALGORITHM);
    expect(params.OFFLINE_SEED_BYTES).toBe(serverParams.OFFLINE_SEED_BYTES);
    expect(params.OFFLINE_CODE_ACCEPTED_STEP_WINDOW).toBe(serverParams.OFFLINE_CODE_WINDOW_STEPS);
    expect([params.OFFLINE_CODE_STEP_SECONDS, params.OFFLINE_CODE_DIGITS, params.OFFLINE_CODE_ALGORITHM]).toEqual([600, 6, "SHA256"]);
  });
});

describe("the TOTP equals the server's totp.ts", () => {
  it("on 400 random seeds and random times (including steps beyond 2^8, 2^16 and 2^24, which tell a big-endian counter from a little-endian one)", async () => {
    const rnd = prng(42);
    for (let i = 0; i < 400; i += 1) {
      const seed = bytes(rnd, 32);
      const unix = i < 100 ? Math.floor(rnd() * 5_000) : i < 200 ? Math.floor(rnd() * 1e9) : Math.floor(rnd() * 4e9);
      expect(codeAtSeconds(seed, unix), `seed #${i} t=${unix}`).toBe(await serverTotpAt(seed, unix));
      expect(codeAt(seed, unix * 1000 + Math.floor(rnd() * 1000))).toBe(await serverTotpAt(seed, unix));
    }
  });

  it("hotp with an arbitrary counter equals the server's, up to the 2^53 limit (the 8-byte counter's high half is written too)", async () => {
    const rnd = prng(7);
    const seed = bytes(rnd, 32);
    for (const counter of [0, 1, 255, 256, 65535, 65536, 2 ** 24, 2 ** 32 - 1, 2 ** 32, 2 ** 32 + 1, 0x0102030405, Number.MAX_SAFE_INTEGER]) {
      expect(hotp(seed, counter), String(counter)).toBe(await serverHotp(seed, counter));
      expect(hotp(seed, counter), String(counter)).toBe(referenceCode(seed, counter));
    }
  });

  it("the independent node:crypto reference agrees too (so the server import is not the only judge)", () => {
    const rnd = prng(99);
    for (let i = 0; i < 100; i += 1) {
      const seed = bytes(rnd, 32);
      const counter = Math.floor(rnd() * 1e7);
      expect(hotp(seed, counter)).toBe(referenceCode(seed, counter));
    }
  });

  it("the codes the server's module computed for the RECORDED seed (vectors.offlineCode) are what this computes", () => {
    const v = VECTORS.offlineCode;
    const seed = base32Decode(JSON.parse(RECORDED.offlineseed_200!.body).data.seed)!;
    expect(seed.length).toBe(32);
    expect(v.stepSeconds).toBe(600);
    expect(v.times.length).toBeGreaterThanOrEqual(10);
    for (const t of v.times) {
      expect(stepOf(t.unixSeconds)).toBe(t.step);
      expect(codeAtSeconds(seed, t.unixSeconds), `t=${t.unixSeconds}`).toBe(t.code);
    }
    expect(codeAtSeconds(seed, v.leadingZero.unixSeconds)).toBe(v.leadingZero.code);
  });

  it("stepOf is the server's", () => {
    for (const t of [0, 1, 599, 599.9, 600, 601, 1_790_000_399, 1_790_000_400]) expect(stepOf(t)).toBe(serverStepOf(t));
  });
});

describe("RFC 6238 Appendix B, SHA-256", () => {
  // The RFC's SHA-256 key is the 32 ASCII bytes "12345678901234567890123456789012"; its codes are 8 digits at a 30 s step.
  const KEY = new TextEncoder().encode("12345678901234567890123456789012");
  const RFC: Array<[number, string]> = [
    [59, "46119246"],
    [1111111109, "68084774"],
    [1111111111, "67062674"],
    [1234567890, "91819424"],
    [2000000000, "90698825"],
    [20000000000, "77737706"],
  ];

  it("the HOTP core reproduces the RFC's published values (30 s step, 8 digits)", () => {
    for (const [t, code] of RFC) expect(hotp(KEY, Math.floor(t / 30), 8), `t=${t}`).toBe(code);
  });

  it("recomputed at the 600 s step and 6 digits: equal to an independent HMAC and to the server's totp.ts", async () => {
    for (const [t] of RFC) {
      const counter = Math.floor(t / 600);
      expect(codeAtSeconds(KEY, t), `t=${t}`).toBe(referenceCode(KEY, counter));
      expect(codeAtSeconds(KEY, t), `t=${t}`).toBe(await serverTotpAt(KEY, t));
      expect(codeAtSeconds(KEY, t)).toMatch(/^\d{6}$/);
    }
  });
});

describe("the spec's properties", () => {
  it("leading zeros are kept: the code is always exactly six digits, and one with a leading zero is shown as such", () => {
    const rnd = prng(5);
    const seed = bytes(rnd, 32);
    const codes = Array.from({ length: 3000 }, (_, i) => hotp(seed, i));
    for (const c of codes) expect(c).toMatch(/^\d{6}$/);
    const withZero = codes.filter((c) => c.startsWith("0"));
    expect(withZero.length).toBeGreaterThan(100); // about 1 in 10
    expect(codes.some((c) => c.startsWith("00"))).toBe(true);
    expect(withZero.every((c) => c.length === 6)).toBe(true);
    const v = VECTORS.offlineCode.leadingZero;
    expect(v.code.startsWith("0")).toBe(true);
    const seedRec = base32Decode(JSON.parse(RECORDED.offlineseed_200!.body).data.seed)!;
    expect(codeAtSeconds(seedRec, v.unixSeconds)).toBe(v.code); // "099866": a number would print "99866"
  });

  it("the counter is 8 BIG-endian bytes: counter 1 and counter 2^56 are different messages, and a little-endian counter gives a different code", () => {
    const seed = new Uint8Array(32).fill(7);
    const le = (counter: number): string => {
      const msg = Buffer.alloc(8);
      msg.writeBigUInt64LE(BigInt(counter));
      const h = createHmac("sha256", seed).update(msg).digest();
      const o = h[31]! & 0x0f;
      return String((((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!) % 1e6).padStart(6, "0");
    };
    let differ = 0;
    for (const c of [1, 2, 300, 70000, 2_983_333]) if (hotp(seed, c) !== le(c)) differ += 1;
    expect(differ).toBeGreaterThanOrEqual(4);
    expect(hotp(seed, 2_983_333)).toBe(referenceCode(seed, 2_983_333));
  });

  it("dynamic truncation uses the LOW NIBBLE OF THE LAST BYTE as the offset (h[31] & 0x0f) and masks the top bit", () => {
    // Found by search: counters whose last byte's nibble is 0 and 15 give different windows; compare with the reference for 2000 counters.
    const seed = new Uint8Array(32).fill(3);
    for (let c = 0; c < 2000; c += 1) expect(hotp(seed, c)).toBe(referenceCode(seed, c));
    // a code is below 10^6 even when the 31-bit value is far larger: the mask and the modulus are both applied
    for (let c = 0; c < 200; c += 1) expect(Number(hotp(seed, c))).toBeLessThan(1_000_000);
  });

  it("step boundary: the code is constant for the whole 600 s step and changes exactly at the boundary; the countdown reads 600 on the boundary second and 1 on the last", () => {
    const seed = bytes(prng(11), 32);
    const t0 = 1_790_000_400; // a boundary: 2_983_334 * 600
    expect(t0 % 600).toBe(0);
    const before = codeAtSeconds(seed, t0 - 1);
    const first = codeAtSeconds(seed, t0);
    const last = codeAtSeconds(seed, t0 + 599);
    const next = codeAtSeconds(seed, t0 + 600);
    expect(first).toBe(last);
    expect(first).toBe(hotp(seed, 2_983_334));
    expect(before).toBe(hotp(seed, 2_983_333));
    expect(next).toBe(hotp(seed, 2_983_335));
    expect(new Set([before, first, next]).size).toBe(3);
    expect(codeAt(seed, t0 * 1000 - 1)).toBe(before); // 1 ms before the boundary still shows the old code
    expect(codeAt(seed, t0 * 1000)).toBe(first);
    expect(secondsToNextStep(t0 * 1000)).toBe(600);
    expect(secondsToNextStep(t0 * 1000 + 1)).toBe(600);
    expect(secondsToNextStep(t0 * 1000 + 999)).toBe(600);
    expect(secondsToNextStep(t0 * 1000 + 1000)).toBe(599);
    expect(secondsToNextStep((t0 + 599) * 1000)).toBe(1);
    expect(secondsToNextStep((t0 + 599) * 1000 + 999)).toBe(1);
    expect(secondsToNextStep((t0 + 600) * 1000)).toBe(600);
  });

  it("rejects what is not a 32-byte seed or a non-negative safe integer counter (never a silent wrong code)", () => {
    expect(() => hotp(new Uint8Array(31), 1)).toThrow(/32 bytes/);
    expect(() => hotp(new Uint8Array(33), 1)).toThrow(/32 bytes/);
    expect(() => hotp(new Uint8Array(32), -1)).toThrow(/counter/);
    expect(() => hotp(new Uint8Array(32), 1.5)).toThrow(/counter/);
    expect(() => hotp(new Uint8Array(32), 2 ** 53)).toThrow(/counter/);
    expect(() => hotp([1, 2, 3] as never, 1)).toThrow();
  });
});

describe("base32 (the seed's encoding)", () => {
  it("round-trips 32 random bytes to the 52 characters the server sends, and equals the server's encoder and decoder", () => {
    const rnd = prng(3);
    for (let i = 0; i < 100; i += 1) {
      const b = bytes(rnd, 32);
      const text = base32Encode(b);
      expect(text).toBe(serverBase32Encode(b));
      expect(text).toMatch(/^[A-Z2-7]{52}$/);
      expect(base32Decode(text)).toEqual(b);
      expect(serverBase32Decode(text)).toEqual(b);
    }
  });

  it("RFC 4648 test vectors (unpadded)", () => {
    const enc = (s: string): string => base32Encode(new TextEncoder().encode(s));
    expect([enc(""), enc("f"), enc("fo"), enc("foo"), enc("foob"), enc("fooba"), enc("foobar")]).toEqual(["", "MY", "MZXQ", "MZXW6", "MZXW6YQ", "MZXW6YTB", "MZXW6YTBOI"]);
    expect(new TextDecoder().decode(base32Decode("MZXW6YTBOI")!)).toBe("foobar");
  });

  it("is strict: lower case, padding, whitespace, a wrong character, or a non-canonical last character are refused", () => {
    for (const bad of ["mzxw6ytboi", "MZXW6YTBOI=", "MZXW 6YTBOI", "MZXW6YTBO1", "MZXW6YTBOJ", "", "MY======", "MZ"]) expect(base32Decode(bad), JSON.stringify(bad)).toBeNull();
    expect(base32Decode("MY")).toEqual(new TextEncoder().encode("f"));
  });
});
