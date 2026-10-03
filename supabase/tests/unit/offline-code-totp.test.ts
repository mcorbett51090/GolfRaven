// supabase/tests/unit/offline-code-totp.test.ts
//
// The TOTP primitive of the offline staff code (_shared/offline-code/totp.ts): RFC 6238 HMAC-SHA-256, 6 digits, a 600 s step. Proven two ways that do not
// share code with the implementation: (1) the RFC 6238 Appendix B SHA-256 test vectors, adapted to the 600 s step, and (2) a reference HOTP written here
// over node:crypto, compared across many random seeds and steps.

import { createHmac, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  OFFLINE_CODE_ALGORITHM,
  OFFLINE_CODE_DB_WINDOW_STEPS,
  OFFLINE_CODE_DIGITS,
  OFFLINE_CODE_STAFF_FAILURE_BUCKET,
  OFFLINE_CODE_STAFF_FAILURE_WINDOW_SECONDS,
  OFFLINE_CODE_STAFF_MAX_FAILURES,
  OFFLINE_CODE_STEP_SECONDS,
  OFFLINE_CODE_WINDOW_STEPS,
  OFFLINE_SEED_BYTES,
  OFFLINE_SEED_REVEAL_BUCKET,
  OFFLINE_SEED_REVEAL_PER_HOUR,
  OFFLINE_SEED_ROTATE_BUCKET,
  OFFLINE_SEED_ROTATE_PER_HOUR,
} from "../../functions/_shared/offline-code/params.ts";
import { base32Decode, base32Encode, hotp, stepOf, totpAt } from "../../functions/_shared/offline-code/totp.ts";

/** Reference HOTP over node:crypto (RFC 4226 section 5.3 written out independently of totp.ts). */
function referenceHotp(seed: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha256", seed).update(msg).digest();
  const o = h[h.length - 1]! & 0xf;
  const bin = ((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

describe("the pinned parameters", () => {
  it("are the ones the mobile client implements", () => {
    expect(OFFLINE_CODE_STEP_SECONDS).toBe(600);
    expect(OFFLINE_CODE_DIGITS).toBe(6);
    expect(OFFLINE_CODE_ALGORITHM).toBe("SHA256");
    expect(OFFLINE_SEED_BYTES).toBe(32);
    expect(OFFLINE_CODE_WINDOW_STEPS).toBe(1);
  });
  it("the database's own step bound is WIDER than the core's window (two clocks either side of a boundary must never refuse a code the core accepted)", () => {
    expect(OFFLINE_CODE_DB_WINDOW_STEPS).toBeGreaterThan(OFFLINE_CODE_WINDOW_STEPS);
    expect(OFFLINE_CODE_DB_WINDOW_STEPS).toBe(2); // 0045: abs(step - clock step) > 2
  });
  it("the staff-side limit P5 enforces is the plan's: 5 failures per staff per hour, in a bucket keyed on the staff member (a key suffix; the database prefixes the uid)", () => {
    expect(OFFLINE_CODE_STAFF_MAX_FAILURES).toBe(5);
    expect(OFFLINE_CODE_STAFF_FAILURE_WINDOW_SECONDS).toBe(3600);
    expect(OFFLINE_CODE_STAFF_FAILURE_BUCKET).toBe("offline-code-fail:staff");
  });
  it("the seed-reveal limits are per actor, per hour, and the rotation limit is the tighter one", () => {
    expect(OFFLINE_SEED_REVEAL_BUCKET).toBe("me-offline-seed:user");
    expect(OFFLINE_SEED_ROTATE_BUCKET).toBe("me-offline-seed-rotate:user");
    expect(OFFLINE_SEED_REVEAL_PER_HOUR).toBe(20);
    expect(OFFLINE_SEED_ROTATE_PER_HOUR).toBe(5);
    expect(OFFLINE_SEED_ROTATE_PER_HOUR).toBeLessThan(OFFLINE_SEED_REVEAL_PER_HOUR);
    for (const k of [OFFLINE_SEED_REVEAL_BUCKET, OFFLINE_SEED_ROTATE_BUCKET, OFFLINE_CODE_STAFF_FAILURE_BUCKET]) expect(k.length).toBeLessThanOrEqual(64); // hit_actor_rate_limit allows 128 including the uid prefix
  });
});

describe("RFC 6238 Appendix B, HMAC-SHA-256, adapted to a 600 s step", () => {
  // The RFC's SHA-256 key is the 32-byte ASCII string below; its 8-digit results are for a 30 s step at the listed unix times. The COUNTER of each vector
  // (T = floor(time / 30)) is what the algorithm consumes, so the same counters at our 600 s step are the unix times T * 600, and a 6-digit code is the
  // last six digits of the 8-digit one (HOTP is the 31-bit value mod 10^digits, and 10^8 is a multiple of 10^6). [RFC 6238 Appendix B values recalled
  // from the RFC, and each is ALSO recomputed below by the independent reference, so a mis-recalled digit fails the reference cell, not silently passes.]
  const key = new Uint8Array(Buffer.from("12345678901234567890123456789012", "ascii"));
  const vectors: Array<{ rfcTime: number; eight: string }> = [
    { rfcTime: 59, eight: "46119246" },
    { rfcTime: 1111111109, eight: "68084774" },
    { rfcTime: 1111111111, eight: "67062674" },
    { rfcTime: 1234567890, eight: "91819424" },
    { rfcTime: 2000000000, eight: "90698825" },
    { rfcTime: 20000000000, eight: "77737706" },
  ];
  for (const v of vectors) {
    const counter = Math.floor(v.rfcTime / 30);
    const unixAt600 = counter * OFFLINE_CODE_STEP_SECONDS;
    it(`T = ${counter} (RFC time ${v.rfcTime}): the 6-digit code is ${v.eight.slice(2)}, at unix time ${unixAt600} with our step`, async () => {
      expect(await hotp(key, counter, 8)).toBe(v.eight);
      expect(referenceHotp(Buffer.from(key), counter, 8)).toBe(v.eight);
      expect(await hotp(key, counter)).toBe(v.eight.slice(2));
      expect(await totpAt(key, unixAt600)).toBe(v.eight.slice(2));
      // anywhere inside the same 10-minute step gives the same code
      expect(await totpAt(key, unixAt600 + 599)).toBe(v.eight.slice(2));
    });
  }
});

describe("against an independent reference, over random seeds and steps", () => {
  it("agrees on 200 random (seed, step) pairs, and codes are always exactly 6 digits (leading zeros kept)", async () => {
    let sawLeadingZero = false;
    for (let i = 0; i < 200; i++) {
      const seed = randomBytes(32);
      const step = Math.floor(Math.random() * 3_000_000);
      const mine = await hotp(new Uint8Array(seed), step);
      expect(mine).toBe(referenceHotp(seed, step));
      expect(mine).toMatch(/^[0-9]{6}$/);
      if (mine.startsWith("0")) sawLeadingZero = true;
    }
    expect(sawLeadingZero, "with 200 samples a leading zero is all but certain (p of none = 0.9^200); it proves the padding path ran").toBe(true);
  });

  it("a different seed, or a different step, gives a different code (overwhelmingly): the code depends on both", async () => {
    const a = new Uint8Array(randomBytes(32));
    const b = new Uint8Array(randomBytes(32));
    const codes = new Set<string>();
    for (let s = 1000; s < 1020; s++) {
      codes.add(await hotp(a, s));
      codes.add(await hotp(b, s));
    }
    expect(codes.size).toBeGreaterThan(30);
  });
});

describe("stepOf and totpAt", () => {
  it("step boundaries are at multiples of 600 s", () => {
    expect(stepOf(0)).toBe(0);
    expect(stepOf(599.999)).toBe(0);
    expect(stepOf(600)).toBe(1);
    expect(stepOf(1199)).toBe(1);
    expect(stepOf(1200)).toBe(2);
    expect(stepOf(1_700_000_000)).toBe(Math.floor(1_700_000_000 / 600));
  });
});

describe("input validation", () => {
  it("refuses a seed that is not exactly 32 bytes (a truncated or wrong-length seed must never silently produce codes)", async () => {
    for (const n of [0, 1, 16, 20, 31, 33, 64]) await expect(hotp(new Uint8Array(n), 1)).rejects.toThrow(/32 bytes/);
    await expect(hotp("a".repeat(32) as unknown as Uint8Array, 1)).rejects.toThrow(/32 bytes/);
  });
  it("refuses a counter that is not a non-negative safe integer", async () => {
    const seed = new Uint8Array(32);
    for (const c of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) await expect(hotp(seed, c)).rejects.toThrow(/counter/);
  });
});

describe("base32 (the seed's wire encoding: RFC 4648, upper case, no padding)", () => {
  it("matches the RFC 4648 section 10 vectors (padding stripped)", () => {
    const enc = (s: string) => base32Encode(new Uint8Array(Buffer.from(s, "ascii")));
    expect(enc("")).toBe("");
    expect(enc("f")).toBe("MY");
    expect(enc("fo")).toBe("MZXQ");
    expect(enc("foo")).toBe("MZXW6");
    expect(enc("foob")).toBe("MZXW6YQ");
    expect(enc("fooba")).toBe("MZXW6YTB");
    expect(enc("foobar")).toBe("MZXW6YTBOI");
  });
  it("a 32-byte seed is exactly 52 characters, and round-trips", () => {
    for (let i = 0; i < 50; i++) {
      const seed = new Uint8Array(randomBytes(32));
      const text = base32Encode(seed);
      expect(text).toMatch(/^[A-Z2-7]{52}$/);
      expect(Buffer.from(base32Decode(text)).equals(Buffer.from(seed))).toBe(true);
    }
  });
  it("the decoder is strict: lower case, padding, whitespace and out-of-alphabet characters are refused", () => {
    for (const bad of ["mzxw6", "MZXW6===", "MZXW 6", "MZXW1", "MZXW8", "MZXW0", "MZXW6!"]) expect(() => base32Decode(bad), bad).toThrow();
  });
});
