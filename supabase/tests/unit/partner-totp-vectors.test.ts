// supabase/tests/unit/partner-totp-vectors.test.ts
//
// PA-20 (docs/security/partner-auth-design.md 6.4, N6): the TypeScript HOTP-SHA-1 oracle matches RFC 6238 Appendix B SHA-1 vectors (6-digit truncation). The SQL twin is `private.hotp` in migration
// 0053 (same RFC 4226 dynamic truncation over HMAC-SHA-1); matrix cells prove the database against these same counters. Offline codes use SHA-256 / 600 s — a different parameter set — in
// offline-code/totp.ts.

import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { buildOtpauthUrl, encodeTotpSeed, hotpSha1, PARTNER_TOTP, partnerTotpStep } from "../../functions/_shared/partner/totp-contract.ts";

/** Independent RFC 4226 HOTP over node:crypto HMAC-SHA-1 (no shared code with totp-contract.ts). */
function referenceHotpSha1(seed: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac("sha1", seed).update(msg).digest();
  const o = h[h.length - 1]! & 0xf;
  const bin = ((h[o]! & 0x7f) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!;
  return String(bin % 10 ** digits).padStart(digits, "0");
}

describe("partner TOTP pinned parameters", () => {
  it("are the authenticator-app defaults the design names (SHA-1, 6 digits, 30 s, issuer GolfRaven)", () => {
    expect(PARTNER_TOTP.algo).toBe("SHA1");
    expect(PARTNER_TOTP.digits).toBe(6);
    expect(PARTNER_TOTP.periodSeconds).toBe(30);
    expect(PARTNER_TOTP.issuer).toBe("GolfRaven");
    expect(PARTNER_TOTP.seedBytes).toBe(32);
  });
});

describe("RFC 6238 Appendix B SHA-1 vectors (6 digits)", () => {
  // RFC key = ASCII "12345678901234567890" (20 bytes). Appendix B lists 8-digit codes; HOTP mod 10^6 is the last six digits.
  // SQL twin comment (0053 private.hotp): same counters; key=12345678901234567890, t=59 → 287082.
  const key = Buffer.from("12345678901234567890", "ascii");
  const vectors: Array<{ unix: number; eight: string; six: string }> = [
    { unix: 59, eight: "94287082", six: "287082" },
    { unix: 1111111109, eight: "07081804", six: "081804" },
    { unix: 1111111111, eight: "14050471", six: "050471" },
    { unix: 1234567890, eight: "89005924", six: "005924" },
    { unix: 2000000000, eight: "69279037", six: "279037" },
    { unix: 20000000000, eight: "65353130", six: "353130" },
  ];

  for (const v of vectors) {
    const counter = Math.floor(v.unix / 30);
    it(`T=${counter} (unix ${v.unix}): hotpSha1 = ${v.six} and matches the node:crypto reference`, async () => {
      expect(v.eight.slice(-6)).toBe(v.six);
      expect(partnerTotpStep(v.unix)).toBe(counter);
      const seed = new Uint8Array(key);
      const got = await hotpSha1(seed, counter, 6);
      expect(got).toBe(v.six);
      expect(referenceHotpSha1(key, counter, 6)).toBe(v.six);
      expect(await hotpSha1(seed, counter, 8)).toBe(v.eight);
    });
  }
});

describe("otpauth URI assembly", () => {
  it("encodes the seed as unpadded base32 and carries issuer, algorithm, digits and period", () => {
    const seed = new Uint8Array(20).fill(0x01);
    const url = buildOtpauthUrl({ seed, issuer: "GolfRaven", period: 30, digits: 6, algo: "SHA1" });
    expect(url.startsWith("otpauth://totp/GolfRaven?")).toBe(true);
    const q = new URL(url).searchParams;
    expect(q.get("secret")).toBe(encodeTotpSeed(seed));
    expect(q.get("issuer")).toBe("GolfRaven");
    expect(q.get("algorithm")).toBe("SHA1");
    expect(q.get("digits")).toBe("6");
    expect(q.get("period")).toBe("30");
  });
});
