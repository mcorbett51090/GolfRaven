// supabase/tests/unit/course-qr-shape.test.ts
//
// The strict wire shapes of `course-qr` and `qr-print` (S2b; supabase/functions/_shared/partner/course-qr-shape.ts). Pure: no ports. The handler suites state what the handlers DO with these; this one states which
// bytes are accepted at all: a facility id that could not be put in a token's `fac` claim is not accepted, the nonce hash is exactly what the database stores, and a field nobody reads is refused rather than ignored.

import { describe, expect, it } from "vitest";
import { parseFacilityBody, parseFacilityId, parseFacilityQuery, parseNonceHash, parseRefreshBody } from "../../functions/_shared/partner/course-qr-shape.ts";

describe("parseFacilityId", () => {
  it("accepts the catalog's id alphabet, 1 to 128 characters", () => {
    for (const ok of ["fac_x", "f", "fac:1.2-3_A", "a".repeat(128)]) expect(parseFacilityId(ok), ok).toBe(ok);
  });
  it("refuses everything else: empty, too long, a space, a slash, a control character, a non-string", () => {
    for (const bad of ["", "a".repeat(129), "fac x", "fac/x", "fac\n", "fac\u0000x", "fäc", null, undefined, 1, {}, []]) expect(parseFacilityId(bad), String(bad)).toBeNull();
  });
});

describe("parseNonceHash", () => {
  it("is exactly 64 lower-case hex characters", () => {
    expect(parseNonceHash("0".repeat(64))).toBe("0".repeat(64));
    for (const bad of ["", "0".repeat(63), "0".repeat(65), "A".repeat(64), "g".repeat(64), " " + "0".repeat(63), null, 1]) expect(parseNonceHash(bad), String(bad)).toBeNull();
  });
});

describe("bodies", () => {
  it("parseFacilityBody: { facilityId } and nothing else", () => {
    expect(parseFacilityBody({ facilityId: "fac_x" })).toEqual({ ok: true, value: { facilityId: "fac_x" } });
    for (const bad of [{}, { facilityId: "fac_x", x: 1 }, { facilityId: 1 }, null, [], "x", 1]) expect(parseFacilityBody(bad).ok, JSON.stringify(bad)).toBe(false);
  });
  it("parseRefreshBody: both fields, strict", () => {
    const h = "a".repeat(64);
    expect(parseRefreshBody({ facilityId: "fac_x", nonceHash: h })).toEqual({ ok: true, value: { facilityId: "fac_x", nonceHash: h } });
    for (const bad of [{ facilityId: "fac_x" }, { nonceHash: h }, { facilityId: "fac_x", nonceHash: h, token: "t" }, { facilityId: "fac_x", nonceHash: h.toUpperCase() }, null]) expect(parseRefreshBody(bad).ok, JSON.stringify(bad)).toBe(false);
  });
  it("no body shape has a field for a PIN, a key, a kid or a signature: the client chooses nothing the server signs", () => {
    for (const k of ["pin", "kid", "qrKid", "sig", "signature", "seed", "key", "nonce", "token", "issuedAt", "iat"]) {
      expect(parseFacilityBody({ facilityId: "fac_x", [k]: "x" }).ok, k).toBe(false);
      expect(parseRefreshBody({ facilityId: "fac_x", nonceHash: "a".repeat(64), [k]: "x" }).ok, k).toBe(false);
    }
  });
});

describe("parseFacilityQuery", () => {
  const q = (s: string) => parseFacilityQuery(new URL(`https://x.test/course-qr/pin${s}`));
  it("takes facilityId once and nothing else", () => {
    expect(q("?facilityId=fac_x")).toEqual({ ok: true, value: { facilityId: "fac_x" } });
    for (const bad of ["", "?facilityId=", "?facilityId=fac_x&facilityId=fac_y", "?facilityId=fac_x&x=1", "?x=1", "?facilityId=a%20b", "?facilityId=fac_x%00"]) expect(q(bad).ok, bad).toBe(false);
  });
});
