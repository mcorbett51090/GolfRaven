// supabase/tests/unit/rewards-binding.test.ts
//
// Request binding (rewards/binding.ts): clientDataHash / requestHash =
// SHA-256(canonical_body ‖ server_challenge).

import { describe, expect, it } from "vitest";
import {
  boundBodyBytes,
  bytesEqual,
  canonicalJson,
  computeRequestBinding,
  fromBase64Lenient,
  fromBase64UrlStrict,
  toBase64Url,
  toHex,
  type BoundBody,
} from "../../functions/_shared/rewards/binding.js";
import { sha256 } from "./rewards-test-crypto.js";

const BODY: BoundBody = {
  rewardId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  platform: "ios",
  challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
};
const CHALLENGE = new Uint8Array(32).map((_, i) => i + 1);

describe("canonicalJson", () => {
  it("sorts keys recursively and emits no whitespace", () => {
    expect(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: 2 }], c: null } })).toBe('{"a":{"c":null,"d":[3,{"x":2,"y":1}]},"b":1}');
  });
  it("rejects values JSON cannot represent faithfully", () => {
    expect(() => canonicalJson({ a: undefined })).toThrow(/undefined/);
    expect(() => canonicalJson({ a: Number.NaN })).toThrow(/non-finite/);
    expect(() => canonicalJson({ a: Infinity })).toThrow(/non-finite/);
    expect(() => canonicalJson({ a: () => 1 })).toThrow(/unsupported/);
  });
  it("is independent of key insertion order", () => {
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
  });
});

describe("the bound body and its hash", () => {
  it("H1: iOS binds the hash of the DeviceCheck token; Android binds the install link; an absent field is ABSENT from the bytes (never null)", () => {
    const tokenSha = "ab".repeat(32);
    expect(new TextDecoder().decode(boundBodyBytes({ ...BODY, deviceCheckTokenSha256: tokenSha }))).toBe(
      `{"challengeId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","deviceCheckTokenSha256":"${tokenSha}","deviceId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","platform":"ios","rewardId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}`,
    );
    expect(new TextDecoder().decode(boundBodyBytes({ ...BODY, platform: "android", installLinkId: "install-link-AAAAAAAAAA" }))).toContain('"installLinkId":"install-link-AAAAAAAAAA"');
    expect(new TextDecoder().decode(boundBodyBytes(BODY))).not.toMatch(/deviceCheckTokenSha256|installLinkId|null/);
  });

  it("H1: swapping the DeviceCheck token (a different hash) or the install link changes the binding", async () => {
    const withTok = (h: string): BoundBody => ({ ...BODY, deviceCheckTokenSha256: h });
    const a = toHex(await computeRequestBinding(sha256, withTok("aa".repeat(32)), CHALLENGE));
    const b = toHex(await computeRequestBinding(sha256, withTok("bb".repeat(32)), CHALLENGE));
    const none = toHex(await computeRequestBinding(sha256, BODY, CHALLENGE));
    expect(new Set([a, b, none]).size).toBe(3);
  });

  it("binds exactly {challengeId, deviceId, platform, rewardId}, canonically, when no optional field is present", () => {
    expect(new TextDecoder().decode(boundBodyBytes(BODY))).toBe(
      '{"challengeId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","deviceId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","platform":"ios","rewardId":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}',
    );
  });

  it("is SHA-256(canonical_body ‖ challenge): recomputable independently", async () => {
    const got = await computeRequestBinding(sha256, BODY, CHALLENGE);
    const manual = await sha256(new Uint8Array([...new TextEncoder().encode(new TextDecoder().decode(boundBodyBytes(BODY))), ...CHALLENGE]));
    expect(toHex(got)).toBe(toHex(manual));
  });

  it("changes when ANY bound field or the challenge changes (a mismatched body hash cannot verify)", async () => {
    const base = toHex(await computeRequestBinding(sha256, BODY, CHALLENGE));
    const variants: Array<[string, BoundBody, Uint8Array]> = [
      ["rewardId", { ...BODY, rewardId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }, CHALLENGE],
      ["deviceId", { ...BODY, deviceId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }, CHALLENGE],
      ["platform", { ...BODY, platform: "android" }, CHALLENGE],
      ["challengeId", { ...BODY, challengeId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }, CHALLENGE],
      ["challenge bytes", BODY, CHALLENGE.map((b) => b ^ 1)],
    ];
    for (const [label, body, ch] of variants) {
      expect(toHex(await computeRequestBinding(sha256, body, ch)), label).not.toBe(base);
    }
  });

  it("ignores attestation material and self-reported fields — they are not in the bound body", () => {
    const withExtras = { ...BODY, assertion: "x", hardwareSupportsAttestation: true } as unknown as BoundBody;
    expect(toHex(boundBodyBytes(withExtras))).toBe(toHex(boundBodyBytes(BODY)));
  });
});

describe("base64 helpers", () => {
  it("base64url round-trips and is unpadded", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 1, 2]);
    const s = toBase64Url(bytes);
    expect(s).not.toMatch(/[+/=]/);
    expect(bytesEqual(fromBase64UrlStrict(s)!, bytes)).toBe(true);
  });
  it("strict base64url rejects padding, standard-alphabet characters, junk and impossible lengths", () => {
    for (const bad of ["ab+d", "ab/d", "abc=", "a", "ab cd", "", "ab$d"]) expect(fromBase64UrlStrict(bad), bad).toBeNull();
  });
  it("lenient base64 accepts standard or url-safe, padded or not, and rejects junk", () => {
    const bytes = new Uint8Array([0xfb, 0xff, 0xfe, 1, 2]);
    const std = btoa(String.fromCharCode(...bytes));
    for (const form of [std, std.replace(/=+$/, ""), std.replace(/\+/g, "-").replace(/\//g, "_")]) {
      expect(bytesEqual(fromBase64Lenient(form)!, bytes), form).toBe(true);
    }
    expect(fromBase64Lenient("a")).toBeNull();
    expect(fromBase64Lenient("ab$d")).toBeNull();
  });
  it("bytesEqual compares content and length", () => {
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
    expect(bytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});
