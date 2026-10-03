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
  it("strict base64url rejects every NON-CANONICAL spelling (trailing bits must be zero): AA decodes to 0x00, AB and AP must not", () => {
    // 2 chars = 1 byte + 4 unused bits; 3 chars = 2 bytes + 2 unused bits. Only the all-zero-trailing-bits form is canonical.
    expect(Array.from(fromBase64UrlStrict("AA")!)).toEqual([0]);
    for (const bad of ["AB", "AP", "A_", "A-"]) expect(fromBase64UrlStrict(bad), bad).toBeNull();
    expect(Array.from(fromBase64UrlStrict("AAA")!)).toEqual([0, 0]);
    for (const bad of ["AAB", "AAD", "AA_"]) expect(fromBase64UrlStrict(bad), bad).toBeNull();
    // Exhaustive for one byte: exactly one of the 4 x 16 two-character spellings of each byte survives, and it is toBase64Url's.
    const survivors = new Set<string>();
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (const a of alphabet) for (const b of alphabet) if (fromBase64UrlStrict(a + b) !== null) survivors.add(a + b);
    expect(survivors.size).toBe(256);
    for (let byte = 0; byte < 256; byte++) expect(survivors.has(toBase64Url(new Uint8Array([byte]))), String(byte)).toBe(true);
    // Every canonical encoding of any length still decodes (no regression for honest clients).
    for (let n = 1; n <= 40; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n * 11) & 0xff);
      expect(bytesEqual(fromBase64UrlStrict(toBase64Url(bytes))!, bytes), `len ${n}`).toBe(true);
    }
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

// ---------------------------------------------------------------------------
// The iOS activation binding is the STRING form (string-binding.ts); binding.ts above still serves Android.
// ---------------------------------------------------------------------------
import { computeAttestKeyBinding } from "../../functions/_shared/rewards/app-attest-registration.js";
import { REWARD_ACTIVATION_PURPOSE, computeIosActivationBinding, computeStringBinding, iosActivationChallengeString } from "../../functions/_shared/rewards/string-binding.js";

describe("iOS activation binding (string form)", () => {
  const body = {
    rewardId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    deviceCheckTokenSha256: "ab".repeat(32),
    nonce: "abcDEF_-0123",
  };

  it("is SHA-256 of the one ASCII string a client builds, the nonce as text and the token hash inside it", async () => {
    const s = iosActivationChallengeString(body);
    expect(s).toBe(
      `{"challengeId":"${body.challengeId}","deviceCheckTokenSha256":"${body.deviceCheckTokenSha256}","deviceId":"${body.deviceId}","nonce":"${body.nonce}","platform":"ios","purpose":"${REWARD_ACTIVATION_PURPOSE}","rewardId":"${body.rewardId}"}`,
    );
    expect(toHex(await computeIosActivationBinding(sha256, body))).toBe(toHex(await sha256(new TextEncoder().encode(s))));
  });

  it("binds every field, including the DeviceCheck token hash (H1) and the nonce text", async () => {
    const ref = toHex(await computeIosActivationBinding(sha256, body));
    for (const k of Object.keys(body) as Array<keyof typeof body>) {
      expect(toHex(await computeIosActivationBinding(sha256, { ...body, [k]: "x" })), k).not.toBe(ref);
    }
  });

  it("is domain-separated from key registration and from the raw-bytes (Android) form", async () => {
    const reg = await computeAttestKeyBinding(sha256, { challengeId: body.challengeId, deviceId: body.deviceId, keyId: "k", nonce: body.nonce });
    expect(toHex(reg)).not.toBe(toHex(await computeIosActivationBinding(sha256, body)));
    const raw = await computeRequestBinding(sha256, { rewardId: body.rewardId, deviceId: body.deviceId, platform: "ios", challengeId: body.challengeId, deviceCheckTokenSha256: body.deviceCheckTokenSha256 }, new TextEncoder().encode(body.nonce));
    expect(toHex(raw)).not.toBe(toHex(await computeIosActivationBinding(sha256, body)));
  });
});

// ---------------------------------------------------------------------------
// The check-in token binding (checkin-token, G3-08): iOS string form, Android raw-bytes form.
// The hard-coded vectors below were computed with Python's hashlib over the literal strings, independently of the code under test:
//   python3 -c 'import hashlib; print(hashlib.sha256(S.encode()).hexdigest())'
// A mobile client reproduces them with the same two literals.
// ---------------------------------------------------------------------------
import {
  CHECKIN_TOKEN_PURPOSE,
  checkinAndroidBoundBodyBytes,
  computeCheckinAndroidBinding,
  type CheckinBoundBody,
} from "../../functions/_shared/rewards/binding.js";
import { computeIosCheckinBinding, iosCheckinChallengeString } from "../../functions/_shared/rewards/string-binding.js";

describe("check-in token binding", () => {
  const body: CheckinBoundBody = {
    challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
    deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    userId: "uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu",
  };
  const nonceBytes = new Uint8Array(32).map((_, i) => i + 1);
  const nonce = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";

  it("the purpose is a fixed, versioned domain separator distinct from the activation and registration purposes", () => {
    expect(CHECKIN_TOKEN_PURPOSE).toBe("golfraven/checkin-token/v1");
    expect(CHECKIN_TOKEN_PURPOSE).not.toBe(REWARD_ACTIVATION_PURPOSE);
    expect(CHECKIN_TOKEN_PURPOSE).not.toBe("attest_key_registration");
  });

  it("iOS: S is the canonical string {challengeId, deviceId, nonce, platform, purpose, userId} and clientDataHash is SHA-256(UTF-8(S)) (recorded vector)", async () => {
    const s = iosCheckinChallengeString({ ...body, nonce });
    expect(s).toBe(
      '{"challengeId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","deviceId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","nonce":"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA","platform":"ios","purpose":"golfraven/checkin-token/v1","userId":"uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu"}',
    );
    expect(toHex(await computeIosCheckinBinding(sha256, { ...body, nonce }))).toBe("3c695d6c71722843731e7a80e63d987d628181755c5925db5401f9d36b8077e5");
  });

  it("Android: canonical_body is {challengeId, deviceId, platform, purpose, userId}; requestHash = base64url(SHA-256(canonical_body ‖ raw nonce bytes)) (recorded vector)", async () => {
    expect(new TextDecoder().decode(checkinAndroidBoundBodyBytes(body))).toBe(
      '{"challengeId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc","deviceId":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","platform":"android","purpose":"golfraven/checkin-token/v1","userId":"uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu"}',
    );
    const h = await computeCheckinAndroidBinding(sha256, body, nonceBytes);
    expect(toHex(h)).toBe("f02189d57de25d009ca981f853b7e326b9dc79a7730c4cf96af2a6cbf89d925d");
    expect(toBase64Url(h)).toBe("8CGJ1X3iXQCcqYH4U7fjJrnceadzDEz5avKmy_idkl0");
    expect(toBase64Url(nonceBytes)).toBe(nonce);
  });

  it("binds every field on both platforms: changing the challenge, device, account or nonce changes the hash", async () => {
    const iosRef = toHex(await computeIosCheckinBinding(sha256, { ...body, nonce }));
    for (const k of ["challengeId", "deviceId", "userId"] as const) {
      expect(toHex(await computeIosCheckinBinding(sha256, { ...body, nonce, [k]: "x" })), `ios ${k}`).not.toBe(iosRef);
    }
    expect(toHex(await computeIosCheckinBinding(sha256, { ...body, nonce: "x" }))).not.toBe(iosRef);
    const andRef = toHex(await computeCheckinAndroidBinding(sha256, body, nonceBytes));
    for (const k of ["challengeId", "deviceId", "userId"] as const) {
      expect(toHex(await computeCheckinAndroidBinding(sha256, { ...body, [k]: "x" }, nonceBytes)), `android ${k}`).not.toBe(andRef);
    }
    expect(toHex(await computeCheckinAndroidBinding(sha256, body, nonceBytes.map((b) => b ^ 1)))).not.toBe(andRef);
  });

  it("is domain-separated from the activation binding on both platforms (the same ids and nonce never produce the same hash)", async () => {
    const act = await computeIosActivationBinding(sha256, {
      rewardId: body.userId, // even with the user id standing in for the reward id
      deviceId: body.deviceId,
      challengeId: body.challengeId,
      deviceCheckTokenSha256: "ab".repeat(32),
      nonce,
    });
    expect(toHex(act)).not.toBe(toHex(await computeIosCheckinBinding(sha256, { ...body, nonce })));
    const actAndroid = await computeRequestBinding(sha256, { rewardId: body.userId, deviceId: body.deviceId, platform: "android", challengeId: body.challengeId }, nonceBytes);
    expect(toHex(actAndroid)).not.toBe(toHex(await computeCheckinAndroidBinding(sha256, body, nonceBytes)));
  });

  it("the iOS and Android check-in bindings differ (the platform is bound), and so does a different purpose string", async () => {
    const ios = toHex(await computeIosCheckinBinding(sha256, { ...body, nonce }));
    const android = toHex(await computeCheckinAndroidBinding(sha256, body, nonceBytes));
    expect(ios).not.toBe(android);
    const otherPurpose = toHex(await computeStringBinding(sha256, { challengeId: body.challengeId, deviceId: body.deviceId, nonce, platform: "ios", purpose: "golfraven/checkin-token/v2", userId: body.userId }));
    expect(otherPurpose).not.toBe(ios);
    const samePurpose = toHex(await computeStringBinding(sha256, { challengeId: body.challengeId, deviceId: body.deviceId, nonce, platform: "ios", purpose: CHECKIN_TOKEN_PURPOSE, userId: body.userId }));
    expect(samePurpose).toBe(ios);
  });
});
