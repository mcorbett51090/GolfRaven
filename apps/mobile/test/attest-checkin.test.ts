/**
 * P4.2b-2: the CHECK-IN binding and the native attestor.
 * The bytes are compared with (1) the values the task / the security doc record, (2) what the server's own functions produced for the same inputs
 * (`vectors.binding.checkin` in the fixture, recorded by `scripts/record-edge-contract.rec.ts`), (3) a second implementation on `node:crypto`, and (4) the requests the
 * recorder built for the REAL challenges and the REAL handler accepted (`token_201_attested_*`, `attestkey_201_registered`).
 */
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  NativeAttestor,
  androidCheckinBoundBodyBytes,
  androidCheckinRequestBinding,
  androidCheckinRequestHash,
  attestKeyBinding,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  concatBytes,
  iosCheckinBinding,
  iosCheckinChallengeString,
  nonceBytesStrict,
  selectAttestor,
  CHECKIN_TOKEN_PURPOSE,
} from "../src/attest";
import { FakeNativeAttestModule } from "./support/fake-native-attest";
import { VECTORS, recorded, recordedRequest } from "./support/edge-fixtures";

const sha = (b: Uint8Array | string): string => createHash("sha256").update(b).digest("hex");

// The values given in the P4.2b-2 task and in docs/security/p3-money-path-requirements.md.
const CHALLENGE = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const DEVICE = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const USER = "uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuu";
const NONCE = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA";
const IOS_HASH = "3c695d6c71722843731e7a80e63d987d628181755c5925db5401f9d36b8077e5";
const ANDROID_HASH = "8CGJ1X3iXQCcqYH4U7fjJrnceadzDEz5avKmy_idkl0";
const body = { challengeId: CHALLENGE, deviceId: DEVICE, userId: USER };
const C = VECTORS.binding.checkin;

describe("check-in binding: the recorded vectors", () => {
  it("the fixture's inputs are the task's, and the server's own outputs are the task's constants", () => {
    expect(C.body).toEqual(body);
    expect(C.nonce).toBe(NONCE);
    expect(C.ios.clientDataHashHex).toBe(IOS_HASH);
    expect(C.android.requestHash).toBe(ANDROID_HASH);
  });

  it("iOS: S is the canonical JSON with the six keys sorted, no whitespace, the nonce as TEXT; clientDataHash = SHA-256(UTF-8(S))", () => {
    const S = iosCheckinChallengeString({ ...body, nonce: NONCE });
    expect(S).toBe(C.ios.challengeString);
    expect(S).toBe(`{"challengeId":"${CHALLENGE}","deviceId":"${DEVICE}","nonce":"${NONCE}","platform":"ios","purpose":"golfraven/checkin-token/v1","userId":"${USER}"}`);
    expect(bytesToHex(iosCheckinBinding({ ...body, nonce: NONCE }))).toBe(IOS_HASH);
    expect(sha(S)).toBe(IOS_HASH); // independent
  });

  it("Android: canonical_body (five keys sorted) THEN the RAW nonce bytes, hashed, base64url without padding", () => {
    expect(new TextDecoder().decode(androidCheckinBoundBodyBytes(body))).toBe(C.android.canonicalBodyUtf8);
    expect(new TextDecoder().decode(androidCheckinBoundBodyBytes(body))).toBe(`{"challengeId":"${CHALLENGE}","deviceId":"${DEVICE}","platform":"android","purpose":"golfraven/checkin-token/v1","userId":"${USER}"}`);
    expect(androidCheckinRequestHash(body, NONCE)).toBe(ANDROID_HASH);
    const raw = nonceBytesStrict(NONCE)!;
    expect(raw).toEqual(Uint8Array.from({ length: 32 }, (_, i) => i + 1));
    expect(Buffer.from(createHash("sha256").update(concatBytes(androidCheckinBoundBodyBytes(body), raw)).digest()).toString("base64url")).toBe(ANDROID_HASH); // independent
    expect(sha(concatBytes(raw, androidCheckinBoundBodyBytes(body)))).not.toBe(bytesToHex(androidCheckinRequestBinding(body, NONCE))); // order matters
    expect(sha(Buffer.from(C.android.canonicalBodyUtf8 + NONCE))).not.toBe(bytesToHex(androidCheckinRequestBinding(body, NONCE))); // the nonce is BYTES for Android
  });

  it("every field is bound: dropping or changing any one changes the hash on both platforms", () => {
    const iosBase = bytesToHex(iosCheckinBinding({ ...body, nonce: NONCE }));
    const andBase = androidCheckinRequestHash(body, NONCE);
    for (const k of ["challengeId", "deviceId", "userId"] as const) {
      const other = { ...body, [k]: k === "userId" ? "uuuuuuuu-uuuu-4uuu-8uuu-uuuuuuuuuuuv" : body[k].replace("c", "d").replace("b", "a") };
      expect(bytesToHex(iosCheckinBinding({ ...other, nonce: NONCE })), k).not.toBe(iosBase);
      expect(androidCheckinRequestHash(other, NONCE), k).not.toBe(andBase);
    }
    const nonce2 = bytesToBase64Url(Uint8Array.from({ length: 32 }, (_, i) => i + 2));
    expect(bytesToHex(iosCheckinBinding({ ...body, nonce: nonce2 }))).not.toBe(iosBase);
    expect(androidCheckinRequestHash(body, nonce2)).not.toBe(andBase);
    // the purpose separates a check-in from every other attestation
    expect(CHECKIN_TOKEN_PURPOSE).toBe("golfraven/checkin-token/v1");
    expect(iosCheckinChallengeString({ ...body, nonce: NONCE })).not.toContain("reward_activation");
  });

  it("UUIDs are lowercased before binding (Swift's uuidString is uppercase); the userId is bound exactly as the token's `sub` is written", () => {
    expect(bytesToHex(iosCheckinBinding({ challengeId: CHALLENGE.toUpperCase(), deviceId: DEVICE.toUpperCase(), userId: USER, nonce: NONCE }))).toBe(IOS_HASH);
    expect(androidCheckinRequestHash({ challengeId: CHALLENGE.toUpperCase(), deviceId: DEVICE.toUpperCase(), userId: USER }, NONCE)).toBe(ANDROID_HASH);
    expect(iosCheckinChallengeString({ ...body, userId: "AbC", nonce: NONCE })).toContain('"userId":"AbC"');
  });

  it("a non-canonical nonce (padding, a different spelling of the same bytes, a bad character) is refused: the server refuses it whenever an attestation is presented", () => {
    for (const bad of [`${NONCE}=`, "AB", "AP", "not base64url!", ""]) {
      expect(() => androidCheckinRequestBinding(body, bad), bad).toThrow(/nonce/);
      expect(() => iosCheckinChallengeString({ ...body, nonce: bad }), bad).toThrow(/nonce/);
    }
  });
});

describe("the requests the recorder built for the REAL challenges (accepted by the real handler) carry the bytes this client computes", () => {
  const FAKE_DEVICE = "11111111-1111-4111-8111-111111111111"; // FAKE_DEVICE_ID of the server's fakes; the recorder's account id is "user-a"
  it("Android: the integrity token the real handler accepted is 'it-' + the requestHash this client builds for that challenge", () => {
    const req = recordedRequest<{ challengeId: string; nonce: string; attestation: { platform: string; integrityToken: string } }>("token_201_attested_android");
    expect(req.attestation.platform).toBe("android");
    expect(req.attestation.integrityToken).toBe(`it-${androidCheckinRequestHash({ challengeId: req.challengeId, deviceId: FAKE_DEVICE, userId: "user-a" }, req.nonce)}`);
    expect(JSON.parse(recorded("token_201_attested_android").body).data.attestationGrade).toBe("attested");
    // and a hash over the wrong account is NOT what the handler accepted
    expect(req.attestation.integrityToken).not.toBe(`it-${androidCheckinRequestHash({ challengeId: req.challengeId, deviceId: FAKE_DEVICE, userId: "user-b" }, req.nonce)}`);
  });

  it("iOS: the assertion the real handler accepted is base64url(clientDataHash) of the check-in binding this client builds", () => {
    const req = recordedRequest<{ challengeId: string; nonce: string; attestation: { platform: string; keyId: string; assertion: string } }>("token_201_attested_ios");
    expect(req.attestation.assertion).toBe(bytesToBase64Url(iosCheckinBinding({ challengeId: req.challengeId, deviceId: FAKE_DEVICE, userId: "user-a", nonce: req.nonce })));
    expect(JSON.parse(recorded("token_201_attested_ios").body).data.attestationGrade).toBe("attested");
  });

  it("iOS key registration: the attestation the real handler accepted is base64url of the registration binding this client builds (the existing attestKeyBinding)", () => {
    const req = recordedRequest<{ deviceId: string; challengeId: string; nonce: string; keyId: string; attestation: string }>("attestkey_201_registered");
    expect(req.attestation).toBe(bytesToBase64Url(attestKeyBinding({ challengeId: req.challengeId, deviceId: req.deviceId, keyId: req.keyId, nonce: req.nonce })));
    expect(req.keyId).toMatch(/^[A-Za-z0-9+/]{43}=$/);
  });

  it("the recorded wire bodies have exactly the strict shape: top-level keys, and the two attestation shapes", () => {
    expect(Object.keys(recordedRequest("token_201_attested_android")).sort()).toEqual(["attestation", "challengeId", "hardwareSupportsAttestation", "nonce"]);
    expect(Object.keys(recordedRequest<{ attestation: object }>("token_201_attested_android").attestation).sort()).toEqual(["integrityToken", "platform"]);
    expect(Object.keys(recordedRequest<{ attestation: object }>("token_201_attested_ios").attestation).sort()).toEqual(["assertion", "keyId", "platform"]);
    expect(Object.keys(recordedRequest("attestkey_201_registered")).sort()).toEqual(["attestation", "challengeId", "deviceId", "keyId", "nonce"]);
  });
});

describe("PR #42 gate (d): the checkin-token answer does NOT expose WHY an assertion was graded `failed`", () => {
  it("a `failed` grade carries only jti / expiresAt / attestationGrade: `key_id_mismatch` (a stale local key) cannot be told from a counter replay, a wrong rpId or a wrong binding, so the client cannot recover from it without guessing (the reason goes only to the fraud signal's detail, `token-handler.ts`)", () => {
    for (const name of ["token_201_failed_wrong_binding_ios", "token_201_failed_wrong_binding_android", "token_201_failed_attested_before_no_token"]) {
      const data = JSON.parse(recorded(name).body).data as Record<string, unknown>;
      expect(Object.keys(data).sort(), name).toEqual(["attestationGrade", "expiresAt", "jti"]);
      expect(data["attestationGrade"], name).toBe("failed");
    }
  });
});

describe("bytesToBase64 (the form a hash crosses the native bridge in)", () => {
  it("equals Node's for every length residue, including padding", () => {
    for (let n = 0; n <= 40; n += 1) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + 11) & 255);
      expect(bytesToBase64(b), String(n)).toBe(Buffer.from(b).toString("base64"));
    }
    expect(bytesToBase64(Uint8Array.from(Buffer.from(IOS_HASH, "hex")))).toBe(Buffer.from(IOS_HASH, "hex").toString("base64"));
  });
});

describe("NativeAttestor over the (fake) module", () => {
  const hash32 = Uint8Array.from(Buffer.from(IOS_HASH, "hex"));

  it("iOS: generateKey / attestKey / assert pass the hash as base64 of the 32 bytes UNCHANGED (the module hashes nothing) and return the module's values", async () => {
    const m = new FakeNativeAttestModule();
    const a = new NativeAttestor(m, "ios", null);
    const k = await a.generateKey();
    expect(k.kind).toBe("ok");
    const keyId = k.kind === "ok" ? k.value.keyId : "";
    expect(keyId).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    expect((await a.attestKey(keyId, hash32)).kind).toBe("ok");
    const asr = await a.assert(keyId, hash32);
    expect(asr.kind).toBe("ok");
    expect(m.ops("attestKey")).toEqual([{ op: "attestKey", keyId, hashHex: IOS_HASH }]);
    expect(m.ops("generateAssertion")).toEqual([{ op: "generateAssertion", keyId, hashHex: IOS_HASH }]);
  });

  it("Android: the integrity token is requested with the Cloud project number and the requestHash as base64url TEXT", async () => {
    const m = new FakeNativeAttestModule();
    const a = new NativeAttestor(m, "android", "123456789012");
    const r = await a.integrityToken(androidCheckinRequestBinding(body, NONCE));
    expect(r).toEqual({ kind: "ok", value: { integrityToken: `it.${ANDROID_HASH}` } });
    expect(m.ops("integrityToken")).toEqual([{ op: "integrityToken", cloud: "123456789012", requestHash: ANDROID_HASH }]);
  });

  it("the wrong platform's operations are `unattestable / platform_unsupported`, never a call into the module", async () => {
    const m = new FakeNativeAttestModule();
    const ios = new NativeAttestor(m, "ios", null);
    const and = new NativeAttestor(m, "android", "1");
    expect(await ios.integrityToken(hash32)).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    expect(await and.generateKey()).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    expect(await and.assert("k", hash32)).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    expect(m.events).toEqual([]);
  });

  it("an Android attestor with no Cloud project number says `not_configured` and does not call the module", async () => {
    const m = new FakeNativeAttestModule();
    expect(await new NativeAttestor(m, "android", null).integrityToken(hash32)).toEqual({ kind: "unattestable", reason: "not_configured" });
    expect(m.events).toEqual([]);
  });

  it("a platform failure is `failed` (never `unattestable`, never thrown), and `invalid_key` is carried as a code; a hash that is not 32 bytes is refused before the module", async () => {
    const m = new FakeNativeAttestModule();
    const a = new NativeAttestor(m, "ios", null);
    m.next.generateAssertion = [{ ok: false, code: "invalid_key", message: "gone" }];
    expect(await a.assert("k", hash32)).toEqual({ kind: "failed", message: "generateAssertion: gone", code: "invalid_key" });
    m.next.generateAssertion = [{ ok: false, code: "unavailable", message: "Apple is down" }];
    expect(await a.assert("k", hash32)).toEqual({ kind: "failed", message: "generateAssertion: Apple is down", code: "unavailable" });
    m.next.generateKey = [{ ok: false, code: "unsupported", message: "simulator" }];
    expect(await a.generateKey()).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    const before = m.events.length;
    expect((await a.assert("k", new Uint8Array(31))).kind).toBe("failed");
    expect(m.events.length).toBe(before);
  });

  it("a rejecting or malformed module is `failed`, not a crash", async () => {
    const a = new NativeAttestor({ ...new FakeNativeAttestModule(), capability: async () => ({ supported: true }), generateKey: () => Promise.reject(new Error("bridge down")), attestKey: async () => ({ ok: true, attestation: "not base64 !!" }), generateAssertion: async () => ({ ok: true, assertion: 5 as never }), deviceCheckToken: async () => ({ ok: true, token: "dG9rZW4=" }), integrityToken: async () => ({ ok: true, token: "bad token with spaces" }) }, "ios", null);
    expect(await a.generateKey()).toMatchObject({ kind: "failed", message: expect.stringContaining("bridge down") });
    expect(await a.attestKey("k", new Uint8Array(32))).toMatchObject({ kind: "failed" });
    expect(await a.assert("k", new Uint8Array(32))).toMatchObject({ kind: "failed" });
    expect(await a.deviceCheckToken()).toEqual({ kind: "ok", value: { token: "dG9rZW4=" } });
    expect(await new NativeAttestor({ ...new FakeNativeAttestModule(), integrityToken: async () => ({ ok: true, token: "bad token with spaces" }) } as never, "android", "1").integrityToken(new Uint8Array(32))).toMatchObject({ kind: "failed" });
  });
});

describe("selectAttestor: NativeAttestor only where it can attest; UnattestableAttestor everywhere else", () => {
  const sel = (over: Partial<Parameters<typeof selectAttestor>[0]>) => selectAttestor({ module: new FakeNativeAttestModule(), platform: "ios", playCloudProjectNumber: null, ...over });

  it("iOS with the module present and App Attest supported -> NativeAttestor", async () => {
    const a = await sel({});
    expect(a).toBeInstanceOf(NativeAttestor);
    expect(a.capability).toEqual({ platform: "ios", hardwareSupportsAttestation: true });
  });

  it("Android with the module and a Cloud project number -> NativeAttestor; without the number -> Unattestable / not_configured", async () => {
    expect(await sel({ platform: "android", playCloudProjectNumber: "123456789012" })).toBeInstanceOf(NativeAttestor);
    const none = await sel({ platform: "android" });
    expect(none).not.toBeInstanceOf(NativeAttestor);
    expect(await none.integrityToken(new Uint8Array(32))).toEqual({ kind: "unattestable", reason: "not_configured" });
  });

  it("no module (Expo Go, web, tests) -> Unattestable / not_implemented, capability false", async () => {
    const a = await sel({ module: null });
    expect(a.capability).toEqual({ platform: "none", hardwareSupportsAttestation: false });
    expect(await a.generateKey()).toEqual({ kind: "unattestable", reason: "not_implemented" });
  });

  it("the module present but the device does not support it (an iOS simulator), or the capability call throws -> Unattestable / platform_unsupported", async () => {
    const m = new FakeNativeAttestModule();
    m.supported = false;
    expect(await sel({ module: m })).not.toBeInstanceOf(NativeAttestor);
    expect(await (await sel({ module: m })).generateKey()).toEqual({ kind: "unattestable", reason: "platform_unsupported" });
    const broken = { ...new FakeNativeAttestModule(), capability: () => Promise.reject(new Error("no")) } as never;
    expect(await sel({ module: broken })).not.toBeInstanceOf(NativeAttestor);
  });

  it("web and any other platform -> Unattestable", async () => {
    expect(await sel({ platform: "web" })).not.toBeInstanceOf(NativeAttestor);
    expect(await sel({ platform: "windows" })).not.toBeInstanceOf(NativeAttestor);
  });
});
