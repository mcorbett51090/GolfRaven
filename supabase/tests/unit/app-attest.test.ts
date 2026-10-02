// supabase/tests/unit/app-attest.test.ts
//
// App Attest ASSERTION verification (rewards/app-attest.ts) against assertions
// this repo's own test helper builds. These prove the verifier's logic and its
// fail-closed behaviour; they do NOT prove conformance with a real iOS device
// (`[unverified]` — no Apple device or account in this environment).

import { beforeAll, describe, expect, it } from "vitest";
import { derSignatureToRaw, decodeCbor, parseAssertion, parseAuthenticatorData, verifyAppAttestAssertion, verifyP256WebCrypto, CborError } from "../../functions/_shared/rewards/app-attest.js";
import { toBase64Url } from "../../functions/_shared/rewards/binding.js";
import type { DeviceAttestState } from "../../functions/_shared/rewards/types.js";
import { authenticatorData, bindingFor, buildAssertion, cborBytes, cborMap, cborText, generateP256, rawSignatureToDer, sha256, toB64, type TestKey } from "./rewards-test-crypto.js";

const APP_ID = "TEAMID1234.com.example.golfraven";
const KEY_ID_B64 = toB64(new Uint8Array(32).fill(7));
const CRYPTO = { sha256, verifyP256: verifyP256WebCrypto };
const BODY = {
  rewardId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
  deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  platform: "ios" as const,
  challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
};
const CHALLENGE = new Uint8Array(32).fill(9);

let key: TestKey;
let otherKey: TestKey;
beforeAll(async () => {
  key = await generateP256();
  otherKey = await generateP256();
});

const device = (over: Partial<DeviceAttestState> = {}): DeviceAttestState => ({
  id: BODY.deviceId,
  platform: "ios",
  attestKeyId: KEY_ID_B64,
  attestCounter: 4,
  attestPublicKey: key.publicKeyRaw,
  ...over,
});

async function verify(over: { counter?: number; signWithHash?: Uint8Array; rpIdHash?: Uint8Array; signer?: TestKey; dev?: Partial<DeviceAttestState>; keyId?: string; assertionB64?: string; mutateSignature?: (s: Uint8Array) => Uint8Array } = {}) {
  const hash = await bindingFor(BODY, CHALLENGE);
  const built = await buildAssertion({ key: over.signer ?? key, appId: APP_ID, counter: over.counter ?? 5, clientDataHash: hash, signWithHash: over.signWithHash, rpIdHash: over.rpIdHash, mutateSignature: over.mutateSignature });
  return verifyAppAttestAssertion(
    { assertionB64: over.assertionB64 ?? built.assertionB64, keyId: over.keyId ?? KEY_ID_B64, clientDataHash: hash, device: device(over.dev) },
    { appId: APP_ID },
    CRYPTO,
  );
}

describe("a good assertion", () => {
  it("verifies and returns the new counter", async () => {
    expect(await verify()).toEqual({ ok: true, counter: 5 });
  });
  it("accepts url-safe / unpadded base64 for the assertion and key id", async () => {
    const hash = await bindingFor(BODY, CHALLENGE);
    const built = await buildAssertion({ key, appId: APP_ID, counter: 5, clientDataHash: hash });
    const urlSafe = built.assertionB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(await verify({ assertionB64: urlSafe, keyId: KEY_ID_B64.replace(/=+$/, "") })).toEqual({ ok: true, counter: 5 });
  });
});

describe("AT 5: a mismatched request hash, a replayed counter and a tampered assertion are rejected", () => {
  it("an assertion signed over a DIFFERENT request hash (wrong body / wrong challenge) fails", async () => {
    const other = await bindingFor({ ...BODY, rewardId: "dddddddd-dddd-4ddd-8ddd-dddddddddddd" }, CHALLENGE);
    expect(await verify({ signWithHash: other })).toMatchObject({ ok: false, grade: "failed", reason: "bad_signature_or_request_hash" });
    const otherChallenge = await bindingFor(BODY, new Uint8Array(32).fill(1));
    expect(await verify({ signWithHash: otherChallenge })).toMatchObject({ ok: false, grade: "failed" });
  });

  it("a replayed counter (equal to, or below, the stored one) fails", async () => {
    expect(await verify({ counter: 4 })).toMatchObject({ ok: false, grade: "failed", reason: "counter_not_monotonic" });
    expect(await verify({ counter: 3 })).toMatchObject({ ok: false, grade: "failed", reason: "counter_not_monotonic" });
  });

  it("a signature from a different key fails", async () => {
    expect(await verify({ signer: otherKey })).toMatchObject({ ok: false, grade: "failed", reason: "bad_signature_or_request_hash" });
  });

  it("a flipped signature byte fails", async () => {
    const r = await verify({ mutateSignature: (s) => s.map((b, i) => (i === s.length - 3 ? b ^ 0x55 : b)) });
    expect(r).toMatchObject({ ok: false, grade: "failed" });
  });

  it("a wrong rpIdHash (a different app) fails", async () => {
    const r = await verify({ rpIdHash: await sha256(new TextEncoder().encode("OTHERTEAM.com.example.other")) });
    expect(r).toMatchObject({ ok: false, grade: "failed", reason: "rp_id_mismatch" });
  });

  it("a key id that is not the one on record fails", async () => {
    expect(await verify({ keyId: toB64(new Uint8Array(32).fill(8)) })).toMatchObject({ ok: false, grade: "failed", reason: "key_id_mismatch" });
  });
});

describe("fails CLOSED on anything it does not recognise", () => {
  it("no registered key -> unattestable (never 'verified')", async () => {
    expect(await verify({ dev: { attestPublicKey: null } })).toMatchObject({ ok: false, grade: "unattestable", reason: "key_not_registered" });
    expect(await verify({ dev: { attestKeyId: null } })).toMatchObject({ ok: false, grade: "unattestable", reason: "key_not_registered" });
  });
  it("junk base64, a non-CBOR blob and a CBOR map with the wrong shape are malformed -> failed", async () => {
    for (const bad of ["not base64 !!", toB64(new Uint8Array([1, 2, 3])), toB64(cborMap([["signature", cborBytes(new Uint8Array(8))]]))]) {
      expect(await verify({ assertionB64: bad }), bad).toMatchObject({ ok: false, grade: "failed", reason: "malformed_assertion" });
    }
  });
  it("a signature that is not DER is malformed -> failed", async () => {
    const hash = await bindingFor(BODY, CHALLENGE);
    const rpIdHash = await sha256(new TextEncoder().encode(APP_ID));
    const bad = toB64(
      cborMap([
        ["signature", cborBytes(new Uint8Array(64).fill(1))],
        ["authenticatorData", cborBytes(authenticatorData(rpIdHash, 5))],
      ]),
    );
    const r = await verifyAppAttestAssertion({ assertionB64: bad, keyId: KEY_ID_B64, clientDataHash: hash, device: device() }, { appId: APP_ID }, CRYPTO);
    expect(r).toMatchObject({ ok: false, grade: "failed", reason: "malformed_signature" });
  });
  it("a stored key that is not a valid P-256 point fails rather than throwing", async () => {
    const r = await verify({ dev: { attestPublicKey: new Uint8Array(65).fill(4) } });
    expect(r).toMatchObject({ ok: false, grade: "failed" });
  });
});

describe("CBOR decoding is strict", () => {
  it("parses a two-entry byte-string map", () => {
    const parsed = parseAssertion(cborMap([["signature", cborBytes(new Uint8Array([1, 2]))], ["authenticatorData", cborBytes(new Uint8Array(37))]]));
    expect(parsed.signature).toEqual(new Uint8Array([1, 2]));
  });
  it("rejects trailing bytes, duplicate keys, indefinite lengths, tags, floats, arrays and truncation", () => {
    const ok = cborMap([["a", cborBytes(new Uint8Array([1]))]]);
    expect(() => decodeCbor(new Uint8Array([...ok, 0]))).toThrow(CborError);
    expect(() => decodeCbor(new Uint8Array([0xa2, ...cborText("k"), ...cborBytes(new Uint8Array([1])), ...cborText("k"), ...cborBytes(new Uint8Array([2]))]))).toThrow(/duplicate/);
    expect(() => decodeCbor(new Uint8Array([0x5f, 0xff]))).toThrow(CborError); // indefinite-length byte string
    expect(() => decodeCbor(new Uint8Array([0xc0, 0x00]))).toThrow(CborError); // tag
    expect(() => decodeCbor(new Uint8Array([0xfb, 0, 0, 0, 0, 0, 0, 0, 0]))).toThrow(CborError); // float
    expect(() => decodeCbor(new Uint8Array([0x81, 0x00]))).toThrow(CborError); // array
    expect(() => decodeCbor(new Uint8Array([0x58, 0x05, 1, 2]))).toThrow(/truncated/);
    expect(() => decodeCbor(new Uint8Array([]))).toThrow(/truncated/);
  });
  it("rejects a non-text map key", () => {
    expect(() => decodeCbor(new Uint8Array([0xa1, 0x01, 0x01]))).toThrow(/non-text/);
  });
  it("authenticatorData must be exactly 37 bytes", () => {
    expect(() => parseAuthenticatorData(new Uint8Array(36))).toThrow(CborError);
    expect(() => parseAuthenticatorData(new Uint8Array(38))).toThrow(CborError);
    expect(parseAuthenticatorData(authenticatorData(new Uint8Array(32).fill(2), 0xdeadbeef)).counter).toBe(0xdeadbeef);
  });
});

describe("DER -> raw signature conversion", () => {
  it("round-trips signatures with and without a leading zero byte", () => {
    for (const first of [0x01, 0x7f, 0x80, 0xff]) {
      const raw = new Uint8Array(64).map((_, i) => (i === 0 || i === 32 ? first : i + 1));
      expect(derSignatureToRaw(rawSignatureToDer(raw))).toEqual(raw);
    }
  });
  it("round-trips short integers (leading zero bytes stripped by the signer)", () => {
    const raw = new Uint8Array(64);
    raw.set([5, 6, 7], 29); // r = 0x050607 (29 leading zeros)
    raw.set([9], 63);
    expect(derSignatureToRaw(rawSignatureToDer(raw))).toEqual(raw);
  });
  it("returns null for malformed DER", () => {
    for (const bad of [new Uint8Array([]), new Uint8Array([0x31, 0]), new Uint8Array([0x30, 5, 2, 1, 1]), new Uint8Array([0x30, 0x81, 0]), toBytes("30060201010201")]) {
      expect(derSignatureToRaw(bad)).toBeNull();
    }
  });
});

function toBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/../g)!.map((h) => parseInt(h, 16)));
}

describe("key id handling", () => {
  it("toBase64Url of the stored key id still matches (lenient comparison)", async () => {
    expect(await verify({ dev: { attestKeyId: toBase64Url(new Uint8Array(32).fill(7)) } })).toEqual({ ok: true, counter: 5 });
  });
});
