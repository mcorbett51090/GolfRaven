// supabase/tests/unit/rewards-request-shape.test.ts
//
// Wire-shape validation for POST /v1/rewards/{id}/activate
// (rewards/request-shape.ts): the id comes only from the URL; unknown keys are
// rejected; attestation material requires a challenge.

import { describe, expect, it } from "vitest";
import { extractRewardId, parseActivationBody } from "../../functions/_shared/rewards/request-shape.js";

const ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DEV = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const CH = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

describe("extractRewardId", () => {
  it("accepts the three route shapes", () => {
    expect(extractRewardId(`/v1/rewards/${ID}/activate`)).toBe(ID);
    expect(extractRewardId(`/rewards/${ID}/activate`)).toBe(ID);
    expect(extractRewardId(`/rewards-activate/${ID}`)).toBe(ID);
    expect(extractRewardId(`/functions/v1/rewards-activate/${ID}`)).toBe(ID);
    expect(extractRewardId(`/v1/rewards/${ID}/activate/`)).toBe(ID);
  });
  it("lowercases the id (clients should bind the lowercase form)", () => {
    expect(extractRewardId(`/v1/rewards/${ID.toUpperCase()}/activate`)).toBe(ID);
  });
  it("is null for anything else: no id, two ids, a glued id, a wrong verb, a trailing segment", () => {
    for (const p of [
      "/v1/rewards//activate",
      "/v1/rewards/activate",
      `/v1/rewards/${ID}/${DEV}/activate`,
      `/v1/rewards/${ID}x/activate`,
      `/v1/rewards/${ID}/redeem`,
      `/v1/rewards/${ID}/activate/extra`,
      `/v1/other/${ID}/activate`,
      `/rewards-activate/${ID}/more`,
      "/",
      "",
    ]) {
      expect(extractRewardId(p), p).toBeNull();
    }
  });
});

const ios = { kind: "ios", keyId: "S2V5SWQ=", assertion: "QVNTRVJU", deviceCheckToken: "REVWSUNF" };
const base = (over: Record<string, unknown> = {}) => ({ deviceId: DEV, platform: "ios", challengeId: CH, nonce: "bm9uY2U", attestation: ios, ...over });
const issuePaths = (raw: unknown) => {
  const r = parseActivationBody(raw);
  return r.ok ? [] : r.issues.map((i) => i.path);
};

describe("parseActivationBody", () => {
  it("accepts a well-formed iOS, Android and attestation-less body", () => {
    expect(parseActivationBody(base()).ok).toBe(true);
    expect(parseActivationBody(base({ platform: "android", attestation: { kind: "android", integrityToken: "eyJhbGciOi.payload.sig" } })).ok).toBe(true);
    expect(parseActivationBody({ deviceId: DEV, platform: "android", attestation: { kind: "none", hardwareSupportsAttestation: false } }).ok).toBe(true);
    expect(parseActivationBody({ deviceId: DEV, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: true, deviceCheckToken: "REVWSUNF" } }).ok).toBe(true);
  });

  it("the reward id is NOT accepted in the body", () => {
    expect(issuePaths(base({ rewardId: ID }))).toContain("rewardId");
    expect(issuePaths(base({ id: ID }))).toContain("id");
  });

  it("rejects unknown fields at both levels, and non-objects", () => {
    expect(issuePaths(base({ extra: 1 }))).toContain("extra");
    expect(issuePaths(base({ attestation: { ...ios, bonus: true } }))).toContain("attestation.bonus");
    for (const bad of [null, [], "x", 1]) expect(parseActivationBody(bad).ok).toBe(false);
  });

  it("validates ids, platform and base64 fields", () => {
    expect(issuePaths(base({ deviceId: "not-a-uuid" }))).toContain("deviceId");
    expect(issuePaths(base({ platform: "windows" }))).toContain("platform");
    expect(issuePaths(base({ challengeId: "x" }))).toContain("challengeId");
    expect(issuePaths(base({ nonce: "has+plus" }))).toContain("nonce");
    expect(issuePaths(base({ attestation: { ...ios, assertion: "not base64 !" } }))).toContain("attestation.assertion");
    expect(issuePaths(base({ attestation: { ...ios, deviceCheckToken: "" } }))).toContain("attestation.deviceCheckToken");
  });

  it("attestation material is bound to a challenge: ios/android without challengeId or nonce is invalid", () => {
    expect(issuePaths({ deviceId: DEV, platform: "ios", attestation: ios })).toEqual(expect.arrayContaining(["challengeId", "nonce"]));
    expect(issuePaths({ deviceId: DEV, platform: "android", attestation: { kind: "android", integrityToken: "abc.def" } })).toEqual(expect.arrayContaining(["challengeId", "nonce"]));
  });

  it("the attestation kind must match the platform", () => {
    expect(issuePaths(base({ platform: "android" }))).toContain("attestation.kind");
    expect(issuePaths(base({ attestation: { kind: "android", integrityToken: "a.b" } }))).toContain("attestation.kind");
  });

  it("kind none: hardwareSupportsAttestation is a required boolean; DeviceCheck exists on iOS only", () => {
    expect(issuePaths({ deviceId: DEV, platform: "ios", attestation: { kind: "none" } })).toContain("attestation.hardwareSupportsAttestation");
    expect(issuePaths({ deviceId: DEV, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: "no" } })).toContain("attestation.hardwareSupportsAttestation");
    expect(issuePaths({ deviceId: DEV, platform: "android", attestation: { kind: "none", hardwareSupportsAttestation: false, deviceCheckToken: "REVWSUNF" } })).toContain("attestation.deviceCheckToken");
  });

  it("an unknown attestation kind", () => {
    expect(issuePaths(base({ attestation: { kind: "magic" } }))).toContain("attestation.kind");
    expect(issuePaths(base({ attestation: "x" }))).toContain("attestation");
  });

  it("lowercases ids on the way out", () => {
    const r = parseActivationBody(base({ deviceId: DEV.toUpperCase(), challengeId: CH.toUpperCase() }));
    expect(r.ok && r.value.deviceId).toBe(DEV);
    expect(r.ok && r.value.challengeId).toBe(CH);
  });
});

describe("installLinkId (Android substitute, A20)", () => {
  const base = { deviceId: DEV, platform: "android", challengeId: CH, nonce: "AAAA", attestation: { kind: "android", integrityToken: "tok.en" } };
  it("is accepted on Android and carried through", () => {
    const r = parseActivationBody({ ...base, installLinkId: "install-link-AAAAAAAAAA" });
    expect(r.ok && r.value.installLinkId).toBe("install-link-AAAAAAAAAA");
  });
  it("is optional", () => {
    const r = parseActivationBody(base);
    expect(r.ok && r.value.installLinkId).toBeUndefined();
  });
  it("is rejected on iOS, and when too short, too long, or not opaque-id characters", () => {
    expect(parseActivationBody({ ...base, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false }, installLinkId: "install-link-AAAAAAAAAA" }).ok).toBe(false);
    for (const bad of ["short", "x".repeat(129), "has space in it 123456", 7, null]) {
      expect(parseActivationBody({ ...base, installLinkId: bad }).ok, String(bad)).toBe(false);
    }
  });
});
