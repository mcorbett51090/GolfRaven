// supabase/tests/unit/play-integrity.test.ts
//
// Play Integrity verdict evaluation (rewards/play-integrity.ts): requestHash,
// package name, certificate digest, deviceIntegrity (+ freshness). AT 5: "a
// wrong Play Integrity requestHash is rejected".

import { describe, expect, it } from "vitest";
import { evaluateIntegrityPayload, extractRecallBits, type IntegrityExpectations } from "../../functions/_shared/rewards/play-integrity.js";

const NOW = Date.parse("2026-06-01T12:00:00.000Z");
const EXP: IntegrityExpectations = {
  packageName: "com.example.golfraven",
  certificateSha256Digests: ["CERTDIGESTONE", "CERTDIGESTTWO"],
  expectedRequestHash: "expectedRequestHashBase64Url",
  nowMs: NOW,
  maxAgeMs: 5 * 60_000,
  maxFutureSkewMs: 60_000,
};

function payload(over: Record<string, unknown> = {}) {
  return {
    requestDetails: { requestPackageName: "com.example.golfraven", requestHash: "expectedRequestHashBase64Url", timestampMillis: String(NOW - 5_000) },
    appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", packageName: "com.example.golfraven", certificateSha256Digest: ["CERTDIGESTONE"], versionCode: "1" },
    deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
    ...over,
  };
}
const reasonsOf = (p: unknown) => {
  const r = evaluateIntegrityPayload(p, EXP);
  return r.grade === "failed" ? r.reasons : [];
};

describe("a good verdict", () => {
  it("is attested", () => {
    expect(evaluateIntegrityPayload(payload(), EXP)).toEqual({ grade: "attested" });
  });
  it("accepts any one of several allowed certificate digests", () => {
    const p = payload({ appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", packageName: "com.example.golfraven", certificateSha256Digest: ["unlisted", "CERTDIGESTTWO"] } });
    expect(evaluateIntegrityPayload(p, EXP)).toEqual({ grade: "attested" });
  });
});

describe("AT 5 + §7.5: each check, failing alone, fails the verdict", () => {
  it("a wrong requestHash (a different body or challenge) is rejected", () => {
    const p = payload({ requestDetails: { requestPackageName: "com.example.golfraven", requestHash: "someOtherHash", timestampMillis: String(NOW) } });
    expect(reasonsOf(p)).toEqual(["request_hash_mismatch"]);
  });
  it("a wrong package name is rejected", () => {
    const p = payload({ requestDetails: { requestPackageName: "com.evil.repack", requestHash: "expectedRequestHashBase64Url", timestampMillis: String(NOW) } });
    expect(reasonsOf(p)).toEqual(["package_name_mismatch"]);
  });
  it("a certificate digest that is not allow-listed is rejected", () => {
    const p = payload({ appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", certificateSha256Digest: ["EVILDIGEST"] } });
    expect(reasonsOf(p)).toEqual(["certificate_digest_not_allowed"]);
  });
  it("an app that is not PLAY_RECOGNIZED is rejected", () => {
    const p = payload({ appIntegrity: { appRecognitionVerdict: "UNRECOGNIZED_VERSION", certificateSha256Digest: ["CERTDIGESTONE"] } });
    expect(reasonsOf(p)).toEqual(["app_not_play_recognized"]);
  });
  it("a device that does not meet device integrity (empty or basic-only verdict) is rejected", () => {
    for (const verdict of [[], ["MEETS_BASIC_INTEGRITY"], ["MEETS_STRONG_INTEGRITY"]]) {
      const p = payload({ deviceIntegrity: { deviceRecognitionVerdict: verdict } });
      expect(reasonsOf(p), JSON.stringify(verdict)).toEqual(["device_integrity_not_met"]);
    }
  });
  it("a stale verdict (older than the window) or one from the future is rejected", () => {
    const old = payload({ requestDetails: { requestPackageName: "com.example.golfraven", requestHash: "expectedRequestHashBase64Url", timestampMillis: String(NOW - 6 * 60_000) } });
    const future = payload({ requestDetails: { requestPackageName: "com.example.golfraven", requestHash: "expectedRequestHashBase64Url", timestampMillis: String(NOW + 2 * 60_000) } });
    expect(reasonsOf(old)).toEqual(["verdict_not_fresh"]);
    expect(reasonsOf(future)).toEqual(["verdict_not_fresh"]);
  });
  it("reports every failing check, not just the first", () => {
    const p = payload({
      requestDetails: { requestPackageName: "x", requestHash: "y", timestampMillis: String(NOW) },
      deviceIntegrity: { deviceRecognitionVerdict: [] },
    });
    expect(reasonsOf(p).sort()).toEqual(["device_integrity_not_met", "package_name_mismatch", "request_hash_mismatch"]);
  });
});

describe("fails CLOSED on missing or oddly typed fields", () => {
  it("non-object payloads", () => {
    for (const bad of [null, undefined, "x", 1, [], true]) expect(evaluateIntegrityPayload(bad, EXP).grade, String(bad)).toBe("failed");
  });
  it("each missing top-level section is a named failure", () => {
    expect(reasonsOf({})).toEqual(["missing_requestDetails", "missing_appIntegrity", "missing_deviceIntegrity"]);
  });
  it("a requestHash that is not a string, a timestamp that is not numeric, digests of the wrong type", () => {
    const p = {
      requestDetails: { requestPackageName: "com.example.golfraven", requestHash: 5, timestampMillis: "soon" },
      appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", certificateSha256Digest: [1, 2] },
      deviceIntegrity: { deviceRecognitionVerdict: "MEETS_DEVICE_INTEGRITY" },
    };
    const r = reasonsOf(p);
    expect(r).toContain("request_hash_mismatch");
    expect(r).toContain("missing_timestamp");
    expect(r).toContain("missing_certificate_digest");
    expect(r).toContain("device_integrity_not_met");
  });
  it("an empty digest list", () => {
    expect(reasonsOf(payload({ appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", certificateSha256Digest: [] } }))).toEqual(["missing_certificate_digest"]);
  });
});

describe("extractRecallBits — absent or malformed is null, never 'clear'", () => {
  it("reads the two bits when present", () => {
    expect(extractRecallBits({ deviceIntegrity: { deviceRecall: { values: { bitFirst: true, bitSecond: false } } } })).toEqual({ bit0: true, bit1: false, lastUpdateMonth: null });
  });
  it("returns null for every other shape", () => {
    for (const p of [null, {}, { deviceIntegrity: {} }, { deviceIntegrity: { deviceRecall: {} } }, { deviceIntegrity: { deviceRecall: { values: { bitFirst: "yes", bitSecond: false } } } }, { deviceIntegrity: { deviceRecall: { values: { bitFirst: true } } } }]) {
      expect(extractRecallBits(p), JSON.stringify(p)).toBeNull();
    }
  });
});
