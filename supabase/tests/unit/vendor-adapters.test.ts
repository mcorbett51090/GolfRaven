// supabase/tests/unit/vendor-adapters.test.ts
//
// The PRODUCTION vendor adapters (devicecheck-client.ts, play-integrity-client.ts,
// production-ports.ts) against a SCRIPTED `fetch`. LIVE VENDOR VERIFICATION IS
// NOT EXERCISED: there is no Apple or Google credential or network route in this
// environment, so every vendor "response" below is one this file invented from
// training knowledge of the wire contract (`[unverified]`). What these tests DO
// prove: the request shape each adapter sends, the JWTs it signs (verified with
// the matching public key), the status -> error-class mapping, and — most
// importantly — that every unconfigured / unusable / unrecognised case FAILS
// CLOSED rather than reading as "clean".

import { beforeAll, describe, expect, it } from "vitest";
import { createDeviceCheckClient, isCompleteDeviceCheckConfig, type DeviceCheckConfig } from "../../functions/_shared/rewards/devicecheck-client.js";
import { createIntegrityDecoder, isCompletePlayIntegrityConfig, type PlayIntegrityConfig } from "../../functions/_shared/rewards/play-integrity-client.js";
import { buildAndroidPort, buildAttestationPorts, buildIosPort } from "../../functions/_shared/rewards/production-ports.js";
import { fromBase64UrlStrict } from "../../functions/_shared/rewards/binding.js";
import { verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.js";
import { VendorNotConfiguredError, VendorRejectedError, VendorUnavailableError } from "../../functions/_shared/rewards/types.js";
import { pemToDer, type VendorHttp } from "../../functions/_shared/rewards/vendor-http.js";
import { sha256, toB64 } from "./rewards-test-crypto.js";

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

function scriptedHttp(responses: Array<Response | Error | ((c: Call) => Response)>): VendorHttp & { calls: Call[] } {
  const calls: Call[] = [];
  let i = 0;
  return {
    calls,
    timeoutMs: 1_000,
    nowMs: () => 1_780_000_000_000,
    randomUuid: () => "00000000-0000-4000-8000-000000000001",
    async fetch(url, init) {
      const call = { url, method: init.method, headers: init.headers, body: init.body };
      calls.push(call);
      const r = responses[Math.min(i++, responses.length - 1)]!;
      if (r instanceof Error) throw r;
      return typeof r === "function" ? r(call) : r.clone();
    },
  };
}
const text = (status: number, body: string) => new Response(body, { status });
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

function pem(label: string, der: ArrayBuffer): string {
  const b64 = toB64(new Uint8Array(der)).replace(/(.{64})/g, "$1\n");
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
}

let ecKeys: CryptoKeyPair;
let applePem: string;
let rsaKeys: CryptoKeyPair;
let googlePem: string;
beforeAll(async () => {
  ecKeys = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  applePem = pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", ecKeys.privateKey));
  rsaKeys = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  googlePem = pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", rsaKeys.privateKey));
}, 60_000);

const appleConfig = (over: Partial<DeviceCheckConfig> = {}): DeviceCheckConfig => ({ teamId: "TEAMID1234", keyId: "KEYID12345", privateKeyPem: applePem, environment: "production", ...over });
const googleConfig = (over: Partial<PlayIntegrityConfig> = {}): PlayIntegrityConfig => ({
  packageName: "com.example.golfraven",
  certificateSha256Digests: ["CERTDIGESTONE"],
  serviceAccountEmail: "svc@example.iam.gserviceaccount.test",
  serviceAccountPrivateKeyPem: googlePem,
  ...over,
});

function decodeJwt(jwt: string): { header: Record<string, unknown>; claims: Record<string, unknown>; signingInput: string; sig: Uint8Array } {
  const [h, c, s] = jwt.split(".");
  const dec = (x: string) => JSON.parse(new TextDecoder().decode(fromBase64UrlStrict(x)!));
  return { header: dec(h!), claims: dec(c!), signingInput: `${h}.${c}`, sig: fromBase64UrlStrict(s!)! };
}

describe("DeviceCheck adapter", () => {
  it("query_two_bits: sends the documented request and a verifiable ES256 JWT", async () => {
    const http = scriptedHttp([json(200, { bit0: true, bit1: false, last_update_time: "2026-03" })]);
    const bits = await createDeviceCheckClient(appleConfig(), http).queryTwoBits("DEVICETOKENBASE64");
    expect(bits).toEqual({ bit0: true, bit1: false, lastUpdateMonth: "2026-03" });

    const call = http.calls[0]!;
    expect(call.url).toBe("https://api.devicecheck.apple.com/v1/query_two_bits");
    expect(call.method).toBe("POST");
    expect(JSON.parse(call.body)).toEqual({ device_token: "DEVICETOKENBASE64", transaction_id: "00000000-0000-4000-8000-000000000001", timestamp: 1_780_000_000_000 });

    const jwt = decodeJwt(call.headers.authorization!.replace(/^Bearer /, ""));
    expect(jwt.header).toEqual({ kid: "KEYID12345", typ: "JWT", alg: "ES256" });
    expect(jwt.claims).toEqual({ iss: "TEAMID1234", iat: 1_780_000_000 });
    // The signature really verifies under the matching public key.
    const pub = new Uint8Array(await crypto.subtle.exportKey("raw", ecKeys.publicKey));
    expect(await verifyP256WebCrypto(pub, jwt.sig, new TextEncoder().encode(jwt.signingInput))).toBe(true);
  });

  it("uses the development host for environment=development", async () => {
    const http = scriptedHttp([json(200, { bit0: false, bit1: false })]);
    await createDeviceCheckClient(appleConfig({ environment: "development" }), http).queryTwoBits("T");
    expect(http.calls[0]!.url).toBe("https://api.development.devicecheck.apple.com/v1/query_two_bits");
  });

  it("the documented 'never set' text is clean/clear; any other 200 text is NOT", async () => {
    const never = await createDeviceCheckClient(appleConfig(), scriptedHttp([text(200, "Failed to find bit state")])).queryTwoBits("T");
    expect(never).toEqual({ bit0: false, bit1: false, lastUpdateMonth: null });
    for (const body of ["", "OK", "<html>maintenance</html>", "{}", '{"bit0":"yes","bit1":false}', '{"bit0":true}', "null", "[]"]) {
      await expect(createDeviceCheckClient(appleConfig(), scriptedHttp([text(200, body)])).queryTwoBits("T"), body).rejects.toBeInstanceOf(VendorUnavailableError);
    }
  });

  it("ignores a malformed last_update_time rather than trusting it", async () => {
    const bits = await createDeviceCheckClient(appleConfig(), scriptedHttp([json(200, { bit0: true, bit1: false, last_update_time: "yesterday" })])).queryTwoBits("T");
    expect(bits.lastUpdateMonth).toBeNull();
  });

  it("update_two_bits sends both bits", async () => {
    const http = scriptedHttp([text(200, "")]);
    await createDeviceCheckClient(appleConfig(), http).updateTwoBits("TOK", { bit0: true, bit1: true });
    expect(http.calls[0]!.url).toBe("https://api.devicecheck.apple.com/v1/update_two_bits");
    expect(JSON.parse(http.calls[0]!.body)).toMatchObject({ device_token: "TOK", bit0: true, bit1: true });
  });

  it("status mapping: 400 blaming the token -> rejected token; 401/403 -> not configured; 429/5xx/network -> unavailable", async () => {
    const run = (r: Response | Error) => createDeviceCheckClient(appleConfig(), scriptedHttp([r])).queryTwoBits("T");
    await expect(run(text(400, "Missing or incorrectly formatted device token"))).rejects.toBeInstanceOf(VendorRejectedError);
    await expect(run(text(400, "Bad Device Token"))).rejects.toBeInstanceOf(VendorRejectedError);
    await expect(run(text(401, ""))).rejects.toBeInstanceOf(VendorNotConfiguredError);
    await expect(run(text(403, ""))).rejects.toBeInstanceOf(VendorNotConfiguredError);
    await expect(run(text(429, ""))).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(run(text(503, ""))).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(run(new Error("ECONNRESET"))).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("400 SPLIT: a 400 that does NOT blame the device token is a request/environment fault (503, no account-wide signal), not a bad token", async () => {
    const run = (r: Response | Error) => createDeviceCheckClient(appleConfig(), scriptedHttp([r])).queryTwoBits("T");
    for (const body of ["Missing or incorrectly formatted payload", "Missing or incorrectly formatted transaction id", "Missing or incorrectly formatted timestamp", "", "Bad Request", "<html>"]) {
      await expect(run(text(400, body)), body).rejects.toBeInstanceOf(VendorNotConfiguredError);
    }
    // ... and the same split holds for the write.
    const w = (r: Response) => createDeviceCheckClient(appleConfig(), scriptedHttp([r])).updateTwoBits("T", { bit0: true, bit1: false });
    await expect(w(text(400, "Missing or incorrectly formatted payload"))).rejects.toBeInstanceOf(VendorNotConfiguredError);
    await expect(w(text(400, "Missing or incorrectly formatted device token"))).rejects.toBeInstanceOf(VendorRejectedError);
  });

  it("FAILS CLOSED when unconfigured, half-configured, or the key is unusable — and never calls out", async () => {
    const cases: Array<[string, DeviceCheckConfig | null]> = [
      ["null config", null],
      ["empty team id", appleConfig({ teamId: "" })],
      ["empty key id", appleConfig({ keyId: "" })],
      ["empty private key", appleConfig({ privateKeyPem: "" })],
      ["bad environment", appleConfig({ environment: "staging" as never })],
      ["private key is not PEM", appleConfig({ privateKeyPem: "not a pem" })],
      ["private key is not a P-256 key", appleConfig({ privateKeyPem: googlePem })],
    ];
    for (const [label, cfg] of cases) {
      const http = scriptedHttp([json(200, { bit0: false, bit1: false })]);
      const client = createDeviceCheckClient(cfg, http);
      await expect(client.queryTwoBits("T"), label).rejects.toBeInstanceOf(VendorNotConfiguredError);
      await expect(client.updateTwoBits("T", { bit0: true, bit1: false }), label).rejects.toBeInstanceOf(VendorNotConfiguredError);
      expect(http.calls, label).toHaveLength(0);
    }
  });

  it("the token and the JWT never appear in an error message", async () => {
    const http = scriptedHttp([text(500, "boom")]);
    const err = await createDeviceCheckClient(appleConfig(), http).queryTwoBits("SECRETDEVICETOKEN").catch((e) => e as Error);
    expect(String(err.message)).not.toContain("SECRETDEVICETOKEN");
    expect(String(err.message)).not.toMatch(/eyJ/);
  });

  it("isCompleteDeviceCheckConfig mirrors the checks", () => {
    expect(isCompleteDeviceCheckConfig(appleConfig())).toBe(true);
    expect(isCompleteDeviceCheckConfig(null)).toBe(false);
    expect(isCompleteDeviceCheckConfig(appleConfig({ teamId: "" }))).toBe(false);
  });
});

describe("Play Integrity decoder adapter", () => {
  const PAYLOAD = { requestDetails: { requestHash: "h" } };
  const tokenOk = () => json(200, { access_token: "ya29.test", expires_in: 3600 });

  it("exchanges a verifiable RS256 service-account JWT, then decodes the token", async () => {
    const http = scriptedHttp([tokenOk(), json(200, { tokenPayloadExternal: PAYLOAD })]);
    const payload = await createIntegrityDecoder(googleConfig(), http).decode("INTEGRITYTOKEN");
    expect(payload).toEqual(PAYLOAD);

    const [oauth, decode] = http.calls;
    expect(oauth!.url).toBe("https://oauth2.googleapis.com/token");
    const form = new URLSearchParams(oauth!.body);
    expect(form.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    const jwt = decodeJwt(form.get("assertion")!);
    expect(jwt.header).toEqual({ typ: "JWT", alg: "RS256" });
    expect(jwt.claims).toMatchObject({ iss: "svc@example.iam.gserviceaccount.test", scope: "https://www.googleapis.com/auth/playintegrity", aud: "https://oauth2.googleapis.com/token" });
    expect(await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, rsaKeys.publicKey, jwt.sig.slice().buffer, new TextEncoder().encode(jwt.signingInput))).toBe(true);

    expect(decode!.url).toBe("https://playintegrity.googleapis.com/v1/com.example.golfraven:decodeIntegrityToken");
    expect(decode!.headers.authorization).toBe("Bearer ya29.test");
    expect(JSON.parse(decode!.body)).toEqual({ integrity_token: "INTEGRITYTOKEN" });
  });

  it("caches the access token across decodes", async () => {
    const http = scriptedHttp([tokenOk(), json(200, { tokenPayloadExternal: PAYLOAD }), json(200, { tokenPayloadExternal: PAYLOAD })]);
    const decoder = createIntegrityDecoder(googleConfig(), http);
    await decoder.decode("A");
    await decoder.decode("B");
    expect(http.calls.filter((c) => c.url.includes("oauth2"))).toHaveLength(1);
  });

  it("status mapping: 400 -> rejected; 401/403 -> not configured; 5xx/network -> unavailable; junk 200 -> unavailable", async () => {
    const run = (r: Response | Error) => createIntegrityDecoder(googleConfig(), scriptedHttp([tokenOk(), r])).decode("T");
    await expect(run(text(400, ""))).rejects.toBeInstanceOf(VendorRejectedError);
    await expect(run(text(401, ""))).rejects.toBeInstanceOf(VendorNotConfiguredError);
    await expect(run(text(403, ""))).rejects.toBeInstanceOf(VendorNotConfiguredError);
    await expect(run(text(500, ""))).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(run(new Error("timeout"))).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(run(text(200, "not json"))).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(run(json(200, {}))).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(run(json(200, { tokenPayloadExternal: "x" }))).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("an OAuth failure is not configured (bad credentials) or unavailable (Google down)", async () => {
    await expect(createIntegrityDecoder(googleConfig(), scriptedHttp([text(401, "")])).decode("T")).rejects.toBeInstanceOf(VendorNotConfiguredError);
    await expect(createIntegrityDecoder(googleConfig(), scriptedHttp([text(503, "")])).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
    await expect(createIntegrityDecoder(googleConfig(), scriptedHttp([json(200, { access_token: "" })])).decode("T")).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("FAILS CLOSED when unconfigured, half-configured, or the key is unusable — and never calls out", async () => {
    const cases: Array<[string, PlayIntegrityConfig | null]> = [
      ["null config", null],
      ["empty package", googleConfig({ packageName: "" })],
      ["no cert digests", googleConfig({ certificateSha256Digests: [] })],
      ["empty digest string", googleConfig({ certificateSha256Digests: [""] })],
      ["no service account", googleConfig({ serviceAccountEmail: "" })],
      ["no key", googleConfig({ serviceAccountPrivateKeyPem: "" })],
      ["key is not PEM", googleConfig({ serviceAccountPrivateKeyPem: "nope" })],
      ["key is not RSA", googleConfig({ serviceAccountPrivateKeyPem: applePem })],
    ];
    for (const [label, cfg] of cases) {
      const http = scriptedHttp([tokenOk(), json(200, { tokenPayloadExternal: PAYLOAD })]);
      await expect(createIntegrityDecoder(cfg, http).decode("T"), label).rejects.toBeInstanceOf(VendorNotConfiguredError);
      expect(http.calls, label).toHaveLength(0);
    }
  });

  it("isCompletePlayIntegrityConfig mirrors the checks", () => {
    expect(isCompletePlayIntegrityConfig(googleConfig())).toBe(true);
    expect(isCompletePlayIntegrityConfig(null)).toBe(false);
    expect(isCompletePlayIntegrityConfig(googleConfig({ certificateSha256Digests: [] }))).toBe(false);
  });
});

describe("production port assembly", () => {
  const crypt = { sha256, verifyP256: verifyP256WebCrypto };
  const http = () => scriptedHttp([json(200, { bit0: false, bit1: false })]);

  it("an unconfigured platform has NO port (so a request carrying its attestation material fails closed upstream)", () => {
    expect(buildAttestationPorts({ apple: null, google: null }, http(), crypt)).toEqual({ ios: null, android: null });
  });

  it("an incomplete config yields no port either — half-set is not configured", () => {
    const ports = buildAttestationPorts({ apple: { ...appleConfig(), bundleId: "" }, google: googleConfig({ certificateSha256Digests: [] }) }, http(), crypt);
    expect(ports).toEqual({ ios: null, android: null });
  });

  it("a complete config yields ports", () => {
    const ports = buildAttestationPorts({ apple: { ...appleConfig(), bundleId: "com.example.golfraven" }, google: googleConfig() }, http(), crypt);
    expect(ports.ios).not.toBeNull();
    expect(ports.android).not.toBeNull();
  });

  it("iOS setBit0 writes bit0 true and bit1 back AS READ (never clears an admin's bit1) in ONE vendor call", async () => {
    const h = scriptedHttp([text(200, "")]);
    await buildIosPort({ ...appleConfig(), bundleId: "b" }, h, crypt).setBit0("TOK", { bit0: false, bit1: true, lastUpdateMonth: "2026-04" });
    expect(h.calls.map((c) => c.url.split("/").pop())).toEqual(["update_two_bits"]);
    expect(JSON.parse(h.calls[0]!.body)).toMatchObject({ device_token: "TOK", bit0: true, bit1: true });
    const h2 = scriptedHttp([text(200, "")]);
    await buildIosPort({ ...appleConfig(), bundleId: "b" }, h2, crypt).setBit0("TOK", { bit0: false, bit1: false, lastUpdateMonth: null });
    expect(JSON.parse(h2.calls[0]!.body)).toMatchObject({ bit0: true, bit1: false });
  });

  it("iOS setBit0 surfaces a vendor failure (the handler turns it into a rolled-back 503)", async () => {
    const h = scriptedHttp([text(503, "")]);
    await expect(buildIosPort({ ...appleConfig(), bundleId: "b" }, h, crypt).setBit0("TOK", { bit0: false, bit1: false, lastUpdateMonth: null })).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("Android: a Google decode rejection grades the verdict failed (not an exception)", async () => {
    const port = buildAndroidPort(googleConfig(), scriptedHttp([json(200, { access_token: "t", expires_in: 3600 }), text(400, "")]));
    const r = await port.verifyIntegrity({ integrityToken: "T", expectedRequestHash: "h", nowMs: 1 });
    expect(r).toEqual({ grade: "failed", reasons: ["token_rejected_by_google"] });
  });

  it("Android: unavailable and not-configured propagate (the handler turns them into 503)", async () => {
    const port = buildAndroidPort(googleConfig(), scriptedHttp([json(200, { access_token: "t", expires_in: 3600 }), text(500, "")]));
    await expect(port.verifyIntegrity({ integrityToken: "T", expectedRequestHash: "h", nowMs: 1 })).rejects.toBeInstanceOf(VendorUnavailableError);
  });

  it("Android: a good verdict is attested; the port has NO persistent-bit methods at all (device recall is spike A20)", async () => {
    const now = 1_780_000_000_000;
    const good = {
      requestDetails: { requestPackageName: "com.example.golfraven", requestHash: "REQHASH", timestampMillis: String(now) },
      appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", certificateSha256Digest: ["CERTDIGESTONE"] },
      deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
    };
    const port = buildAndroidPort(googleConfig(), scriptedHttp([json(200, { access_token: "t", expires_in: 3600 }), json(200, { tokenPayloadExternal: good })]));
    expect(await port.verifyIntegrity({ integrityToken: "T", expectedRequestHash: "REQHASH", nowMs: now })).toEqual({ grade: "attested" });
    // A port that could read bits it cannot write would be half a mechanism.
    expect(Object.keys(port)).toEqual(["verifyIntegrity"]);
  });

  it("Android: a wrong requestHash from Google's payload is graded failed", async () => {
    const now = 1_780_000_000_000;
    const payload = {
      requestDetails: { requestPackageName: "com.example.golfraven", requestHash: "SOMETHINGELSE", timestampMillis: String(now) },
      appIntegrity: { appRecognitionVerdict: "PLAY_RECOGNIZED", certificateSha256Digest: ["CERTDIGESTONE"] },
      deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
    };
    const port = buildAndroidPort(googleConfig(), scriptedHttp([json(200, { access_token: "t", expires_in: 3600 }), json(200, { tokenPayloadExternal: payload })]));
    const r = await port.verifyIntegrity({ integrityToken: "T", expectedRequestHash: "REQHASH", nowMs: now });
    expect(r).toMatchObject({ grade: "failed", reasons: ["request_hash_mismatch"] });
  });
});

describe("pemToDer", () => {
  it("round-trips a PKCS#8 PEM and rejects everything else", () => {
    expect(pemToDer(applePem)!.length).toBeGreaterThan(30);
    for (const bad of ["", "nope", "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----", "-----BEGIN PRIVATE KEY-----\n!!!\n-----END PRIVATE KEY-----"]) {
      expect(pemToDer(bad), bad).toBeNull();
    }
  });
});
