// supabase/tests/unit/device-platform.test.ts
//
// 0042: a device first seen by an endpoint that carries no platform (checkin-challenge, evidence) has an UNKNOWN platform until its first
// platform-bearing use, instead of a guessed 'ios'. The first such use wins; a later request naming the other platform is refused.
// (The old behaviour: an Android device first seen at checkin-challenge was labelled iOS, and rewards-activate then answered 422
// platform_mismatch to its Android activation.) Real-database coverage: supabase/tests/integration/device-platform.deno.test.ts and the
// pgTAP matrix 21_device_platform_claim.sql.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { handleTokenRequest } from "../../functions/_shared/checkin/token-handler.js";
import { HttpError } from "../../functions/_shared/http.js";
import { handlePushTokenRequest } from "../../functions/_shared/me/push-token-handler.js";
import { handleActivation } from "../../functions/_shared/rewards/activate-handler.js";
import { computeAttestKeyBinding, createAttestationVerifier } from "../../functions/_shared/rewards/app-attest-registration.js";
import { handleAttestKey } from "../../functions/_shared/rewards/attest-key-handler.js";
import { toHex } from "../../functions/_shared/rewards/binding.js";
import type { ActivationRequest } from "../../functions/_shared/rewards/request-shape.js";
import { buildAttestation, buildTestPki, genPair, toB64, type TestPki } from "./attest-test-pki.ts";
import { seedAttestDevice } from "./fake-attest-key-repo.js";
import { makeFakeRepo, makeFakeState, type FakeState } from "./fake-repo.js";
import { makeFakeAndroidPort, makeFakeIosPort, ports, rewardsState, seedReward } from "./fake-rewards-repo.js";

const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer));
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));
const APP_ID = "TEAMID1234.com.example.golfraven";
const USER = "user-a";
const OTHER = "user-b";
const DEV = "44444444-4444-4444-8444-444444444444";

let pki: TestPki;
beforeAll(async () => {
  pki = await buildTestPki({ nowMs: Date.now() });
});

function world(): FakeState {
  const state = makeFakeState({ now: new Date() });
  state.devices.clear();
  return state;
}
const platformOf = (state: FakeState, id = DEV) => rewardsState(state).deviceAttest.get(id)?.platform;
async function firstSeenAtChallenge(state: FakeState, uid = USER, deviceId = DEV) {
  const [c] = await handleChallengeRequest({ deviceId }, makeFakeRepo(state, uid), randomBytes, digestHex);
  return c!;
}
const status = async (p: Promise<unknown>): Promise<string | null> => {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return `${e.status} ${e.code}`;
    throw e;
  }
};
const noneReq = (platform: "ios" | "android", deviceId = DEV): ActivationRequest => ({ deviceId, platform, attestation: { kind: "none", hardwareSupportsAttestation: false } });
// every activation uses its OWN earned reward: a reward already held (or active on this device) short-circuits before the platform is looked at
let rewardSeq = 0;
const activate = (state: FakeState, req: ActivationRequest, uid = USER) => {
  const id = `aaaaaaaa-0000-4000-8000-${String(++rewardSeq).padStart(12, "0")}`;
  seedReward(state, { id, userId: uid, kind: "offer_code" });
  return handleActivation(id, req, makeFakeRepo(state, uid), { ports: ports({ ios: makeFakeIosPort(), android: makeFakeAndroidPort() }), sha256 });
};

describe("a device first seen without a platform is UNKNOWN, not 'ios'", () => {
  it("checkin-challenge leaves the platform unknown (it used to store 'ios' for an Android device too)", async () => {
    const state = world();
    await firstSeenAtChallenge(state);
    expect(platformOf(state)).toBeNull();
  });

  it("ensureOwn with a platform stores it; ensureOwn with none stores nothing", async () => {
    const state = world();
    const repo = makeFakeRepo(state, USER);
    await repo.device.ensureOwn("dev-android", "android");
    await repo.device.ensureOwn("dev-unknown", null);
    expect(platformOf(state, "dev-android")).toBe("android");
    expect(platformOf(state, "dev-unknown")).toBeNull();
  });
});

describe("reward activation: the first platform-bearing use wins", () => {
  it("an Android device first seen at checkin-challenge, then activated on Android, is NOT refused, and is now Android", async () => {
    const state = world();
    await firstSeenAtChallenge(state);
    expect(await status(activate(state, noneReq("android")))).toBeNull();
    expect(platformOf(state)).toBe("android");
  });

  it("...and with a real Android attestation too (a live challenge, the integrity port)", async () => {
    const state = world();
    const first = await firstSeenAtChallenge(state);
    void first;
    const c = await firstSeenAtChallenge(state);
    const req: ActivationRequest = { deviceId: DEV, platform: "android", challengeId: c.id, nonce: c.nonce, attestation: { kind: "android", integrityToken: "TOKEN.abc" } };
    expect(await status(activate(state, req))).toBeNull();
    expect(platformOf(state)).toBe("android");
  });

  it("an unknown device activated as iOS becomes iOS; a later Android activation is refused (first wins)", async () => {
    const state = world();
    await firstSeenAtChallenge(state);
    expect(await status(activate(state, noneReq("ios")))).toBeNull();
    expect(platformOf(state)).toBe("ios");
    expect(await status(activate(state, noneReq("android")))).toBe("422 platform_mismatch");
    expect(platformOf(state)).toBe("ios");
  });

  it("an Android-first device stays Android: an iOS activation is refused", async () => {
    const state = world();
    await firstSeenAtChallenge(state);
    await activate(state, noneReq("android"));
    expect(await status(activate(state, noneReq("ios")))).toBe("422 platform_mismatch");
    expect(platformOf(state)).toBe("android");
  });

  it("a refused activation labels nothing it was refused on (the platform on record is unchanged)", async () => {
    const state = world();
    const repo = makeFakeRepo(state, USER);
    await repo.device.ensureOwn(DEV, "ios");
    expect(await status(activate(state, noneReq("android")))).toBe("422 platform_mismatch");
    expect(platformOf(state)).toBe("ios");
  });

  it("another account's unknown device cannot be claimed (the repo is actor-scoped: null, nothing set)", async () => {
    const state = world();
    await firstSeenAtChallenge(state, OTHER);
    expect(await makeFakeRepo(state, USER).device.claimPlatform(DEV, "android")).toBeNull();
    expect(platformOf(state)).toBeNull();
  });
});

describe("App Attest key registration", () => {
  const verifier = () => createAttestationVerifier({ appId: APP_ID, environment: "production", trustAnchorDer: pki.rootDer }, { sha256 });
  async function registrationRequest(state: FakeState, platform: "ios" | "android" | null) {
    const c = await firstSeenAtChallenge(state);
    seedAttestDevice(state, { id: DEV, userId: USER, platform });
    const leaf = await genPair("P-256");
    const keyId = toB64(await sha256(leaf.point));
    const clientDataHash = await computeAttestKeyBinding(sha256, { challengeId: c.id, deviceId: DEV, keyId, nonce: c.nonce });
    const built = await buildAttestation({ pki, appId: APP_ID, environment: "production", clientDataHash, leaf });
    return { deviceId: DEV, challengeId: c.id, nonce: c.nonce, keyId, attestation: built.attestationB64 };
  }

  it("a device first seen at checkin-challenge (platform unknown) registers a key, and is thereby iOS: a later Android activation is refused", async () => {
    const state = world();
    const req = await registrationRequest(state, null);
    const out = await handleAttestKey(req, makeFakeRepo(state, USER), { verifier: verifier(), sha256 });
    expect(out.ok).toBe(true);
    expect(platformOf(state)).toBe("ios");
    expect(await status(activate(state, noneReq("android")))).toBe("422 platform_mismatch");
  });

  it("a FAILED verification labels nothing: the device stays unknown and can still be Android", async () => {
    const state = world();
    const req = await registrationRequest(state, null);
    const out = await handleAttestKey({ ...req, attestation: req.attestation.slice(0, -8) + "AAAAAAAA" }, makeFakeRepo(state, USER), { verifier: verifier(), sha256 });
    expect(out.ok).toBe(false);
    expect(platformOf(state)).toBeNull();
    expect(await status(activate(state, noneReq("android")))).toBeNull();
  });

  it("a device already known as Android is still refused key registration", async () => {
    const state = world();
    const req = await registrationRequest(state, "android");
    expect(await status(handleAttestKey(req, makeFakeRepo(state, USER), { verifier: verifier(), sha256 }))).toBe("422 platform_mismatch");
  });

  it("a device first seen as iOS through attest-key, then activated as Android, is still refused", async () => {
    const state = world();
    const req = await registrationRequest(state, "ios");
    await handleAttestKey(req, makeFakeRepo(state, USER), { verifier: verifier(), sha256 });
    expect(await status(activate(state, noneReq("android")))).toBe("422 platform_mismatch");
  });
});

describe("the other platform-bearing uses", () => {
  it("a push-token registration that names a platform labels an unknown device; one that names none does not; a set platform is kept", async () => {
    const state = world();
    await firstSeenAtChallenge(state);
    await handlePushTokenRequest({ deviceId: DEV, expoToken: "ExponentPushToken[a]" }, makeFakeRepo(state, USER));
    expect(platformOf(state)).toBeNull();
    await handlePushTokenRequest({ deviceId: DEV, expoToken: "ExponentPushToken[a]", platform: "android" }, makeFakeRepo(state, USER));
    expect(platformOf(state)).toBe("android");
    await handlePushTokenRequest({ deviceId: DEV, expoToken: "ExponentPushToken[a]", platform: "ios" }, makeFakeRepo(state, USER));
    expect(platformOf(state)).toBe("android");
  });

  it("a check-in token whose Android attestation VERIFIED labels an unknown device Android; a failed one labels nothing", async () => {
    const state = world();
    const c = await firstSeenAtChallenge(state);
    const body = { challengeId: c.id, nonce: c.nonce, hardwareSupportsAttestation: true, attestation: { platform: "android" as const, integrityToken: "TOKEN.abc" } };
    const failing = makeFakeAndroidPort({ result: () => ({ grade: "failed", reasons: ["request_hash_mismatch"] }) });
    await handleTokenRequest(body, makeFakeRepo(state, USER), digestHex, { userId: USER, ports: { ios: null, android: failing }, sha256 });
    expect(platformOf(state)).toBeNull();
    const c2 = await firstSeenAtChallenge(state);
    const ok = makeFakeAndroidPort();
    const out = await handleTokenRequest({ ...body, challengeId: c2.id, nonce: c2.nonce }, makeFakeRepo(state, USER), digestHex, { userId: USER, ports: { ios: null, android: ok }, sha256 });
    expect(out.attestationGrade).toBe("attested");
    expect(platformOf(state)).toBe("android");
    expect(await status(activate(state, noneReq("android")))).toBeNull();
    expect(await status(activate(state, noneReq("ios")))).toBe("422 platform_mismatch");
  });
});

describe("the real Repo (privileged.ts) never guesses a platform", () => {
  const src = readFileSync(join(import.meta.dirname, "..", "..", "functions", "_shared", "privileged.ts"), "utf8");
  it("ensureOwn inserts the platform it was given (NULL when none) and never defaults to 'ios'", () => {
    expect(src).toMatch(/insert into app\.device \(id, user_id, platform\) values \(\$\{id\}, \$\{uid\}, \$\{platform\}\)/);
    expect(src).not.toMatch(/platform \?\? "ios"/);
  });
  it("the claim goes through the definer, never a direct UPDATE of platform", () => {
    expect(src).toMatch(/private\.claim_device_platform_for_actor/);
    expect(src).not.toMatch(/update app\.device set platform/i);
  });
});
