// supabase/tests/unit/attest-key-handler.test.ts
//
// `POST /v1/devices/attest-key` — the pure handler (attest-key-handler.ts) over the in-memory fake repo, with the
// REAL registration verifier and synthetic attestations (attest-test-pki.ts). What this proves: the order of the
// checks, the challenge discipline (live, single-use, device-bound, spent by a FAILED attempt too), ownership with
// no existence oracle, re-registration, and fail-closed configuration. Whether the SQL does the same is the Deno
// integration suite's job (attest-key.deno.test.ts runs these scenarios against real Postgres).
//
// Self-consistency only: no real iPhone attestation has been seen (`[unverified]`).

import { beforeAll, describe, expect, it } from "vitest";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { HttpError } from "../../functions/_shared/http.js";
import { computeAttestKeyBinding, createAttestationVerifier } from "../../functions/_shared/rewards/app-attest-registration.js";
import { RATE_LIMIT_PER_DEVICE_DAY, RATE_LIMIT_PER_USER_HOUR, enforceAttestKeyRateLimits, handleAttestKey, type AttestKeyDeps } from "../../functions/_shared/rewards/attest-key-handler.js";
import { parseAttestKeyBody, type AttestKeyRequest } from "../../functions/_shared/rewards/attest-key-request.js";
import { toHex } from "../../functions/_shared/rewards/binding.js";
import { buildAttestation, buildTestPki, genPair, toB64, type TestPki } from "./attest-test-pki.ts";
import { fakeAttestDevices, seedAttestDevice } from "./fake-attest-key-repo.ts";
import { makeFakeRepo, makeFakeState, type FakeState } from "./fake-repo.ts";

const sha256 = async (b: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", b.slice().buffer));
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));
const APP_ID = "TEAMID1234.com.example.golfraven";
const USER = "user-a";
const OTHER = "user-b";
const DEV = "11111111-1111-4111-8111-111111111111";
const DEV2 = "22222222-2222-4222-8222-222222222222";
const FOREIGN = "33333333-3333-4333-8333-333333333333";

let pki: TestPki;
beforeAll(async () => {
  pki = await buildTestPki({ nowMs: Date.now() });
});

const verifier = () => createAttestationVerifier({ appId: APP_ID, environment: "production", trustAnchorDer: pki.rootDer }, { sha256 });
const deps = (over: Partial<AttestKeyDeps> = {}): AttestKeyDeps => ({ verifier: verifier(), sha256, ...over });

function world() {
  const state: FakeState = makeFakeState({ now: new Date() });
  state.devices.clear();
  return state;
}
const repoFor = (state: FakeState, uid = USER) => makeFakeRepo(state, uid);

/** A live challenge for (uid, device), issued through the real challenge handler. */
async function issue(state: FakeState, uid: string, deviceId: string, opts: { prefetch?: boolean } = {}) {
  const repo = repoFor(state, uid);
  const [c] = await handleChallengeRequest({ deviceId, ...(opts.prefetch ? { prefetchCount: 1 } : {}) }, repo, randomBytes, digestHex);
  return c!;
}

interface Request {
  req: AttestKeyRequest;
  keyId: string;
  leaf: Awaited<ReturnType<typeof genPair>>;
}

/** A well-formed registration request: an attestation bound to (challenge, device, key). */
async function request(c: { id: string; nonce: string }, deviceId: string, over: { bindDevice?: string; bindChallenge?: string; bindNonce?: string } = {}): Promise<Request> {
  const leaf = await genPair("P-256");
  const keyId = toB64(await sha256(leaf.point));
    const clientDataHash = await computeAttestKeyBinding(sha256, { challengeId: over.bindChallenge ?? c.id, deviceId: over.bindDevice ?? deviceId, keyId, nonce: over.bindNonce ?? c.nonce });
  const built = await buildAttestation({ pki, appId: APP_ID, environment: "production", clientDataHash, leaf });
  return { req: { deviceId, challengeId: c.id, nonce: c.nonce, keyId, attestation: built.attestationB64 }, keyId, leaf };
}

async function expectHttp(p: Promise<unknown>, status: number, code?: string) {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(HttpError);
    expect((e as HttpError).status).toBe(status);
    if (code) expect((e as HttpError).code).toBe(code);
    return;
  }
  throw new Error(`expected HttpError ${status}`);
}

describe("devices-attest-key handler: registration", () => {
  it("registers the attested key on the caller's own device (201) and spends the challenge", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const c = await issue(state, USER, DEV);
    const { req, keyId, leaf } = await request(c, DEV);
    const out = await handleAttestKey(req, repoFor(state), deps());
    expect(out).toEqual({ ok: true, status: 201, body: { deviceId: DEV, keyId, replaced: false } });
    const d = fakeAttestDevices(state).get(DEV)!;
    expect(d.keyId).toBe(keyId);
    expect(Array.from(d.publicKey!)).toEqual(Array.from(leaf.point));
    expect(d.registeredAt).not.toBeNull();
    expect(state.challenges.get(c.id)!.usedAt).not.toBeNull();
  });

  it("a reinstall: a NEW key replaces the old one on the same device (200, replaced), counter back to 0, old key retired", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const first = await request(await issue(state, USER, DEV), DEV);
    await handleAttestKey(first.req, repoFor(state), deps());
    fakeAttestDevices(state).get(DEV)!.counter = 40;
    const second = await request(await issue(state, USER, DEV), DEV);
    const out = await handleAttestKey(second.req, repoFor(state), deps());
    expect(out).toEqual({ ok: true, status: 200, body: { deviceId: DEV, keyId: second.keyId, replaced: true } });
    const d = fakeAttestDevices(state).get(DEV)!;
    expect(d.keyId).toBe(second.keyId);
    expect(d.counter).toBe(0);
    expect(d.retired.length).toBe(1);
  });

  it("the same key again is a 409 and does NOT spend a challenge", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const first = await request(await issue(state, USER, DEV), DEV);
    await handleAttestKey(first.req, repoFor(state), deps());
    const c2 = await issue(state, USER, DEV);
    await expectHttp(handleAttestKey({ ...first.req, challengeId: c2.id, nonce: c2.nonce }, repoFor(state), deps()), 409, "key_already_registered");
    expect(state.challenges.get(c2.id)!.usedAt).toBeNull();
  });

  it("a key that was retired cannot come back (409), and the challenge rolls back with the request", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const a = await request(await issue(state, USER, DEV), DEV);
    await handleAttestKey(a.req, repoFor(state), deps());
    const b = await request(await issue(state, USER, DEV), DEV);
    await handleAttestKey(b.req, repoFor(state), deps()); // a is now retired
    // Re-attest key `a`'s leaf under a fresh challenge (what a replay of an old key would need).
    const c = await issue(state, USER, DEV);
    const clientDataHash = await computeAttestKeyBinding(sha256, { challengeId: c.id, deviceId: DEV, keyId: a.keyId, nonce: c.nonce });
    const built = await buildAttestation({ pki, appId: APP_ID, environment: "production", clientDataHash, leaf: a.leaf });
    await expectHttp(handleAttestKey({ deviceId: DEV, challengeId: c.id, nonce: c.nonce, keyId: a.keyId, attestation: built.attestationB64 }, repoFor(state), deps()), 409, "key_previously_retired");
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBe(b.keyId);
  });
});

describe("devices-attest-key handler: MUST-FAIL", () => {
  it("unconfigured (no verifier) is a 503 before anything is read or written", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const c = await issue(state, USER, DEV);
    const { req } = await request(c, DEV);
    await expectHttp(handleAttestKey(req, repoFor(state), deps({ verifier: null })), 503, "attestation_not_configured");
    expect(state.challenges.get(c.id)!.usedAt).toBeNull();
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBeNull();
  });

  it("a failed attestation is returned (not thrown), spends the challenge, registers nothing, and the challenge cannot be tried again", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const c = await issue(state, USER, DEV);
    // The attestation was made for a DIFFERENT challenge id than the one the server consumes.
    const bad = await request(c, DEV, { bindChallenge: "99999999-9999-4999-8999-999999999999" });
    const out = await handleAttestKey(bad.req, repoFor(state), deps());
    expect(out).toEqual({ ok: false, status: 422, code: "attestation_rejected", message: "the attestation could not be verified" });
    expect(state.challenges.get(c.id)!.usedAt).not.toBeNull();
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBeNull();
    // A second guess on the same challenge: the challenge is spent.
    const good = await request(c, DEV);
    await expectHttp(handleAttestKey(good.req, repoFor(state), deps()), 422, "challenge_not_consumable");
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBeNull();
  });

  it("a replayed challenge is refused after a successful registration", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const c = await issue(state, USER, DEV);
    const first = await request(c, DEV);
    await handleAttestKey(first.req, repoFor(state), deps());
    const second = await request(c, DEV); // a different key, the SAME (now spent) challenge
    await expectHttp(handleAttestKey(second.req, repoFor(state), deps()), 422, "challenge_not_consumable");
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBe(first.keyId);
  });

  it("another user's device and a nonexistent device are the same 422 (no existence oracle), and nothing is written", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    seedAttestDevice(state, { id: FOREIGN, userId: OTHER });
    const cMine = await issue(state, USER, DEV);
    const foreign = await request(cMine, FOREIGN);
    await expectHttp(handleAttestKey(foreign.req, repoFor(state, USER), deps()), 422, "challenge_not_consumable");
    const nonexistent = await request(cMine, "44444444-4444-4444-8444-444444444444");
    await expectHttp(handleAttestKey(nonexistent.req, repoFor(state, USER), deps()), 422, "challenge_not_consumable");
    expect(fakeAttestDevices(state).get(FOREIGN)!.keyId).toBeNull();
    expect(state.challenges.get(cMine.id)!.usedAt).toBeNull();
  });

  it("another user's CHALLENGE is refused (it is not visible to the caller)", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    seedAttestDevice(state, { id: FOREIGN, userId: OTHER });
    const theirs = await issue(state, OTHER, FOREIGN);
    const attempt = await request(theirs, DEV);
    await expectHttp(handleAttestKey(attempt.req, repoFor(state, USER), deps()), 422, "challenge_not_consumable");
    expect(state.challenges.get(theirs.id)!.usedAt).toBeNull();
  });

  it("a challenge issued to another device of the same user is refused", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    seedAttestDevice(state, { id: DEV2, userId: USER });
    const forDev2 = await issue(state, USER, DEV2);
    const attempt = await request(forDev2, DEV);
    await expectHttp(handleAttestKey(attempt.req, repoFor(state), deps()), 422, "challenge_not_consumable");
    expect(state.challenges.get(forDev2.id)!.usedAt).toBeNull();
  });

  it("a prefetched challenge, an expired challenge and a wrong nonce are refused", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    const pre = await issue(state, USER, DEV, { prefetch: true });
    await expectHttp(handleAttestKey((await request(pre, DEV)).req, repoFor(state), deps()), 422, "challenge_not_consumable");
    const live = await issue(state, USER, DEV);
    state.challenges.get(live.id)!.expiresAt = new Date(state.now.getTime() - 1000).toISOString();
    await expectHttp(handleAttestKey((await request(live, DEV)).req, repoFor(state), deps()), 422, "challenge_not_consumable");
    const live2 = await issue(state, USER, DEV);
    const wrongNonce = await request(live2, DEV);
    const tampered = { ...wrongNonce.req, nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" };
    await expectHttp(handleAttestKey(tampered, repoFor(state), deps()), 422, "challenge_not_consumable");
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBeNull();
  });

  it("an Android device cannot register an App Attest key (422 platform_mismatch)", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER, platform: "android" });
    const c = await issue(state, USER, DEV);
    await expectHttp(handleAttestKey((await request(c, DEV)).req, repoFor(state), deps()), 422, "platform_mismatch");
    expect(state.challenges.get(c.id)!.usedAt).toBeNull();
  });

  it("an attestation bound to another device, a tampered key id and a wrong-environment attestation are all rejected after spending the challenge", async () => {
    const state = world();
    seedAttestDevice(state, { id: DEV, userId: USER });
    seedAttestDevice(state, { id: DEV2, userId: USER });
    // Bound to DEV2's id, submitted for DEV.
    const c1 = await issue(state, USER, DEV);
    expect((await handleAttestKey((await request(c1, DEV, { bindDevice: DEV2 })).req, repoFor(state), deps())).ok).toBe(false);
    // The client names a different key id than the one it attested.
    const c2 = await issue(state, USER, DEV);
    const r2 = await request(c2, DEV);
    expect((await handleAttestKey({ ...r2.req, keyId: toB64(new Uint8Array(32).fill(1)) }, repoFor(state), deps())).ok).toBe(false);
    // A development attestation against a production deployment.
    const c3 = await issue(state, USER, DEV);
    const leaf = await genPair("P-256");
    const keyId = toB64(await sha256(leaf.point));
    const cdh = await computeAttestKeyBinding(sha256, { challengeId: c3.id, deviceId: DEV, keyId, nonce: c3.nonce });
    const built = await buildAttestation({ pki, appId: APP_ID, environment: "development", clientDataHash: cdh, leaf });
    expect((await handleAttestKey({ deviceId: DEV, challengeId: c3.id, nonce: c3.nonce, keyId, attestation: built.attestationB64 }, repoFor(state), deps())).ok).toBe(false);
    expect(fakeAttestDevices(state).get(DEV)!.keyId).toBeNull();
    for (const id of [c1.id, c2.id, c3.id]) expect(state.challenges.get(id)!.usedAt).not.toBeNull();
  });
});

describe("devices-attest-key: rate limits and the request shape", () => {
  it("hits the user bucket first and short-circuits; then the device bucket", async () => {
    const calls: Array<[string, number, number]> = [];
    const ok = await enforceAttestKeyRateLimits(async (k, w, m) => (calls.push([k, w, m]), { ok: true }), DEV);
    expect(ok).toEqual({ ok: true });
    expect(calls).toEqual([
      ["devices-attest-key:user", 3600, RATE_LIMIT_PER_USER_HOUR],
      [`devices-attest-key:device:${DEV}`, 86_400, RATE_LIMIT_PER_DEVICE_DAY],
    ]);
    const blockedUser = await enforceAttestKeyRateLimits(async (k) => ({ ok: !k.endsWith(":user"), retryAfterSeconds: 9 }), DEV);
    expect(blockedUser).toEqual({ ok: false, retryAfterSeconds: 9 });
    let deviceHits = 0;
    const blockedUserFirst = await enforceAttestKeyRateLimits(async (k) => {
      if (k.includes(":device:")) deviceHits++;
      return { ok: false, retryAfterSeconds: 1 };
    }, DEV);
    expect(blockedUserFirst.ok).toBe(false);
    expect(deviceHits).toBe(0);
  });

  const good = { deviceId: DEV.toUpperCase(), challengeId: "55555555-5555-4555-8555-555555555555", nonce: "abcDEF_-", keyId: toB64(new Uint8Array(32).fill(2)), attestation: "AAECAw==" };
  it("accepts the five fields and lowercases the UUIDs", () => {
    const r = parseAttestKeyBody(good);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.value.deviceId).toBe(DEV);
  });
  it("rejects unknown fields, a missing field, wrong shapes and an oversize attestation", () => {
    const bad = (v: unknown) => expect(parseAttestKeyBody(v).ok).toBe(false);
    bad(null);
    bad([]);
    bad({ ...good, extra: 1 });
    for (const k of Object.keys(good)) bad({ ...good, [k]: undefined });
    bad({ ...good, deviceId: "not-a-uuid" });
    bad({ ...good, challengeId: 5 });
    bad({ ...good, nonce: "has+plus" });
    bad({ ...good, nonce: "padded==" });
    bad({ ...good, keyId: good.keyId.replace("=", "") });
    bad({ ...good, keyId: "A".repeat(44) });
    bad({ ...good, attestation: "" });
    bad({ ...good, attestation: "***" });
    bad({ ...good, attestation: "A".repeat(24 * 1024 + 1) });
  });
});
