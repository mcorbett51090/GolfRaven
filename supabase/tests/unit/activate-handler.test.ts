// supabase/tests/unit/activate-handler.test.ts
//
// rewards/activate-handler.ts against the in-memory fake Repo (fake-repo.ts +
// fake-rewards-repo.ts) and scripted fake vendor ports. Real-database coverage
// of the SAME scenarios lives in supabase/tests/integration/
// rewards-activate.deno.test.ts.
//
// P3 acceptance test (9) — every §7.5 DeviceCheck/activation fixture — is mapped
// test-by-test in the section headed "AT (9)" below (and again, against a real
// Postgres, in the Deno suite). Live vendor verification is NOT exercised; the
// fake ports are scripts.

import { describe, expect, it } from "vitest";
import { enforceActivationRateLimits, handleActivation, type ActivationDeps } from "../../functions/_shared/rewards/activate-handler.js";
import { computeRequestBinding, toBase64Url, toHex } from "../../functions/_shared/rewards/binding.js";
import { verifyAppAttestAssertion, verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.js";
import type { ActivationRequest } from "../../functions/_shared/rewards/request-shape.js";
import { VendorNotConfiguredError, VendorUnavailableError, VendorRejectedError, type IosPort } from "../../functions/_shared/rewards/types.js";
import { HttpError } from "../../functions/_shared/http.js";
import { fakeHitRateLimitForActor, makeFakeRepo, makeFakeState, type FakeState } from "./fake-repo.js";
import { fakeResolveHeld, makeFakeAndroidPort, makeFakeIosPort, openSignal, ports, rewardsState, seedDevice, seedReward, type FakeAndroidPort, type FakeIosPort } from "./fake-rewards-repo.js";
import { buildAssertion, generateP256, sha256, toB64 } from "./rewards-test-crypto.js";

const USER_A = "user-a";
const USER_B = "user-b";
const D1 = "11111111-1111-4111-8111-111111111111"; // seeded by makeFakeState for user-a
const D2 = "22222222-2222-4222-8222-222222222222";
const R1 = "aaaaaaaa-0000-4000-8000-000000000001";
const R2 = "aaaaaaaa-0000-4000-8000-000000000002";
const R3 = "aaaaaaaa-0000-4000-8000-000000000003";
const NOW_ISO = "2026-06-01T12:00:00.000Z";

function newWorld() {
  const state = makeFakeState();
  seedDevice(state, { id: D1, userId: USER_A, platform: "ios" });
  return state;
}

/** Issues a live challenge for `deviceId` (as POST /v1/checkin/challenge would)
 * and returns the request fields that name it. */
async function issueChallenge(state: FakeState, uid: string, deviceId: string, kind: "live" | "prefetched" = "live", ttlMs = 120_000) {
  const nonce = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff);
  const nonceHash = toHex(await sha256(nonce));
  const repo = makeFakeRepo(state, uid);
  const inserted = await repo.challenge.insert({ deviceId, facilityId: null, nonceHash, kind, expiresAt: new Date(state.now.getTime() + ttlMs).toISOString() });
  return { challengeId: inserted.id, nonce: toBase64Url(nonce), nonceBytes: nonce };
}

async function iosRequest(state: FakeState, over: { deviceId?: string; uid?: string; challenge?: { challengeId: string; nonce: string } } = {}): Promise<ActivationRequest> {
  const deviceId = over.deviceId ?? D1;
  const ch = over.challenge ?? (await issueChallenge(state, over.uid ?? USER_A, deviceId));
  return {
    deviceId,
    platform: "ios",
    challengeId: ch.challengeId,
    nonce: ch.nonce,
    attestation: { kind: "ios", keyId: "S0VZ", assertion: "QVNTRVJUSU9O", deviceCheckToken: "REVWSUNFVE9LRU4=" },
  };
}

function deps(p: Parameters<typeof ports>[0]): ActivationDeps {
  return { ports: ports(p), sha256 };
}

async function activate(state: FakeState, rewardId: string, req: ActivationRequest, d: ActivationDeps, uid = USER_A) {
  return handleActivation(rewardId, req, makeFakeRepo(state, uid), d);
}
const status = async (p: Promise<unknown>) => {
  try {
    await p;
    return 200;
  } catch (e) {
    if (e instanceof HttpError) return e.status;
    throw e;
  }
};
const codeOf = async (p: Promise<unknown>) => {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return e.code;
    throw e;
  }
};
const signalKinds = (state: FakeState, uid = USER_A) => rewardsState(state).signals.filter((s) => s.userId === uid).map((s) => s.kind);
const ledgerFor = (state: FakeState, rewardId: string) => rewardsState(state).ledger.filter((l) => l.rewardId === rewardId);
const CLEAR = { bit0: false, bit1: false, lastUpdateMonth: null };
const BIT0 = { bit0: true, bit1: false, lastUpdateMonth: "2026-02" };
const BIT1 = { bit0: false, bit1: true, lastUpdateMonth: "2026-04" };
const BOTH = { bit0: true, bit1: true, lastUpdateMonth: "2026-04" };

/** A prior, already-activated reward for `uid` on `deviceId` — what makes an
 * account a "repeat user" (table row 5). */
function priorReward(state: FakeState, uid: string, deviceId: string, kind: "offer_code" | "entitlement" = "offer_code") {
  const id = `99999999-0000-4000-8000-0000000000${state.nextId++}`.slice(0, 36);
  seedReward(state, { id, userId: uid, kind, state: kind === "offer_code" ? "issued" : "redeemable", activatedDeviceId: deviceId, activatedAt: NOW_ISO });
  rewardsState(state).ledger.push({ deviceId, userId: uid, kind, rewardId: id, tokenHash: "h" });
  return id;
}

// ===========================================================================
// AT (9): every §7.5 DeviceCheck / activation fixture
// ===========================================================================
describe("AT (9): §7.5 golden fixtures", () => {
  it("same account, second offer on the same device -> issued (row 5: bit0 set, prior reward)", async () => {
    const state = newWorld();
    priorReward(state, USER_A, D1);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ios = makeFakeIosPort({ bits: BIT0 });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(out).toMatchObject({ id: R1, kind: "offer_code", state: "issued", held: false, replay: false });
    expect(signalKinds(state)).toEqual([]);
    expect(ios.calls.setBit0).toBe(0); // bit0 is already set
    expect(ledgerFor(state, R1)).toHaveLength(1);
  });

  it("same account, special marker on a second trail -> issued (an entitlement becomes redeemable)", async () => {
    const state = newWorld();
    priorReward(state, USER_A, D1, "entitlement");
    seedReward(state, { id: R2, userId: USER_A, kind: "entitlement" });
    const ios = makeFakeIosPort({ bits: BIT0 });
    const out = await activate(state, R2, await iosRequest(state), deps({ ios }));
    expect(out).toMatchObject({ kind: "entitlement", state: "redeemable", held: false });
    expect(signalKinds(state)).toEqual([]);
  });

  it("same account after REINSTALL -> issued (a new install has a new device id and App Attest key; bit0 persists; the ledger remembers the account)", async () => {
    const state = newWorld();
    priorReward(state, USER_A, D1); // the reward received on the OLD install
    seedDevice(state, { id: D2, userId: USER_A, platform: "ios" }); // the reinstall
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ios = makeFakeIosPort({ bits: BIT0 }); // same hardware: DeviceCheck bit0 survived
    const out = await activate(state, R1, await iosRequest(state, { deviceId: D2 }), deps({ ios }));
    expect(out.state).toBe("issued");
    expect(signalKinds(state)).toEqual([]);
    expect(ledgerFor(state, R1)[0]?.deviceId).toBe(D2);
  });

  it("the account's OWN already-issued reward re-activated on a reinstalled device is itself the prior reward -> issued (a single-reward user can reinstall)", async () => {
    const state = newWorld();
    seedDevice(state, { id: D2, userId: USER_A, platform: "ios" });
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    // first activation, on the OLD install (clean device: sets bit0)
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }));
    // reinstall: same hardware, so bit0 persists; the only reward is the one being re-run
    const ios = makeFakeIosPort({ bits: BIT0 });
    const out = await activate(state, R1, await iosRequest(state, { deviceId: D2 }), deps({ ios }));
    expect(out.state).toBe("issued");
    expect(signalKinds(state)).toEqual([]);
  });

  it("a new account on a bit0 device -> held_review (not refused) + fraud_signal(multi_account_device)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" }); // no prior reward
    const ios = makeFakeIosPort({ bits: BIT0 });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(out).toMatchObject({ state: "held_review", held: true });
    expect(signalKinds(state)).toEqual(["multi_account_device"]);
    expect(ledgerFor(state, R1)).toHaveLength(0); // nothing was issued
  });

  it("ANY account on a bit1 device -> held_review + a high-priority fraud_signal (even a repeat user)", async () => {
    for (const hasPrior of [false, true]) {
      const state = newWorld();
      if (hasPrior) priorReward(state, USER_A, D1);
      seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
      const out = await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
      expect(out.state, `prior=${hasPrior}`).toBe("held_review");
      const sig = rewardsState(state).signals.find((s) => s.kind === "flagged_device_activation");
      expect(sig?.detail).toMatchObject({ priority: "high", rewardId: R1, deviceCheckLastUpdateMonth: "2026-04" });
    }
    // and with bit0 also set
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BOTH }) }))).state).toBe("held_review");
  });

  it("a reward earned by a server-side re-score reads NO bits until activation", async () => {
    const state = newWorld();
    const ios = makeFakeIosPort({ bits: CLEAR });
    // Earning (anything that creates a reward) never touches a vendor: the ports exist
    // only inside handleActivation's deps. A reward just sits `earned`...
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect(ios.calls).toEqual({ verify: 0, readBits: 0, setBit0: 0 });
    // ...a request that is rejected before the table runs reads none either...
    expect(await status(activate(state, "aaaaaaaa-0000-4000-8000-00000000dead", await iosRequest(state), deps({ ios })))).toBe(404);
    expect(ios.calls).toEqual({ verify: 0, readBits: 0, setBit0: 0 });
    // ...and the table's bits are read exactly once, by the activation itself.
    await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(ios.calls.readBits).toBe(1);
  });

  it("a redemption QR from the account's SECOND device re-runs the table -> issued", async () => {
    const state = newWorld();
    seedDevice(state, { id: D2, userId: USER_A, platform: "ios" });
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ios1 = makeFakeIosPort({ bits: CLEAR });
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: ios1 }))).state).toBe("issued");
    expect(ios1.calls.setBit0).toBe(1); // first reward on a clean device sets bit0
    expect(ios1.lastSetBit0Known).toEqual(CLEAR); // ...handed the reading the table just ran on (so bit1 is written back unchanged)

    const ios2 = makeFakeIosPort({ bits: CLEAR }); // device 2 is a clean device too
    const out = await activate(state, R1, await iosRequest(state, { deviceId: D2 }), deps({ ios: ios2 }));
    expect(out).toMatchObject({ state: "issued", replay: false }); // not a no-op: the table RAN
    expect(ios2.calls.readBits).toBe(1);
    expect(ledgerFor(state, R1).map((l) => l.deviceId).sort()).toEqual([D1, D2].sort());
    expect(rewardsState(state).rewards.get(R1)?.activatedDeviceId).toBe(D1); // provenance of the FIRST activation is kept
  });

  it("...and a second device that is FLAGGED sends the already-issued reward back to held_review", async () => {
    const state = newWorld();
    seedDevice(state, { id: D2, userId: USER_A, platform: "ios" });
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }));
    const out = await activate(state, R1, await iosRequest(state, { deviceId: D2 }), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(out.state).toBe("held_review");
    expect(signalKinds(state)).toContain("flagged_device_activation");
  });

  it("a held code whose offer ends during review is honoured, with its budget reserved (the reservation is taken at hold time)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", faceValue: 15, expiresAt: "2026-07-01T00:00:00.000Z" });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(out.state).toBe("held_review");
    const code = rewardsState(state).rewards.get(R1)!;
    expect(code.reservedAmount).toBe(15);
    expect(rewardsState(state).budgetReserved).toBe(15);
    expect(code.expiryPausedAt).not.toBeNull(); // the expiry clock is paused while held
    // (approval after the offer ended, and the validity restarting at approval, are DB behaviour:
    //  asserted against real SQL in rewards-activate.deno.test.ts and matrix/15_rewards_activation.sql)
  });

  it("precedence (G3-08): an unattestable-resting reward activated on a CLEAN device is held, not activated", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", restsOnUnattestable: true });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }));
    expect(out.state).toBe("held_review");
    expect(signalKinds(state)).toEqual([]);
  });

  it("precedence: a reward backed by a held play (the scorer's unattestable/quarantine hold) is held too", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", playHeld: true });
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }))).state).toBe("held_review");
  });

  it("precedence: an account with an OPEN attestation_failed signal has every activation held (even a repeat user on a bit0 device)", async () => {
    const state = newWorld();
    priorReward(state, USER_A, D1);
    openSignal(state, USER_A, "attestation_failed");
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT0 }) }))).state).toBe("held_review");
  });

  it("a CLEARED attestation_failed signal no longer holds the account", async () => {
    const state = newWorld();
    openSignal(state, USER_A, "attestation_failed");
    rewardsState(state).signals[0]!.cleared = true;
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }))).state).toBe("issued");
  });

  it("an unattestable DEVICE (no token, hardware cannot attest) routes the reward to held_review", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const req: ActivationRequest = { deviceId: D1, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } };
    const out = await activate(state, R1, req, deps({}));
    expect(out.state).toBe("held_review");
    expect(signalKinds(state)).toEqual([]); // unattestable is routing, not an accusation
  });

  it("a FAILED verdict raises fraud_signal(attestation_failed) AT INTAKE and the reward is held", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ios = makeFakeIosPort({ assertion: () => ({ ok: false, grade: "failed", reason: "bad_signature_or_request_hash" }), bits: CLEAR });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(out.state).toBe("held_review");
    const sig = rewardsState(state).signals.find((s) => s.kind === "attestation_failed");
    expect(sig?.detail).toMatchObject({ rewardId: R1, deviceId: D1, source: "rewards-activate", reasons: ["bad_signature_or_request_hash"] });
    // ...and the open signal now holds this account's NEXT activation too
    seedReward(state, { id: R2, userId: USER_A, kind: "offer_code" });
    expect((await activate(state, R2, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }))).state).toBe("held_review");
  });

  it("a submission with NO token: failed on hardware that supports attestation, unattestable otherwise (G3-08) — never issued", async () => {
    const capable = newWorld();
    seedReward(capable, { id: R1, userId: USER_A, kind: "offer_code" });
    const reqCapable: ActivationRequest = { deviceId: D1, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: true } };
    expect((await activate(capable, R1, reqCapable, deps({}))).state).toBe("held_review");
    expect(signalKinds(capable)).toEqual(["attestation_failed"]); // omitting the token on capable hardware is `failed`

    const incapable = newWorld();
    seedReward(incapable, { id: R1, userId: USER_A, kind: "offer_code" });
    const reqIncapable: ActivationRequest = { deviceId: D1, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } };
    expect((await activate(incapable, R1, reqIncapable, deps({}))).state).toBe("held_review");
    expect(signalKinds(incapable)).toEqual([]); // `unattestable`: routing only
  });
});

// ===========================================================================
// AT (5) shapes through the handler: a mismatched body hash and a replayed
// counter are rejected (graded failed), using the REAL assertion verifier.
// ===========================================================================
describe("AT (5): body-hash binding and counter replay, end to end with the real App Attest verifier", () => {
  const APP_ID = "TEAMID1234.com.example.golfraven";
  const KEY_ID = toB64(new Uint8Array(32).fill(7));

  async function realIos(state: FakeState, bits = CLEAR, counter = 5) {
    const key = await generateP256();
    const rs = rewardsState(state);
    rs.deviceAttest.get(D1)!.attestKeyId = KEY_ID;
    rs.deviceAttest.get(D1)!.attestPublicKey = key.publicKeyRaw;
    rs.deviceAttest.get(D1)!.attestCounter = counter;
    const fake = makeFakeIosPort({ bits });
    const port: IosPort = {
      verifyAssertion: (input) => verifyAppAttestAssertion(input, { appId: APP_ID }, { sha256, verifyP256: verifyP256WebCrypto }),
      readBits: (t) => fake.readBits(t),
      setBit0: (t, k) => fake.setBit0(t, k),
    };
    return { key, port, fake };
  }

  const SIGNED_TOKEN = "REVWSUNF";
  const tokenSha = async (t: string) => toHex(await sha256(new TextEncoder().encode(t)));

  async function signedRequest(
    state: FakeState,
    key: Awaited<ReturnType<typeof generateP256>>,
    o: { rewardId: string; counter: number; bindRewardId?: string; bindChallengeBytes?: Uint8Array; sendToken?: string; bindToken?: string | null },
  ) {
    const ch = await issueChallenge(state, USER_A, D1);
    // H1: the assertion covers the hash of the DeviceCheck token the request carries.
    const bindToken = o.bindToken === undefined ? SIGNED_TOKEN : o.bindToken;
    const hash = await computeRequestBinding(
      sha256,
      {
        rewardId: o.bindRewardId ?? o.rewardId,
        deviceId: D1,
        platform: "ios",
        challengeId: ch.challengeId,
        ...(bindToken !== null ? { deviceCheckTokenSha256: await tokenSha(bindToken) } : {}),
      },
      o.bindChallengeBytes ?? ch.nonceBytes,
    );
    const built = await buildAssertion({ key, appId: APP_ID, counter: o.counter, clientDataHash: hash });
    const req: ActivationRequest = {
      deviceId: D1,
      platform: "ios",
      challengeId: ch.challengeId,
      nonce: ch.nonce,
      attestation: { kind: "ios", keyId: KEY_ID, assertion: built.assertionB64, deviceCheckToken: o.sendToken ?? SIGNED_TOKEN },
    };
    return req;
  }

  it("a correctly bound, monotonic assertion is attested -> issued, and the counter advances", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state);
    const out = await activate(state, R1, await signedRequest(state, key, { rewardId: R1, counter: 6 }), deps({ ios: port }));
    expect(out.state).toBe("issued");
    expect(rewardsState(state).deviceAttest.get(D1)!.attestCounter).toBe(6);
    expect(signalKinds(state)).toEqual([]);
  });

  it("an assertion bound to a DIFFERENT reward id (a mismatched body hash) is failed -> signal + held", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state);
    const req = await signedRequest(state, key, { rewardId: R1, counter: 6, bindRewardId: R2 });
    const out = await activate(state, R1, req, deps({ ios: port }));
    expect(out.state).toBe("held_review");
    expect(rewardsState(state).signals.find((s) => s.kind === "attestation_failed")?.detail.reasons).toEqual(["bad_signature_or_request_hash"]);
    expect(rewardsState(state).deviceAttest.get(D1)!.attestCounter).toBe(5); // a failed assertion never advances the counter
  });

  it("H1: a VALID assertion next to a SWAPPED DeviceCheck token is failed -> attestation_failed + held (and the swapped token's clean bits are never trusted)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port, fake } = await realIos(state, CLEAR);
    // The assertion was made for the device's real token; the request carries another
    // device's (clean) token — the one input the persistent-bit lookup uses.
    const req = await signedRequest(state, key, { rewardId: R1, counter: 6, sendToken: "T1RIRVJERVZJQ0U=" });
    const out = await activate(state, R1, req, deps({ ios: port }));
    expect(out.state).toBe("held_review");
    expect(rewardsState(state).signals.find((s) => s.kind === "attestation_failed")?.detail.reasons).toEqual(["bad_signature_or_request_hash"]);
    expect(rewardsState(state).deviceAttest.get(D1)!.attestCounter).toBe(5);
    expect(ledgerFor(state, R1)).toHaveLength(0);
    expect(fake.calls.setBit0).toBe(0);
  });

  it("H1: an assertion that does not bind the token hash at all (the pre-fix binding) is failed", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state);
    const req = await signedRequest(state, key, { rewardId: R1, counter: 6, bindToken: null });
    expect((await activate(state, R1, req, deps({ ios: port }))).state).toBe("held_review");
    expect(signalKinds(state)).toContain("attestation_failed");
  });

  it("an assertion bound to a different CHALLENGE is failed", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state);
    const req = await signedRequest(state, key, { rewardId: R1, counter: 6, bindChallengeBytes: new Uint8Array(32).fill(1) });
    expect((await activate(state, R1, req, deps({ ios: port }))).state).toBe("held_review");
    expect(signalKinds(state)).toContain("attestation_failed");
  });

  it("a REPLAYED counter (assertion counter <= stored) is failed", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state, CLEAR, 5);
    const req = await signedRequest(state, key, { rewardId: R1, counter: 5 });
    expect((await activate(state, R1, req, deps({ ios: port }))).state).toBe("held_review");
    expect(rewardsState(state).signals.find((s) => s.kind === "attestation_failed")?.detail.reasons).toEqual(["counter_not_monotonic"]);
  });

  it("a counter that passes verification but loses the atomic advance (a race) is also failed", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state);
    const req = await signedRequest(state, key, { rewardId: R1, counter: 6 });
    // A concurrent request advanced the counter between verification and the UPDATE.
    const wrapped: IosPort = { ...port, verifyAssertion: async (i) => { const r = await port.verifyAssertion(i); rewardsState(state).deviceAttest.get(D1)!.attestCounter = 9; return r; } };
    expect((await activate(state, R1, req, deps({ ios: wrapped }))).state).toBe("held_review");
    expect(rewardsState(state).signals.find((s) => s.kind === "attestation_failed")?.detail.reasons).toEqual(["counter_replay"]);
  });

  it("the same signed request cannot be replayed: the challenge is single-use", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    seedReward(state, { id: R2, userId: USER_A, kind: "offer_code" });
    const { key, port } = await realIos(state);
    const req = await signedRequest(state, key, { rewardId: R1, counter: 6 });
    await activate(state, R1, req, deps({ ios: port }));
    // Same challenge, aimed at another reward: the challenge is already consumed.
    expect(await codeOf(activate(state, R2, req, deps({ ios: port })))).toBe("challenge_not_consumable");
  });

  it("the verifier is handed SHA-256(canonical_body ‖ challenge) built from the request's own fields", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ios = makeFakeIosPort({ bits: CLEAR });
    const ch = await issueChallenge(state, USER_A, D1);
    const req = await iosRequest(state, { challenge: ch });
    await activate(state, R1, req, deps({ ios }));
    const token = (req.attestation as { deviceCheckToken: string }).deviceCheckToken;
    const expected = await computeRequestBinding(
      sha256,
      { rewardId: R1, deviceId: D1, platform: "ios", challengeId: ch.challengeId, deviceCheckTokenSha256: toHex(await sha256(new TextEncoder().encode(token))) },
      ch.nonceBytes,
    );
    expect(toHex(ios.lastVerifyInput!.clientDataHash)).toBe(toHex(expected));
  });
});

// ===========================================================================
// Android
// ===========================================================================
describe("Android (Play Integrity) — the §7.5 server-side substitute for the two persistent bits (A20)", () => {
  const AND_DEV = "33333333-3333-4333-8333-333333333333";
  const LINK = "install-link-AAAAAAAAAA";
  const linkHash = async (id: string) => toHex(await sha256(new TextEncoder().encode(id)));
  function androidWorld() {
    const state = makeFakeState();
    seedDevice(state, { id: AND_DEV, userId: USER_A, platform: "android" });
    return state;
  }
  async function androidRequest(state: FakeState, installLinkId: string | null = LINK): Promise<{ req: ActivationRequest; nonceBytes: Uint8Array; challengeId: string }> {
    const ch = await issueChallenge(state, USER_A, AND_DEV);
    return {
      req: {
        deviceId: AND_DEV,
        platform: "android",
        challengeId: ch.challengeId,
        nonce: ch.nonce,
        ...(installLinkId !== null ? { installLinkId } : {}),
        attestation: { kind: "android", integrityToken: "tok.en.value" },
      },
      nonceBytes: ch.nonceBytes,
      challengeId: ch.challengeId,
    };
  }
  /** Other accounts' device rows on the SAME install (what makes "seen on > 2 accounts"). */
  async function otherAccountsOnInstall(state: FakeState, n: number, opts: { voided?: boolean } = {}) {
    for (let i = 0; i < n; i++) {
      const id = `44444444-4444-4444-8444-44444444440${i}`;
      state.devices.set(id, { id, userId: `other-${i}` });
      seedDevice(state, { id, userId: `other-${i}`, platform: "android", installLinkHash: await linkHash(LINK), fraudVoided: opts.voided === true && i === 0 });
    }
  }
  const attested = () => makeFakeAndroidPort({ result: () => ({ grade: "attested" }) });

  it("is handed requestHash = base64url(SHA-256(canonical_body ‖ challenge)) with the install link bound in; a clean install runs row 6 -> issued", async () => {
    const state = androidWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const android = attested();
    const { req, nonceBytes, challengeId } = await androidRequest(state);
    const out = await activate(state, R1, req, deps({ android }));
    expect(out.state).toBe("issued"); // row 6
    const expected = toBase64Url(await computeRequestBinding(sha256, { rewardId: R1, deviceId: AND_DEV, platform: "android", challengeId, installLinkId: LINK }, nonceBytes));
    expect(android.lastInput?.expectedRequestHash).toBe(expected);
    // The "write": the install link is recorded (hashed) on the device row.
    expect(rewardsState(state).deviceAttest.get(AND_DEV)!.installLinkHash).toBe(await linkHash(LINK));
  });

  it("the install link is part of the binding: a request whose installLinkId differs from the one bound produces a different hash", async () => {
    const a = await computeRequestBinding(sha256, { rewardId: R1, deviceId: AND_DEV, platform: "android", challengeId: "c", installLinkId: "install-link-AAAAAAAAAA" }, new Uint8Array(32));
    const b = await computeRequestBinding(sha256, { rewardId: R1, deviceId: AND_DEV, platform: "android", challengeId: "c", installLinkId: "install-link-BBBBBBBBBB" }, new Uint8Array(32));
    const c = await computeRequestBinding(sha256, { rewardId: R1, deviceId: AND_DEV, platform: "android", challengeId: "c" }, new Uint8Array(32));
    expect(new Set([toHex(a), toHex(b), toHex(c)]).size).toBe(3);
  });

  it("AT(9) on Android — same account, second offer -> issued (1 account on the install: bit0-substitute clear)", async () => {
    const state = androidWorld();
    priorReward(state, USER_A, AND_DEV);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const out = await activate(state, R1, (await androidRequest(state)).req, deps({ android: attested() }));
    expect(out.state).toBe("issued");
    expect(signalKinds(state)).toEqual([]);
  });

  it("AT(9) on Android — same account after reinstall -> issued (a new device row with a new install link: one account on each)", async () => {
    const state = androidWorld();
    priorReward(state, USER_A, AND_DEV);
    const D_NEW = "55555555-5555-4555-8555-555555555555";
    seedDevice(state, { id: D_NEW, userId: USER_A, platform: "android" });
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ch = await issueChallenge(state, USER_A, D_NEW);
    const req: ActivationRequest = { deviceId: D_NEW, platform: "android", challengeId: ch.challengeId, nonce: ch.nonce, installLinkId: "install-link-NEWINSTALL", attestation: { kind: "android", integrityToken: "tok.en.value" } };
    expect((await activate(state, R1, req, deps({ android: attested() }))).state).toBe("issued");
    expect(signalKinds(state)).toEqual([]);
  });

  it("AT(9) on Android — a new account on an install seen on > 2 accounts -> held_review + multi_account_device (not refused)", async () => {
    const state = androidWorld();
    await otherAccountsOnInstall(state, 2); // this account is the 3rd
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" }); // no prior reward
    const out = await activate(state, R1, (await androidRequest(state)).req, deps({ android: attested() }));
    expect(out).toMatchObject({ state: "held_review", held: true });
    expect(signalKinds(state)).toEqual(["multi_account_device"]);
    const code = rewardsState(state).rewards.get(R1)!;
    expect(code.holdDetail).toMatchObject({ bitsSource: "server_substitute", bits: { bit0: true, bit1: false }, primaryRow: 4, matchedRows: [4], androidInstallSignals: { accountsOnInstall: 3, voidedAccountUsedInstall: false } });
  });

  it("the threshold is '> 2': exactly 2 accounts on the install (this one + one other) is NOT bit0", async () => {
    const state = androidWorld();
    await otherAccountsOnInstall(state, 1);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect((await activate(state, R1, (await androidRequest(state)).req, deps({ android: attested() }))).state).toBe("issued");
  });

  it("AT(9) on Android — a repeat user on a '> 2 accounts' install -> issued (row 5)", async () => {
    const state = androidWorld();
    await otherAccountsOnInstall(state, 2);
    priorReward(state, USER_A, AND_DEV);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect((await activate(state, R1, (await androidRequest(state)).req, deps({ android: attested() }))).state).toBe("issued");
  });

  it("AT(9) on Android — ANY account on an install a fraud-voided account used -> held_review + a high-priority signal (the bit1 substitute)", async () => {
    for (const hasPrior of [false, true]) {
      const state = androidWorld();
      await otherAccountsOnInstall(state, 1, { voided: true });
      if (hasPrior) priorReward(state, USER_A, AND_DEV);
      seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
      const out = await activate(state, R1, (await androidRequest(state)).req, deps({ android: attested() }));
      expect(out.state, `prior=${hasPrior}`).toBe("held_review");
      const sig = rewardsState(state).signals.find((s) => s.kind === "flagged_device_activation");
      expect(sig?.detail).toMatchObject({ priority: "high", rewardId: R1, tableRow: 1 });
    }
  });

  it("an Android activation with NO install link on record (none sent, no attest key) has no substitute signal: held, never activated, never refused", async () => {
    const state = androidWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const out = await activate(state, R1, (await androidRequest(state, null)).req, deps({ android: attested() }));
    expect(out).toMatchObject({ state: "held_review", held: true });
    expect(signalKinds(state)).toEqual([]);
    expect(rewardsState(state).rewards.get(R1)!.holdDetail).toMatchObject({ bits: null, primaryRow: "no_persistent_signal" });
  });

  it("an install link that arrives later is first-writer-wins on the device row", async () => {
    const state = androidWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    seedReward(state, { id: R2, userId: USER_A, kind: "offer_code" });
    await activate(state, R1, (await androidRequest(state, "install-link-FIRSTFIRST")).req, deps({ android: attested() }));
    await activate(state, R2, (await androidRequest(state, "install-link-SECONDSECOND")).req, deps({ android: attested() }));
    expect(rewardsState(state).deviceAttest.get(AND_DEV)!.installLinkHash).toBe(await linkHash("install-link-FIRSTFIRST"));
  });

  it("a wrong requestHash / failed verdict raises attestation_failed and holds", async () => {
    const state = androidWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const android = makeFakeAndroidPort({ result: () => ({ grade: "failed", reasons: ["request_hash_mismatch"] }) });
    const out = await activate(state, R1, (await androidRequest(state)).req, deps({ android }));
    expect(out.state).toBe("held_review");
    expect(rewardsState(state).signals.find((s) => s.kind === "attestation_failed")?.detail.reasons).toEqual(["request_hash_mismatch"]);
  });

  it("with Android unconfigured, a request carrying an integrity token fails closed (503) and writes nothing", async () => {
    const state = androidWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const { req } = await androidRequest(state);
    expect(await codeOf(activate(state, R1, req, deps({})))).toBe("attestation_not_configured");
    expect(rewardsState(state).rewards.get(R1)!.state).toBe("earned");
    expect(rewardsState(state).applyCalls).toHaveLength(0);
    expect(rewardsState(state).deviceAttest.get(AND_DEV)!.installLinkHash).toBeNull();
  });
});

// ===========================================================================
// 404 / ownership
// ===========================================================================
describe("the app-review demo account (§4.7.7)", () => {
  it("is refused with a 403 before any reward is read — an existing id, a foreign id and an unknown id all answer the same", async () => {
    const state = newWorld();
    rewardsState(state).demoAccounts.add(USER_A);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    seedReward(state, { id: R2, userId: USER_B, kind: "offer_code" });
    for (const id of [R1, R2, R3]) {
      const ios = makeFakeIosPort();
      expect(await status(activate(state, id, await iosRequest(state), deps({ ios }))), id).toBe(403);
      expect(ios.calls).toEqual({ verify: 0, readBits: 0, setBit0: 0 });
    }
    expect(rewardsState(state).rewards.get(R1)!.state).toBe("earned");
  });
});

describe("ownership: another user's reward is a 404, never a 403", () => {
  it("player A activating player B's offer code or entitlement -> 404, and nothing about B's reward changes or is read from a vendor", async () => {
    const state = newWorld();
    seedDevice(state, { id: D2, userId: USER_B, platform: "ios" });
    seedReward(state, { id: R1, userId: USER_B, kind: "offer_code" });
    seedReward(state, { id: R2, userId: USER_B, kind: "entitlement" });
    for (const id of [R1, R2]) {
      const ios = makeFakeIosPort({ bits: CLEAR });
      const p = activate(state, id, await iosRequest(state), deps({ ios }));
      expect(await status(p), id).toBe(404);
      expect(ios.calls).toEqual({ verify: 0, readBits: 0, setBit0: 0 });
      expect(rewardsState(state).rewards.get(id)!.state).toBe("earned");
    }
    expect(rewardsState(state).applyCalls).toHaveLength(0);
  });

  it("a foreign id and a nonexistent id are indistinguishable (same status, same code, same message)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_B, kind: "offer_code" });
    const get = async (id: string) => {
      try {
        await activate(state, id, await iosRequest(state), deps({ ios: makeFakeIosPort() }));
      } catch (e) {
        const h = e as HttpError;
        return { status: h.status, code: h.code, message: h.message };
      }
      return null;
    };
    expect(await get(R1)).toEqual(await get("aaaaaaaa-0000-4000-8000-0000000000ff"));
    expect(await get(R1)).toEqual({ status: 404, code: "not_found", message: "no such reward" });
  });
});

// ===========================================================================
// State machine, idempotency, validation
// ===========================================================================
describe("state machine and idempotency", () => {
  it("activating an already-active reward from the SAME device is an idempotent no-op: no verification, no vendor call, no write", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "issued", activatedDeviceId: D1 });
    const ios = makeFakeIosPort();
    const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(out).toMatchObject({ state: "issued", replay: true });
    expect(ios.calls).toEqual({ verify: 0, readBits: 0, setBit0: 0 });
    expect(rewardsState(state).applyCalls).toHaveLength(0);
  });

  it("a held reward stays held: activation never releases it (even on a now-clean device) and never re-runs the table", async () => {
    for (const kind of ["offer_code", "entitlement"] as const) {
      const state = newWorld();
      seedReward(state, { id: R1, userId: USER_A, kind, state: "held_review", expiryPausedAt: NOW_ISO });
      const ios = makeFakeIosPort({ bits: CLEAR });
      const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
      expect(out).toMatchObject({ state: "held_review", held: true, replay: true });
      expect(ios.calls.readBits).toBe(0);
    }
  });

  it("terminal / post-activation states cannot be activated: redeemed, void, expired, vouchered -> 409", async () => {
    for (const [kind, st] of [["offer_code", "redeemed"], ["offer_code", "void"], ["offer_code", "expired"], ["entitlement", "redeemed"], ["entitlement", "void"], ["entitlement", "vouchered"]] as const) {
      const state = newWorld();
      seedReward(state, { id: R1, userId: USER_A, kind, state: st });
      expect(await codeOf(activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort() }))), `${kind}/${st}`).toBe("reward_not_activatable");
    }
  });

  it("an earned offer code past its expiry (clock running) -> 409 reward_expired; a paused clock is not expired", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", expiresAt: "2026-05-01T00:00:00.000Z" });
    expect(await codeOf(activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort() })))).toBe("reward_expired");
    seedReward(state, { id: R2, userId: USER_A, kind: "offer_code", state: "held_review", expiresAt: "2026-05-01T00:00:00.000Z", expiryPausedAt: NOW_ISO });
    expect((await activate(state, R2, await iosRequest(state), deps({ ios: makeFakeIosPort() }))).state).toBe("held_review");
  });

  it("an entitlement activation never reserves budget; an offer code with no face value reserves nothing", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "entitlement" });
    seedReward(state, { id: R2, userId: USER_A, kind: "offer_code", faceValue: 0 });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    await activate(state, R2, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(rewardsState(state).budgetReserved).toBe(0);
  });

  it("the signals are raised once per (reward, device): a retry does not duplicate them", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    // The reward is now held, so a retry short-circuits; force the table to run again:
    rewardsState(state).rewards.get(R1)!.state = "earned";
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(signalKinds(state)).toEqual(["flagged_device_activation"]);
  });
});

describe("device and challenge validation", () => {
  it("the device cap is checked before a new device row is created", async () => {
    const state = newWorld();
    for (let i = 0; i < 19; i++) seedDevice(state, { id: `44444444-4444-4444-8444-${String(i).padStart(12, "0")}`, userId: USER_A, platform: "ios" });
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect(state.devices.size).toBe(20);
    const req: ActivationRequest = { deviceId: D2, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } };
    expect(await codeOf(activate(state, R1, req, deps({})))).toBe("device_limit_exceeded");
    expect(state.devices.has(D2)).toBe(false);
  });

  it("a device registered under the other platform -> 422 platform_mismatch", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const req: ActivationRequest = { deviceId: D1, platform: "android", attestation: { kind: "none", hardwareSupportsAttestation: false } };
    expect(await codeOf(activate(state, R1, req, deps({})))).toBe("platform_mismatch");
  });

  it("a challenge that is unknown, another device's, prefetched, expired, used, or presented with the wrong nonce is one and the same 422", async () => {
    const mk = async (variant: string) => {
      const state = newWorld();
      seedDevice(state, { id: D2, userId: USER_A, platform: "ios" });
      seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
      const ios = makeFakeIosPort();
      let ch: { challengeId: string; nonce: string };
      switch (variant) {
        case "unknown":
          ch = { challengeId: "chal_nope", nonce: "AAAA" };
          break;
        case "other-device":
          ch = await issueChallenge(state, USER_A, D2);
          break;
        case "prefetched":
          ch = await issueChallenge(state, USER_A, D1, "prefetched");
          break;
        case "expired":
          ch = await issueChallenge(state, USER_A, D1, "live", -1000);
          break;
        case "used": {
          ch = await issueChallenge(state, USER_A, D1);
          const repo = makeFakeRepo(state, USER_A);
          await repo.challenge.consume(ch.challengeId, toHex(await sha256(new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff))));
          break;
        }
        default: {
          const real = await issueChallenge(state, USER_A, D1);
          ch = { challengeId: real.challengeId, nonce: toBase64Url(new Uint8Array(32).fill(1)) };
        }
      }
      const req = await iosRequest(state, { challenge: ch });
      try {
        await activate(state, R1, req, deps({ ios }));
        return { status: 200, code: "", calls: ios.calls.verify };
      } catch (e) {
        return { status: (e as HttpError).status, code: (e as HttpError).code, calls: ios.calls.verify };
      }
    };
    for (const variant of ["unknown", "other-device", "prefetched", "expired", "used", "wrong-nonce"]) {
      expect(await mk(variant), variant).toEqual({ status: 422, code: "challenge_not_consumable", calls: 0 });
    }
  });

  it("another user's challenge id is the same 422", async () => {
    const state = newWorld();
    seedDevice(state, { id: D2, userId: USER_B, platform: "ios" });
    const theirs = await issueChallenge(state, USER_B, D2);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect(await codeOf(activate(state, R1, await iosRequest(state, { challenge: theirs }), deps({ ios: makeFakeIosPort() })))).toBe("challenge_not_consumable");
  });

  it("attestation material without a challenge is a 400", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const req = { ...(await iosRequest(state)), challengeId: undefined, nonce: undefined } as ActivationRequest;
    expect(await status(activate(state, R1, req, deps({ ios: makeFakeIosPort() })))).toBe(400);
  });
});

// ===========================================================================
// Vendor failure modes: fail CLOSED
// ===========================================================================
describe("vendor failure modes fail closed — never 'clean'", () => {
  async function run(state: FakeState, ios: IosPort | null) {
    return activate(state, R1, await iosRequest(state), deps({ ios }));
  }

  it("iOS not configured -> 503 attestation_not_configured; the reward is untouched and no challenge was consumed", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const req = await iosRequest(state);
    expect(await codeOf(activate(state, R1, req, deps({ ios: null })))).toBe("attestation_not_configured");
    expect(rewardsState(state).rewards.get(R1)!.state).toBe("earned");
    expect([...state.challenges.values()].every((c) => c.usedAt === null)).toBe(true);
  });

  it("DeviceCheck unavailable (attested grade) -> 503 attestation_unavailable; apply is never reached", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect(await codeOf(run(state, makeFakeIosPort({ bits: new VendorUnavailableError("down") })))).toBe("attestation_unavailable");
    expect(rewardsState(state).applyCalls).toHaveLength(0);
  });

  it("DeviceCheck not configured / credentials rejected (attested grade) -> 503 attestation_not_configured", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    expect(await codeOf(run(state, makeFakeIosPort({ bits: new VendorNotConfiguredError("no key") })))).toBe("attestation_not_configured");
    expect(rewardsState(state).applyCalls).toHaveLength(0);
  });

  it("a DeviceCheck token Apple REJECTS (attested assertion, bad token) is graded failed -> signal + held", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const out = await run(state, makeFakeIosPort({ bits: new VendorRejectedError("bad token") }));
    expect(out.state).toBe("held_review");
    expect(rewardsState(state).signals.find((s) => s.kind === "attestation_failed")?.detail.reasons).toEqual(["devicecheck_token_rejected"]);
  });

  it("for a NON-attested grade the bit read is best-effort: a vendor outage does not 503 a reward that is held anyway", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const ios = makeFakeIosPort({ bits: new VendorUnavailableError("down") });
    const req: ActivationRequest = { deviceId: D1, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false, deviceCheckToken: "REVWSUNF" } };
    const out = await activate(state, R1, req, deps({ ios }));
    expect(out.state).toBe("held_review");
    expect(ios.calls.readBits).toBe(1);
  });

  it("...and when it succeeds on a flagged device, the high-priority signal is still raised (precedence: row 1 first)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const req: ActivationRequest = { deviceId: D1, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false, deviceCheckToken: "REVWSUNF" } };
    await activate(state, R1, req, deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(signalKinds(state)).toEqual(["flagged_device_activation"]);
  });

  it("row 6: bit0 is set only AFTER the database transition, and a failure to set it surfaces as 503 (the real transaction then rolls back)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const order: string[] = [];
    const ios = makeFakeIosPort({ bits: CLEAR, setBit0Error: new VendorUnavailableError("down") });
    const orig = ios.setBit0.bind(ios);
    ios.setBit0 = async (t, k) => {
      order.push(`setBit0 (applyCalls so far: ${rewardsState(state).applyCalls.length})`);
      return orig(t, k);
    };
    expect(await codeOf(run(state, ios))).toBe("attestation_unavailable");
    expect(order).toEqual(["setBit0 (applyCalls so far: 1)"]);
  });

  it("an unexpected error is not swallowed or relabelled", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    await expect(run(state, makeFakeIosPort({ bits: new TypeError("a bug") }))).rejects.toThrow("a bug");
  });
});

// ===========================================================================
// H2: a reviewer-cleared reward with no device, and the rest of the gate round
// ===========================================================================
describe("H2 — approving a held reward no device ever ran the table on returns it to `earned`, review-cleared", () => {
  it("probe B: a play-hold code (no device) approved by a reviewer is NOT issued; activation on a bit0 device with no prior reward still holds (row 4) with multi_account_device", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review", faceValue: 15, reservedAmount: 15, expiryPausedAt: NOW_ISO });
    rewardsState(state).budgetReserved = 15;
    expect(fakeResolveHeld(state, R1, true)).toBe("earned"); // NOT issued: no device, no table
    const code = rewardsState(state).rewards.get(R1)!;
    expect(code).toMatchObject({ state: "earned", activatedDeviceId: null, reservedAmount: 15 }); // reservation kept
    expect(code.reviewClearedAt).not.toBeNull();
    expect(ledgerFor(state, R1)).toHaveLength(0);

    const ios = makeFakeIosPort({ bits: BIT0 });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(out.state).toBe("held_review");
    expect(signalKinds(state)).toEqual(["multi_account_device"]);
  });

  it("approve-then-activate on a clean, attested device -> issued, ledger row written, bit0 set (rows 2 and 3 were cleared; rows 1 and 4-6 ran)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review", restsOnUnattestable: true });
    fakeResolveHeld(state, R1, true);
    const ios = makeFakeIosPort({ bits: CLEAR });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios }));
    expect(out.state).toBe("issued");
    expect(ledgerFor(state, R1)).toHaveLength(1);
    expect(ios.calls.setBit0).toBe(1);
  });

  it("the cleared reward is still held on a FLAGGED device (row 1 is never cleared by a review of the reward)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review", restsOnUnattestable: true });
    fakeResolveHeld(state, R1, true);
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }))).state).toBe("held_review");
    expect(signalKinds(state)).toContain("flagged_device_activation");
  });

  it("the cleared reward is still held when the ACTIVATING DEVICE is unattestable (the clearing covers the reward's basis, not this device)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review", restsOnUnattestable: true });
    fakeResolveHeld(state, R1, true);
    const req: ActivationRequest = { deviceId: D1, platform: "ios", attestation: { kind: "none", hardwareSupportsAttestation: false } };
    expect((await activate(state, R1, req, deps({}))).state).toBe("held_review");
  });

  it("an attestation_failed signal raised BEFORE the review does not hold the cleared reward; one raised AFTER does", async () => {
    const state = newWorld();
    openSignal(state, USER_A, "attestation_failed"); // the reviewer saw this one
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review" });
    fakeResolveHeld(state, R1, true);
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }))).state).toBe("issued");

    const state2 = newWorld();
    seedReward(state2, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review" });
    fakeResolveHeld(state2, R1, true);
    openSignal(state2, USER_A, "attestation_failed"); // raised after the review
    expect((await activate(state2, R1, await iosRequest(state2), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }))).state).toBe("held_review");
  });

  it("a held PLAY is not cleared by a review of the code: the reward stays held", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "held_review", playHeld: true });
    fakeResolveHeld(state, R1, true);
    expect((await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }))).state).toBe("held_review");
  });

  it("hasPriorReward ignores a reward no device ever ran the table on (even one in an `issued` state)", async () => {
    const state = newWorld();
    seedReward(state, { id: R2, userId: USER_A, kind: "offer_code", state: "issued", activatedDeviceId: null });
    seedReward(state, { id: R3, userId: USER_A, kind: "entitlement", state: "redeemable", activatedDeviceId: null });
    expect(await makeFakeRepo(state, USER_A).rewards.hasPriorReward()).toBe(false);
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", state: "issued", activatedDeviceId: D1 });
    expect(await makeFakeRepo(state, USER_A).rewards.hasPriorReward()).toBe(true);
  });

  it("a held reward that DID run on a device is approved straight to the active state (the table already ran there)", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(fakeResolveHeld(state, R1, true)).toBe("issued");
    expect(ledgerFor(state, R1)).toHaveLength(1);
  });

  it("an entitlement follows the same rule", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "entitlement", state: "held_review" });
    expect(fakeResolveHeld(state, R1, true)).toBe("earned");
  });
});

describe("M2 / hold detail — what the reviewer sees", () => {
  it("probe C: first account, bit0 device, unattestable reward -> held WITH multi_account_device, and the hold records the bits, every matched row and the DeviceCheck month", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", restsOnUnattestable: true });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT0 }) }));
    expect(out.state).toBe("held_review");
    expect(signalKinds(state)).toEqual(["multi_account_device"]);
    const code = rewardsState(state).rewards.get(R1)!;
    expect(code.holdDetail).toMatchObject({
      bits: { bit0: true, bit1: false },
      bitsSource: "devicecheck",
      matchedRows: [3, 4],
      primaryRow: 3,
      deviceCheckLastUpdateMonth: "2026-02",
      platform: "ios",
      grade: "attested",
    });
    expect(rewardsState(state).signals.find((x) => x.kind === "multi_account_device")?.detail).toMatchObject({ tableRow: 3, matchedRows: [3, 4] });
  });

  it("an activation that is NOT held stores no hold detail", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }));
    expect(rewardsState(state).applyCalls[0]!.holdDetail).toBeNull();
  });

  it("the hold detail is never part of the response", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code" });
    const out = await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(Object.keys(out).sort()).toEqual(["held", "id", "kind", "replay", "state"]);
  });
});

describe("M3 — the budget model", () => {
  it("activating an `earned` code that holds no reservation reserves its face value as it issues it", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", faceValue: 15 });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }));
    expect(rewardsState(state).rewards.get(R1)).toMatchObject({ state: "issued", reservedAmount: 15 });
    expect(rewardsState(state).budgetReserved).toBe(15);
  });

  it("the hold path is idempotent against an earn-time reservation: no double reservation", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", faceValue: 15, reservedAmount: 15 });
    rewardsState(state).budgetReserved = 15; // the earn path (not built) reserved already
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(rewardsState(state).rewards.get(R1)!.reservedAmount).toBe(15);
    expect(rewardsState(state).budgetReserved).toBe(15);
  });

  it("...and so is the issue path", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", faceValue: 15, reservedAmount: 15 });
    rewardsState(state).budgetReserved = 15;
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: CLEAR }) }));
    expect(rewardsState(state).budgetReserved).toBe(15);
  });

  it("a rejected held code gives its reservation back exactly once", async () => {
    const state = newWorld();
    seedReward(state, { id: R1, userId: USER_A, kind: "offer_code", faceValue: 15 });
    await activate(state, R1, await iosRequest(state), deps({ ios: makeFakeIosPort({ bits: BIT1 }) }));
    expect(rewardsState(state).budgetReserved).toBe(15);
    fakeResolveHeld(state, R1, false);
    expect(rewardsState(state).budgetReserved).toBe(0);
  });
});

describe("F6 — the transaction's timing budget", () => {
  it("lock wait + the vendor calls fit inside transaction_timeout, with the real constants", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const privileged = readFileSync(fileURLToPath(new URL("../../functions/_shared/privileged.ts", import.meta.url)), "utf8");
    const seconds = (re: RegExp) => Number(re.exec(privileged)?.[1]) * 1000;
    const lockMs = seconds(/const LOCK_TIMEOUT = "(\d+)s"/);
    const txMs = seconds(/set local transaction_timeout = '(\d+)s'/);
    expect(lockMs).toBeGreaterThan(0);
    expect(txMs).toBeGreaterThan(lockMs);
    const { VENDOR_CALL_TIMEOUT_MS, MAX_VENDOR_CALLS_PER_REQUEST, platformVendorHttp } = await import("../../functions/_shared/rewards/vendor-http.js");
    expect(platformVendorHttp().timeoutMs).toBe(VENDOR_CALL_TIMEOUT_MS);
    const worstCase = lockMs + MAX_VENDOR_CALLS_PER_REQUEST * VENDOR_CALL_TIMEOUT_MS;
    // 2 s of headroom for every other statement and for signing.
    expect(worstCase + 2_000).toBeLessThanOrEqual(txMs);
  });
});

// ===========================================================================
// Rate limits (§4.7 item 8): 10/user/h and 20/device/day
// ===========================================================================
describe("rate limits", () => {
  const hitFor = (state: FakeState, uid = USER_A) => (key: string, w: number, max: number) => fakeHitRateLimitForActor(state, uid, key, w, max);

  it("the 11th activation request in an hour is refused", async () => {
    const state = makeFakeState();
    const results: boolean[] = [];
    for (let i = 0; i < 11; i++) results.push((await enforceActivationRateLimits(hitFor(state), D1)).ok);
    expect(results.slice(0, 10).every(Boolean)).toBe(true);
    expect(results[10]).toBe(false);
  });

  it("a single user hitting one device: the device bucket trips at 21 once the user bucket allows it", async () => {
    // Bypass the hourly user bucket by giving it an unlimited fake, to isolate the device bucket.
    let deviceHits = 0;
    const hit = async (key: string, _w: number, max: number) => {
      if (key === "rewards-activate:user") return { ok: true };
      deviceHits++;
      return { ok: deviceHits <= max };
    };
    const outcomes: boolean[] = [];
    for (let i = 0; i < 21; i++) outcomes.push((await enforceActivationRateLimits(hit, D1)).ok);
    expect(outcomes.filter(Boolean)).toHaveLength(20);
    expect(outcomes[20]).toBe(false);
  });

  it("a user over their hourly cap does not also burn their device's daily budget", async () => {
    const seen: string[] = [];
    const hit = async (key: string) => {
      seen.push(key);
      return { ok: !key.endsWith(":user") };
    };
    await enforceActivationRateLimits(hit, D1);
    expect(seen).toEqual(["rewards-activate:user"]);
  });

  it("the bucket windows and caps are the plan's: 10 per 3600 s per user, 20 per 86400 s per device", async () => {
    const seen: Array<[string, number, number]> = [];
    await enforceActivationRateLimits(async (k, w, m) => (seen.push([k, w, m]), { ok: true }), D1);
    expect(seen).toEqual([["rewards-activate:user", 3_600, 10], [`rewards-activate:device:${D1}`, 86_400, 20]]);
  });
});
