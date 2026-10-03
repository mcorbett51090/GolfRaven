// supabase/tests/unit/checkin-token-attestation.test.ts
//
// checkin/token-handler.ts with a PRESENTED attestation (build plan §4.5 G3-08, §7.5) against the in-memory fake Repo and:
//   - iOS: the REAL assertion verifier (rewards/app-attest.ts) over assertions this file builds with Web Crypto (self-consistency, NOT
//     conformance with a real iPhone: `[unverified — no Apple device in this environment]`);
//   - Android: the REAL `buildAndroidPort` (rewards/verification-ports.ts) over a scripted `fetch` that stands in for Google
//     (`[unverified]` wire shapes, exactly as vendor-adapters.test.ts).
// Real-database coverage of the same flows (the atomic counter advance, the fraud signal, the transaction rollback on a vendor error) lives in
// supabase/tests/integration/checkin-attest.deno.test.ts.

import { beforeAll, describe, expect, it } from "vitest";
import { handleChallengeRequest } from "../../functions/_shared/checkin/challenge-handler.js";
import { handleTokenRequest, type CheckinAttestationDeps } from "../../functions/_shared/checkin/token-handler.js";
import { parseTokenBody, type TokenRequest } from "../../functions/_shared/checkin/token-request-shape.js";
import { HttpError } from "../../functions/_shared/http.js";
import { verifyP256WebCrypto } from "../../functions/_shared/rewards/app-attest.js";
import { canonicalJson, computeCheckinAndroidBinding, computeRequestBinding, fromBase64UrlStrict, toBase64Url, toHex } from "../../functions/_shared/rewards/binding.js";
import { computeIosActivationBinding, computeIosCheckinBinding, computeStringBinding } from "../../functions/_shared/rewards/string-binding.js";
import { computeAttestKeyBinding } from "../../functions/_shared/rewards/app-attest-registration.js";
import type { PlayIntegrityConfig } from "../../functions/_shared/rewards/play-integrity-client.js";
import { handleActivation } from "../../functions/_shared/rewards/activate-handler.js";
import { VendorRejectedError, type AndroidPort, type AssertionResult } from "../../functions/_shared/rewards/types.js";
import { buildAndroidPort, buildIosAssertionPort, buildVerificationPorts, type VerificationPorts } from "../../functions/_shared/rewards/verification-ports.js";
import type { VendorHttp } from "../../functions/_shared/rewards/vendor-http.js";
import { makeFakeRepo, makeFakeState, FAKE_DEVICE_ID, type FakeState } from "./fake-repo.js";
import { makeFakeIosPort, rewardsState, seedDevice, seedReward } from "./fake-rewards-repo.js";
import { buildAssertion, generateP256, sha256, toB64, type TestKey } from "./rewards-test-crypto.js";

const USER_A = "user-a";
const USER_B = "user-b";
const D1 = FAKE_DEVICE_ID;
const D2 = "22222222-2222-4222-8222-222222222222";
const APP_ID = "TEAMID1234.com.example.golfraven";
const digestHex = async (bytes: Uint8Array) => toHex(await sha256(bytes));
const randomBytes = (n: number) => crypto.getRandomValues(new Uint8Array(n));
const keyIdOf = async (key: TestKey) => toB64(await sha256(key.publicKeyRaw));
const crypt = { sha256, verifyP256: verifyP256WebCrypto };

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
async function statusOf(p: Promise<unknown>): Promise<{ status: number; code: string } | null> {
  try {
    await p;
    return null;
  } catch (e) {
    if (e instanceof HttpError) return { status: e.status, code: e.code };
    throw e;
  }
}

const tokens = (state: FakeState) => [...state.checkinTokens.values()];
const openSignals = (state: FakeState) => rewardsState(state).signals.filter((s) => s.kind === "attestation_failed" && !s.cleared);
const counterOf = (state: FakeState, deviceId = D1) => rewardsState(state).deviceAttest.get(deviceId)!.attestCounter;
const challengeUsed = (state: FakeState, id: string) => state.challenges.get(id)!.usedAt !== null;

async function issueChallenge(state: FakeState, uid = USER_A, deviceId = D1) {
  const [c] = await handleChallengeRequest({ deviceId }, makeFakeRepo(state, uid), randomBytes, digestHex);
  return { id: c!.id, nonce: c!.nonce, nonceBytes: fromBase64UrlStrict(c!.nonce)! };
}

/** A user-a world whose device D1 carries a REGISTERED App Attest key (counter 5), so a verified assertion can grade `attested`. */
async function iosWorld(counter = 5) {
  const state = makeFakeState();
  const key = await generateP256();
  seedDevice(state, { id: D1, userId: USER_A, platform: "ios", attestKeyId: await keyIdOf(key), attestCounter: counter, attestPublicKey: key.publicKeyRaw });
  return { state, key };
}

function deps(ports: Partial<VerificationPorts>, userId = USER_A): CheckinAttestationDeps {
  return { userId, ports: { ios: null, android: null, ...ports }, sha256 };
}
const iosDeps = (userId = USER_A) => deps({ ios: buildIosAssertionPort(APP_ID, crypt) }, userId);

interface IosOpts {
  key: TestKey;
  counter: number;
  /** override what the assertion BINDS (the client signs a different message than the server will compute) */
  bind?: Partial<{ challengeId: string; deviceId: string; nonce: string; userId: string }>;
  /** sign this hash instead (e.g. an activation or registration binding) */
  hash?: Uint8Array;
  keyId?: string;
}
async function iosToken(challenge: { id: string; nonce: string }, o: IosOpts): Promise<TokenRequest> {
  const hash =
    o.hash ??
    (await computeIosCheckinBinding(sha256, {
      challengeId: o.bind?.challengeId ?? challenge.id,
      deviceId: o.bind?.deviceId ?? D1,
      nonce: o.bind?.nonce ?? challenge.nonce,
      userId: o.bind?.userId ?? USER_A,
    }));
  const built = await buildAssertion({ key: o.key, appId: APP_ID, counter: o.counter, clientDataHash: hash });
  return {
    challengeId: challenge.id,
    nonce: challenge.nonce,
    hardwareSupportsAttestation: true,
    attestation: { platform: "ios", keyId: o.keyId ?? (await keyIdOf(o.key)), assertion: built.assertionB64 },
  };
}

async function runIos(state: FakeState, body: TokenRequest, d: CheckinAttestationDeps = iosDeps()) {
  return handleTokenRequest(body, makeFakeRepo(state, USER_A), digestHex, d);
}

// ---------------------------------------------------------------------------
// request shape
// ---------------------------------------------------------------------------
describe("parseTokenBody (strict wire shape)", () => {
  const base = { challengeId: "AAAAAAAA-0000-4000-8000-000000000001", nonce: "abc", hardwareSupportsAttestation: false };
  const ok = (v: unknown) => {
    const r = parseTokenBody(v);
    if (!r.ok) throw new Error(JSON.stringify(r.issues));
    return r.value;
  };
  const issues = (v: unknown) => {
    const r = parseTokenBody(v);
    if (r.ok) throw new Error("expected a refusal");
    return r.issues.map((i) => i.path);
  };

  it("accepts the unchanged no-attestation body (and lowercases the challenge id)", () => {
    expect(ok(base)).toEqual({ challengeId: "aaaaaaaa-0000-4000-8000-000000000001", nonce: "abc", hardwareSupportsAttestation: false });
  });

  it("accepts an iOS block {platform, keyId, assertion} and an Android block {platform, integrityToken}", () => {
    expect(ok({ ...base, attestation: { platform: "ios", keyId: "S0VZ", assertion: "QVNTRVJU" } }).attestation).toEqual({ platform: "ios", keyId: "S0VZ", assertion: "QVNTRVJU" });
    expect(ok({ ...base, attestation: { platform: "android", integrityToken: "integrity-token.abc_def-1" } }).attestation).toEqual({ platform: "android", integrityToken: "integrity-token.abc_def-1" });
  });

  it("refuses an unknown top-level key", () => {
    expect(issues({ ...base, deviceId: D1 })).toEqual(["deviceId"]);
    expect(issues({ ...base, kind: "ios" })).toEqual(["kind"]);
  });

  it("refuses an unknown key inside either attestation block, and fields from the other platform", () => {
    expect(issues({ ...base, attestation: { platform: "ios", keyId: "S0VZ", assertion: "QVNT", extra: 1 } })).toEqual(["attestation.extra"]);
    expect(issues({ ...base, attestation: { platform: "ios", keyId: "S0VZ", assertion: "QVNT", integrityToken: "t" } })).toEqual(["attestation.integrityToken"]);
    expect(issues({ ...base, attestation: { platform: "android", integrityToken: "tok", keyId: "S0VZ" } })).toEqual(["attestation.keyId"]);
    expect(issues({ ...base, attestation: { platform: "android", integrityToken: "tok", deviceCheckToken: "x" } })).toEqual(["attestation.deviceCheckToken"]);
    // the activation spelling `kind` is not this endpoint's
    expect(issues({ ...base, attestation: { kind: "ios", keyId: "S0VZ", assertion: "QVNT" } })).toContain("attestation.platform");
  });

  it("refuses a malformed attestation: missing/oversized/ill-formed members, a non-object, an unknown platform", () => {
    expect(issues({ ...base, attestation: { platform: "ios", keyId: "S0VZ" } })).toEqual(["attestation.assertion"]);
    expect(issues({ ...base, attestation: { platform: "ios", keyId: "not base64!", assertion: "QVNT" } })).toEqual(["attestation.keyId"]);
    expect(issues({ ...base, attestation: { platform: "ios", keyId: "A".repeat(257), assertion: "QVNT" } })).toEqual(["attestation.keyId"]);
    expect(issues({ ...base, attestation: { platform: "ios", keyId: "S0VZ", assertion: "A".repeat(16 * 1024 + 1) } })).toEqual(["attestation.assertion"]);
    expect(issues({ ...base, attestation: { platform: "android" } })).toEqual(["attestation.integrityToken"]);
    expect(issues({ ...base, attestation: { platform: "android", integrityToken: "has space" } })).toEqual(["attestation.integrityToken"]);
    expect(issues({ ...base, attestation: { platform: "windows" } })).toEqual(["attestation.platform"]);
    expect(issues({ ...base, attestation: "ios" })).toEqual(["attestation"]);
    expect(issues({ ...base, attestation: null })).toEqual(["attestation"]);
    expect(issues({ ...base, attestation: [] })).toEqual(["attestation"]);
  });

  it("refuses a bad body: not an object, bad challenge id, missing nonce, non-boolean hardware claim", () => {
    expect(parseTokenBody(null).ok).toBe(false);
    expect(parseTokenBody([]).ok).toBe(false);
    expect(issues({ ...base, challengeId: "nope" })).toEqual(["challengeId"]);
    expect(issues({ challengeId: base.challengeId, hardwareSupportsAttestation: true })).toEqual(["nonce"]);
    expect(issues({ ...base, hardwareSupportsAttestation: "yes" })).toEqual(["hardwareSupportsAttestation"]);
  });
});

// ---------------------------------------------------------------------------
// iOS
// ---------------------------------------------------------------------------
describe("iOS: App Attest assertion over the check-in binding", () => {
  it("a valid assertion grades `attested`, advances the stored counter, issues an attested token, and raises no signal", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const out = await runIos(state, await iosToken(ch, { key, counter: 6 }));
    expect(out.attestationGrade).toBe("attested");
    expect(counterOf(state)).toBe(6);
    expect(tokens(state).map((t) => t.attestationGrade)).toEqual(["attested"]);
    expect(challengeUsed(state, ch.id)).toBe(true);
    expect(openSignals(state)).toEqual([]);
    expect(state.fraudSignals).toEqual([]);
  });

  it("the verifier is handed the key on record for THIS device and the binding the SERVER computes (a spy port)", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const spy = makeFakeIosPort({ assertion: (i) => ({ ok: true, counter: i.device.attestCounter + 1 }) });
    await runIos(state, await iosToken(ch, { key, counter: 6 }), deps({ ios: spy }));
    expect(spy.lastVerifyInput?.device.id).toBe(D1);
    expect(spy.lastVerifyInput?.keyId).toBe(await keyIdOf(key));
    expect(toHex(spy.lastVerifyInput!.clientDataHash)).toBe(toHex(await computeIosCheckinBinding(sha256, { challengeId: ch.id, deviceId: D1, nonce: ch.nonce, userId: USER_A })));
  });

  it("successive check-ins advance the counter each time; reusing the last counter then grades `failed`", async () => {
    const { state, key } = await iosWorld(5);
    for (const counter of [6, 7, 9]) {
      const ch = await issueChallenge(state);
      expect((await runIos(state, await iosToken(ch, { key, counter }))).attestationGrade).toBe("attested");
      expect(counterOf(state)).toBe(counter);
    }
    const ch = await issueChallenge(state);
    const out = await runIos(state, await iosToken(ch, { key, counter: 9 }));
    expect(out.attestationGrade).toBe("failed");
    expect(counterOf(state)).toBe(9);
  });

  // --- purpose separation -------------------------------------------------
  it("WRONG PURPOSE: an assertion over the reward-ACTIVATION binding presented to check-in grades `failed` and opens the signal", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const activationHash = await computeIosActivationBinding(sha256, {
      rewardId: "aaaaaaaa-0000-4000-8000-000000000001",
      deviceId: D1,
      challengeId: ch.id,
      deviceCheckTokenSha256: "ab".repeat(32),
      nonce: ch.nonce,
    });
    const out = await runIos(state, await iosToken(ch, { key, counter: 6, hash: activationHash }));
    expect(out.attestationGrade).toBe("failed");
    expect(counterOf(state)).toBe(5); // a failed assertion never advances the counter
    expect(openSignals(state)).toHaveLength(1);
    expect(openSignals(state)[0]!.detail).toMatchObject({ source: "checkin-token", reasons: ["bad_signature_or_request_hash"], platform: "ios", deviceId: D1, challengeId: ch.id });
  });

  it("WRONG PURPOSE: every other purpose string over the SAME fields and nonce fails: activation, key registration, a v2 label, empty, none", async () => {
    for (const purpose of ["reward_activation", "attest_key_registration", "golfraven/checkin-token/v2", "golfraven/checkin-token", "", undefined]) {
      const { state, key } = await iosWorld(5);
      const ch = await issueChallenge(state);
      const fields: Record<string, string> = { challengeId: ch.id, deviceId: D1, nonce: ch.nonce, platform: "ios", userId: USER_A };
      if (purpose !== undefined) fields.purpose = purpose;
      const out = await runIos(state, await iosToken(ch, { key, counter: 6, hash: await computeStringBinding(sha256, fields) }));
      expect(out.attestationGrade, String(purpose)).toBe("failed");
      expect(counterOf(state), String(purpose)).toBe(5);
    }
  });

  it("WRONG PURPOSE: an assertion over the key-REGISTRATION binding grades `failed`", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const regHash = await computeAttestKeyBinding(sha256, { challengeId: ch.id, deviceId: D1, keyId: await keyIdOf(key), nonce: ch.nonce });
    expect((await runIos(state, await iosToken(ch, { key, counter: 6, hash: regHash }))).attestationGrade).toBe("failed");
  });

  it("the reverse: a check-in assertion presented to reward ACTIVATION is graded `failed` there (held), and never issues a reward", async () => {
    const { state, key } = await iosWorld(5);
    seedReward(state, { id: "aaaaaaaa-0000-4000-8000-000000000001", userId: USER_A, kind: "offer_code" });
    const ch = await issueChallenge(state);
    const req = await iosToken(ch, { key, counter: 6 }); // signed over the CHECK-IN binding
    const att = req.attestation as { platform: "ios"; keyId: string; assertion: string };
    // The REAL verifier under activation's own binding: a check-in assertion cannot verify there.
    const port = { ...makeFakeIosPort(), verifyAssertion: buildIosAssertionPort(APP_ID, crypt).verifyAssertion };
    const out = await handleActivation(
      "aaaaaaaa-0000-4000-8000-000000000001",
      { deviceId: D1, platform: "ios", challengeId: ch.id, nonce: ch.nonce, attestation: { kind: "ios", keyId: att.keyId, assertion: att.assertion, deviceCheckToken: "REVWSUNF" } },
      makeFakeRepo(state, USER_A),
      { ports: { ios: port, android: null }, sha256 },
    );
    expect(out.held).toBe(true);
    expect(rewardsState(state).signals.filter((s) => s.kind === "attestation_failed")[0]!.detail).toMatchObject({ reasons: ["bad_signature_or_request_hash"] });
    expect(counterOf(state)).toBe(5);
  });

  // --- counter -------------------------------------------------------------
  it("a REPLAYED or NON-INCREASING counter grades `failed` (counter_not_monotonic), is not advanced, and opens the signal", async () => {
    for (const counter of [5, 4, 0]) {
      const { state, key } = await iosWorld(5);
      const ch = await issueChallenge(state);
      const out = await runIos(state, await iosToken(ch, { key, counter }));
      expect(out.attestationGrade, `counter ${counter}`).toBe("failed");
      expect(counterOf(state)).toBe(5);
      expect(openSignals(state)[0]!.detail).toMatchObject({ reasons: ["counter_not_monotonic"] });
    }
  });

  it("an assertion bound to a PREVIOUS challenge, replayed on a fresh challenge, grades `failed` and does not advance the counter", async () => {
    const { state, key } = await iosWorld(5);
    const ch1 = await issueChallenge(state);
    const first = await iosToken(ch1, { key, counter: 6 });
    expect((await runIos(state, first)).attestationGrade).toBe("attested");
    const ch2 = await issueChallenge(state);
    const replay: TokenRequest = { ...first, challengeId: ch2.id, nonce: ch2.nonce };
    expect((await runIos(state, replay)).attestationGrade).toBe("failed");
    expect(counterOf(state)).toBe(6);
  });

  it("a counter that verifies but LOSES the atomic advance (a concurrent request moved it) grades `failed` (counter_replay), never `attested`", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const real = buildIosAssertionPort(APP_ID, crypt);
    const racing = {
      verifyAssertion: async (input: Parameters<typeof real.verifyAssertion>[0]): Promise<AssertionResult> => {
        const r = await real.verifyAssertion(input);
        rewardsState(state).deviceAttest.get(D1)!.attestCounter = 9; // another request advanced it in between
        return r;
      },
    };
    const out = await runIos(state, await iosToken(ch, { key, counter: 6 }), deps({ ios: racing }));
    expect(out.attestationGrade).toBe("failed");
    expect(counterOf(state)).toBe(9);
    expect(openSignals(state)[0]!.detail).toMatchObject({ reasons: ["counter_replay"] });
  });

  it("an assertion whose key was REPLACED between the read and the advance grades `failed` (key_replaced), never `attested`", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const real = buildIosAssertionPort(APP_ID, crypt);
    const racing = {
      verifyAssertion: async (input: Parameters<typeof real.verifyAssertion>[0]): Promise<AssertionResult> => {
        const r = await real.verifyAssertion(input);
        const row = rewardsState(state).deviceAttest.get(D1)!;
        row.attestKeyId = "A-NEW-KEY-ID"; // a reinstall registered a new key (counter restarts)
        row.attestCounter = 0;
        return r;
      },
    };
    const out = await runIos(state, await iosToken(ch, { key, counter: 6 }), deps({ ios: racing }));
    expect(out.attestationGrade).toBe("failed");
    expect(counterOf(state)).toBe(0);
    expect(openSignals(state)[0]!.detail).toMatchObject({ reasons: ["key_replaced"] });
  });

  // --- key ownership -------------------------------------------------------
  it("a key registered to ANOTHER user's device grades `failed` (key_id_mismatch); the other user's counter is untouched", async () => {
    const { state, key: keyA } = await iosWorld(5);
    const keyB = await generateP256();
    seedDevice(state, { id: D2, userId: USER_B, platform: "ios", attestKeyId: await keyIdOf(keyB), attestCounter: 40, attestPublicKey: keyB.publicKeyRaw });
    const ch = await issueChallenge(state);
    // user-a signs with user-b's key and names user-b's key id
    const out = await runIos(state, await iosToken(ch, { key: keyB, counter: 41 }));
    expect(out.attestationGrade).toBe("failed");
    expect(openSignals(state)[0]!.detail).toMatchObject({ reasons: ["key_id_mismatch"] });
    expect(counterOf(state, D2)).toBe(40);
    expect(counterOf(state, D1)).toBe(5);
    // naming OWN key id but signing with the other user's key does not verify either
    const ch2 = await issueChallenge(state);
    const out2 = await runIos(state, await iosToken(ch2, { key: keyB, counter: 41, keyId: await keyIdOf(keyA) }));
    expect(out2.attestationGrade).toBe("failed");
    expect(counterOf(state, D2)).toBe(40);
  });

  it("another user cannot redeem this user's challenge, and so cannot spend this user's key (404; nothing consumed, no counter advance)", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const req = await iosToken(ch, { key, counter: 6 });
    const thief = makeFakeRepo(state, USER_B);
    expect(await statusOf(handleTokenRequest(req, thief, digestHex, iosDeps(USER_B)))).toEqual({ status: 404, code: "not_found" });
    expect(challengeUsed(state, ch.id)).toBe(false);
    expect(counterOf(state)).toBe(5);
  });

  it("a device with NO registered key grades `unattestable` (key_not_registered), as activation does: no signal, and never `attested`", async () => {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "ios", attestKeyId: null, attestPublicKey: null });
    const key = await generateP256();
    const ch = await issueChallenge(state);
    const out = await runIos(state, await iosToken(ch, { key, counter: 1 }));
    expect(out.attestationGrade).toBe("unattestable");
    expect(openSignals(state)).toEqual([]);
  });

  // --- nonce / challenge / device / user ----------------------------------
  it("WRONG NONCE signed: an assertion over a different nonce text grades `failed`", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const other = toBase64Url(randomBytes(32));
    const out = await runIos(state, await iosToken(ch, { key, counter: 6, bind: { nonce: other } }));
    expect(out.attestationGrade).toBe("failed");
    expect(counterOf(state)).toBe(5);
  });

  it("WRONG NONCE presented: the challenge is not consumable (422), nothing is issued, the counter does not move, and a retry with the right nonce works", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const good = await iosToken(ch, { key, counter: 6 });
    const wrongNonce = toBase64Url(randomBytes(32));
    expect(await statusOf(runIos(state, { ...good, nonce: wrongNonce }))).toEqual({ status: 422, code: "challenge_not_consumable" });
    expect(tokens(state)).toEqual([]);
    expect(counterOf(state)).toBe(5);
    expect(challengeUsed(state, ch.id)).toBe(false);
    expect((await runIos(state, good)).attestationGrade).toBe("attested");
  });

  it("a NON-CANONICAL spelling of the right nonce is refused (400) when an attestation is sent — one consumed nonce, one binding", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const last = ch.nonce.at(-1)!;
    const variant = ch.nonce.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1]; // flips an unused trailing bit: same bytes, different text
    expect(fromBase64UrlStrict(variant)).toBeNull();
    const req = await iosToken(ch, { key, counter: 6 });
    expect(await statusOf(runIos(state, { ...req, nonce: variant }))).toEqual({ status: 400, code: "bad_request" });
    expect(challengeUsed(state, ch.id)).toBe(false);
    // ...whereas the no-attestation path keeps its lenient decode, unchanged
    const keyless = makeFakeState();
    const ch2 = await issueChallenge(keyless);
    const variant2 = ch2.nonce.slice(0, -1) + alphabet[alphabet.indexOf(ch2.nonce.at(-1)!) ^ 1];
    const plain = await handleTokenRequest({ challengeId: ch2.id, nonce: variant2, hardwareSupportsAttestation: false }, makeFakeRepo(keyless, USER_A), digestHex);
    expect(plain.attestationGrade).toBe("unattestable");
  });

  it("WRONG CHALLENGE / DEVICE / USER signed: each grades `failed`", async () => {
    const variants: Array<[string, Partial<{ challengeId: string; deviceId: string; userId: string }>]> = [
      ["challenge", { challengeId: "00000000-0000-4000-8000-000000000999" }],
      ["device", { deviceId: D2 }],
      ["user", { userId: USER_B }],
    ];
    for (const [label, bind] of variants) {
      const { state, key } = await iosWorld(5);
      const ch = await issueChallenge(state);
      const out = await runIos(state, await iosToken(ch, { key, counter: 6, bind }));
      expect(out.attestationGrade, label).toBe("failed");
      expect(counterOf(state), label).toBe(5);
    }
  });

  it("the account bound is the AUTHENTICATED one: an assertion signed for user-a does not verify when the entrypoint says the actor is someone else", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const out = await runIos(state, await iosToken(ch, { key, counter: 6 }), iosDeps("some-other-uid"));
    expect(out.attestationGrade).toBe("failed");
  });

  // --- the signal ----------------------------------------------------------
  it("a failed attestation opens ONE open fraud_signal(attestation_failed) the way activation does (deduped while one is open); detail carries reasons only", async () => {
    const { state, key } = await iosWorld(5);
    for (let i = 0; i < 3; i++) {
      const ch = await issueChallenge(state);
      expect((await runIos(state, await iosToken(ch, { key, counter: 5 }))).attestationGrade).toBe("failed");
    }
    expect(openSignals(state)).toHaveLength(1);
    expect(state.fraudSignals.filter((s) => s.kind === "attestation_failed")).toHaveLength(1);
    const detail = openSignals(state)[0]!.detail;
    expect(Object.keys(detail).sort()).toEqual(["challengeId", "deviceId", "platform", "reasons", "source"]);
    expect(JSON.stringify(detail)).not.toMatch(/assertion|keyId|publicKey/i);
  });

  it("a failed attestation still issues a token graded `failed` (the grade IS the outcome, §4.5) and spends its challenge", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const out = await runIos(state, await iosToken(ch, { key, counter: 5 }));
    expect(out.attestationGrade).toBe("failed");
    expect(tokens(state).map((t) => t.attestationGrade)).toEqual(["failed"]);
    expect(challengeUsed(state, ch.id)).toBe(true);
  });

  it("a malformed assertion (not CBOR) grades `failed`, not a 500", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const req = await iosToken(ch, { key, counter: 6 });
    const bad: TokenRequest = { ...req, attestation: { platform: "ios", keyId: await keyIdOf(key), assertion: "AAAA" } };
    expect((await runIos(state, bad)).attestationGrade).toBe("failed");
    expect(openSignals(state)[0]!.detail).toMatchObject({ reasons: ["malformed_assertion"] });
  });
});

// ---------------------------------------------------------------------------
// Android
// ---------------------------------------------------------------------------
describe("Android: Play Integrity token over the check-in binding", () => {
  const PACKAGE = "com.example.golfraven";
  const CERT = "CERTDIGESTONE";
  let googlePem: string;
  beforeAll(async () => {
    const rsa = (await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", rsa.privateKey));
    googlePem = `-----BEGIN PRIVATE KEY-----\n${toB64(der).replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----`;
  }, 60_000);
  const google = (): PlayIntegrityConfig => ({ packageName: PACKAGE, certificateSha256Digests: [CERT], serviceAccountEmail: "svc@example.iam.gserviceaccount.test", serviceAccountPrivateKeyPem: googlePem });

  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  type Scripted = Response | Error | (() => Response);
  function scriptedHttp(responses: Scripted[]): VendorHttp & { calls: string[] } {
    const calls: string[] = [];
    let i = 0;
    return {
      calls,
      timeoutMs: 1_000,
      nowMs: () => 1_780_000_000_000,
      randomUuid: () => "00000000-0000-4000-8000-000000000001",
      async fetch(url) {
        calls.push(url);
        const r = responses[Math.min(i++, responses.length - 1)]!;
        if (r instanceof Error) throw r;
        return typeof r === "function" ? r() : r.clone();
      },
    };
  }
  const oauthOk = () => json(200, { access_token: "ya29.test", expires_in: 3600 });

  async function androidWorld() {
    const state = makeFakeState();
    seedDevice(state, { id: D1, userId: USER_A, platform: "android" });
    return state;
  }
  /** The requestHash an Android client must send, computed independently of the handler. */
  const expectedHash = async (ch: { id: string; nonceBytes: Uint8Array }, over: Partial<{ challengeId: string; deviceId: string; userId: string }> = {}) =>
    toBase64Url(await computeCheckinAndroidBinding(sha256, { challengeId: ch.id, deviceId: D1, userId: USER_A, ...over }, ch.nonceBytes));
  const payload = (state: FakeState, over: { requestHash: string; pkg?: string; cert?: string; recognition?: string; device?: string[]; ts?: number }) => ({
    requestDetails: { requestPackageName: over.pkg ?? PACKAGE, requestHash: over.requestHash, timestampMillis: String(over.ts ?? state.now.getTime()) },
    appIntegrity: { appRecognitionVerdict: over.recognition ?? "PLAY_RECOGNIZED", certificateSha256Digest: [over.cert ?? CERT] },
    deviceIntegrity: { deviceRecognitionVerdict: over.device ?? ["MEETS_DEVICE_INTEGRITY"] },
  });
  const androidReq = (ch: { id: string; nonce: string }): TokenRequest => ({
    challengeId: ch.id,
    nonce: ch.nonce,
    hardwareSupportsAttestation: true,
    attestation: { platform: "android", integrityToken: "TOKEN.abc_def-1" },
  });
  const run = (state: FakeState, req: TokenRequest, http: VendorHttp) => handleTokenRequest(req, makeFakeRepo(state, USER_A), digestHex, deps({ android: buildAndroidPort(google(), http) }));
  const decodeResponse = (p: unknown) => json(200, { tokenPayloadExternal: p });

  it("a valid verdict over our requestHash grades `attested`, issues an attested token, and raises no signal", async () => {
    const state = await androidWorld();
    const ch = await issueChallenge(state);
    const http = scriptedHttp([oauthOk(), decodeResponse(payload(state, { requestHash: await expectedHash(ch) }))]);
    const out = await run(state, androidReq(ch), http);
    expect(out.attestationGrade).toBe("attested");
    expect(tokens(state).map((t) => t.attestationGrade)).toEqual(["attested"]);
    expect(openSignals(state)).toEqual([]);
    expect(http.calls.some((u) => u.includes(":decodeIntegrityToken"))).toBe(true);
  });

  it("the port is asked for exactly base64url(SHA-256(canonical_body ‖ raw nonce bytes)) and the handler's clock (a spy port)", async () => {
    const state = await androidWorld();
    const ch = await issueChallenge(state);
    let seen: { expectedRequestHash: string; nowMs: number; integrityToken: string } | null = null;
    const spy: AndroidPort = {
      async verifyIntegrity(i) {
        seen = i;
        return { grade: "attested" };
      },
    };
    await handleTokenRequest(androidReq(ch), makeFakeRepo(state, USER_A), digestHex, deps({ android: spy }));
    expect(seen).toEqual({ expectedRequestHash: await expectedHash(ch), nowMs: state.now.getTime(), integrityToken: "TOKEN.abc_def-1" });
  });

  it("a requestHash over the wrong binding grades `failed`: activation body, another purpose, another nonce/device/user/challenge", async () => {
    const wrong: Array<[string, (ch: { id: string; nonceBytes: Uint8Array }) => Promise<string>]> = [
      ["activation body", async (ch) => toBase64Url(await computeRequestBinding(sha256, { rewardId: USER_A, deviceId: D1, platform: "android", challengeId: ch.id }, ch.nonceBytes))],
      [
        "another purpose",
        async (ch) =>
          toBase64Url(await sha256(new Uint8Array([...new TextEncoder().encode(canonicalJson({ challengeId: ch.id, deviceId: D1, platform: "android", purpose: "reward_activation", userId: USER_A })), ...ch.nonceBytes]))),
      ],
      ["another nonce", async (ch) => toBase64Url(await computeCheckinAndroidBinding(sha256, { challengeId: ch.id, deviceId: D1, userId: USER_A }, randomBytes(32)))],
      ["another device", (ch) => expectedHash(ch, { deviceId: D2 })],
      ["another user", (ch) => expectedHash(ch, { userId: USER_B })],
      ["another challenge", (ch) => expectedHash(ch, { challengeId: "00000000-0000-4000-8000-000000000999" })],
    ];
    for (const [label, hashOf] of wrong) {
      const state = await androidWorld();
      const ch = await issueChallenge(state);
      const http = scriptedHttp([oauthOk(), decodeResponse(payload(state, { requestHash: await hashOf(ch) }))]);
      const out = await run(state, androidReq(ch), http);
      expect(out.attestationGrade, label).toBe("failed");
      expect(openSignals(state)[0]!.detail, label).toMatchObject({ source: "checkin-token", platform: "android", reasons: ["request_hash_mismatch"] });
    }
  });

  it("a wrong PACKAGE, a certificate digest that is not allowed, an unrecognised app, a failing device verdict, and a stale verdict each grade `failed` with their reason", async () => {
    const cases: Array<[string, (h: string, s: FakeState) => unknown, string]> = [
      ["package", (h, s) => payload(s, { requestHash: h, pkg: "com.evil.app" }), "package_name_mismatch"],
      ["cert", (h, s) => payload(s, { requestHash: h, cert: "SOMEOTHERCERT" }), "certificate_digest_not_allowed"],
      ["app recognition", (h, s) => payload(s, { requestHash: h, recognition: "UNRECOGNIZED_VERSION" }), "app_not_play_recognized"],
      ["device integrity (basic only)", (h, s) => payload(s, { requestHash: h, device: ["MEETS_BASIC_INTEGRITY"] }), "device_integrity_not_met"],
      ["device integrity (empty verdict)", (h, s) => payload(s, { requestHash: h, device: [] }), "device_integrity_not_met"],
      ["stale verdict", (h, s) => payload(s, { requestHash: h, ts: s.now.getTime() - 6 * 60_000 }), "verdict_not_fresh"],
    ];
    for (const [label, build, reason] of cases) {
      const state = await androidWorld();
      const ch = await issueChallenge(state);
      const http = scriptedHttp([oauthOk(), decodeResponse(build(await expectedHash(ch), state))]);
      const out = await run(state, androidReq(ch), http);
      expect(out.attestationGrade, label).toBe("failed");
      expect(openSignals(state)[0]!.detail, label).toMatchObject({ reasons: [reason] });
    }
  });

  it("a payload that is not a verdict at all grades `failed`, not a 500", async () => {
    const state = await androidWorld();
    const ch = await issueChallenge(state);
    const out = await run(state, androidReq(ch), scriptedHttp([oauthOk(), decodeResponse({ nothing: "useful" })]));
    expect(out.attestationGrade).toBe("failed");
  });

  it("Google rejecting the token itself (400: cannot decode) grades `failed` (token_rejected_by_google)", async () => {
    const state = await androidWorld();
    const ch = await issueChallenge(state);
    const out = await run(state, androidReq(ch), scriptedHttp([oauthOk(), new Response("", { status: 400 })]));
    expect(out.attestationGrade).toBe("failed");
    expect(openSignals(state)[0]!.detail).toMatchObject({ reasons: ["token_rejected_by_google"] });
  });

  it("a rejection raised by the port as an exception is NOT a vendor outage: only the port's own mapping decides (VendorRejectedError escaping a custom port propagates, never a silent grade)", async () => {
    const state = await androidWorld();
    const ch = await issueChallenge(state);
    const port: AndroidPort = {
      async verifyIntegrity() {
        throw new VendorRejectedError("x");
      },
    };
    await expect(handleTokenRequest(androidReq(ch), makeFakeRepo(state, USER_A), digestHex, deps({ android: port }))).rejects.toBeInstanceOf(VendorRejectedError);
    expect(openSignals(state)).toEqual([]);
  });

  // --- vendor unavailable ---------------------------------------------------
  describe("vendor / transport errors are NEVER graded `failed`: 503, no failed token, no fraud signal", () => {
    const outages: Array<[string, () => Scripted[], string]> = [
      ["decodeIntegrityToken answers 503", () => [oauthOk(), new Response("", { status: 503 })], "attestation_unavailable"],
      ["decodeIntegrityToken answers 500", () => [oauthOk(), new Response("", { status: 500 })], "attestation_unavailable"],
      ["decodeIntegrityToken answers 429 (quota)", () => [oauthOk(), new Response("", { status: 429 })], "attestation_unavailable"],
      ["decodeIntegrityToken network failure", () => [oauthOk(), new Error("ECONNRESET")], "attestation_unavailable"],
      ["the response is not JSON", () => [oauthOk(), new Response("<html>", { status: 200 })], "attestation_unavailable"],
      ["the response has no payload", () => [oauthOk(), json(200, {})], "attestation_unavailable"],
      ["the OAuth exchange answers 500", () => [new Response("", { status: 500 })], "attestation_unavailable"],
      ["the OAuth exchange cannot connect", () => [new Error("ENOTFOUND")], "attestation_unavailable"],
      ["our service-account credentials are rejected (401)", () => [new Response("", { status: 401 })], "attestation_not_configured"],
      ["Google rejects the decode with 403", () => [oauthOk(), new Response("", { status: 403 })], "attestation_not_configured"],
    ];
    for (const [label, script, code] of outages) {
      it(`${label} -> 503 ${code}`, async () => {
        const state = await androidWorld();
        const ch = await issueChallenge(state);
        const err = await statusOf(run(state, androidReq(ch), scriptedHttp(script())));
        expect(err).toEqual({ status: 503, code });
        expect(tokens(state)).toEqual([]); // nothing issued, so nothing graded `failed`
        expect(openSignals(state)).toEqual([]);
        expect(state.fraudSignals).toEqual([]);
      });
    }

    it("a 5xx on the vendor leaves the SAME challenge usable for a retry against a recovered vendor (real transaction rollback: checkin-attest.deno.test.ts)", async () => {
      const state = await androidWorld();
      const ch = await issueChallenge(state);
      const snapshot = structuredClone(state.challenges.get(ch.id)!);
      // The fake Repo has no transaction, so emulate what withOwnership does on a throw: roll back what the handler wrote.
      await expect(run(state, androidReq(ch), scriptedHttp([oauthOk(), new Response("", { status: 503 })]))).rejects.toBeInstanceOf(HttpError);
      state.challenges.set(ch.id, snapshot);
      const out = await run(state, androidReq(ch), scriptedHttp([oauthOk(), decodeResponse(payload(state, { requestHash: await expectedHash(ch) }))]));
      expect(out.attestationGrade).toBe("attested");
    });
  });
});

// ---------------------------------------------------------------------------
// not configured / no attestation
// ---------------------------------------------------------------------------
describe("configuration and the no-attestation path", () => {
  it("an attestation for a platform with NO port fails closed (503 attestation_not_configured) BEFORE the challenge is touched; nothing is issued or signalled", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    const req = await iosToken(ch, { key, counter: 6 });
    for (const d of [undefined, deps({}), deps({ android: { verifyIntegrity: async () => ({ grade: "attested" as const }) } })]) {
      expect(await statusOf(handleTokenRequest(req, makeFakeRepo(state, USER_A), digestHex, d))).toEqual({ status: 503, code: "attestation_not_configured" });
    }
    expect(challengeUsed(state, ch.id)).toBe(false);
    expect(tokens(state)).toEqual([]);
    expect(openSignals(state)).toEqual([]);
    expect(counterOf(state)).toBe(5);
    // and an Android attestation with only an iOS port
    const andReq: TokenRequest = { ...req, attestation: { platform: "android", integrityToken: "T" } };
    expect(await statusOf(handleTokenRequest(andReq, makeFakeRepo(state, USER_A), digestHex, iosDeps()))).toEqual({ status: 503, code: "attestation_not_configured" });
  });

  it("buildVerificationPorts: a half-set configuration is NOT configured", () => {
    const http = { fetch: async () => new Response(""), nowMs: () => 0, randomUuid: () => "x", timeoutMs: 1 } as VendorHttp;
    expect(buildVerificationPorts({ appId: null, google: null }, http, crypt)).toEqual({ ios: null, android: null });
    expect(buildVerificationPorts({ appId: "", google: { packageName: "p", certificateSha256Digests: [], serviceAccountEmail: "e", serviceAccountPrivateKeyPem: "k" } }, http, crypt)).toEqual({ ios: null, android: null });
    const ok = buildVerificationPorts({ appId: APP_ID, google: { packageName: "p", certificateSha256Digests: ["d"], serviceAccountEmail: "e", serviceAccountPrivateKeyPem: "k" } }, http, crypt);
    expect(ok.ios).not.toBeNull();
    expect(ok.android).not.toBeNull();
    // verification only: the iOS port can verify an assertion and nothing else (no persistent-bit methods exist on it)
    expect(Object.keys(ok.ios!)).toEqual(["verifyAssertion"]);
    expect(Object.keys(ok.android!)).toEqual(["verifyIntegrity"]);
  });

  it("NO attestation: hardwareSupportsAttestation=true grades `failed` + signal; false grades `unattestable` — unchanged, with or without deps", async () => {
    for (const d of [undefined, iosDeps()]) {
      const s1 = makeFakeState();
      const c1 = await issueChallenge(s1);
      expect((await handleTokenRequest({ challengeId: c1.id, nonce: c1.nonce, hardwareSupportsAttestation: true }, makeFakeRepo(s1, USER_A), digestHex, d)).attestationGrade).toBe("failed");
      expect(s1.fraudSignals.some((s) => s.kind === "attestation_failed")).toBe(true);
      const s2 = makeFakeState();
      const c2 = await issueChallenge(s2);
      expect((await handleTokenRequest({ challengeId: c2.id, nonce: c2.nonce, hardwareSupportsAttestation: false }, makeFakeRepo(s2, USER_A), digestHex, d)).attestationGrade).toBe("unattestable");
      expect(s2.fraudSignals).toEqual([]);
    }
  });

  it("NO attestation never consults a verifier (no port is called) and never touches the device counter", async () => {
    const { state } = await iosWorld(5);
    const spy = makeFakeIosPort();
    const ch = await issueChallenge(state);
    await handleTokenRequest({ challengeId: ch.id, nonce: ch.nonce, hardwareSupportsAttestation: false }, makeFakeRepo(state, USER_A), digestHex, deps({ ios: spy }));
    expect(spy.calls.verify).toBe(0);
    expect(counterOf(state)).toBe(5);
  });

  it("the issued token carries the challenge's own device and kind (unchanged), whatever the grade", async () => {
    const { state, key } = await iosWorld(5);
    const ch = await issueChallenge(state);
    await runIos(state, await iosToken(ch, { key, counter: 6 }));
    expect(tokens(state)[0]).toMatchObject({ deviceId: D1, challengeKind: "live", challengeId: ch.id, userId: USER_A });
  });
});
