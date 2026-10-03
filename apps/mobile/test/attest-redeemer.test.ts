/**
 * P4.2b-2: what a check-in redemption carries (`src/attest/redeemer.ts`), against a fake native module and a scripted HTTP layer.
 * Each `describe` is one rule of the file's header.
 */
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AttestationDeferred, PlainRedeemer, attestKeyBinding, bytesToBase64Url, bytesToHex, iosCheckinBinding, wireRequest } from "../src/attest";
import { ApiError } from "../src/api/errors";
import { apiError } from "./support/fakes";
import { CHALLENGE, DEVICE, NONCE, USER, grade, input, makeRig, tokenFor } from "./support/attest-rig";

const IOS_HASH = "3c695d6c71722843731e7a80e63d987d628181755c5925db5401f9d36b8077e5";
const ANDROID_HASH = "8CGJ1X3iXQCcqYH4U7fjJrnceadzDEz5avKmy_idkl0";

afterEach(() => vi.useRealTimers());

const deferred = <T = void>() => {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((a, b) => {
    resolve = a;
    reject = b;
  });
  return { promise, resolve, reject };
};
const tick = async (n = 80): Promise<void> => {
  for (let i = 0; i < n; i += 1) await Promise.resolve();
};

/** Registers an iOS key through the redeemer's own flow once, so later redemptions find a registered key. */
async function registeredIos() {
  const rig = makeRig("ios");
  await rig.redeemer.redeem(input(), rig.io());
  rig.posts.length = 0;
  rig.registrations.length = 0;
  rig.timeline.length = 0;
  rig.module.events.length = 0;
  return rig;
}

describe("rule 1 — HONEST CAPABILITY: hardwareSupportsAttestation is true if and only if the request carries an attestation", () => {
  it("wireRequest is the only constructor: the claim follows the block, never a free input", () => {
    expect(wireRequest({ challengeId: "c", nonce: "n" })).toEqual({ challengeId: "c", nonce: "n", hardwareSupportsAttestation: false });
    const withBlock = wireRequest({ challengeId: "c", nonce: "n" }, { platform: "android", integrityToken: "t" });
    expect(withBlock).toEqual({ challengeId: "c", nonce: "n", hardwareSupportsAttestation: true, attestation: { platform: "android", integrityToken: "t" } });
    expect("attestation" in wireRequest({ challengeId: "c", nonce: "n" })).toBe(false); // absent, never `undefined`
  });

  it("PlainRedeemer (no native attestor) never claims", async () => {
    const rig = makeRig("android");
    await new PlainRedeemer().redeem(input(), rig.io());
    expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
  });

  it("across every outcome that reaches the server, claim === (attestation present): Android success, Android local failure (never attested), iOS success, iOS refused registration", async () => {
    const seen: { claim: boolean; has: boolean }[] = [];
    const note = (posts: { hardwareSupportsAttestation: boolean; attestation?: unknown }[]) => posts.forEach((p) => seen.push({ claim: p.hardwareSupportsAttestation, has: p.attestation !== undefined }));

    const a = makeRig("android");
    await a.redeemer.redeem(input(), a.io());
    note(a.posts);

    const f = makeRig("android");
    f.module.always.integrityToken = { ok: false, code: "unavailable", message: "no play services" };
    await f.redeemer.redeem(input(), f.io());
    note(f.posts);

    const i = makeRig("ios");
    await i.redeemer.redeem(input(), i.io());
    note(i.posts);

    const r = makeRig("ios");
    r.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
    await r.redeemer.redeem(input(), r.io());
    note(r.posts);

    expect(seen).toEqual([
      { claim: true, has: true },
      { claim: false, has: false },
      { claim: true, has: true },
      { claim: false, has: false },
    ]);
    expect(seen.every((s) => s.claim === s.has)).toBe(true);
  });

  it("a request that cannot carry an attestation never claims one, even on hardware that can attest (never-attested Android, local failure)", async () => {
    const rig = makeRig("android");
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" };
    await rig.redeemer.redeem(input(), rig.io());
    expect(rig.posts).toHaveLength(1);
    expect(rig.posts[0]).toEqual({ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false });
  });
});

describe("Android: the check-in binding goes to Play Integrity, and the attestation block is what the server's strict parser takes", () => {
  it("requestHash is the recorded vector (challenge cccc…, device bbbb…, the TOKEN's sub, nonce 1..32) and the token rides in {platform:'android', integrityToken}", async () => {
    const rig = makeRig("android");
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(rig.module.ops("integrityToken")).toEqual([{ op: "integrityToken", cloud: "123456789012", requestHash: ANDROID_HASH }]);
    expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: true, attestation: { platform: "android", integrityToken: `it.${ANDROID_HASH}` } }]);
  });

  it("the account in the binding is the access token's `sub`, not a free argument: a token for another account is not attested for this one", async () => {
    const rig = makeRig("android");
    await expect(rig.redeemer.redeem(input({ accessToken: tokenFor("someone-else") }), rig.io())).rejects.toMatchObject({ reason: "account_mismatch" });
    await expect(rig.redeemer.redeem(input({ accessToken: "not-a-jwt" }), rig.io())).rejects.toMatchObject({ reason: "no_account_binding" });
    expect(rig.module.events.length).toBe(0);
    expect(rig.posts).toEqual([]);
  });

  it("a binding field dropped would change the hash the module is given (guards the wiring: the hash the module saw is the one for exactly this challenge, device and account)", async () => {
    const rig = makeRig("android");
    await rig.redeemer.redeem(input({ deviceId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbc" }), rig.io());
    const seen = rig.module.ops("integrityToken")[0] as { requestHash: string };
    expect(seen.requestHash).not.toBe(ANDROID_HASH);
  });
});

describe("rule 2 — NEVER TOKEN-LESS ONCE THE DEVICE HAS SHOWN IT CAN ATTEST (Android: the attested-before rule)", () => {
  it("a device that has NEVER attested and cannot get a token now sends token-less with the claim false (the server grades `unattestable`)", async () => {
    const rig = makeRig("android");
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "Play services updating" };
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested"); // whatever the scripted server says; what matters is what was sent:
    expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
  });

  it("after ONE token graded `attested`, the fact is persisted; from then on a local failure sends NOTHING and defers", async () => {
    const rig = makeRig("android");
    await rig.redeemer.redeem(input(), rig.io()); // grade attested
    expect(await rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    rig.posts.length = 0;
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "no network to Google" };
    await expect(rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-ccccccccccc2" }), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.posts).toEqual([]); // no token-less request: it would be graded `failed` + fraud signal
  });

  it("the fact survives a restart (it is in the secure store, keyed per user AND device), and is not shared with another user or device", async () => {
    const rig = makeRig("android");
    await rig.redeemer.redeem(input(), rig.io());
    expect(rig.secure.keys().some((k) => k.startsWith("gr.attest.android_attested."))).toBe(true);
    expect(await rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    expect(await rig.state.hasAttestedAndroid("other-user", DEVICE)).toBe(false);
    expect(await rig.state.hasAttestedAndroid(USER, "aaaaaaaa-bbbb-4bbb-8bbb-bbbbbbbbbbbb")).toBe(false);
  });

  it("only a grade of `attested` records it: `unattestable` and `failed` grades do not (a failed token proves nothing)", async () => {
    for (const g of ["unattestable", "failed"] as const) {
      const rig = makeRig("android");
      rig.postReplies = [grade(g)];
      await rig.redeemer.redeem(input(), rig.io());
      expect(await rig.state.hasAttestedAndroid(USER, DEVICE), g).toBe(false);
    }
  });

  it("a token that was SENT and whose outcome is unknown (network error, 5xx) marks the device as attested-before (the server may have graded it `attested`); a definite non-application (503 attestation_*, 4xx) does not", async () => {
    for (const [e, marked] of [
      [apiError("network", 0, null), true],
      [apiError("server", 500, "internal_error"), true],
      [apiError("unavailable", 503, "attestation_unavailable"), false],
      [apiError("rejected", 422, "challenge_used"), false],
      [apiError("rate_limited", 429, "rate_limited"), false],
    ] as const) {
      const rig = makeRig("android");
      rig.postReplies = [e];
      await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBe(e);
      expect(await rig.state.hasAttestedAndroid(USER, DEVICE), `${e.kind}/${e.code}`).toBe(marked);
    }
    // and the next local failure then defers
    const rig = makeRig("android");
    rig.postReplies = [apiError("network", 0, null)];
    await rig.redeemer.redeem(input(), rig.io()).catch(() => undefined);
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" };
    rig.posts.length = 0;
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.posts).toEqual([]);
  });

  it("an unreadable store reads as 'attested before' (the unsafe reading is 'never'): defer, do not send token-less", async () => {
    const rig = makeRig("android");
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" };
    rig.state.hasAttestedAndroid = () => Promise.reject(new Error("keystore locked"));
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.posts).toEqual([]);
  });

  it("a non-canonical nonce is a local failure (the binding refuses it): same rule", async () => {
    const rig = makeRig("android");
    await rig.redeemer.redeem(input(), rig.io());
    rig.posts.length = 0;
    await expect(rig.redeemer.redeem(input({ nonce: "AB" }), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.posts).toEqual([]);
  });

  it("iOS: while a key is registered or pending, no token-less request is ever sent, whatever fails locally", async () => {
    const rig = await registeredIos();
    rig.module.always.generateAssertion = { ok: false, code: "unavailable", message: "Apple is down" };
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "assertion_unavailable" });
    rig.module.destroyKeys();
    delete rig.module.always.generateAssertion;
    rig.module.always.generateKey = { ok: false, code: "other", message: "no" };
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.posts).toEqual([]);
  });
});

describe("rule 4 — a 503 attestation_unavailable / attestation_not_configured from checkin-token is rethrown untouched (the challenge was not consumed)", () => {
  it.each([
    ["Android", "android"],
    ["iOS", "ios"],
  ] as const)("%s: the ApiError reaches the caller as it is, and the same challenge can be redeemed again", async (_n, platform) => {
    const rig = makeRig(platform);
    const e503 = apiError("unavailable", 503, "attestation_unavailable");
    rig.postReplies = [e503, grade("attested")];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBe(e503);
    const again = await rig.redeemer.redeem(input(), rig.io());
    expect(again.attestationGrade).toBe("attested");
    expect(rig.posts.map((p) => p.challengeId)).toEqual([CHALLENGE, CHALLENGE]); // the SAME challenge, twice
    expect(rig.posts.every((p) => p.hardwareSupportsAttestation && p.attestation !== undefined)).toBe(true);
  });

  it("a 503 does not set the attested-before mark and does not clear an iOS key", async () => {
    const a = makeRig("android");
    a.postReplies = [apiError("unavailable", 503, "attestation_not_configured")];
    await expect(a.redeemer.redeem(input(), a.io())).rejects.toBeInstanceOf(ApiError);
    expect(await a.state.hasAttestedAndroid(USER, DEVICE)).toBe(false);
    const i = await registeredIos();
    const before = await i.state.getIosKey(USER, DEVICE);
    i.postReplies = [apiError("unavailable", 503, "attestation_unavailable")];
    await expect(i.redeemer.redeem(input(), i.io())).rejects.toBeInstanceOf(ApiError);
    expect(await i.state.getIosKey(USER, DEVICE)).toEqual(before);
  });
});

describe("rule 5 — iOS key lifecycle", () => {
  it("first need: live challenge -> generateKey -> attestKey over the registration binding -> POST devices-attest-key -> key kept -> assertion -> POST checkin-token", async () => {
    const rig = makeRig("ios");
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(rig.timeline).toEqual(["http:live", "native:generateKey", "native:attestKey", "http:register", "native:generateAssertion", "http:post:start", "http:post:end"]);
    const reg = rig.registrations[0]!;
    const live = { id: "dddddddd-dddd-4ddd-8ddd-000000000001", nonce: NONCE };
    expect(reg).toMatchObject({ deviceId: DEVICE, challengeId: live.id, nonce: live.nonce });
    expect(reg.keyId).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    // attestKey was given SHA-256(UTF-8(S)) of exactly the registration binding the server computes
    const att = rig.module.ops("attestKey")[0] as { keyId: string; hashHex: string };
    expect(att.keyId).toBe(reg.keyId);
    expect(att.hashHex).toBe(bytesToHex(attestKeyBinding({ challengeId: live.id, deviceId: DEVICE, keyId: reg.keyId, nonce: live.nonce })));
    // the key is in the secure store, registered, for this user and device
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: reg.keyId });
    // the check-in request: assertion over the CHECK-IN binding (the recorded vector), the registered key id
    const asr = rig.module.ops("generateAssertion")[0] as { keyId: string; hashHex: string };
    expect(asr.keyId).toBe(reg.keyId);
    expect(asr.hashHex).toBe(IOS_HASH);
    expect(rig.posts[0]).toEqual({
      challengeId: CHALLENGE,
      nonce: NONCE,
      hardwareSupportsAttestation: true,
      attestation: { platform: "ios", keyId: reg.keyId, assertion: expect.any(String) },
    });
  });

  it("the second redemption reuses the stored key: no new key, no registration", async () => {
    const rig = makeRig("ios");
    await rig.redeemer.redeem(input(), rig.io());
    const keyId = rig.registrations[0]!.keyId;
    await rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-ccccccccccc2" }), rig.io());
    expect(rig.module.ops("generateKey")).toHaveLength(1);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.module.ops("generateAssertion").map((e) => (e as { keyId: string }).keyId)).toEqual([keyId, keyId]);
  });

  it("a key id is per USER and per DEVICE: another account on the same install registers its own; the first account's record is untouched", async () => {
    const rig = makeRig("ios");
    await rig.redeemer.redeem(input(), rig.io());
    const b = "vvvvvvvv-vvvv-4vvv-8vvv-vvvvvvvvvvvv";
    await rig.redeemer.redeem(input({ userId: b, accessToken: tokenFor(b) }), rig.io());
    expect(rig.registrations).toHaveLength(2);
    expect(rig.registrations[0]!.keyId).not.toBe(rig.registrations[1]!.keyId);
    expect(await rig.state.getIosKey(USER, DEVICE)).toMatchObject({ state: "registered", keyId: rig.registrations[0]!.keyId });
    expect(await rig.state.getIosKey(b, DEVICE)).toMatchObject({ state: "registered", keyId: rig.registrations[1]!.keyId });
    expect(rig.secure.keys().filter((k) => k.startsWith("gr.attest.ios_key."))).toHaveLength(2);
  });

  it("DCError.invalidKey on the assertion (a reinstall): the key is dropped and a fresh one registered ONCE, then the assertion succeeds with the new key", async () => {
    const rig = await registeredIos();
    const oldKey = (await rig.state.getIosKey(USER, DEVICE) as { keyId: string }).keyId;
    rig.module.destroyKeys(); // the Secure Enclave key is gone, the Keychain record is not
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(rig.timeline).toEqual(["native:generateAssertion", "http:live", "native:generateKey", "native:attestKey", "http:register", "native:generateAssertion", "http:post:start", "http:post:end"]);
    const fresh = rig.registrations[0]!.keyId;
    expect(fresh).not.toBe(oldKey);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: fresh });
    expect(rig.posts[0]!.attestation).toMatchObject({ platform: "ios", keyId: fresh });
  });

  it("invalid key AGAIN right after the re-registration is not retried a second time: defer (one re-registration per redemption)", async () => {
    const rig = await registeredIos();
    rig.module.destroyKeys();
    rig.module.always.generateAssertion = { ok: false, code: "invalid_key", message: "still invalid" };
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "key_invalid_after_registration" });
    expect(rig.module.ops("generateKey")).toHaveLength(1);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.posts).toEqual([]);
  });

  it("a key that was JUST registered and is invalid at once is not registered a second time in the same redemption: defer", async () => {
    const rig = makeRig("ios");
    rig.module.next.generateAssertion = [{ ok: false, code: "invalid_key", message: "invalid at once" }];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "key_invalid_after_registration" });
    expect(rig.module.ops("generateKey")).toHaveLength(1);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.posts).toEqual([]);
  });

  it("the server already holds exactly this key (409 key_already_registered: our first request was applied and its answer lost) -> treated as registered", async () => {
    const rig = makeRig("ios");
    rig.registerReplies = [apiError("conflict", 409, "key_already_registered")];
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(await rig.state.getIosKey(USER, DEVICE)).toMatchObject({ state: "registered" });
    expect(rig.posts).toHaveLength(1);
  });

  it("the registration is REFUSED (422 attestation_rejected: a dev build against a production deployment) and the server holds no key: nothing is registered, the record is cleared, the check-in goes token-less with the claim false", async () => {
    const rig = makeRig("ios");
    rig.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested"); // scripted reply; what matters is the request:
    expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
    expect(await rig.state.getIosKey(USER, DEVICE)).toBeNull();
    expect(rig.module.ops("generateAssertion")).toEqual([]);
  });

  it("a refusal when the server MAY already hold a key (a registered key was dropped for invalidKey; or a `pending` record) defers instead of going token-less, and keeps the `pending` mark", async () => {
    const rig = await registeredIos();
    rig.module.destroyKeys();
    rig.registerReplies = [apiError("rejected", 422, "platform_mismatch")];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "pending" });
    expect(rig.posts).toEqual([]);
    // the next redemption sees `pending` and defers again on a refusal (never token-less)
    rig.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
    expect(rig.posts).toEqual([]);
  });

  it("a transport failure DURING registration leaves `pending` (the server may have applied it), is rethrown as the ApiError (retry), and the retry registers a NEW key", async () => {
    const rig = makeRig("ios");
    const net = apiError("network", 0, null);
    rig.registerReplies = [net, undefined];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBe(net);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "pending" });
    expect(rig.posts).toEqual([]);
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(rig.registrations).toHaveLength(2);
    expect(rig.registrations[0]!.keyId).not.toBe(rig.registrations[1]!.keyId);
    expect(await rig.state.getIosKey(USER, DEVICE)).toMatchObject({ state: "registered", keyId: rig.registrations[1]!.keyId });
  });

  it("an answer that is about the REGISTRATION (a used / expired live challenge, 422 challenge_not_consumable) never reaches the caller as a refusal of the CHECK-IN challenge: it is a deferral", async () => {
    const rig = makeRig("ios");
    rig.registerReplies = [apiError("rejected", 422, "challenge_not_consumable")];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    const rig2 = makeRig("ios");
    rig2.liveReplies = [apiError("rejected", 400, "bad_request")];
    await expect(rig2.redeemer.redeem(input(), rig2.io())).rejects.toBeInstanceOf(AttestationDeferred);
    // while transport / account errors in that phase pass through
    const rig3 = makeRig("ios");
    const e429 = apiError("rate_limited", 429, "rate_limited");
    rig3.liveReplies = [e429];
    await expect(rig3.redeemer.redeem(input(), rig3.io())).rejects.toBe(e429);
    const rig4 = makeRig("ios");
    const e401 = apiError("unauthenticated", 401, null);
    rig4.registerReplies = [e401];
    await expect(rig4.redeemer.redeem(input(), rig4.io())).rejects.toBe(e401);
  });

  it("generateKey / attestKey failing LOCALLY defer, send nothing, and leave NO record: no registration was sent, so the server cannot hold a key (`pending` is written only right before the registration request)", async () => {
    const a = makeRig("ios");
    a.module.always.generateKey = { ok: false, code: "unavailable", message: "x" };
    await expect(a.redeemer.redeem(input(), a.io())).rejects.toMatchObject({ reason: "generate_key_failed" });
    const b = makeRig("ios");
    b.module.always.attestKey = { ok: false, code: "unavailable", message: "x" };
    await expect(b.redeemer.redeem(input(), b.io())).rejects.toMatchObject({ reason: "attest_key_failed" });
    for (const r of [a, b]) {
      expect(await r.state.getIosKey(USER, DEVICE)).toBeNull();
      expect(r.registrations).toEqual([]);
      expect(r.posts).toEqual([]);
    }
  });

  it("a failure BEFORE the registration is sent (a 429 on the live challenge) leaves no `pending` mark, so a build whose registrations are later REFUSED still falls back to token-less `unattestable` (not a permanent deferral)", async () => {
    const rig = makeRig("ios");
    const e429 = apiError("rate_limited", 429, "rate_limited");
    rig.liveReplies = [e429];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBe(e429);
    expect(await rig.state.getIosKey(USER, DEVICE)).toBeNull();
    rig.liveReplies = [];
    rig.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
    await rig.redeemer.redeem(input(), rig.io());
    expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
  });

  it("invalid key, and a LOCAL failure before the fresh registration is sent: the record is already `pending` (the server still holds the old key), so the next redemption cannot go token-less after a refusal", async () => {
    const rig = await registeredIos();
    rig.module.destroyKeys();
    rig.module.next.generateKey = [{ ok: false, code: "unavailable", message: "x" }];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "generate_key_failed" });
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "pending" });
    rig.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
    expect(rig.posts).toEqual([]);
  });

  it("we presented a verifiable assertion and the server graded `unattestable` (it holds no key for this device): the local record is dropped so the next redemption registers again", async () => {
    const rig = await registeredIos();
    rig.postReplies = [grade("unattestable")];
    await rig.redeemer.redeem(input(), rig.io());
    expect(await rig.state.getIosKey(USER, DEVICE)).toBeNull();
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input(), rig.io());
    expect(rig.registrations).toHaveLength(1); // re-registered
  });

  it("an unreadable / unwritable key store defers; a corrupt record reads as `pending` (forgetting a registered key is the unsafe direction)", async () => {
    const rig = makeRig("ios");
    rig.secure.get = () => Promise.reject(new Error("keychain locked"));
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "key_state_unreadable" });
    const rig2 = makeRig("ios");
    await rig2.secure.set(`gr.attest.ios_key.${USER}.${DEVICE}`, "{not json");
    expect(await rig2.state.getIosKey(USER, DEVICE)).toEqual({ state: "pending" });
    const rig3 = makeRig("ios");
    rig3.secure.set = () => Promise.reject(new Error("keychain full"));
    await expect(rig3.redeemer.redeem(input(), rig3.io())).rejects.toMatchObject({ reason: "key_state_unwritable" });
    expect(rig3.posts).toEqual([]);
  });
});

describe("rule 3 — ONE ASSERTION IN FLIGHT PER KEY: held from generateAssertion until the HTTP response returns or fails", () => {
  it("two concurrent check-ins are strictly sequential END TO END: the second assertion is not generated until the first request has answered", async () => {
    const rig = await registeredIos();
    const gate1 = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate1.promise, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await tick();
    // first: asserted and its request is in flight; second: NOT asserted yet
    expect(rig.timeline).toEqual(["native:generateAssertion", "http:post:start"]);
    gate1.resolve(grade("attested"));
    await Promise.all([p1, p2]);
    expect(rig.timeline).toEqual([
      "native:generateAssertion", "http:post:start", "http:post:end",
      "native:generateAssertion", "http:post:start", "http:post:end",
    ]);
    expect(rig.posts.map((p) => p.challengeId)).toEqual(["cccccccc-cccc-4ccc-8ccc-cccccccccc01", "cccccccc-cccc-4ccc-8ccc-cccccccccc02"]);
  });

  it("the counter order equals the arrival order: assertions are generated in call order (the fake's counter is 1 then 2) and posted in the same order", async () => {
    const rig = await registeredIos();
    const slow = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => slow.promise, grade()];
    rig.module.assertionGate = Promise.resolve();
    const ps = [1, 2, 3].map((n) => rig.redeemer.redeem(input({ challengeId: `cccccccc-cccc-4ccc-8ccc-cccccccccc0${n}` }), rig.io()));
    await tick();
    slow.resolve(grade());
    await Promise.all(ps);
    const counters = rig.posts.map((p) => Buffer.from((p.attestation as { assertion: string }).assertion, "base64").toString().split(":")[2]);
    expect(counters).toEqual(["2", "3", "4"]); // the registration redemption used counter 1; three more, in call order
  });

  it("the lock is held while the first assertion is being GENERATED too (a slow platform call): nothing overlaps", async () => {
    const rig = await registeredIos();
    const gate = deferred();
    rig.module.assertionGate = gate.promise;
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await tick();
    expect(rig.module.ops("generateAssertion")).toHaveLength(1);
    gate.resolve();
    await Promise.all([p1, p2]);
    expect(rig.module.ops("generateAssertion")).toHaveLength(2);
  });

  it("released on ERROR: a request that fails (network) does not block the next check-in", async () => {
    const rig = await registeredIos();
    const net = apiError("network", 0, null);
    rig.postReplies = [net, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await expect(p1).rejects.toBe(net);
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.timeline.filter((t) => t === "native:generateAssertion")).toHaveLength(2);
  });

  it("released on a LOCAL failure too (assertion refused): the next one still runs", async () => {
    const rig = await registeredIos();
    rig.module.next.generateAssertion = [{ ok: false, code: "unavailable", message: "x" }];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await expect(p1).rejects.toBeInstanceOf(AttestationDeferred);
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
  });

  it("released on TIMEOUT: a request that never answers is abandoned after the hold time as a deferral, and the next check-in proceeds", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    await rig.redeemer.redeem(input(), rig.io()); // register the key first
    rig.timeline.length = 0;
    rig.module.events.length = 0;
    rig.posts.length = 0;
    rig.registrations.length = 0;
    const never = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => never.promise, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p1Result = p1.then(
      () => "resolved",
      (e: unknown) => e,
    );
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(4_999);
    expect(rig.module.ops("generateAssertion")).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(2);
    expect(await p1Result).toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.module.ops("generateAssertion")).toHaveLength(2);
  });

  it("different keys (another account, or another device) do NOT wait for each other", async () => {
    const rig = makeRig("ios");
    const b = "vvvvvvvv-vvvv-4vvv-8vvv-vvvvvvvvvvvv";
    await rig.redeemer.redeem(input(), rig.io());
    await rig.redeemer.redeem(input({ userId: b, accessToken: tokenFor(b) }), rig.io());
    rig.timeline.length = 0;
    rig.posts.length = 0;
    const gate = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate.promise, () => gate.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02", userId: b, accessToken: tokenFor(b) }), rig.io());
    await tick();
    expect(rig.timeline.filter((t) => t === "native:generateAssertion")).toHaveLength(2); // both asserted before either answered
    gate.resolve(grade());
    await Promise.all([p1, p2]);
  });

  it("two concurrent FIRST redemptions on a fresh install register ONE key (the registration is inside the lock)", async () => {
    const rig = makeRig("ios");
    await Promise.all([
      rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io()),
      rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io()),
    ]);
    expect(rig.module.ops("generateKey")).toHaveLength(1);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.module.ops("generateAssertion")).toHaveLength(2);
  });
});

describe("sanity of the rig itself", () => {
  it("the recorded iOS hash is what the redeemer hands the module (independent SHA-256 of S)", () => {
    const S = `{"challengeId":"${CHALLENGE}","deviceId":"${DEVICE}","nonce":"${NONCE}","platform":"ios","purpose":"golfraven/checkin-token/v1","userId":"${USER}"}`;
    expect(createHash("sha256").update(S).digest("hex")).toBe(IOS_HASH);
    expect(bytesToHex(iosCheckinBinding({ challengeId: CHALLENGE, deviceId: DEVICE, userId: USER, nonce: NONCE }))).toBe(IOS_HASH);
    expect(bytesToBase64Url(Uint8Array.from(Buffer.from(IOS_HASH, "hex"))).length).toBe(43);
  });
});
