/**
 * P4.2b-2: what a check-in redemption carries (`src/attest/redeemer.ts`), against a fake native module and a scripted HTTP layer.
 * Each `describe` is one rule of the file's header.
 */
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AttestationDeferred, LockReentryError, PlainRedeemer, assertionLockKey, attestKeyBinding, bytesToBase64Url, bytesToHex, iosCheckinBinding, withAssertionLock, wireRequest } from "../src/attest";
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
      [apiError("unavailable", 504, null), true], // a gateway timeout: the request may have been executed
      [apiError("unavailable", 502, null), true],
      [apiError("unavailable", 503, null), true], // a 503 that is NOT the attestation_* rollback
      [apiError("unavailable", 503, "service_unavailable"), true],
      [apiError("bad_response", 201, null), true], // a 201 whose body could not be read: it WAS applied
      [apiError("unavailable", 503, "attestation_unavailable"), false],
      [apiError("unavailable", 503, "attestation_not_configured"), false],
      [apiError("rejected", 422, "challenge_used"), false],
      [apiError("rejected", 400, "bad_request"), false],
      [apiError("unauthenticated", 401, null), false],
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
    expect(rig.timeline).toEqual(["native:generateKey", "http:live", "native:attestKey", "http:register", "native:generateAssertion", "http:post:start", "http:post:end"]);
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
    expect(rig.timeline).toEqual(["native:generateAssertion", "native:generateKey", "http:live", "native:attestKey", "http:register", "native:generateAssertion", "http:post:start", "http:post:end"]);
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

  describe("PR #42 gate MEDIUM-2: a deployment that cannot hold an App Attest key (503 attestation_not_configured from devices-attest-key)", () => {
    const e503 = () => apiError("unavailable", 503, "attestation_not_configured");

    it("nothing was applied: the `pending` mark is cleared (no earlier key), THIS redemption goes token-less with the claim false, and the registration is not retried for the backoff", async () => {
      let t = 1_000_000;
      const rig = makeRig("ios", { now: () => t, backoffMs: 60_000 });
      rig.registerReplies = [e503()];
      await rig.redeemer.redeem(input(), rig.io());
      expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
      expect(await rig.state.getIosKey(USER, DEVICE)).toBeNull(); // no `pending` left behind
      expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(t + 60_000);
      expect(rig.registrations).toHaveLength(1);
      // every retry inside the backoff: no live challenge, no generateKey, no attestKey, no registration, token-less again
      rig.timeline.length = 0;
      const keys = rig.module.ops("generateKey").length;
      for (let i = 0; i < 3; i += 1) {
        t += 10_000;
        await rig.redeemer.redeem(input(), rig.io());
      }
      expect(rig.timeline.filter((x) => x !== "http:post:start" && x !== "http:post:end")).toEqual([]);
      expect(rig.module.ops("generateKey")).toHaveLength(keys);
      expect(rig.registrations).toHaveLength(1);
      expect(rig.posts.every((p) => !p.hardwareSupportsAttestation && p.attestation === undefined)).toBe(true);
      // after the backoff ONE new attempt is made (a fixed deployment is picked up); success clears the backoff
      t += 60_000;
      rig.registerReplies = [undefined];
      rig.postReplies = [grade("attested")];
      const r = await rig.redeemer.redeem(input(), rig.io());
      expect(r.attestationGrade).toBe("attested");
      expect(rig.registrations).toHaveLength(2);
      expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(0);
      expect(await rig.state.getIosKey(USER, DEVICE)).toMatchObject({ state: "registered" });
    });

    it("the backoff is PERSISTED: a new redeemer over the same secure store (an app restart) still honours it", async () => {
      const t = 5_000_000;
      const rig = makeRig("ios", { now: () => t, backoffMs: 60_000 });
      rig.registerReplies = [e503()];
      await rig.redeemer.redeem(input(), rig.io());
      const again = makeRig("ios", { now: () => t + 1_000, backoffMs: 60_000 });
      for (const k of rig.secure.keys()) await again.secure.set(k, (await rig.secure.get(k))!);
      await again.redeemer.redeem(input(), again.io());
      expect(again.timeline.filter((x) => x.startsWith("native:") || x === "http:live" || x === "http:register")).toEqual([]);
      expect(again.posts[0]).toEqual({ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false });
    });

    it("when a key MAY already be on record (a dropped invalid key, or a pending mark) the same 503 defers instead of going token-less, keeps `pending`, and still sets the backoff", async () => {
      const t = 9_000_000;
      const rig = await registeredIos();
      const rig2 = makeRig("ios", { now: () => t, backoffMs: 60_000 });
      for (const k of rig.secure.keys()) await rig2.secure.set(k, (await rig.secure.get(k))!);
      rig2.module.keys.add((await rig2.state.getIosKey(USER, DEVICE) as { keyId: string }).keyId);
      rig2.module.destroyKeys();
      rig2.registerReplies = [e503()];
      await expect(rig2.redeemer.redeem(input(), rig2.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
      expect(await rig2.state.getIosKey(USER, DEVICE)).toEqual({ state: "pending" });
      expect(rig2.posts).toEqual([]);
      expect(await rig2.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(t + 60_000);
      // inside the backoff nothing is attempted and nothing is sent
      rig2.timeline.length = 0;
      await expect(rig2.redeemer.redeem(input(), rig2.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
      expect(rig2.timeline).toEqual([]);
    });

    it("any OTHER 503 from devices-attest-key (a gateway, a transient outage) is still transient: rethrown for a retry, `pending` kept, no backoff", async () => {
      for (const code of [null, "service_unavailable", "attestation_unavailable"]) {
        const rig = makeRig("ios");
        const e = apiError("unavailable", 503, code);
        rig.registerReplies = [e];
        await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toBe(e);
        expect(await rig.state.getIosKey(USER, DEVICE), String(code)).toEqual({ state: "pending" });
        expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE), String(code)).toBe(0);
      }
    });

    it("a refusal of the key itself (422 attestation_rejected) sets the same backoff, so a mismatched build does not spend a live challenge on every retry", async () => {
      const t = 3_000_000;
      const rig = makeRig("ios", { now: () => t, backoffMs: 60_000 });
      rig.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
      await rig.redeemer.redeem(input(), rig.io());
      expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(t + 60_000);
      rig.timeline.length = 0;
      await rig.redeemer.redeem(input(), rig.io());
      expect(rig.timeline).toEqual(["http:post:start", "http:post:end"]);
    });
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

  it("generateKey failing LOCALLY defers, sends nothing, spends NO live challenge (the key is made BEFORE the challenge is requested) and leaves no record", async () => {
    const a = makeRig("ios");
    a.module.always.generateKey = { ok: false, code: "other", message: "x" };
    await expect(a.redeemer.redeem(input(), a.io())).rejects.toMatchObject({ reason: "generate_key_failed" });
    expect(a.timeline).toEqual(["native:generateKey"]); // no http:live
    expect(await a.state.getIosKey(USER, DEVICE)).toBeNull();
    expect(a.registrations).toEqual([]);
    expect(a.posts).toEqual([]);
  });

  it("attestKey failing with a service outage keeps the SAME key and retries it next time (no new generateKey); any other attestKey failure burns the key", async () => {
    const rig = makeRig("ios");
    rig.module.next.attestKey = [{ ok: false, code: "unavailable", message: "Apple attestation service down" }];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "attest_key_unavailable" });
    expect(await rig.state.getIosKey(USER, DEVICE)).toBeNull();
    const kept = await rig.state.getUnattestedKey(USER, DEVICE);
    expect(kept).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(rig.module.ops("generateKey")).toHaveLength(1); // the same key
    expect(rig.registrations).toHaveLength(1);
    expect(rig.registrations[0]!.keyId).toBe(kept);
    expect(await rig.state.getUnattestedKey(USER, DEVICE)).toBeNull(); // attested: cleared

    const burn = makeRig("ios");
    burn.module.next.attestKey = [{ ok: false, code: "other", message: "invalid input" }];
    await expect(burn.redeemer.redeem(input(), burn.io())).rejects.toMatchObject({ reason: "attest_key_failed" });
    expect(await burn.state.getUnattestedKey(USER, DEVICE)).toBeNull();
    await burn.redeemer.redeem(input(), burn.io());
    expect(burn.module.ops("generateKey")).toHaveLength(2); // a new key
  });

  it("the device cannot do App Attest at all (generateKey / attestKey answer `unsupported`): nothing is registered, it goes token-less with the claim false, and registration is not retried for the backoff (the `unattestable` mapping matters)", async () => {
    const rig = makeRig("ios");
    rig.module.next.generateKey = [{ ok: false, code: "unsupported", message: "featureUnsupported" }];
    await rig.redeemer.redeem(input(), rig.io());
    expect(rig.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
    expect(rig.timeline).not.toContain("http:live");
    expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBeGreaterThan(Date.now());
    const k = makeRig("ios");
    k.module.next.attestKey = [{ ok: false, code: "unsupported", message: "x" }];
    await k.redeemer.redeem(input(), k.io());
    expect(k.posts).toEqual([{ challengeId: CHALLENGE, nonce: NONCE, hardwareSupportsAttestation: false }]);
    expect(await k.state.getIosKey(USER, DEVICE)).toBeNull();
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

  // ---- PR #42 gate HIGH-1: a lock timeout must not leave the abandoned holder running OUTSIDE the lock -----------------------------------------------

  /** The state the client and the (scripted) server end in: the key the client believes in, and the last key the server was asked to register. */
  const consistent = async (rig: ReturnType<typeof makeRig>): Promise<void> => {
    const rec = await rig.state.getIosKey(USER, DEVICE);
    const serverKey = rig.registrations.length > 0 ? rig.registrations[rig.registrations.length - 1]!.keyId : null;
    expect(rec).toEqual(serverKey === null ? null : { state: "registered", keyId: serverKey });
    // every assertion-carrying post names the key the server holds
    for (const p of rig.posts) if (p.attestation?.platform === "ios") expect(p.attestation.keyId).toBe(serverKey);
  };

  it("the gate's PoC: the first holder stalls in generateKey past the hold time; the next check-in registers key B; when the first resumes it does NOTHING (no key A registered, no state written): client and server end holding the same key", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    const gate = deferred();
    rig.module.stall.generateKey = [gate.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p1Result = p1.then(() => "resolved", (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await p1Result).toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.registrations).toHaveLength(1);
    const before = { events: rig.timeline.length, posts: rig.posts.length, key: await rig.state.getIosKey(USER, DEVICE) };
    gate.resolve(); // the stuck native call finally returns key A
    await vi.advanceTimersByTimeAsync(10);
    expect(rig.timeline.length).toBe(before.events + 0); // nothing new: no live challenge, no attestKey, no register, no assertion, no post
    expect(rig.posts.length).toBe(before.posts);
    expect(rig.registrations).toHaveLength(1);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual(before.key);
    expect(await rig.state.getUnattestedKey(USER, DEVICE)).toBeNull(); // the abandoned holder did not even store key A
    await consistent(rig);
  });

  it.each(["generateKey", "attestKey", "generateAssertion"] as const)("NO side effect after abort, whichever native call the holder was stuck in (%s): nothing it does on resuming reaches the state, the server or the key", async (op) => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    if (op === "generateAssertion") {
      await rig.redeemer.redeem(input(), rig.io()); // a registered key first
      rig.timeline.length = 0;
      rig.posts.length = 0; // (the registration stays on record: it is what the server holds)
    }
    const gate = deferred();
    rig.module.stall[op] = [gate.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p1Result = p1.then(() => "resolved", (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await p1Result).toMatchObject({ reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    const snapshot = JSON.stringify({ t: rig.timeline, p: rig.posts, r: rig.registrations, k: await rig.state.getIosKey(USER, DEVICE), u: await rig.state.getUnattestedKey(USER, DEVICE), s: rig.secure.dump() });
    gate.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(JSON.stringify({ t: rig.timeline, p: rig.posts, r: rig.registrations, k: await rig.state.getIosKey(USER, DEVICE), u: await rig.state.getUnattestedKey(USER, DEVICE), s: rig.secure.dump() })).toBe(snapshot);
    await consistent(rig);
  });

  it("an aborted holder whose stuck native call returns a FAILURE still writes nothing: generateKey `unsupported` after the abort sets no backoff, and an `invalid_key` assertion after the abort does not downgrade the record or register a key", async () => {
    vi.useFakeTimers();
    // (a) generateKey answers `unsupported` after the abort
    const a = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    const gA = deferred();
    a.module.stall.generateKey = [gA.promise];
    a.module.next.generateKey = [{ ok: false, code: "unsupported", message: "x" }];
    const a1 = a.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), a.io()).then(() => "ok", (e: unknown) => e);
    a.module.next.generateKey = [{ ok: false, code: "unsupported", message: "x" }];
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await a1).toMatchObject({ reason: "assertion_lock_timeout" });
    expect(await a.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(0);
    gA.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(await a.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(0); // the abandoned holder wrote no backoff
    // (b) an invalid_key assertion after the abort
    const b = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    vi.useRealTimers();
    await b.redeemer.redeem(input(), b.io());
    vi.useFakeTimers();
    b.timeline.length = 0;
    const regs = b.registrations.length;
    const keyBefore = await b.state.getIosKey(USER, DEVICE);
    const gB = deferred();
    b.module.stall.generateAssertion = [gB.promise];
    b.module.next.generateAssertion = [{ ok: false, code: "invalid_key", message: "gone" }];
    const b1 = b.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), b.io()).then(() => "ok", (e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await b1).toMatchObject({ reason: "assertion_lock_timeout" });
    gB.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(b.registrations).toHaveLength(regs);
    expect(await b.state.getIosKey(USER, DEVICE)).toEqual(keyBefore); // not downgraded to `pending`
    expect(b.timeline.filter((x) => x === "http:live" || x === "http:register" || x === "native:generateKey")).toEqual([]);
  });

  it("a holder stuck BEFORE its first native call (a slow secure-store read) that resumes after the abort does not generate an assertion", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    vi.useRealTimers();
    await rig.redeemer.redeem(input(), rig.io()); // a registered key
    vi.useFakeTimers();
    rig.timeline.length = 0;
    rig.posts.length = 0;
    const gate = deferred();
    const realGet = rig.secure.get.bind(rig.secure);
    let first = true;
    rig.secure.get = async (k: string) => {
      if (first) {
        first = false;
        await gate.promise;
      }
      return realGet(k);
    };
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io()).then(() => "ok", (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await p1).toMatchObject({ reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    const assertions = rig.module.ops("generateAssertion").length;
    gate.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(rig.module.ops("generateAssertion")).toHaveLength(assertions); // none for the abandoned holder
    expect(rig.posts).toHaveLength(1);
  });

  it("the lock is NOT released while a request that was SENT is in flight: a post that outlives the hold time keeps the next check-in waiting, and its real answer is returned (not thrown away)", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    await rig.redeemer.redeem(input(), rig.io());
    rig.timeline.length = 0;
    rig.posts.length = 0;
    const slow = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => slow.promise, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(60_000); // far past the hold time
    expect(rig.timeline).toEqual(["native:generateAssertion", "http:post:start"]); // the second has NOT asserted
    slow.resolve(grade("attested"));
    await expect(p1).resolves.toMatchObject({ attestationGrade: "attested" }); // the sent request's answer is kept
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.timeline).toEqual(["native:generateAssertion", "http:post:start", "http:post:end", "native:generateAssertion", "http:post:start", "http:post:end"]);
  });

  it("the same for a key REGISTRATION in flight: it is never abandoned, the key is recorded as it settles, and the waiting check-in then asserts with THAT key", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    const slow = deferred();
    rig.registerReplies = [() => slow.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(60_000);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.module.ops("generateKey")).toHaveLength(1); // p2 has not started a second registration
    slow.resolve();
    // p1 was told to stop at its next step (the aborted holder performs no further effect: its assertion is not generated), p2 then reuses the registered key
    await expect(p1).rejects.toMatchObject({ reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.registrations).toHaveLength(1);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: rig.registrations[0]!.keyId });
    await consistent(rig);
  });

  it("each native call has its OWN timeout: a stuck attestKey is a transient local failure after it, the lock is released normally and the key is kept for a retry", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 90_000, nativeTimeoutMs: 1_000 });
    rig.module.stall.attestKey = [deferred().promise]; // never answers
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p1Result = p1.then(() => "resolved", (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(1_001);
    expect(await p1Result).toMatchObject({ reason: "attest_key_unavailable" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.module.ops("generateKey")).toHaveLength(1); // p2 retried the SAME key
    // an assertion that never answers
    const rig2 = makeRig("ios", { holdMs: 90_000, nativeTimeoutMs: 1_000 });
    await rig2.redeemer.redeem(input(), rig2.io());
    rig2.module.stall.generateAssertion = [deferred().promise];
    const q = rig2.redeemer.redeem(input(), rig2.io());
    const qResult = q.then(() => "resolved", (e: unknown) => e);
    await vi.advanceTimersByTimeAsync(1_001);
    expect(await qResult).toMatchObject({ reason: "assertion_unavailable" });
  });

  it("assertionLockKey lowercases the device id: the same device spelled in upper and lower case is ONE lock (serialised), and the lock is the one the activation seam takes", async () => {
    expect(assertionLockKey(USER, DEVICE.toUpperCase())).toBe(assertionLockKey(USER, DEVICE));
    const rig = await registeredIos();
    const gate = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate.promise, grade()];
    const p1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02", deviceId: DEVICE.toUpperCase() }), rig.io());
    await tick();
    expect(rig.module.ops("generateAssertion")).toHaveLength(1);
    gate.resolve(grade());
    await Promise.all([p1, p2]);
    expect(rig.module.ops("generateAssertion")).toHaveLength(2);
  });

  it("the activation seam (P4.2c): withAssertionLock takes the EXACT lock check-in uses, so a check-in assertion waits for an activation holding it, and the other way round", async () => {
    const rig = await registeredIos();
    const holder = deferred();
    const seam = withAssertionLock(rig.locks, USER, DEVICE.toUpperCase(), async (g) => {
      g.check();
      await holder.promise;
      return "activated";
    });
    const redeem = rig.redeemer.redeem(input(), rig.io());
    await tick();
    expect(rig.module.ops("generateAssertion")).toHaveLength(0); // waiting behind the activation
    holder.resolve();
    expect(await seam).toBe("activated");
    await expect(redeem).resolves.toMatchObject({ attestationGrade: "attested" });
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

describe("rule 3 on ANDROID — check-in redemption takes the assertion lock (PR #44 gate LOW-1)", () => {
  const FAIL = { ok: false, code: "unavailable", message: "no network to Google" } as const;
  const C1 = "cccccccc-cccc-4ccc-8ccc-cccccccccc01";
  const C2 = "cccccccc-cccc-4ccc-8ccc-cccccccccc02";

  it("two concurrent Android check-ins are strictly sequential END TO END: the second does not call Play Integrity until the first request has answered", async () => {
    const rig = makeRig("android");
    const gate1 = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate1.promise, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await tick();
    expect(rig.timeline).toEqual(["native:integrityToken", "http:post:start"]);
    expect(rig.locks.pendingKeys()).toEqual([assertionLockKey(USER, DEVICE)]);
    gate1.resolve(grade("attested"));
    await Promise.all([p1, p2]);
    expect(rig.timeline).toEqual(["native:integrityToken", "http:post:start", "http:post:end", "native:integrityToken", "http:post:start", "http:post:end"]);
    expect(rig.posts.map((p) => p.challengeId)).toEqual([C1, C2]);
    expect(rig.locks.pendingKeys()).toEqual([]);
  });

  it("the lock is held while Play Integrity is being asked too (a slow platform call): nothing overlaps", async () => {
    const rig = makeRig("android");
    const gate = deferred();
    rig.module.stall.integrityToken = [gate.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await tick();
    expect(rig.module.ops("integrityToken")).toHaveLength(1);
    gate.resolve();
    await Promise.all([p1, p2]);
    expect(rig.module.ops("integrityToken")).toHaveLength(2);
  });

  it("the gate's race between two Android check-ins: the first has a token in flight, the second fails locally; the second reads the mark only AFTER the first's `attested` grade is recorded, so it defers", async () => {
    const rig = makeRig("android");
    const gate = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    await tick();
    rig.module.always.integrityToken = FAIL;
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    const r2 = p2.then(() => "resolved", (e: unknown) => e);
    await tick();
    expect(rig.posts).toHaveLength(1); // the second has sent nothing, token-less or otherwise
    gate.resolve(grade("attested"));
    await p1;
    expect(await r2).toMatchObject({ name: "AttestationDeferred", reason: "integrity_token_unavailable" });
    expect(rig.posts).toHaveLength(1);
  });

  it("the attested-before READ and the token-less POST happen inside the lock: a holder paused in the read, or with its token-less request in flight, keeps the next check-in out", async () => {
    const rig = makeRig("android");
    rig.module.always.integrityToken = FAIL; // never attested: the first goes token-less
    const readGate = deferred();
    const postGate = deferred<ReturnType<typeof grade>>();
    const realRead = rig.state.hasAttestedAndroid.bind(rig.state);
    rig.state.hasAttestedAndroid = async (u, d) => {
      rig.timeline.push("state:read");
      await readGate.promise;
      return realRead(u, d);
    };
    rig.postReplies = [() => postGate.promise, grade("unattestable")];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await tick();
    // the first is inside its read; the second has not started at all (no native call, no read)
    expect(rig.timeline).toEqual(["native:integrityToken", "state:read"]);
    readGate.resolve();
    await tick();
    // the first's TOKEN-LESS request is in flight; the second is still queued
    expect(rig.timeline).toEqual(["native:integrityToken", "state:read", "http:post:start"]);
    expect(rig.posts).toEqual([{ challengeId: C1, nonce: NONCE, hardwareSupportsAttestation: false }]);
    postGate.resolve(grade("unattestable"));
    await Promise.all([p1, p2]);
    expect(rig.timeline).toEqual([
      "native:integrityToken", "state:read", "http:post:start", "http:post:end",
      "native:integrityToken", "state:read", "http:post:start", "http:post:end",
    ]);
  });

  it("released on ERROR, on a LOCAL failure (a deferral) and on a thrown read: the next check-in still runs", async () => {
    const rig = makeRig("android");
    const net = apiError("network", 0, null);
    rig.postReplies = [net, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await expect(p1).rejects.toBe(net);
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    // now attested-before: a local failure defers (inside the lock) and still releases it
    rig.module.always.integrityToken = FAIL;
    await expect(rig.redeemer.redeem(input({ challengeId: C1 }), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    delete rig.module.always.integrityToken;
    await expect(rig.redeemer.redeem(input({ challengeId: C2 }), rig.io())).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.locks.pendingKeys()).toEqual([]);
  });

  it("the lock is the activation's EXACT lock (same key as iOS, device id case-folded): a different device does not wait, the same device in upper case does", async () => {
    const rig = makeRig("android");
    const holder = deferred();
    const seam = withAssertionLock(rig.locks, USER, DEVICE.toUpperCase(), async (g) => {
      g.check();
      await holder.promise;
      return "activated";
    });
    const waiting = rig.redeemer.redeem(input(), rig.io());
    const other = rig.redeemer.redeem(input({ deviceId: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }), rig.io());
    await expect(other).resolves.toMatchObject({ attestationGrade: "attested" });
    await tick();
    expect(rig.module.ops("integrityToken")).toHaveLength(1); // only the other device's
    holder.resolve();
    expect(await seam).toBe("activated");
    await expect(waiting).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.module.ops("integrityToken")).toHaveLength(2);
  });

  it("an aborted Android holder (stuck in Play Integrity past the hold time) defers, sends nothing and writes nothing when the call finally returns; the next check-in is not blocked", async () => {
    vi.useFakeTimers();
    const rig = makeRig("android", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    const gate = deferred();
    rig.module.stall.integrityToken = [gate.promise];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const r1 = p1.then(() => "resolved", (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await r1).toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.posts.map((p) => p.challengeId)).toEqual([C2]);
    gate.resolve(); // the stuck call finally returns a token
    await vi.advanceTimersByTimeAsync(10);
    expect(rig.posts.map((p) => p.challengeId), "the aborted holder sent nothing").toEqual([C2]);
  });

  it("a request that was SENT is never abandoned by the hold timeout, and its real answer (and the attested mark) is kept", async () => {
    vi.useFakeTimers();
    const rig = makeRig("android", { holdMs: 5_000 });
    const gate = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate.promise, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await vi.advanceTimersByTimeAsync(20_000);
    expect(rig.posts).toHaveLength(1); // the second is still waiting
    gate.resolve(grade("attested"));
    await expect(p1).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(await rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
  });
});

describe("the state write that follows a SENT request is held by the lock (`settle`): the hold timeout cannot release it mid-write (PR #42 / #44 gate NITs)", () => {
  const C1 = "cccccccc-cccc-4ccc-8ccc-cccccccccc01";
  const C2 = "cccccccc-cccc-4ccc-8ccc-cccccccccc02";

  it("Android: the attested mark is slow past the hold time: the lock stays held, the next check-in waits, the real answer is returned, the mark is written", async () => {
    vi.useFakeTimers();
    const rig = makeRig("android", { holdMs: 5_000 });
    const gate = deferred();
    const orig = rig.state.markAttestedAndroid.bind(rig.state);
    let slow = true;
    rig.state.markAttestedAndroid = async (u, d) => {
      if (slow) {
        slow = false;
        await gate.promise;
      }
      return orig(u, d);
    };
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const r1 = p1.then((r) => r, (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await vi.advanceTimersByTimeAsync(9_000); // past the 5 s hold time, inside the 10 s settle bound
    expect(rig.posts).toHaveLength(1); // the second has not started: the lock was not released under the write
    expect(rig.module.ops("integrityToken")).toHaveLength(1);
    gate.resolve();
    expect(await r1).toMatchObject({ attestationGrade: "attested" });
    expect(await rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
  });

  it("Android: the same for the mark written after a token whose outcome is UNKNOWN (the request failed): the error still reaches the caller, after the write", async () => {
    vi.useFakeTimers();
    const rig = makeRig("android", { holdMs: 5_000 });
    const gate = deferred();
    const orig = rig.state.markAttestedAndroid.bind(rig.state);
    rig.state.markAttestedAndroid = async (u, d) => {
      await gate.promise;
      return orig(u, d);
    };
    const e = apiError("network", 0, null);
    rig.postReplies = [e];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io()).then(() => "resolved", (x: unknown) => x);
    await vi.advanceTimersByTimeAsync(9_000); // past the 5 s hold time, inside the 10 s settle bound
    gate.resolve();
    expect(await p1).toBe(e);
    expect(await rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(true);
  });

  it("iOS: the record of a registration that WAS applied is slow past the hold time: the lock stays held, so the next check-in finds the key it names (never a second registration)", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    const gate = deferred();
    const orig = rig.state.setIosKey.bind(rig.state);
    rig.state.setIosKey = async (u, d, rec) => {
      if (rec.state === "registered") await gate.promise;
      return orig(u, d, rec);
    };
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const r1 = p1.then((r) => r, (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await vi.advanceTimersByTimeAsync(9_000); // past the 5 s hold time, inside the 10 s settle bound
    expect(rig.module.ops("generateAssertion")).toHaveLength(0);
    gate.resolve();
    // the first holder was told to stop (the hold time is long gone) and does not go on to assert; but its registration WAS applied, and the record it kept names it
    expect(await r1).toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.registrations).toHaveLength(1);
    expect(rig.posts.map((p) => (p.attestation as { keyId: string }).keyId)).toEqual([rig.registrations[0]!.keyId]);
  });

  it("iOS: the stale mark of a `rekey` answer is held the same way (the next holder reads the mark, never the stale key as registered)", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    await rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const gate = deferred();
    const orig = rig.state.setIosKey.bind(rig.state);
    rig.state.setIosKey = async (u, d, rec) => {
      if (rec.state === "stale") await gate.promise;
      return orig(u, d, rec);
    };
    rig.postReplies = [grade("attested"), { ...grade("failed"), rekey: true }, grade("attested")]; // indexed by the number of posts so far: the first redemption's is #1
    const p1 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    const r1 = p1.then((r) => r, (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc03" }), rig.io());
    await vi.advanceTimersByTimeAsync(9_000); // past the 5 s hold time, inside the 10 s settle bound
    expect(rig.posts).toHaveLength(2); // the first registration's request is gone; the second check-in's assertion has NOT been made
    gate.resolve();
    expect(await r1).toMatchObject({ rekey: true });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.registrations).toHaveLength(2); // the first key, then the recovery's
  });
});

describe("a secure-store write that never settles cannot hold the assertion lock for ever (gate LOW-1)", () => {
  it("the Android attested mark hangs: past the hold time and the 10 s bound the lock is released, the first check-in is deferred, and the next check-in runs", async () => {
    vi.useFakeTimers();
    const rig = makeRig("android", { holdMs: 5_000 });
    const orig = rig.state.markAttestedAndroid.bind(rig.state);
    let hang = true;
    rig.state.markAttestedAndroid = (u, d) => (hang ? new Promise<void>(() => undefined) : orig(u, d));
    const r1 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc01" }), rig.io()).then((r) => r, (e: unknown) => e);
    const p2 = rig.redeemer.redeem(input({ challengeId: "cccccccc-cccc-4ccc-8ccc-cccccccccc02" }), rig.io());
    await vi.advanceTimersByTimeAsync(9_000);
    expect(rig.posts).toHaveLength(1); // the second is still waiting inside the bound
    hang = false;
    await vi.advanceTimersByTimeAsync(2_000);
    expect(await r1).toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
  }, 10_000);
});

describe("the assertion lock is not re-entrant: redeem / activate inside withAssertionLock is refused, not deadlocked", () => {
  it.each(["ios", "android"] as const)("%s: `redeem` called from inside a holder of the same (user, device) rejects with LockReentryError at once and sends nothing", async (platform) => {
    const rig = makeRig(platform);
    const inner = withAssertionLock(rig.locks, USER, DEVICE, () => rig.redeemer.redeem(input(), rig.io()));
    await expect(inner).rejects.toBeInstanceOf(LockReentryError);
    expect(rig.posts).toEqual([]);
    expect(rig.module.events.length).toBe(0);
    await expect(rig.redeemer.redeem(input(), rig.io())).resolves.toMatchObject({ attestationGrade: "attested" }); // the lock is free again
  });
});

describe("PR #44 gate test gap A16: a check-in's token-less (`none`) request is a SENT request held through `effect`", () => {
  const C1 = "cccccccc-cccc-4ccc-8ccc-cccccccccc01";
  const C2 = "cccccccc-cccc-4ccc-8ccc-cccccccccc02";

  it("iOS, a device that cannot do App Attest (the server holds no key): the `none` request in flight past the hold time keeps the lock, the next check-in waits, and its real answer is returned (not a lock timeout)", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000 });
    rig.module.next.generateKey = [{ ok: false, code: "unsupported", message: "featureUnsupported" }];
    const gate = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate.promise, grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await vi.advanceTimersByTimeAsync(20_000);
    expect(rig.posts).toEqual([{ challengeId: C1, nonce: NONCE, hardwareSupportsAttestation: false }]); // the second is still waiting
    expect(rig.locks.pendingKeys()).toEqual([assertionLockKey(USER, DEVICE)]);
    gate.resolve(grade("unattestable"));
    await expect(p1).resolves.toMatchObject({ attestationGrade: "unattestable" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.locks.pendingKeys()).toEqual([]);
  });

  it("Android, never attested and Play Integrity failing: the same for the token-less request", async () => {
    vi.useFakeTimers();
    const rig = makeRig("android", { holdMs: 5_000 });
    rig.module.always.integrityToken = { ok: false, code: "unavailable", message: "x" };
    const gate = deferred<ReturnType<typeof grade>>();
    rig.postReplies = [() => gate.promise, grade("unattestable")];
    const p1 = rig.redeemer.redeem(input({ challengeId: C1 }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: C2 }), rig.io());
    await vi.advanceTimersByTimeAsync(20_000);
    expect(rig.posts).toHaveLength(1);
    gate.resolve(grade("unattestable"));
    await expect(p1).resolves.toMatchObject({ attestationGrade: "unattestable" });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "unattestable" });
    expect(rig.posts).toHaveLength(2);
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
