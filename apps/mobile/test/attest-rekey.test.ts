/**
 * Stale App Attest key recovery: the client side of `checkin-token`'s `rekey: true` hint (`src/attest/redeemer.ts` rule 6; server: `docs/security/p3-money-path-requirements.md`
 * "Stale App Attest key recovery"). Against the fake native module, the scripted `RedeemIo`, and (last block) the real HTTP client over the server's RECORDED answers.
 */
import { createHash } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHttpApiClient } from "../src/api";
import { attestKeyResultSchema, checkinTokenResultSchema } from "../src/api/schemas";
import type { CheckinTokenResult } from "../src/api/types";
import { AttestStateStore, AttestationDeferred, KeyedMutex, NativeAttestor, NativeRedeemer, assertionLockKey, attestKeyBinding } from "../src/attest";
import { parseEvidencePayload } from "../src/evidence";
import { createItem, type OutboxItem } from "../src/outbox";
import { MemorySecureStore } from "../src/secure";
import { apiError, jwt } from "./support/fakes";
import { makeActivationRig, actInput } from "./support/activation-rig";
import { CHALLENGE, DEVICE, NONCE, USER, grade, input, makeRig } from "./support/attest-rig";
import { recorded, scriptedFetch, type Step } from "./support/edge-fixtures";
import { FakeNativeAttestModule } from "./support/fake-native-attest";
import { T0, itemFor, wireOf } from "./support/evidence";

afterEach(() => vi.useRealTimers());

const HOUR = 60 * 60_000;
const rekeyed = (g: "failed" | "unattestable" = "failed", jti = "jti_rekey"): CheckinTokenResult => ({ jti, expiresAt: "2026-06-01T12:15:00.000Z", attestationGrade: g, rekey: true });
const ch = (n: number): string => `cccccccc-cccc-4ccc-8ccc-cccccccccc${String(n).padStart(2, "0")}`;
const KEY_STALE = createHash("sha256").update("a-key-the-server-no-longer-holds").digest("base64");
const deferred = <T = void>() => {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((a) => {
    resolve = a;
  });
  return { promise, resolve };
};

/** A rig with a controllable clock (epoch ms), key A registered through the redeemer's own flow, and the logs emptied. */
async function registered(opts: { holdMs?: number } = {}) {
  const clock = { t: 10 * HOUR };
  const rig = makeRig("ios", { now: () => clock.t, ...opts });
  await rig.redeemer.redeem(input(), rig.io()); // registers key A, asserts with it: attested
  const keyA = (await rig.state.getIosKey(USER, DEVICE)) as { state: "registered"; keyId: string };
  const clear = (): void => {
    rig.posts.length = 0;
    rig.registrations.length = 0;
    rig.timeline.length = 0;
    rig.module.events.length = 0;
  };
  clear();
  return { rig, clock, keyA: keyA.keyId, clear };
}
const posted = (rig: { posts: { attestation?: unknown }[] }, i: number): { platform: string; keyId: string } => rig.posts[i]!.attestation as { platform: string; keyId: string };
const gen = (rig: { module: FakeNativeAttestModule }): number => rig.module.ops("generateKey").length;

describe("the schema: `rekey` is explicit, typed and optional", () => {
  const data = (name: string): unknown => (JSON.parse(recorded(name).body) as { data: unknown }).data;

  it("the recorded rekey answers parse, with the jti, the grade and `rekey: true`", () => {
    expect(checkinTokenResultSchema.parse(data("token_201_failed_rekey_ios"))).toEqual({ jti: "jti_3", expiresAt: "2026-06-01T12:15:00.000Z", attestationGrade: "failed", rekey: true });
    expect(checkinTokenResultSchema.parse(data("token_201_unattestable_rekey_ios"))).toEqual({ jti: "jti_2", expiresAt: "2026-06-01T12:15:00.000Z", attestationGrade: "unattestable", rekey: true });
  });

  it("every other recorded token answer parses WITHOUT the member (it is omitted, never false)", () => {
    for (const name of ["token_201_attested_ios", "token_201_attested_android", "token_201_failed_wrong_binding_ios", "token_201_failed_attested_before_no_token", "token_201_unattestable"]) {
      const r = checkinTokenResultSchema.parse(data(name));
      expect(r.rekey, name).toBeUndefined();
      expect("rekey" in r, name).toBe(false);
    }
  });

  it("anything but the literal `true` is a contract violation: `false`, a string and a number are refused", () => {
    const base = { jti: "abc", expiresAt: "x", attestationGrade: "failed" };
    for (const bad of [false, "true", 1, null]) expect(checkinTokenResultSchema.safeParse({ ...base, rekey: bad }).success, String(bad)).toBe(false);
    expect(checkinTokenResultSchema.safeParse({ ...base, rekey: true }).success).toBe(true);
    expect(checkinTokenResultSchema.safeParse(base).success).toBe(true);
  });

  it("an unknown member is still ignored (non-strict), and the recovery registration answer (201 registered / 200 replaced) parses", () => {
    expect(checkinTokenResultSchema.safeParse({ jti: "abc", expiresAt: "x", attestationGrade: "attested", somethingNew: 1 }).success).toBe(true);
    expect(attestKeyResultSchema.parse(data("attestkey_201_registered_for_rekey"))).toMatchObject({ replaced: false });
    expect(recorded("attestkey_200_replaced").status).toBe(200);
    expect(attestKeyResultSchema.parse(data("attestkey_200_replaced"))).toMatchObject({ replaced: true });
  });

  it("the recorded replace / retired answers are what the redeemer is written against: 200 `replaced: true` for a fresh key over a held one, 409 `key_previously_retired` for the retired one (the real handler's words)", () => {
    expect(recorded("attestkey_200_replaced").status).toBe(200);
    expect(recorded("attestkey_409_previously_retired").status).toBe(409);
    const e = JSON.parse(recorded("attestkey_409_previously_retired").body) as { error: { code: string } };
    expect(e.error.code).toBe("key_previously_retired");
    // the redeemer reads that exact code from the ApiError the HTTP client builds (`conflict` + code), as the rig's scripted 409 does
    expect(apiError("conflict", 409, e.error.code)).toMatchObject({ kind: "conflict", status: 409, code: "key_previously_retired" });
  });
});

describe("a `rekey: true` answer marks the local key stale, INSIDE the assertion lock; the token is used as it is", () => {
  it.each(["failed", "unattestable"] as const)("grade %s: the answer is returned untouched (jti, grade, rekey), the key is marked stale, and NOTHING else happens in this redemption", async (g) => {
    const { rig, keyA, clear } = await registered();
    rig.postReplies = [rekeyed(g, "jti_keep")];
    const r = await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    expect(r).toEqual({ jti: "jti_keep", expiresAt: "2026-06-01T12:15:00.000Z", attestationGrade: g, rekey: true });
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "stale", keyId: keyA });
    expect(rig.posts).toHaveLength(1);
    expect(posted(rig, 0).keyId).toBe(keyA);
    // no recovery inside the same redemption: no new key, no live challenge, no registration, no second request
    expect(rig.timeline).toEqual(["native:generateAssertion", "http:post:start", "http:post:end"]);
    expect(rig.registrations).toEqual([]);
    clear();
  });

  it("the mark is written while the lock is HELD (not after it is released)", async () => {
    const { rig, keyA } = await registered();
    const held: boolean[] = [];
    const orig = rig.state.setIosKey.bind(rig.state);
    rig.state.setIosKey = async (u, d, rec) => {
      if (rec.state === "stale") held.push(rig.locks.pendingKeys().includes(assertionLockKey(USER, DEVICE)));
      return orig(u, d, rec);
    };
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    expect(held).toEqual([true]);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "stale", keyId: keyA });
  });

  it("a check-in queued behind the one that got the hint never asserts with the stale key: it finds the mark and recovers", async () => {
    const { rig, keyA } = await registered();
    rig.postReplies = [rekeyed(), grade("attested")];
    const p1 = rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    const p2 = rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    await expect(p1).resolves.toMatchObject({ rekey: true });
    await expect(p2).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(rig.posts.map((p) => (p.attestation as { keyId: string }).keyId)).toEqual([keyA, expect.not.stringMatching(keyA)]);
    expect(rig.module.ops("generateAssertion").filter((e) => (e as { keyId: string }).keyId === keyA)).toHaveLength(1); // the stale key asserted exactly once
    expect(rig.registrations).toHaveLength(1);
  });

  it("the mark is persisted per USER and per DEVICE: it survives a restart (a new redeemer over the same secure store) and touches no other account or device", async () => {
    const { rig, keyA, clock } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    expect(rig.secure.keys().filter((k) => k.startsWith("gr.attest.ios_key."))).toHaveLength(1);
    const restarted = new AttestStateStore(rig.secure);
    expect(await restarted.getIosKey(USER, DEVICE)).toEqual({ state: "stale", keyId: keyA });
    expect(await restarted.getIosKey("other-user", DEVICE)).toBeNull();
    expect(await restarted.getIosKey(USER, "aaaaaaaa-bbbb-4bbb-8bbb-bbbbbbbbbbbb")).toBeNull();
    // and a fresh process recovers from it
    const second = new NativeRedeemer({ attestor: new NativeAttestor(rig.module, "ios", null), state: restarted, locks: new KeyedMutex({ holdTimeoutMs: 60_000 }), now: () => clock.t });
    rig.postReplies = [grade("attested")];
    await second.redeem(input({ challengeId: ch(2) }), rig.io());
    expect(rig.registrations).toHaveLength(1);
  });

  it("an answer WITHOUT the hint changes nothing: a `failed` grade alone (a wrong binding, a counter replay) never marks the key; `unattestable` without it keeps the old behaviour (the record is dropped)", async () => {
    const { rig, keyA } = await registered();
    rig.postReplies = [grade("failed")];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: keyA });
    rig.postReplies = [grade("unattestable")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    expect(await rig.state.getIosKey(USER, DEVICE)).toBeNull();
  });

  it("a `rekey` on an Android answer is not a thing the client acts on: no iOS record, no attested mark", async () => {
    const rig = makeRig("android");
    rig.postReplies = [rekeyed("failed")];
    const r = await rig.redeemer.redeem(input(), rig.io());
    expect(r.rekey).toBe(true);
    expect(rig.secure.keys().filter((k) => k.startsWith("gr.attest.ios_"))).toEqual([]);
    expect(await rig.state.hasAttestedAndroid(USER, DEVICE)).toBe(false);
  });

  it("a mark that cannot be written loses only the mark (the real answer, with its jti, is still returned); the next assertion with that key brings the same hint", async () => {
    const { rig, keyA } = await registered();
    const orig = rig.state.setIosKey.bind(rig.state);
    rig.state.setIosKey = (u, d, rec) => (rec.state === "stale" ? Promise.reject(new Error("keychain locked")) : orig(u, d, rec));
    rig.postReplies = [rekeyed("failed", "jti_lost_mark")];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io())).resolves.toMatchObject({ jti: "jti_lost_mark", rekey: true });
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: keyA });
  });
});

describe("the next iOS assertion need: a FRESH key, registered ONCE, then used", () => {
  it("generateKey -> live challenge -> attestKey over the registration binding -> devices-attest-key (the fresh key) -> assertion with it; the stale key is neither reused nor re-registered; the check-in AFTER that uses the new key", async () => {
    const { rig, keyA, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();

    rig.postReplies = [grade("attested")];
    const r = await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    expect(r.attestationGrade).toBe("attested");
    expect(rig.timeline).toEqual(["native:generateKey", "http:live", "native:attestKey", "http:register", "native:generateAssertion", "http:post:start", "http:post:end"]);
    expect(rig.registrations).toHaveLength(1);
    const reg = rig.registrations[0]!;
    expect(reg.keyId).not.toBe(keyA);
    expect(reg.keyId).toMatch(/^[A-Za-z0-9+/]{43}=$/);
    // the registration is bound to the fresh key and the live challenge (the existing binding)
    const attest = rig.module.ops("attestKey")[0] as { keyId: string; hashHex: string };
    expect(attest.keyId).toBe(reg.keyId);
    expect(attest.hashHex).toBe(Buffer.from(attestKeyBinding({ challengeId: reg.challengeId, deviceId: DEVICE, keyId: reg.keyId, nonce: reg.nonce })).toString("hex"));
    expect(Buffer.from(reg.attestation, "base64").toString()).toBe(`attestation:${reg.keyId}:${Buffer.from(attestKeyBinding({ challengeId: reg.challengeId, deviceId: DEVICE, keyId: reg.keyId, nonce: reg.nonce })).toString("base64")}`);
    // the assertion, and the request, use the fresh key; the stale key is never touched again
    expect(posted(rig, 0).keyId).toBe(reg.keyId);
    expect(rig.module.ops("generateAssertion").map((e) => (e as { keyId: string }).keyId)).toEqual([reg.keyId]);
    expect(rig.module.ops("attestKey").map((e) => (e as { keyId: string }).keyId)).not.toContain(keyA);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: reg.keyId });

    // and the following check-in uses the NEW key: no registration, no new key
    clear();
    await rig.redeemer.redeem(input({ challengeId: ch(3) }), rig.io());
    expect(rig.registrations).toEqual([]);
    expect(gen(rig)).toBe(0);
    expect(posted(rig, 0).keyId).toBe(reg.keyId);
    // the server answered `replaced` for it (HTTP 200, counter restarts at 0): the client keeps no trace of the old key but the fact that it was replaced (the cooldown)
    expect(rig.secure.keys().some((k) => k.startsWith("gr.attest.ios_unattested."))).toBe(false);
  });

  it("an `unattestable` + rekey (the server holds NO key: a restore, a reset) recovers the same way, and a refused fresh registration there still never goes token-less", async () => {
    const { rig, keyA, clear } = await registered();
    rig.postReplies = [rekeyed("unattestable")];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "stale", keyId: keyA });
    clear();
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    expect(rig.registrations).toHaveLength(1);
    expect(posted(rig, 0).keyId).toBe(rig.registrations[0]!.keyId);
  });

  it("the recovery generates a key even when the stale one is the only thing in the store: a key left over from an earlier unavailable `attestKey` is the ONLY key ever reused (it was never registered)", async () => {
    const { rig, keyA, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.module.next.attestKey = [{ ok: false, code: "unavailable", message: "Apple is down" }];
    rig.postReplies = [grade("attested")];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).rejects.toMatchObject({ reason: "attest_key_unavailable" });
    const fresh = await rig.state.getUnattestedKey(USER, DEVICE);
    expect(fresh).not.toBeNull();
    expect(fresh).not.toBe(keyA);
    expect(rig.registrations).toEqual([]); // nothing reached the server: no cooldown was spent either
    expect(await rig.state.getRekeyCooldownUntil(USER, DEVICE)).toBe(0);
    await rig.redeemer.redeem(input({ challengeId: ch(3) }), rig.io());
    expect(rig.registrations.map((r) => r.keyId)).toEqual([fresh]); // the SAME fresh key, retried
    expect(gen(rig)).toBe(1);
  });

  it("the cooldown is written BEFORE the registration request is sent (and is the registration backoff's length), and persists", async () => {
    const { rig, clock } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    let atRequest = -1;
    rig.registerReplies = [
      async () => {
        atRequest = await rig.state.getRekeyCooldownUntil(USER, DEVICE);
      },
    ];
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    expect(atRequest).toBe(clock.t + HOUR);
    expect(await new AttestStateStore(rig.secure).getRekeyCooldownUntil(USER, DEVICE)).toBe(clock.t + HOUR);
  });
});

describe("never a loop: at most one recovery registration per cooldown", () => {
  it("a SECOND rekey inside the cooldown does not register again: the key is marked stale, the need defers (no assertion, no token-less request, no key, no challenge), and recovery resumes once the cooldown ends", async () => {
    const { rig, clock, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io()); // recovery: key B
    const keyB = rig.registrations[0]!.keyId;
    clock.t += 10 * 60_000;
    rig.postReplies = [rekeyed("failed", "jti_second")];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(3) }), rig.io())).resolves.toMatchObject({ jti: "jti_second", rekey: true }); // B is now stale too
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "stale", keyId: keyB });

    clear();
    for (let i = 4; i < 12; i += 1) {
      clock.t += 60_000;
      await expect(rig.redeemer.redeem(input({ challengeId: ch(i) }), rig.io())).rejects.toMatchObject({ name: "AttestationDeferred", reason: "rekey_cooldown" });
    }
    expect(rig.timeline).toEqual([]); // not one native call, not one request
    expect(rig.registrations).toEqual([]);
    expect(rig.posts).toEqual([]);

    clock.t = 10 * HOUR + HOUR + 30 * 60_000 + 1; // past the first recovery's cooldown
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(20) }), rig.io());
    expect(rig.registrations).toHaveLength(1);
    expect(rig.registrations[0]!.keyId).not.toBe(keyB);
    expect(posted(rig, 0).keyId).toBe(rig.registrations[0]!.keyId);
  });

  it("account deletion wipes the cooldown with the rest of the user's attestation record, and only THEIR record (gate NIT R14)", async () => {
    const { rig, clock } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io()); // recovery: the cooldown is written
    const OTHER = "99999999-9999-4999-8999-999999999999";
    await rig.state.setRekeyCooldownUntil(OTHER, DEVICE, clock.t + HOUR);
    expect(await rig.state.getRekeyCooldownUntil(USER, DEVICE)).toBe(clock.t + HOUR);
    expect(rig.secure.keys().some((k) => k.startsWith(`gr.attest.ios_rekey_cooldown.${USER}.`))).toBe(true);

    await rig.state.wipeUser(USER, DEVICE);
    expect(await rig.state.getRekeyCooldownUntil(USER, DEVICE)).toBe(0);
    expect(rig.secure.keys().filter((k) => k.includes(USER))).toEqual([]); // nothing of the deleted user's is left: key record, cooldown, backoff, unattested key
    expect(await rig.state.getRekeyCooldownUntil(OTHER, DEVICE)).toBe(clock.t + HOUR); // another account on the install keeps theirs
  });

  it("the cooldown survives a restart", async () => {
    const { rig, clock, keyA } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(3) }), rig.io());
    const restarted = new NativeRedeemer({ attestor: new NativeAttestor(rig.module, "ios", null), state: new AttestStateStore(rig.secure), locks: new KeyedMutex({ holdTimeoutMs: 60_000 }), now: () => clock.t });
    const before = rig.registrations.length;
    await expect(restarted.redeem(input({ challengeId: ch(4) }), rig.io())).rejects.toMatchObject({ reason: "rekey_cooldown" });
    expect(rig.registrations).toHaveLength(before);
    expect(keyA).toBeTruthy();
  });

  it("a cooldown that lies further away than one cooldown (the clock moved) is not honoured past one cooldown", async () => {
    const { rig, clock } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    await rig.state.setRekeyCooldownUntil(USER, DEVICE, clock.t + 40 * HOUR);
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io());
    expect(rig.registrations).toHaveLength(1);
  });

  it("the registration request is answered 429: the ApiError reaches the caller (the outbox's own backoff and Retry-After), the key stays stale, and the retries inside the cooldown register NOTHING", async () => {
    const { rig, clock, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    const e = apiError("rate_limited", 429, "rate_limited");
    rig.registerReplies = [e];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).rejects.toBe(e);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.posts).toEqual([]);
    expect((await rig.state.getIosKey(USER, DEVICE))?.state).toBe("stale");
    clear();
    for (let i = 3; i < 13; i += 1) {
      clock.t += 5 * 60_000;
      await expect(rig.redeemer.redeem(input({ challengeId: ch(i) }), rig.io())).rejects.toMatchObject({ reason: "rekey_cooldown" });
    }
    expect(rig.timeline).toEqual([]);
    // an hour after the request, ONE more try
    clock.t += HOUR;
    rig.registerReplies = [undefined];
    rig.postReplies = [grade("attested")];
    await rig.redeemer.redeem(input({ challengeId: ch(30) }), rig.io());
    expect(rig.registrations).toHaveLength(1);
  });

  it("a registration whose answer is LOST (network) is not retried inside the cooldown either, however often the outbox retries: one key, one live challenge, one request", async () => {
    const { rig, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.registerReplies = [apiError("network", 0, null)];
    for (let i = 2; i < 30; i += 1) await rig.redeemer.redeem(input({ challengeId: ch(i) }), rig.io()).catch(() => undefined);
    expect(rig.registrations).toHaveLength(1);
    expect(gen(rig)).toBe(1);
    expect(rig.timeline.filter((t) => t === "http:live")).toHaveLength(1);
    expect(rig.posts).toEqual([]);
  });

  it("the registration is REFUSED (422 attestation_rejected): the registration backoff is set as for any refusal, the key stays stale and nothing goes token-less", async () => {
    const { rig, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.registerReplies = [apiError("rejected", 422, "attestation_rejected")];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
    expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBeGreaterThan(0);
    expect((await rig.state.getIosKey(USER, DEVICE))?.state).toBe("stale");
    for (let i = 3; i < 8; i += 1) await expect(rig.redeemer.redeem(input({ challengeId: ch(i) }), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.registrations).toHaveLength(1);
    expect(rig.posts).toEqual([]);
  });

  it("the device cannot do App Attest any more (generateKey `unsupported`) while the key is stale: deferred, never token-less (the server holds a key)", async () => {
    const { rig, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.module.always.generateKey = { ok: false, code: "unsupported", message: "no" };
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).rejects.toMatchObject({ reason: "key_registration_refused" });
    expect(rig.posts).toEqual([]);
    expect(rig.registrations).toEqual([]);
  });
});

describe("409 key_previously_retired on the recovery registration: exactly ONE more fresh key, then the backoff", { timeout: 5_000 }, () => { // a regression into a loop must fail, not hang
  const retired = () => apiError("conflict", 409, "key_previously_retired");

  it("the second key is accepted: two keys generated, two registrations (different keys), the assertion uses the second", async () => {
    const { rig, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.registerReplies = [retired(), undefined];
    rig.postReplies = [grade("attested")];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).resolves.toMatchObject({ attestationGrade: "attested" });
    expect(gen(rig)).toBe(2);
    expect(rig.registrations).toHaveLength(2);
    expect(rig.registrations[1]!.keyId).not.toBe(rig.registrations[0]!.keyId);
    expect(rig.registrations[1]!.challengeId).not.toBe(rig.registrations[0]!.challengeId); // each try has its own live challenge
    expect(posted(rig, 0).keyId).toBe(rig.registrations[1]!.keyId);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "registered", keyId: rig.registrations[1]!.keyId });
  });

  it("a regression into a loop fails CLEANLY instead of hanging: the server keeps answering 409 forever, and the registrations stop at exactly 2 (a third request would be refused by this script)", async () => {
    const { rig, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.registerReplies = [
      async (n: number) => {
        if (n > 3) throw new Error("LOOP: more than 3 registrations"); // not an ApiError: ends the redemption at once
        throw retired();
      },
    ];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).rejects.toMatchObject({ reason: "registration_key_previously_retired" });
    expect(rig.registrations.length).toBeLessThanOrEqual(2);
    expect(rig.registrations).toHaveLength(2);
    expect(gen(rig)).toBe(2);
    expect(rig.timeline.filter((t) => t === "http:register")).toHaveLength(2);
  }, 5_000);

  it("the second key is retired too: no third key; the registration backoff is set; the need defers; the key stays stale; nothing is sent token-less; and nothing is retried inside the cooldown", async () => {
    const { rig, clock, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    rig.registerReplies = [retired()];
    await expect(rig.redeemer.redeem(input({ challengeId: ch(2) }), rig.io())).rejects.toMatchObject({ name: "AttestationDeferred", reason: "registration_key_previously_retired" });
    expect(gen(rig)).toBe(2);
    expect(rig.registrations).toHaveLength(2);
    expect(rig.posts).toEqual([]);
    expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBe(clock.t + HOUR);
    expect((await rig.state.getIosKey(USER, DEVICE))?.state).toBe("stale");
    clear();
    for (let i = 3; i < 9; i += 1) await expect(rig.redeemer.redeem(input({ challengeId: ch(i) }), rig.io())).rejects.toBeInstanceOf(AttestationDeferred);
    expect(rig.timeline).toEqual([]);
  });

  it("the same on a FIRST registration (no stale key): one more fresh key, then the backoff and a deferral, never token-less (a retired key proves the server holds one)", async () => {
    const rig = makeRig("ios");
    rig.registerReplies = [retired()];
    await expect(rig.redeemer.redeem(input(), rig.io())).rejects.toMatchObject({ reason: "registration_key_previously_retired" });
    expect(gen(rig)).toBe(2);
    expect(rig.registrations).toHaveLength(2);
    expect(rig.posts).toEqual([]);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "pending" });
    expect(await rig.state.getRegistrationBackoffUntil(USER, DEVICE)).toBeGreaterThan(0);
  });
});

describe("abort semantics: an aborted holder does nothing more", () => {
  it.each(["generateKey", "attestKey"] as const)("a recovery stuck in %s past the hold time: when the call returns NOTHING happens (no live challenge, no attestKey, no registration, no cooldown, the record stays stale)", async (op) => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    await rig.state.setIosKey(USER, DEVICE, { state: "stale", keyId: KEY_STALE });
    const gate = deferred();
    rig.module.stall[op] = [gate.promise];
    const p = rig.redeemer.redeem(input(), rig.io()).then(() => "resolved", (e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await p).toMatchObject({ name: "AttestationDeferred", reason: "assertion_lock_timeout" });
    const snapshot = JSON.stringify({ t: rig.timeline, p: rig.posts, r: rig.registrations, s: rig.secure.dump() });
    gate.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(JSON.stringify({ t: rig.timeline, p: rig.posts, r: rig.registrations, s: rig.secure.dump() })).toBe(snapshot);
    expect(rig.registrations).toEqual([]);
    expect(await rig.state.getIosKey(USER, DEVICE)).toEqual({ state: "stale", keyId: KEY_STALE });
  });

  it("an aborted holder's late `rekey` result: the request was SENT, so its real answer (jti) is returned and the mark follows the server; the holder does nothing else (no key, no challenge, no registration)", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    await rig.redeemer.redeem(input(), rig.io());
    rig.timeline.length = 0;
    const gate = deferred<CheckinTokenResult>();
    rig.postReplies = [() => gate.promise];
    const p = rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    await vi.advanceTimersByTimeAsync(5_001); // aborted, but its request is in flight: the lock is kept
    gate.resolve(rekeyed("failed", "jti_late"));
    await expect(p).resolves.toMatchObject({ jti: "jti_late", rekey: true });
    expect((await rig.state.getIosKey(USER, DEVICE))?.state).toBe("stale");
    expect(rig.timeline).toEqual(["native:generateAssertion", "http:post:start", "http:post:end"]);
    expect(rig.registrations).toHaveLength(1); // the first-ever registration only
  });

  it("an holder aborted BEFORE it sends anything (stuck reading the store) writes no mark and sends nothing, whatever it is told afterwards", async () => {
    vi.useFakeTimers();
    const rig = makeRig("ios", { holdMs: 5_000, nativeTimeoutMs: 600_000 });
    await rig.redeemer.redeem(input(), rig.io());
    rig.timeline.length = 0;
    rig.posts.length = 0;
    const gate = deferred();
    const orig = rig.state.getIosKey.bind(rig.state);
    rig.state.getIosKey = async (u, d) => {
      await gate.promise;
      return orig(u, d);
    };
    rig.postReplies = [rekeyed()];
    const p = rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io()).then(() => "resolved", (e: unknown) => e);
    await vi.advanceTimersByTimeAsync(5_001);
    expect(await p).toMatchObject({ reason: "assertion_lock_timeout" });
    const before = JSON.stringify({ t: rig.timeline, p: rig.posts, s: rig.secure.dump() });
    gate.resolve();
    await vi.advanceTimersByTimeAsync(10);
    expect(JSON.stringify({ t: rig.timeline, p: rig.posts, s: rig.secure.dump() })).toBe(before);
  });
});

describe("no token-less request on a device the server knows can attest (the attested-before rules of #42 / #46 still apply)", () => {
  it("through the whole recovery, whatever fails, `posts` never holds a request without an attestation", async () => {
    const { rig, clock, clear } = await registered();
    rig.postReplies = [rekeyed()];
    await rig.redeemer.redeem(input({ challengeId: ch(1) }), rig.io());
    clear();
    const failures: Array<() => void> = [
      () => void (rig.module.next.generateKey = [{ ok: false, code: "other", message: "x" }]),
      () => void (rig.module.next.attestKey = [{ ok: false, code: "other", message: "x" }]),
      () => void (rig.module.next.attestKey = [{ ok: false, code: "unsupported", message: "x" } as never]),
      () => void (rig.registerReplies = [apiError("unavailable", 503, "attestation_not_configured")]),
      () => void (rig.registerReplies = [apiError("rejected", 422, "platform_mismatch")]),
      () => void (rig.registerReplies = [apiError("server", 500, "internal_error")]),
    ];
    for (const [n, fail] of failures.entries()) {
      fail();
      clock.t += 2 * HOUR; // each try is outside the previous cooldown and backoff
      await rig.redeemer.redeem(input({ challengeId: ch(10 + n) }), rig.io()).then(
        () => expect.fail(`failure ${n} went through`),
        () => undefined,
      );
      expect(rig.posts.filter((p) => p.attestation === undefined || p.hardwareSupportsAttestation === false), `failure ${n}`).toEqual([]);
      expect((await rig.state.getIosKey(USER, DEVICE))?.state, `failure ${n}`).toBe("stale");
    }
    expect(rig.posts).toEqual([]);
  });
});

describe("activation: no hint of its own; a stale mark set by a check-in is honoured by the shared key lifecycle", () => {
  it("inside the cooldown an activation defers (no assertion with the stale key, no request, no challenge); after it, the activation performs the recovery itself and asserts with the fresh key", async () => {
    const clock = { t: 10 * HOUR };
    const a = makeActivationRig("ios", { now: () => clock.t });
    await a.rig.redeemer.redeem(input(), a.rig.io()); // key A
    a.rig.postReplies = [rekeyed()];
    await a.rig.redeemer.redeem(input({ challengeId: ch(1) }), a.rig.io());
    a.rig.postReplies = [grade("attested")];
    await a.rig.redeemer.redeem(input({ challengeId: ch(2) }), a.rig.io()); // recovery: key B
    a.rig.postReplies = [rekeyed()];
    await a.rig.redeemer.redeem(input({ challengeId: ch(3) }), a.rig.io()); // B is stale inside the cooldown
    a.rig.registrations.length = 0;
    a.rig.module.events.length = 0;
    a.liveCalls = 0;

    await expect(a.activator.activate(actInput(), a.io())).rejects.toMatchObject({ reason: "rekey_cooldown" });
    expect(a.posts).toEqual([]);
    expect(a.liveCalls).toBe(0);
    expect(a.rig.module.events.length).toBe(0);

    clock.t += 2 * HOUR;
    await a.activator.activate(actInput(), a.io());
    expect(a.rig.registrations).toHaveLength(1);
    expect(a.posts).toHaveLength(1);
    const att = a.posts[0]!.attestation as { kind: string; keyId: string };
    expect(att.kind).toBe("ios");
    expect(att.keyId).toBe(a.rig.registrations[0]!.keyId);
  });
});

describe("end to end: the real HTTP client, the native redeemer over a fake module, the RECORDED rekey answers", { timeout: 10_000 }, () => {
  const CREDS = { userId: "user-a", accessToken: jwt({ sub: "user-a" }) };
  const BASE = "https://p.supabase.co/functions/v1";
  const SERVER_DEVICE = "11111111-1111-4111-8111-111111111111";
  const fn = (u: string): string | undefined => u.split("/").pop();

  function held(n: number): OutboxItem {
    const base = itemFor(wireOf("evidence_accepted_no_challenge"), 1);
    const p = JSON.parse(JSON.stringify(base.payload)) as { challenges: Record<string, unknown> };
    const k = Object.keys(p.challenges)[0]!;
    p.challenges[k] = { state: "held", challengeId: ch(n), nonce: NONCE, kind: "prefetched", expiresAt: T0 + 20 * 3600_000 };
    return { ...createItem({ id: `ev${n}`, sourceRef: `r${n}`, ownerUserId: "user-a", courseId: base.courseId, catalogVersion: base.catalogVersion, payload: p as never }, T0), status: "sent" };
  }
  // Recorded from the REAL handler (`attestkey_200_replaced`: the server held a key, a fresh one replaced it; `attestkey_409_previously_retired`: that retired key registered again).
  const replaced200: Step = { respond: "attestkey_200_replaced" };

  async function client(steps: Step[]) {
    const module = new FakeNativeAttestModule();
    const secure = new MemorySecureStore();
    const state = new AttestStateStore(secure);
    const attestor = new NativeAttestor(module, "ios", null);
    const redeemer = new NativeRedeemer({ attestor, state, locks: new KeyedMutex({ holdTimeoutMs: 60_000 }) });
    const gk = await attestor.generateKey(); // key A: the one the server will say is not its own
    if (gk.kind !== "ok") throw new Error("fake generateKey failed");
    await state.setIosKey("user-a", SERVER_DEVICE, { state: "registered", keyId: gk.value.keyId });
    const f = scriptedFetch(...steps);
    const api = createHttpApiClient({ baseUrl: BASE, fetch: f.fetch, getAccessToken: () => Promise.reject(new Error("no")), rng: () => 0.5, sleep: () => Promise.resolve(), now: () => T0, redeemer });
    return { api, seen: f.seen, state, module, keyA: gk.value.keyId };
  }
  const jtiOf = (body: unknown): string | undefined => (body as { fix: { checkinTokenJti?: string } }).fix.checkinTokenJti;

  it("rekey (failed) -> the evidence goes with THAT token (jti kept) -> the next check-in registers a fresh key at devices-attest-key (200 replaced) and attests with it -> the following one uses it with no registration", async () => {
    const { api, seen, state, keyA } = await client([
      { respond: "token_201_failed_rekey_ios" },
      { respond: "evidence_accepted_with_challenge" },
      { respond: "challenge_live_201" },
      replaced200,
      { respond: "token_201_attested_ios" },
      { respond: "evidence_accepted_with_challenge" },
      { respond: "token_201_attested_ios" },
      { respond: "evidence_accepted_with_challenge" },
    ]);
    // 1. the stale key is asserted, the server answers `failed` + rekey
    const a1 = await api.submitEvidence(held(1), CREDS);
    expect(a1).toMatchObject({ kind: "response", status: 200 });
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-token", "evidence"]);
    expect((seen[0]!.body as { attestation: { keyId: string } }).attestation.keyId).toBe(keyA);
    expect(jtiOf(seen[1]!.body)).toBe("jti_3"); // the token is used as it is: its jti rides on the fix
    const stored = parseEvidencePayload((a1 as unknown as { payload: never }).payload);
    expect(stored.ok && Object.values(stored.payload.challenges)[0]).toMatchObject({ state: "redeemed", jti: "jti_3", grade: "failed" });
    expect(await state.getIosKey("user-a", SERVER_DEVICE)).toEqual({ state: "stale", keyId: keyA });

    // 2. the next check-in: fresh key, registered once
    seen.length = 0;
    expect(await api.submitEvidence(held(2), CREDS)).toMatchObject({ kind: "response", status: 200 });
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key", "checkin-token", "evidence"]);
    expect(seen[0]!.body).toEqual({ deviceId: SERVER_DEVICE });
    const reg = seen[1]!.body as { keyId: string; deviceId: string };
    expect(reg.keyId).not.toBe(keyA);
    expect(reg.deviceId).toBe(SERVER_DEVICE);
    expect((seen[2]!.body as { attestation: { keyId: string } }).attestation.keyId).toBe(reg.keyId);
    expect(jtiOf(seen[3]!.body)).toBe(JSON.parse(recorded("token_201_attested_ios").body).data.jti);
    expect(await state.getIosKey("user-a", SERVER_DEVICE)).toEqual({ state: "registered", keyId: reg.keyId });

    // 3. the following check-in: the new key, no registration
    seen.length = 0;
    await api.submitEvidence(held(3), CREDS);
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-token", "evidence"]);
    expect((seen[0]!.body as { attestation: { keyId: string } }).attestation.keyId).toBe(reg.keyId);
  });

  it("rekey (unattestable) behaves the same on the wire", async () => {
    const { api, seen, state, keyA } = await client([{ respond: "token_201_unattestable_rekey_ios" }, { respond: "evidence_accepted_with_challenge" }, { respond: "challenge_live_201" }, { respond: "attestkey_201_registered_for_rekey" }, { respond: "token_201_attested_ios" }, { respond: "evidence_accepted_with_challenge" }]);
    await api.submitEvidence(held(1), CREDS);
    expect(jtiOf(seen[1]!.body)).toBe("jti_2");
    expect(await state.getIosKey("user-a", SERVER_DEVICE)).toEqual({ state: "stale", keyId: keyA });
    seen.length = 0;
    await api.submitEvidence(held(2), CREDS);
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key", "checkin-token", "evidence"]);
  });

  it("a second rekey inside the cooldown: nothing at all reaches the server for the next check-in (it retries later), and no token-less request is ever made", async () => {
    const { api, seen } = await client([
      { respond: "token_201_failed_rekey_ios" },
      { respond: "evidence_accepted_with_challenge" },
      { respond: "challenge_live_201" },
      replaced200,
      { respond: "token_201_failed_rekey_ios" }, // the fresh key is refused as stale too
      { respond: "evidence_accepted_with_challenge" },
    ]);
    await api.submitEvidence(held(1), CREDS);
    await api.submitEvidence(held(2), CREDS);
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-token", "evidence", "checkin-challenge", "devices-attest-key", "checkin-token", "evidence"]);
    seen.length = 0;
    for (let n = 3; n < 8; n += 1) {
      const item = held(n);
      const answer = await api.submitEvidence(item, CREDS);
      expect(answer.kind).toBe("network_error"); // a deferral: a retry, the held challenge stays
    }
    expect(seen).toEqual([]);
  });

  it("devices-attest-key answers 409 key_previously_retired twice: two fresh keys at most, then silence", async () => {
    const retired: Step = { respond: "attestkey_409_previously_retired" };
    const { api, seen } = await client([{ respond: "token_201_failed_rekey_ios" }, { respond: "evidence_accepted_with_challenge" }, { respond: "challenge_live_201" }, retired, { respond: "challenge_live_201" }, retired]);
    await api.submitEvidence(held(1), CREDS);
    seen.length = 0;
    const item = held(2);
    expect((await api.submitEvidence(item, CREDS)).kind).toBe("network_error");
    expect(seen.map((s) => fn(s.url))).toEqual(["checkin-challenge", "devices-attest-key", "checkin-challenge", "devices-attest-key"]);
    seen.length = 0;
    expect((await api.submitEvidence(held(3), CREDS)).kind).toBe("network_error");
    expect(seen).toEqual([]);
  });
});
