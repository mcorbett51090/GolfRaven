/**
 * P4.2c-1 LOW-1: a user switch during a check-in must never book the play (or A's live token) to the other account.
 * The owner is bound for the whole run: the flow re-checks it after the fix and passes it to `enqueueEvidence`, which refuses when the signed-in user is no longer the owner, and refuses a
 * pre-acquired challenge that was not issued to this owner and device. Also pins `acquireLive`'s own owner re-checks and that a pre-acquired challenge covers a `foreground_checkin` only.
 */
import { describe, expect, it } from "vitest";
import { ChallengeManager, MemoryChallengeStore } from "../src/challenges";
import { enqueueEvidence, type EvidenceInput } from "../src/evidence";
import { MemoryOutboxStore, OutboxEnqueueError, enqueueOutboxItem } from "../src/outbox";
import { DEVICE, NOW0, SITE_VERSION, FakeCheckinApi, entryOf, facility, makeRig, rawFix } from "./support/checkin-rig";

const E = entryOf(facility());
const fix = (id = "f1") => ({ fixId: id, lat: 36.1467, lng: -86.7816, accuracyMeters: 8, capturedAt: NOW0, simulated: false, foreground: true, fromApp: true });
const checkinInput = (over: Partial<EvidenceInput> = {}): EvidenceInput => ({
  origin: "live",
  facilityId: "fac_x",
  courseId: "crs_x1",
  catalogVersion: SITE_VERSION,
  localDate: "2026-06-01",
  submission: { source: "foreground_checkin", fix: fix() },
  ...over,
});
const LIVE = { state: "redeemed", challengeId: "live1", kind: "live", jti: "jti_live1", grade: "unattestable" } as const;

describe("LOW-1: the account switches during the check-in", () => {
  it("the PoC: A taps online, B is signed in during the fix: 'account_changed', NOTHING is stored for either account, A's live token goes nowhere, the pool is untouched", async () => {
    const rig = makeRig();
    await rig.seedPool(3, NOW0 - 3600_000);
    rig.location.onFix = async () => {
      rig.who.user = "user-b"; // the account switches while the fix is being taken
    };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 100) }];
    const o = await rig.run(E);
    expect(o).toEqual({ kind: "account_changed" });
    expect(rig.api.redeemed).toEqual(["live1"]); // A's live token was minted for A ...
    expect(await rig.outbox.list()).toEqual([]); // ... and no item exists for anyone
    expect(rig.enqueued).toEqual([]);
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(3);
    expect(await rig.challengeStore.countUsable("user-b", DEVICE, NOW0)).toBe(0);
  });

  it("signing OUT during the fix stays 'signed_out'", async () => {
    const rig = makeRig();
    rig.location.onFix = async () => {
      rig.who.user = null;
    };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    expect((await rig.run(E)).kind).toBe("signed_out");
  });

  it("the flow passes the owner and the challenge's binding to enqueueEvidence", async () => {
    const rig = makeRig();
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 + 100) }];
    expect((await rig.run(E)).kind).toBe("queued");
    expect(rig.enqueued[0]).toMatchObject({ owner: "user-a", challenge: { state: "redeemed", jti: "jti_live1" }, challengeFor: { ownerUserId: "user-a", deviceId: DEVICE } });
  });
});

describe("enqueueEvidence binds the owner itself (the race after the flow's own check)", () => {
  function rig() {
    const who = { user: "user-b" as string | null };
    const outbox = new MemoryOutboxStore();
    const store = new MemoryChallengeStore();
    const api = new FakeCheckinApi();
    const session = { currentUserId: () => who.user, accessTokenFor: (u: string) => Promise.resolve(who.user === u ? "t" : null) };
    const challenges = new ChallengeManager({ store, api, session, deviceId: () => Promise.resolve(DEVICE), now: () => NOW0 });
    const enqueue = (input: EvidenceInput) =>
      enqueueEvidence(
        { challenges, currentUserId: () => who.user, deviceId: () => Promise.resolve(DEVICE), enqueue: (d) => enqueueOutboxItem({ store: outbox, currentUserId: () => who.user, now: () => NOW0 }, d), existing: (o) => outbox.listByOwner(o), newId: () => "i1" },
        input,
      );
    return { who, outbox, store, enqueue };
  }

  it("owner A, signed-in B: refused with account_changed; no row for anyone and no pooled challenge consumed", async () => {
    const r = rig();
    await r.store.insertMany("user-b", DEVICE, [{ id: "p1", nonce: "bm9uY2U", kind: "prefetched", facilityId: null, expiresAt: NOW0 + 86_400_000 }], NOW0 - 1000);
    await expect(r.enqueue(checkinInput({ owner: "user-a", challenge: LIVE, challengeFor: { ownerUserId: "user-a", deviceId: DEVICE } }))).rejects.toMatchObject({ name: "OutboxEnqueueError", code: "account_changed" });
    await expect(r.enqueue(checkinInput({ owner: "user-a" }))).rejects.toMatchObject({ code: "account_changed" });
    expect(await r.outbox.list()).toEqual([]);
    expect(await r.store.countUsable("user-b", DEVICE, NOW0)).toBe(1);
  });

  it("the same user: accepted; a challenge issued to ANOTHER owner is refused even when `owner` matches", async () => {
    const r = rig();
    const ok = await r.enqueue(checkinInput({ owner: "user-b", challenge: LIVE, challengeFor: { ownerUserId: "user-b", deviceId: DEVICE } }));
    expect(ok.inserted).toBe(true);
    const r2 = rig();
    const err = await r2.enqueue(checkinInput({ owner: "user-b", challenge: LIVE, challengeFor: { ownerUserId: "user-a", deviceId: DEVICE } })).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(OutboxEnqueueError);
    expect((err as OutboxEnqueueError).code).toBe("account_changed");
    expect(await r2.outbox.list()).toEqual([]);
  });

  it("a challenge issued to another DEVICE, or one that names no owner and device, is refused", async () => {
    const r = rig();
    await expect(r.enqueue(checkinInput({ challenge: LIVE, challengeFor: { ownerUserId: "user-b", deviceId: "22222222-2222-4222-8222-222222222222" } }))).rejects.toThrow(/another device/);
    await expect(r.enqueue(checkinInput({ challenge: LIVE }))).rejects.toThrow(/name its owner and device/);
    expect(await r.outbox.list()).toEqual([]);
  });

  it("C6: a pre-acquired challenge covers a foreground_checkin ONLY: a dwell (two fixes, each needing its own single-use challenge) is refused, and nothing is written", async () => {
    const r = rig();
    const dwell = checkinInput({
      submission: { source: "foreground_dwell", checkinFix: fix("a"), checkoutFix: { ...fix("b"), capturedAt: NOW0 + 4 * 3600_000 }, apartMinutes: 240 },
      challenge: LIVE,
      challengeFor: { ownerUserId: "user-b", deviceId: DEVICE },
    });
    await expect(r.enqueue(dwell)).rejects.toThrow(/foreground_checkin only/);
    expect(await r.outbox.list()).toEqual([]);
    // and the same input without a pre-acquired challenge is fine for a dwell
    const { challenge: _c, challengeFor: _f, ...plain } = dwell;
    expect((await r.enqueue(plain)).inserted).toBe(true);
  });

  it("a self_report / health_workout with a pre-acquired challenge is refused too", async () => {
    const r = rig();
    for (const source of ["self_report", "health_workout"] as const) {
      await expect(r.enqueue(checkinInput({ submission: { source }, challenge: LIVE, challengeFor: { ownerUserId: "user-b", deviceId: DEVICE } }))).rejects.toThrow(/foreground_checkin only/);
    }
  });
});

describe("C7: acquireLive re-checks the owner (before the request and after the redemption)", () => {
  /** `lax`: a session that hands out a token for ANY user (so only acquireLive's own owner check can stop a request for the wrong one). */
  function mgr(lax = false) {
    const who = { user: "user-a" as string | null };
    const api = new FakeCheckinApi();
    const session = { currentUserId: () => who.user, accessTokenFor: (u: string) => Promise.resolve(lax || who.user === u ? `t-${u}` : null) };
    const m = new ChallengeManager({ store: new MemoryChallengeStore(), api, session, deviceId: () => Promise.resolve(DEVICE), now: () => NOW0 });
    return { who, api, m };
  }

  it("a live challenge for A is never handed back when the signed-in user changed during the redemption", async () => {
    const { who, api, m } = mgr();
    const real = api.redeemCheckinChallenge.bind(api);
    api.redeemCheckinChallenge = (req) => {
      who.user = "user-b";
      return real(req);
    };
    expect(await m.acquireLive("user-a", "fac_x")).toBeNull();
    expect(api.redeemed).toEqual(["live1"]); // the token was minted for A and goes nowhere
  });

  it("... or during the challenge request; and a user who is not signed in at the start makes no request at all", async () => {
    const { who, api, m } = mgr();
    const real = api.requestCheckinChallenges.bind(api);
    api.requestCheckinChallenges = (req) => {
      who.user = "user-b";
      return real(req);
    };
    expect(await m.acquireLive("user-a")).toBeNull();
    const again = mgr(true);
    again.who.user = "user-b";
    expect(await again.m.acquireLive("user-a")).toBeNull();
    expect(again.api.requests).toEqual([]);
    expect(await again.m.acquireLive("")).toBeNull();
  });

  it("the same user gets the challenge, stamped with its owner and device", async () => {
    const { m } = mgr();
    const live = await m.acquireLive("user-a", "fac_x");
    expect(live).toMatchObject({ ownerUserId: "user-a", deviceId: DEVICE, challenge: { state: "redeemed", kind: "live" } });
  });
});
