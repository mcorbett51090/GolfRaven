/**
 * P4.2b-1: prefetched check-in challenges (build plan §7.6 FM-10): the stores (memory reference + the real SQL over node:sqlite), the manager,
 * and the check-in -> outbox flow. Owner isolation, atomic single use, expiry, the cap of 10, the penalty path, deletion.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { deleteAccountAndWipeLocal } from "../src/account";
import { createHttpApiClient, ApiError, type CheckinApi, type IssuedChallenge } from "../src/api";
import { UnattestableAttestor } from "../src/attest";
import {
  ChallengeManager,
  MAX_PREFETCHED,
  MIN_REMAINING_MS,
  MemoryChallengeStore,
  SqliteChallengeStore,
  type ChallengeStore,
  type IssuedChallengeInput,
} from "../src/challenges";
import { enqueueEvidence, evidencePenaltyApplies, parseEvidencePayload, newFixId, type EvidenceInput } from "../src/evidence";
import { MemoryOutboxStore, createItem, OutboxEnqueueError, OutboxRunner, SqliteOutboxStore, enqueueOutboxItem, type OutboxSession, type OutboxStore } from "../src/outbox";
import { recorded, scriptedFetch, type Step } from "./support/edge-fixtures";
import { openNodeSqlite } from "./support/node-sqlite";
import { MemorySecureStore } from "../src/secure";
import { FakeAuth } from "./support/fakes";

const T = 1_800_000_000_000;
const DEV = "11111111-1111-4111-8111-111111111111";
const A = "user-a";
const B = "user-b";
const H = 3600_000;

const ch = (n: number, expiresIn = 24 * H, now = T): IssuedChallengeInput => ({ id: `c${n}`, nonce: `bm9uY2U${n}`, kind: "prefetched", facilityId: null, expiresAt: now + expiresIn });

const STORES: [string, () => Promise<ChallengeStore>][] = [
  ["memory store", async () => new MemoryChallengeStore()],
  ["SQLite store", async () => new SqliteChallengeStore(await openNodeSqlite())],
];

describe.each(STORES)("challenge store (%s)", (_n, make) => {
  it("keeps at most 10 usable per owner and device, whatever it is handed", async () => {
    const s = await make();
    expect(await s.insertMany(A, DEV, Array.from({ length: 15 }, (_, i) => ch(i)), T)).toBe(MAX_PREFETCHED);
    expect(await s.countUsable(A, DEV, T)).toBe(10);
    expect(await s.insertMany(A, DEV, [ch(100)], T)).toBe(0); // full
    expect(await s.insertMany(A, "22222222-2222-4222-8222-222222222222", [ch(101)], T)).toBe(1); // another device has its own 10
  });

  it("OWNER ISOLATION: B can never consume (or count) A's challenges; each owner has an own pool of 10", async () => {
    const s = await make();
    await s.insertMany(A, DEV, Array.from({ length: 10 }, (_, i) => ch(i)), T);
    expect(await s.countUsable(B, DEV, T)).toBe(0);
    expect(await s.consumeOne(B, DEV, T, T)).toBeNull();
    await s.insertMany(B, DEV, [{ ...ch(50), id: "b1" }], T);
    const got = await s.consumeOne(B, DEV, T, T);
    expect(got).toMatchObject({ ownerUserId: B, id: "b1" }); // B gets B's, never one of A's ten
    expect(await s.consumeOne(B, DEV, T, T)).toBeNull();
    expect(await s.countUsable(A, DEV, T)).toBe(10); // A's pool is untouched
    // the same challenge id for two owners is two rows
    await s.insertMany(B, DEV, [ch(0)], T);
    expect((await s.listByOwner(A)).filter((r) => r.id === "c0")).toHaveLength(1);
    expect((await s.listByOwner(B)).filter((r) => r.id === "c0")).toHaveLength(1);
  });

  it("DEVICE: a challenge issued for another device id (e.g. a restored backup) is never selected", async () => {
    const s = await make();
    await s.insertMany(A, "22222222-2222-4222-8222-222222222222", [ch(1)], T);
    expect(await s.consumeOne(A, DEV, T, T)).toBeNull();
  });

  it("ATOMIC and single use: 25 concurrent check-ins over 10 challenges get 10 DISTINCT challenges and 15 'none'", async () => {
    const s = await make();
    await s.insertMany(A, DEV, Array.from({ length: 10 }, (_, i) => ch(i)), T);
    const got = await Promise.all(Array.from({ length: 25 }, () => s.consumeOne(A, DEV, T, T)));
    const ids = got.filter((g) => g !== null).map((g) => g!.id);
    expect(ids).toHaveLength(10);
    expect(new Set(ids).size).toBe(10);
    expect(got.filter((g) => g === null)).toHaveLength(15);
    expect(await s.countUsable(A, DEV, T)).toBe(0);
  });

  it("a consumed challenge is consumed before it is returned, never offered again, and a re-insert does not resurrect it", async () => {
    const s = await make();
    await s.insertMany(A, DEV, [ch(1)], T);
    const first = await s.consumeOne(A, DEV, T, T);
    expect(first).toMatchObject({ id: "c1", consumedAt: T });
    expect((await s.listByOwner(A))[0]!.consumedAt).toBe(T); // already persisted as consumed
    expect(await s.consumeOne(A, DEV, T, T + 5)).toBeNull();
    expect(await s.insertMany(A, DEV, [ch(1)], T + 10)).toBe(0); // the server never re-issues an id; if it did, it stays consumed
    expect(await s.consumeOne(A, DEV, T, T + 20)).toBeNull();
    expect((await s.listByOwner(A))[0]!.consumedAt).toBe(T);
  });

  it("EXPIRY: an expired challenge (or one about to expire) is never selected; the freshest valid one is preferred", async () => {
    const s = await make();
    await s.insertMany(A, DEV, [ch(1, 100 * 60_000), ch(2, 10 * H), ch(3, 5 * H), ch(4, MIN_REMAINING_MS - 1)], T);
    // ch4 has less than the margin left: not selectable
    const order: string[] = [];
    for (let i = 0; i < 20; i += 1) {
      const c = await s.consumeOne(A, DEV, T, T);
      if (!c) break;
      order.push(c.id);
    }
    expect(order).toEqual(["c2", "c3", "c1"]); // latest expiry first
    // later, with everything expired
    const s2 = await make();
    await s2.insertMany(A, DEV, [ch(1, H)], T);
    expect(await s2.consumeOne(A, DEV, T + 2 * H, T + 2 * H)).toBeNull();
    expect(await s2.consumeOne(A, DEV, T, T + 2 * H)).toBeNull(); // captured earlier, but it has expired by now (it would be redeemed after expiry)
    expect(await s2.consumeOne(A, DEV, T + H - 30_000, T)).toBeNull(); // captured inside the last minute: too late to be worth it
    expect(await s2.consumeOne(A, DEV, T - 1, T)).toBeNull(); // captured BEFORE the device even had it
  });

  it("purgeExpired deletes expired rows (consumed or not) and nothing else", async () => {
    const s = await make();
    await s.insertMany(A, DEV, [ch(1, H), ch(2, 10 * H)], T);
    await s.consumeOne(A, DEV, T, T); // consumes c2 (latest expiry)
    expect(await s.purgeExpired(T + 2 * H)).toBe(1); // c1 expired
    expect((await s.listByOwner(A)).map((r) => r.id)).toEqual(["c2"]);
    expect(await s.purgeExpired(T + 11 * H)).toBe(1);
    expect(await s.listByOwner(A)).toEqual([]);
  });

  it("the ownerless sentinel is nobody", async () => {
    const s = await make();
    await expect(s.insertMany("", DEV, [ch(1)], T)).rejects.toThrow(/owner/);
    expect(await s.consumeOne("", DEV, T, T)).toBeNull();
    expect(await s.countUsable("", DEV, T)).toBe(0);
  });

  it("deleteOwner removes that owner's rows only (account deletion), and sign-out has no hook here at all (rows stay dormant)", async () => {
    const s = await make();
    await s.insertMany(A, DEV, [ch(1), ch(2)], T);
    await s.insertMany(B, DEV, [ch(3)], T);
    await s.consumeOne(A, DEV, T, T);
    await s.deleteOwner(A);
    expect(await s.listByOwner(A)).toEqual([]);
    expect((await s.listByOwner(B)).map((r) => r.id)).toEqual(["c3"]);
  });
});

// ---------------------------------------------------------------------------------------------------------------------------------------------

class FakeCheckinApi implements CheckinApi {
  readonly requests: { req: Parameters<CheckinApi["requestCheckinChallenges"]>[0]; token: string }[] = [];
  readonly redemptions: { req: Parameters<CheckinApi["redeemCheckinChallenge"]>[0]; token: string }[] = [];
  next: (() => Promise<IssuedChallenge[]>) | null = null;
  respond: (n: number, live: boolean) => IssuedChallenge[] = (n, live) =>
    Array.from({ length: n }, (_, i) => ({ id: `s${this.requests.length}-${i}`, nonce: `bm9uY2U${i}`, expiresAt: new Date(T + (live ? 120_000 : 24 * H)).toISOString(), kind: live ? "live" : "prefetched" }));
  redeemError: ApiError | null = null;
  requestCheckinChallenges(req: Parameters<CheckinApi["requestCheckinChallenges"]>[0], c: { accessToken: string }): Promise<IssuedChallenge[]> {
    this.requests.push({ req, token: c.accessToken });
    if (this.next) return this.next();
    return Promise.resolve(this.respond(req.prefetchCount ? req.prefetchCount : 1, !req.prefetchCount));
  }
  redeemCheckinChallenge(req: Parameters<CheckinApi["redeemCheckinChallenge"]>[0], c: { accessToken: string }) {
    this.redemptions.push({ req, token: c.accessToken });
    if (this.redeemError) return Promise.reject(this.redeemError);
    return Promise.resolve({ jti: `jti_${req.challengeId}`.replace(/[^A-Za-z0-9_-]/g, "_"), expiresAt: new Date(T + 900_000).toISOString(), attestationGrade: "unattestable" as const });
  }
}

function rig(makeStore: () => ChallengeStore = () => new MemoryChallengeStore()) {
  const clock = { now: T };
  const who = { user: A as string | null };
  const tokens: string[] = [];
  const store = makeStore();
  const api = new FakeCheckinApi();
  const session: OutboxSession = {
    currentUserId: () => who.user,
    accessTokenFor: async (u) => {
      tokens.push(u);
      return who.user === u ? `token-${u}` : null;
    },
  };
  const manager = new ChallengeManager({ store, api, session, deviceId: async () => DEV, attestor: new UnattestableAttestor(), now: () => clock.now });
  return { clock, who, tokens, store, api, session, manager };
}

describe("ChallengeManager.prefetch", () => {
  it("while online and signed in, tops the pool up to 10 with ONE request for the shortfall, as the owner, for this device", async () => {
    const r = rig();
    expect(await r.manager.prefetch()).toEqual({ kind: "filled", added: 10, usable: 10 });
    expect(r.api.requests).toEqual([{ req: { deviceId: DEV, prefetchCount: 10 }, token: `token-${A}` }]);
    // 4 consumed offline -> only 4 are requested next time
    for (let i = 0; i < 4; i += 1) await r.store.consumeOne(A, DEV, T, T);
    expect(await r.manager.prefetch()).toMatchObject({ kind: "filled", added: 4, usable: 10 });
    expect(r.api.requests[1]!.req.prefetchCount).toBe(4);
    expect(await r.manager.prefetch()).toEqual({ kind: "full", usable: 10 });
    expect(r.api.requests).toHaveLength(2); // a full pool makes no request
  });

  it("never keeps more than the shortfall, even if the server hands back more; ignores live, expired and malformed-kind entries", async () => {
    const r = rig();
    r.api.next = async () => [
      ...Array.from({ length: 14 }, (_, i): IssuedChallenge => ({ id: `p${i}`, nonce: `bm9uY2U${i}`, expiresAt: new Date(T + 24 * H).toISOString(), kind: "prefetched" })),
      { id: "live1", nonce: "bm9uY2U", expiresAt: new Date(T + 24 * H).toISOString(), kind: "live" },
      { id: "old", nonce: "bm9uY2U", expiresAt: new Date(T - 1).toISOString(), kind: "prefetched" },
    ];
    const out = await r.manager.prefetch();
    expect(out).toMatchObject({ kind: "filled", added: 10 });
    const rows = await r.store.listByOwner(A);
    expect(rows).toHaveLength(10);
    expect(rows.some((x) => x.id === "live1" || x.id === "old")).toBe(false);
  });

  it("the TTL is the server's own (24 h in the recorded answer), read from each challenge's expiresAt", async () => {
    const f = scriptedFetch({ respond: "challenge_prefetch_10_201" });
    const api = createHttpApiClient({ baseUrl: "https://p.supabase.co/functions/v1", fetch: f.fetch, getAccessToken: () => Promise.reject(new Error("no")), sleep: async () => undefined });
    const store = new MemoryChallengeStore();
    const now = Date.parse("2026-06-01T12:00:00.000Z");
    const m = new ChallengeManager({ store, api, session: { currentUserId: () => A, accessTokenFor: async () => "tok" }, deviceId: async () => DEV, attestor: new UnattestableAttestor(), now: () => now });
    expect(await m.prefetch()).toEqual({ kind: "filled", added: 10, usable: 10 });
    const rows = await store.listByOwner(A);
    expect(new Set(rows.map((r) => r.expiresAt))).toEqual(new Set([Date.parse("2026-06-02T12:00:00.000Z")]));
    expect(f.seen[0]).toMatchObject({ url: "https://p.supabase.co/functions/v1/checkin-challenge", body: { deviceId: DEV, prefetchCount: 10 } });
    expect(f.seen[0]!.headers["Authorization"]).toBe("Bearer tok");
  });

  it("the server's own 429 (device already holds 10 unused) and a network failure are reported, not thrown", async () => {
    for (const [step, reason] of [
      [{ respond: "challenge_prefetch_429_full" }, "rate_limited"],
      [{ network: "offline" }, "network"],
      [{ respond: "err_500_internal" }, "network"],
      [{ respond: "err_403_forbidden" }, "rejected"],
    ] as [Step, string][]) {
      const f = scriptedFetch(step);
      const api = createHttpApiClient({ baseUrl: "https://p.supabase.co/functions/v1", fetch: f.fetch, getAccessToken: () => Promise.reject(new Error("no")), sleep: async () => undefined });
      const m = new ChallengeManager({ store: new MemoryChallengeStore(), api, session: { currentUserId: () => A, accessTokenFor: async () => "tok" }, deviceId: async () => DEV, attestor: new UnattestableAttestor(), now: () => T });
      expect(await m.prefetch(), reason).toEqual({ kind: "failed", reason });
      expect(f.seen, "a challenge request is not retried").toHaveLength(1);
    }
  });

  it("signed out: nothing is requested; no token for the owner: skipped", async () => {
    const r = rig();
    r.who.user = null;
    expect(await r.manager.prefetch()).toEqual({ kind: "skipped", reason: "signed_out" });
    expect(r.api.requests).toEqual([]);
    r.who.user = A;
    r.session.accessTokenFor = async () => null;
    expect(await r.manager.prefetch()).toEqual({ kind: "skipped", reason: "no_token" });
    expect(r.api.requests).toEqual([]);
  });

  it("a user switch while the request is in flight: the challenges are stored under the user the credentials belong to, and B cannot consume them", async () => {
    const r = rig();
    r.api.next = async () => {
      r.who.user = B; // B signs in while A's request is in flight
      return r.api.respond(10, false);
    };
    expect(await r.manager.prefetch()).toMatchObject({ kind: "filled", added: 10 });
    expect(await r.store.countUsable(A, DEV, T)).toBe(10);
    expect(await r.store.countUsable(B, DEV, T)).toBe(0);
    expect(await r.manager.acquireForFix(B, T)).toEqual({ state: "none", reason: "none_available" });
  });

  it("is single-flight per user", async () => {
    const r = rig();
    const [a, b] = await Promise.all([r.manager.prefetch(), r.manager.prefetch()]);
    expect(a).toEqual(b);
    expect(r.api.requests).toHaveLength(1);
  });

  it("expired rows are purged first and do not count against the cap", async () => {
    const r = rig();
    await r.store.insertMany(A, DEV, Array.from({ length: 10 }, (_, i) => ch(i, H)), T);
    r.clock.now = T + 2 * H;
    expect(await r.manager.prefetch()).toMatchObject({ kind: "filled", added: 10 });
    expect((await r.store.listByOwner(A)).every((x) => x.expiresAt > r.clock.now)).toBe(true);
  });
});

describe("ChallengeManager.acquireForFix", () => {
  it("consumes exactly one prefetched challenge per fix; the eleventh check-in has none", async () => {
    const r = rig();
    await r.manager.prefetch();
    const got = [];
    for (let i = 0; i < 11; i += 1) got.push(await r.manager.acquireForFix(A, T));
    expect(got.slice(0, 10).every((g) => g.state === "held")).toBe(true);
    expect(new Set(got.slice(0, 10).map((g) => (g as { challengeId: string }).challengeId)).size).toBe(10);
    expect(got[10]).toEqual({ state: "none", reason: "none_available" });
  });

  it("only for the signed-in owner: a request for someone else's account consumes nothing", async () => {
    const r = rig();
    await r.manager.prefetch();
    expect(await r.manager.acquireForFix(B, T)).toEqual({ state: "none", reason: "none_available" });
    r.who.user = B;
    expect(await r.manager.acquireForFix(A, T)).toEqual({ state: "none", reason: "none_available" });
    expect(await r.store.countUsable(A, DEV, T)).toBe(10);
  });

  it("online: a LIVE challenge is requested and redeemed on the spot (as the owner, attestor capability reported), the pool is untouched", async () => {
    const r = rig();
    await r.manager.prefetch();
    const c = await r.manager.acquireForFix(A, T, { live: true, facilityId: "fac_x" });
    expect(c).toMatchObject({ state: "redeemed", kind: "live", grade: "unattestable" });
    expect(r.api.requests[1]).toEqual({ req: { deviceId: DEV, facilityId: "fac_x" }, token: `token-${A}` });
    expect(r.api.redemptions).toEqual([{ req: { challengeId: "s2-0", nonce: "bm9uY2U0", hardwareSupportsAttestation: false }, token: `token-${A}` }]);
    expect(await r.store.countUsable(A, DEV, T)).toBe(10);
  });

  it("a live challenge that cannot be had (offline, rate limited, wrong kind, refused redemption) falls back to the pool, then to none", async () => {
    const r = rig();
    await r.manager.prefetch();
    r.api.next = async () => Promise.reject(new ApiError({ kind: "network" }));
    expect((await r.manager.acquireForFix(A, T, { live: true })).state).toBe("held");
    r.api.next = async () => [{ id: "x", nonce: "bm9uY2U", expiresAt: new Date(T + H).toISOString(), kind: "prefetched" }]; // not live
    expect((await r.manager.acquireForFix(A, T, { live: true })).state).toBe("held");
    r.api.next = null;
    r.api.redeemError = new ApiError({ kind: "rejected", status: 422, code: "challenge_used" });
    expect((await r.manager.acquireForFix(A, T, { live: true })).state).toBe("held");
    const empty = rig();
    empty.api.next = async () => Promise.reject(new ApiError({ kind: "network" }));
    expect(await empty.manager.acquireForFix(A, T, { live: true })).toEqual({ state: "none", reason: "none_available" });
  });

  it("a live challenge needs a token for the owner: with none it falls back without any request", async () => {
    const r = rig();
    r.session.accessTokenFor = async () => null;
    expect((await r.manager.acquireForFix(A, T, { live: true })).state).toBe("none");
    expect(r.api.requests).toEqual([]);
  });
});

// ---------------------------------------------------------------------------------------------------------------------------------------------

describe.each([
  ["memory", async () => ({ challenge: new MemoryChallengeStore() as ChallengeStore, outbox: new MemoryOutboxStore() as OutboxStore })],
  ["sqlite", async () => { const db = await openNodeSqlite(); return { challenge: new SqliteChallengeStore(db) as ChallengeStore, outbox: new SqliteOutboxStore(db) as OutboxStore }; }],
] as const)("check-in -> outbox (%s)", (_n, makeStores) => {
  async function flow() {
    const { challenge, outbox } = await makeStores();
    const r = rig(() => challenge);
    const deps = {
      challenges: r.manager,
      currentUserId: () => r.who.user,
      deviceId: async () => DEV,
      enqueue: (d: Parameters<typeof enqueueOutboxItem>[1]) => enqueueOutboxItem({ store: outbox, currentUserId: () => r.who.user, now: () => r.clock.now }, d),
      existing: (o: string) => outbox.listByOwner(o),
      newId: (() => { let n = 0; return () => `id${(n += 1)}`; })(),
    };
    const input = (n: number, over: Partial<EvidenceInput> = {}): EvidenceInput => ({
      origin: "live",
      facilityId: "fac_x",
      courseId: "crs_x1",
      catalogVersion: "20260520-a000001",
      localDate: "2026-06-01",
      submission: { source: "foreground_checkin", fix: { fixId: `fix_${n}`, lat: 36.1, lng: -86.7, accuracyMeters: 10, capturedAt: r.clock.now, simulated: false, foreground: true, fromApp: true } },
      ...over,
    });
    return { ...r, outbox, challenge, deps, input };
  }

  it("a check-in consumes exactly ONE challenge and records it on the item; the item belongs to the signed-in user", async () => {
    const f = await flow();
    await f.manager.prefetch();
    const out = await enqueueEvidence(f.deps, f.input(1));
    expect(out).toMatchObject({ inserted: true, penalty: false });
    expect(out.item.ownerUserId).toBe(A);
    expect(out.item.sourceRef).toBe("fix:fix_1");
    const p = parseEvidencePayload(out.item.payload);
    expect(p.ok && Object.values(p.payload.challenges)[0]).toMatchObject({ state: "held", kind: "prefetched" });
    expect(await f.challenge.countUsable(A, DEV, T)).toBe(9);
    expect((await f.challenge.listByOwner(A)).filter((c) => c.consumedAt !== null)).toHaveLength(1);
  });

  it("with no challenge left the evidence is still recorded, flagged as the penalty path, and says why", async () => {
    const f = await flow();
    const out = await enqueueEvidence(f.deps, f.input(1));
    expect(out.penalty).toBe(true);
    const p = parseEvidencePayload(out.item.payload);
    expect(p.ok && evidencePenaltyApplies(p.payload)).toBe(true);
    expect(p.ok && Object.values(p.payload.challenges)[0]).toEqual({ state: "none", reason: "none_available" });
  });

  it("a duplicate check-in (same fix) consumes NO challenge and returns the existing item", async () => {
    const f = await flow();
    await f.manager.prefetch();
    const a = await enqueueEvidence(f.deps, f.input(1));
    const b = await enqueueEvidence(f.deps, f.input(1));
    expect(b).toMatchObject({ inserted: false });
    expect(b.item.id).toBe(a.item.id);
    expect(await f.challenge.countUsable(A, DEV, T)).toBe(9);
  });

  it("signed out: refused BEFORE any challenge is touched", async () => {
    const f = await flow();
    await f.manager.prefetch();
    f.who.user = null;
    await expect(enqueueEvidence(f.deps, f.input(1))).rejects.toBeInstanceOf(OutboxEnqueueError);
    expect(await f.challenge.countUsable(A, DEV, T)).toBe(10);
    expect(await f.outbox.list()).toEqual([]);
  });

  it("B signed in on A's device: B's check-in never consumes A's challenges (it goes with none)", async () => {
    const f = await flow();
    await f.manager.prefetch(); // A's ten
    f.who.user = B;
    const out = await enqueueEvidence(f.deps, f.input(1));
    expect(out.item.ownerUserId).toBe(B);
    expect(out.penalty).toBe(true);
    expect(await f.challenge.countUsable(A, DEV, T)).toBe(10);
    f.who.user = A; // A is back: all ten are there, dormant
    expect((await enqueueEvidence(f.deps, f.input(2))).penalty).toBe(false);
  });

  it("a dwell consumes one challenge per fix", async () => {
    const f = await flow();
    await f.manager.prefetch();
    const fix = (id: string, at: number) => ({ fixId: id, lat: 36.1, lng: -86.7, accuracyMeters: 10, capturedAt: at, simulated: false, foreground: true, fromApp: true });
    const out = await enqueueEvidence(f.deps, f.input(1, { submission: { source: "foreground_dwell", checkinFix: fix("d1", T), checkoutFix: fix("d2", T + 3600_000), apartMinutes: 60 } }));
    expect(out.item.sourceRef).toBe("dwell:d1:d2");
    expect(await f.challenge.countUsable(A, DEV, T)).toBe(8);
  });

  it("NEVER REUSED after a failed send: the challenge stays consumed while the item retries, and the next check-in gets a different one", async () => {
    const f = await flow();
    await f.manager.prefetch();
    const first = await enqueueEvidence(f.deps, f.input(1));
    const heldId = ((parseEvidencePayload(first.item.payload) as { ok: true; payload: { challenges: Record<string, { challengeId: string }> } }).payload.challenges["fix_1"] as { challengeId: string }).challengeId;
    // a runner whose every send fails at the network
    const runner = new OutboxRunner({
      store: f.outbox,
      api: { submitEvidence: async () => ({ kind: "network_error" as const }) },
      session: f.session,
      now: () => f.clock.now,
      rng: () => 0,
      refreshCatalog: async () => undefined,
      rematch: async () => ({ ok: false }),
      findCourseForUnlisted: async () => null,
    });
    await runner.run();
    expect((await f.outbox.get(first.item.id))!.status).toBe("retry");
    expect((await f.challenge.listByOwner(A)).find((c) => c.id === heldId)!.consumedAt).not.toBeNull();
    const second = await enqueueEvidence(f.deps, f.input(2));
    const secondId = ((parseEvidencePayload(second.item.payload) as { ok: true; payload: { challenges: Record<string, { challengeId: string }> } }).payload.challenges["fix_2"] as { challengeId: string }).challengeId;
    expect(secondId).not.toBe(heldId);
    // and a prefetch (which only ever ADDS) cannot bring it back either
    await f.manager.prefetch();
    expect((await f.challenge.listByOwner(A)).filter((c) => c.id === heldId)).toHaveLength(1);
    expect((await f.challenge.listByOwner(A)).find((c) => c.id === heldId)!.consumedAt).not.toBeNull();
  });

  it("an expired challenge is never used: with only an expired pool the check-in goes with none", async () => {
    const f = await flow();
    await f.manager.prefetch();
    f.clock.now = T + 25 * H;
    const out = await enqueueEvidence(f.deps, f.input(1));
    expect(out.penalty).toBe(true);
  });

  it("an import carries no fixes (and no challenge)", async () => {
    const f = await flow();
    const out = await enqueueEvidence(f.deps, f.input(1, { origin: "import", submission: { source: "self_report" }, localDate: "2026-05-20" }));
    expect(out.penalty).toBe(false);
    expect(out.item.sourceRef).toMatch(/^hash:[0-9a-f]{64}$/);
    await expect(enqueueEvidence(f.deps, f.input(2, { origin: "import" }))).rejects.toThrow(/no fixes/);
  });

  it("newFixId is unpadded base64url the server accepts", () => {
    const id = newFixId((n) => Uint8Array.from({ length: n }, (_, i) => i * 17));
    expect(id).toMatch(/^[A-Za-z0-9_-]{1,128}$/);
  });
});

describe("account deletion", () => {
  it("removes the deleted user's challenges (and ONLY theirs), purges the export cache, and leaves other users' dormant rows alone", async () => {
    const db = await openNodeSqlite();
    const challenges = new SqliteChallengeStore(db);
    const outbox = new SqliteOutboxStore(db);
    await challenges.insertMany(A, DEV, [ch(1), ch(2)], T);
    await challenges.insertMany(B, DEV, [ch(3)], T);
    const auth = new FakeAuth();
    auth.session = { userId: A, provider: "email", stub: false };
    let purged = 0;
    const secure = new MemorySecureStore();
    const r = await deleteAccountAndWipeLocal({
      api: { deleteAccount: async () => ({ userId: A, deletedAt: "x", authUserDeleted: true, authUserAlreadyGone: false, signinProvidersRevoked: [] }) },
      auth,
      outbox,
      challenges,
      sharer: { purgeStale: async () => void (purged += 1) },
      currentUserId: () => A,
      secure,
      clearUserCaches: () => undefined,
    });
    expect(r).toMatchObject({ status: "deleted", localWipe: "complete" });
    expect(purged).toBe(1);
    expect(await challenges.listByOwner(A)).toEqual([]);
    expect((await challenges.listByOwner(B)).map((c) => c.id)).toEqual(["c3"]);
  });

  it("a failing export-cache purge is a partial wipe and does not stop the other steps", async () => {
    const challenges = new MemoryChallengeStore();
    await challenges.insertMany(A, DEV, [ch(1)], T);
    const r = await deleteAccountAndWipeLocal({
      api: { deleteAccount: async () => ({ userId: A, deletedAt: "x", authUserDeleted: true, authUserAlreadyGone: false, signinProvidersRevoked: [] }) },
      auth: { clearLocalSession: async () => undefined },
      outbox: new MemoryOutboxStore(),
      challenges,
      sharer: { purgeStale: () => Promise.reject(new Error("disk")) },
      currentUserId: () => A,
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(r).toMatchObject({ status: "deleted", localWipe: "partial", failedSteps: ["export-cache"] });
    expect(await challenges.listByOwner(A)).toEqual([]);
  });

  it("with the server's answer lost, the user who WAS signed in is the one deleted; with no user known, no user's rows go", async () => {
    const outbox = new MemoryOutboxStore();
    for (const [id, owner] of [["1", A], ["2", B]] as const) await outbox.insertIfAbsent(createItem({ id, sourceRef: id, ownerUserId: owner, courseId: "c", catalogVersion: "v", payload: null }, 1));
    const deps = (user: string | null) => ({
      api: { deleteAccount: async (): Promise<never> => { throw new ApiError({ kind: "unauthenticated", status: 401, mayHaveBeenApplied: true }); } },
      auth: { clearLocalSession: async () => undefined },
      outbox,
      challenges: new MemoryChallengeStore(),
      sharer: { purgeStale: async () => undefined },
      currentUserId: () => user,
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(await deleteAccountAndWipeLocal(deps(null))).toMatchObject({ status: "deleted_or_session_ended" });
    expect((await outbox.list()).map((i) => i.ownerUserId).sort()).toEqual([A, B]);
    await deleteAccountAndWipeLocal(deps(A));
    expect((await outbox.list()).map((i) => i.ownerUserId)).toEqual([B]);
  });
});

describe("recorded challenge answers", () => {
  it("live: 120 s; prefetched: 24 h; the partial answer has fewer than asked; the cap and over-cap answers are the server's own", () => {
    const live = JSON.parse(recorded("challenge_live_201").body).data.challenges[0];
    expect(Date.parse(live.expiresAt) - Date.parse("2026-06-01T12:00:00.000Z")).toBe(120_000);
    expect(live.kind).toBe("live");
    expect(JSON.parse(recorded("challenge_prefetch_10_201").body).data.challenges).toHaveLength(10);
    expect(JSON.parse(recorded("challenge_prefetch_partial_201").body).data.challenges).toHaveLength(2);
    expect(recorded("challenge_prefetch_429_full").status).toBe(429);
    expect(recorded("challenge_400_prefetch_over_cap").status).toBe(400);
  });
});

describe("wiring (source checks: composition code with no UI harness here)", () => {
  const read = (p: string): string => readFileSync(new URL(p, import.meta.url), "utf8").replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

  it("account deletion is handed the challenge store, the share cache and the signed-in user; sign-out touches no challenge", () => {
    const provider = read("../src/runtime/AppProvider.tsx");
    expect(provider).toMatch(/challenges: services\.challengeStore/);
    expect(provider).toMatch(/sharer: services\.sharer/);
    expect(provider).toMatch(/currentUserId: \(\) => services\.auth\.current\(\)\?\.userId \?\? null/);
    const signOut = provider.match(/signOut: async \(\) => \{[\s\S]*?\n    \},/)?.[0] ?? "";
    expect(signOut).not.toMatch(/challenge/i);
  });

  it("the wipe on deletion removes owners, never everything", () => {
    const del = read("../src/account/delete.ts");
    expect(del).toMatch(/deps\.challenges\.deleteOwner\(deletedUser\)/);
    expect(del).toMatch(/deps\.sharer\.purgeStale\(\)/);
    expect(del).not.toMatch(/deleteAll/);
  });

  it("the composition root builds ONE store pair over the same database and the prefetch runs after a sync, not before", () => {
    const services = read("../src/runtime/services.ts");
    expect(services).toMatch(/challengeStore = new SqliteChallengeStore\(db\)/);
    expect(services).toMatch(/new ChallengeManager\(\{ store: challengeStore, api, session, deviceId, attestor,/);
    const provider = read("../src/runtime/AppProvider.tsx");
    expect(provider.indexOf("outboxRunner.run()")).toBeLessThan(provider.indexOf("challenges.prefetch()"));
  });
});
