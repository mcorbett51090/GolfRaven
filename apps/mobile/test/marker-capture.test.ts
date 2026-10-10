/**
 * P4.2c / P5 §52: "Buying a marker" (build plan §7.6 G2-03): the capture and the local queue. Sending is `marker/send.ts` (fix-only `marker-scan`); flags stay false. Historical note on what was missing:
 * `test/marker-no-sender.test.ts`-style scans below pin that nothing reads the queue to send it).
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { deleteAccountAndWipeLocal } from "../src/account";
import { MemoryChallengeStore, SqliteChallengeStore } from "../src/challenges";
import { markerCosignalUiAvailable } from "../src/checkin";
import { MARKER_LIMITS, captureMarkerCoSignal, heldOpenCount, MemoryMarkerCosignalStore, SqliteMarkerCosignalStore, type MarkerCaptureDeps, type MarkerCosignalStore } from "../src/marker";
import { MemoryOutboxStore } from "../src/outbox";
import { MemorySecureStore } from "../src/secure";
import { FakeCheckinApi, DEVICE, NASHVILLE, NOW0, SITE_VERSION, entryOf, facility, makeRig, rawFix } from "./support/checkin-rig";
import { FakeAuth } from "./support/fakes";
import { openNodeSqlite } from "./support/node-sqlite";

const H = 3600_000;
const E = entryOf(facility());

const STORES: [string, () => Promise<MarkerCosignalStore>][] = [
  ["memory store", async () => new MemoryMarkerCosignalStore()],
  ["SQLite store", async () => new SqliteMarkerCosignalStore(await openNodeSqlite())],
];

function rigWith(store: MarkerCosignalStore) {
  const rig = makeRig();
  let n = 0;
  const deps = (over: Partial<MarkerCaptureDeps> = {}): MarkerCaptureDeps => ({
    enabled: true,
    location: rig.location,
    currentUserId: () => rig.who.user,
    challenges: rig.challenges,
    store,
    deviceId: () => Promise.resolve(DEVICE),
    newId: () => `m${(n += 1)}`,
    newFixId: () => `mfix${n}`,
    now: () => rig.clock.now,
    ...over,
  });
  return { rig, deps, run: (over?: Partial<MarkerCaptureDeps>, entry = E) => captureMarkerCoSignal(deps(over), { entry, catalogVersion: SITE_VERSION }) };
}

describe.each(STORES)("capture (%s)", (_n, make) => {
  it("captures the fix against a PREFETCHED challenge (offline: no live one is ever asked for) and stores it for the signed-in user", async () => {
    const { rig, run } = rigWith(await make());
    rig.api.online = false;
    await rig.seedPool(10, NOW0 - 2 * H);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0 - 1_000, { latitude: 36.14671234, longitude: -86.78159876, accuracyMeters: 9.5 }) }];
    const o = await run();
    expect(o.kind).toBe("captured");
    if (o.kind !== "captured") return;
    expect(o.record).toMatchObject({
      id: "m1",
      ownerUserId: "user-a",
      facilityId: "fac_x",
      catalogVersion: SITE_VERSION,
      deviceId: DEVICE,
      fix: { lat: 36.14671234, lng: -86.78159876, accuracyMeters: 9.5, capturedAt: NOW0 - 1_000, simulated: false, foreground: true, fromApp: true },
      challenge: { state: "held", kind: "prefetched" },
    });
    expect(rig.api.requests).toEqual([]); // never a live challenge request
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(9);
  });

  it("the record's challenge window contains the fix: it was consumed with the fix's own time", async () => {
    const { rig, run } = rigWith(await make());
    rig.api.online = false;
    await rig.seedPool(10, NOW0 + 10_000); // received AFTER the fix: cannot cover it
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    expect((await run()).kind).toBe("no_challenge");
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0 + 20_000)).toBe(10); // not consumed
  });

  it("an empty pool: refused as 'reserved' BEFORE the prompt (a co-signal without a challenge is worth nothing) and NOTHING is stored", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.location.perm = { status: "undetermined" };
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    expect(await run()).toEqual({ kind: "reserved" });
    expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("the player must be AT the facility: a fix outside its circle plus the 50 m buffer is 'not here', no challenge spent, nothing stored", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    await rig.seedPool(10, NOW0 - H);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0, { latitude: NASHVILLE.lat + 0.01 }) }]; // ~1.1 km
    const o = await run();
    expect(o).toMatchObject({ kind: "not_here" });
    expect(await store.listByOwner("user-a")).toEqual([]);
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(10);
  });

  it.each([
    ["disabled", { enabled: false }, "disabled"],
    ["signed out", { currentUserId: () => null }, "signed_out"],
  ] as const)("%s: nothing is asked, spent or stored (no prompt, no fix)", async (_l, over, kind) => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.location.perm = { status: "undetermined" };
    await rig.seedPool(1, NOW0 - H);
    expect((await run(over as Partial<MarkerCaptureDeps>)).kind).toBe(kind);
    expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("NIT: an unverified or approximate facility (no geometry on the device) is refused BEFORE the permission prompt, as the check-in does; nothing is asked, spent or stored", async () => {
    for (const f of [facility({ status: "unverified" }), facility({ approx: true }), facility({ lat: null, lng: null })]) {
      const store = await make();
      const { rig, run } = rigWith(store);
      await rig.seedPool(10, NOW0 - H);
      rig.location.perm = { status: "undetermined" };
      rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
      expect((await run(undefined, entryOf(f))).kind).toBe("no_geometry");
      expect(rig.location.calls).toEqual({ permission: 0, request: 0, services: 0, fix: 0 });
      expect(await store.listByOwner("user-a")).toEqual([]);
      expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(10);
    }
  });

  it.each([
    ["denied", { status: "denied", canAskAgain: false } as const, { kind: "permission", status: "blocked" }],
    ["approximate", { status: "granted", approximate: true } as const, { kind: "permission", status: "approximate" }],
  ])("permission %s: refused with the same outcome as the check-in", async (_l, perm, expected) => {
    const { rig, run } = rigWith(await make());
    await rig.seedPool(10, NOW0 - H);
    rig.location.perm = perm;
    expect(await run()).toEqual(expected);
  });

  it("refuses a simulated, inaccurate, stale or missing fix like the check-in does (no challenge spent)", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    await rig.seedPool(10, NOW0 - H);
    for (const [attempt, kind] of [
      [{ ok: true, fix: rawFix(NOW0, { simulated: true }) }, "simulated"],
      [{ ok: true, fix: rawFix(NOW0, { accuracyMeters: 120 }) }, "inaccurate"],
      [{ ok: true, fix: rawFix(NOW0 - 120_000) }, "stale_fix"],
      [{ ok: false, reason: "timeout" }, "no_fix"],
    ] as const) {
      rig.location.fixes = [attempt];
      expect((await run()).kind).toBe(kind);
    }
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(10);
    expect(await store.listByOwner("user-a")).toEqual([]);
  });
});

describe.each(STORES)("the local queue (%s)", (_n, make) => {
  const rec = (owner: string, id: string, at: number) => ({
    id,
    ownerUserId: owner,
    facilityId: "fac_x",
    catalogVersion: SITE_VERSION,
    deviceId: DEVICE,
    fix: { fixId: `f${id}`, lat: 1, lng: 2, accuracyMeters: 5, capturedAt: at, simulated: false, foreground: true, fromApp: true },
    challenge: { state: "held" as const, challengeId: "c", nonce: "bm9uY2U", kind: "prefetched" as const, expiresAt: at + H },
    createdAt: at,
  });

  it("is per owner: one user never lists another's records; newest first; a repeated insert is ignored; an ownerless record is refused", async () => {
    const s = await make();
    await s.insert(rec("user-a", "1", 10));
    await s.insert(rec("user-a", "2", 20));
    await s.insert(rec("user-a", "2", 99)); // same id: ignored
    await s.insert(rec("user-b", "1", 30));
    expect((await s.listByOwner("user-a")).map((r) => [r.id, r.createdAt])).toEqual([["2", 20], ["1", 10]]);
    expect((await s.listByOwner("user-b")).map((r) => r.id)).toEqual(["1"]);
    await expect(s.insert(rec("", "x", 1))).rejects.toThrow(/no owner/);
  });

  it("account deletion removes the deleted user's records (a location fix per record) and only theirs", async () => {
    const s = await make();
    await s.insert(rec("user-a", "1", 10));
    await s.insert(rec("user-b", "1", 30));
    const out = await deleteAccountAndWipeLocal({
      api: { deleteAccount: () => Promise.resolve({ userId: "user-a", deletedAt: "2026-06-01T00:00:00.000Z" } as never) },
      auth: new FakeAuth(),
      outbox: new MemoryOutboxStore(),
      challenges: new MemoryChallengeStore(),
      markerCosignals: s,
      sharer: { purgeStale: () => Promise.resolve() },
      currentUserId: () => "user-a",
      secure: new MemorySecureStore(),
      clearUserCaches: () => undefined,
    });
    expect(out).toMatchObject({ status: "deleted", localWipe: "complete" });
    expect(await s.listByOwner("user-a")).toEqual([]);
    expect((await s.listByOwner("user-b")).map((r) => r.id)).toEqual(["1"]);
  });
});

describe("the SQLite table is created by the v4 migration and survives a re-open", () => {
  it("record round-trips through the real SQL", async () => {
    const db = await openNodeSqlite();
    const s = new SqliteMarkerCosignalStore(db);
    const r = { id: "1", ownerUserId: "user-a", facilityId: "fac_x", catalogVersion: SITE_VERSION, deviceId: DEVICE, fix: { fixId: "f1", lat: 1.5, lng: -2.5, accuracyMeters: 5, capturedAt: 123, simulated: false, foreground: true, fromApp: true }, challenge: { state: "none" as const, reason: "none_available" as const }, createdAt: 5 };
    await s.insert(r);
    expect(await new SqliteMarkerCosignalStore(db).listByOwner("user-a")).toEqual([r]);
    expect((await db.all<{ captured_at: number }>("SELECT captured_at FROM marker_cosignal"))[0]?.captured_at).toBe(123);
  });
});

describe("MARKER CO-SIGNAL QUEUE (P5 §52): capture produces; send.ts is the sole consumer via scanMarker", () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const files = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : /\.tsx?$/.test(n) ? [join(dir, n)] : []));
  const all = [...files(join(root, "src")), ...files(join(root, "app"))];

  const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  const code = (f: string): string => strip(readFileSync(join(root, f), "utf8"));

  it("listByOwner for marker rows is only capture (caps), store, send (drain), and composition wiring", () => {
    expect(all.filter((f) => /\bmarkerStore\b/.test(strip(readFileSync(f, "utf8")))).map((f) => relative(root, f)).sort()).toEqual(["src/runtime/AppProvider.tsx", "src/runtime/services.ts"]);
    expect(
      all
        .filter((f) => /\blistByOwner\b/.test(strip(readFileSync(f, "utf8"))) && /marker/i.test(f))
        .map((f) => relative(root, f))
        .sort(),
    ).toEqual(["src/marker/capture.ts", "src/marker/send.ts", "src/marker/store.ts"]);
    for (const f of ["src/outbox/runner.ts", "src/evidence/send.ts", "src/evidence/payload.ts"]) expect(code(f), f).not.toMatch(/marker/i);
  });

  it("scanMarker is only called from the API client and marker/send.ts", () => {
    const needle = /marker_purchase|purchase_evidence|staff_presence/;
    expect(all.filter((f) => needle.test(strip(readFileSync(f, "utf8")))).map((f) => relative(root, f))).toEqual([]);
    expect(all.filter((f) => /\.scanMarker\b|scanMarker\s*\(/.test(strip(readFileSync(f, "utf8")))).map((f) => relative(root, f)).sort()).toEqual([
      "src/api/http-client.ts",
      "src/api/mock.ts",
      "src/api/types.ts",
      "src/marker/send.ts",
    ]);
  });

  it("it is behind BOTH switches: the marker one and the check-in one", () => {
    expect([markerCosignalUiAvailable(true, true), markerCosignalUiAvailable(true, false), markerCosignalUiAvailable(false, true), markerCosignalUiAvailable(false, false)]).toEqual([true, false, false, false]);
    expect(markerCosignalUiAvailable()).toBe(false); // today: both are false
  });
});

describe.each(STORES)("LOW-2: marker captures must not starve the check-ins' prefetch slots (%s)", (_n, make) => {
  const B = entryOf(facility({ id: "fac_b", courses: [{ id: "crs_b1", holes: 18 }] }));
  const C = entryOf(facility({ id: "fac_c", courses: [{ id: "crs_c1", holes: 18 }] }));
  const at = (rig: ReturnType<typeof rigWith>["rig"], t: number) => {
    rig.clock.now = t;
    rig.location.fixes = [{ ok: true, fix: rawFix(t) }];
  };

  it("the limits are the documented ones", () => {
    expect(MARKER_LIMITS).toEqual({ perFacilityPerDay: 1, per24h: 2, reserveForCheckins: 8 });
  });

  it("(a) at most ONE capture per facility per facility-local day; the next local day is allowed; a refused capture consumes nothing", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.api.online = false;
    await rig.seedPool(10, NOW0 - H, 48 * H);
    at(rig, NOW0);
    expect((await run()).kind).toBe("captured");
    const usable = await rig.challengeStore.countUsable("user-a", DEVICE, NOW0);
    rig.location.calls.fix = 0;
    at(rig, NOW0 + 60_000);
    expect(await run()).toEqual({ kind: "limit", scope: "facility_day" });
    expect(rig.location.calls).toMatchObject({ request: 0, fix: 0 }); // refused before the prompt and the fix
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0 + 60_000)).toBe(usable);
    expect(await store.listByOwner("user-a")).toHaveLength(1);
    // the next local day (Chicago), more than 24 h on: allowed again
    at(rig, NOW0 + 25 * H);
    expect((await run()).kind).toBe("captured");
  });

  it("(a) at most TWO captures per rolling 24 h overall (any facility); allowed again once the first is 24 h old", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.api.online = false;
    await rig.seedPool(10, NOW0 - H, 48 * H);
    at(rig, NOW0);
    expect((await run(undefined, entryOf(facility()))).kind).toBe("captured");
    at(rig, NOW0 + 1_000);
    expect((await run(undefined, B)).kind).toBe("captured");
    at(rig, NOW0 + 2_000);
    expect(await run(undefined, C)).toEqual({ kind: "limit", scope: "overall" });
    expect(await store.listByOwner("user-a")).toHaveLength(2);
    await rig.seedPool(2, NOW0 + 24 * H + 500, 24 * H, "later");
    at(rig, NOW0 + 24 * H + 500); // the first record is now 24 h + 0.5 s old
    expect((await run(undefined, C)).kind).toBe("captured");
  });

  it("(a) the caps are PERSISTED: a new capture over the same stored records (a restart) still counts them; another user's records do not count", async () => {
    const store = await make();
    const first = rigWith(store);
    first.rig.api.online = false;
    await first.rig.seedPool(10, NOW0 - H);
    at(first.rig, NOW0);
    expect((await first.run()).kind).toBe("captured");
    const second = rigWith(store); // a fresh rig, the same store: the app restarted
    second.rig.api.online = false;
    await second.rig.seedPool(10, NOW0 - H);
    at(second.rig, NOW0 + 5_000);
    expect(await second.run()).toEqual({ kind: "limit", scope: "facility_day" });
    const other = rigWith(store);
    other.rig.who.user = "user-b";
    other.rig.api.online = false;
    await other.rig.seedPool(10, NOW0 - H);
    at(other.rig, NOW0 + 5_000);
    expect((await other.run()).kind).toBe("captured");
  });

  it("(c) a capture never takes the last 8 usable challenges: with 9 usable it may (leaving 8); with 8 or fewer it is refused 'reserved' BEFORE the prompt, nothing consumed", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.api.online = false;
    await rig.seedPool(9, NOW0 - H);
    at(rig, NOW0);
    expect((await run()).kind).toBe("captured");
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(8);
    rig.location.perm = { status: "undetermined" };
    rig.location.calls.request = 0;
    at(rig, NOW0 + 1_000);
    expect(await run(undefined, B)).toEqual({ kind: "reserved" });
    expect(rig.location.calls.request).toBe(0);
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(8);
    expect(await store.listByOwner("user-a")).toHaveLength(1);
  });

  it("(c) the reserve is checked again right before consuming: check-ins that used the pool during the fix leave the capture refused", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.api.online = false;
    await rig.seedPool(9, NOW0 - H);
    rig.location.onFix = async () => {
      await rig.challengeStore.consumeOne("user-a", DEVICE, NOW0, NOW0); // a check-in took one while the fix was being read
    };
    at(rig, NOW0);
    expect(await run()).toEqual({ kind: "reserved" });
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("(c) at the end of the day: of 10 usable, two captures (the caps) leave 8 for check-ins, and a check-in can still take every one of them", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.api.online = false;
    await rig.seedPool(10, NOW0 - H);
    at(rig, NOW0);
    await run();
    at(rig, NOW0 + 1_000);
    await run(undefined, B);
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(8);
    for (let i = 0; i < 8; i += 1) expect(await rig.challengeStore.consumeOne("user-a", DEVICE, NOW0 + 2_000, NOW0 + 2_000)).not.toBeNull();
  });

  it("(b) heldOpenCount: only this owner's, this device's, UNEXPIRED, still-held challenges (the ones the server keeps counting as open)", async () => {
    const s = await make();
    const rec = (owner: string, id: string, device: string, challenge: unknown) => ({ id, ownerUserId: owner, facilityId: "fac_x", catalogVersion: SITE_VERSION, deviceId: device, fix: { fixId: `f${id}`, lat: 1, lng: 2, accuracyMeters: 5, capturedAt: NOW0, simulated: false, foreground: true, fromApp: true }, challenge: challenge as never, createdAt: NOW0 });
    const held = (exp: number) => ({ state: "held", challengeId: "c", nonce: "bm9uY2U", kind: "prefetched", expiresAt: exp });
    await s.insert(rec("user-a", "1", DEVICE, held(NOW0 + H)));
    await s.insert(rec("user-a", "2", DEVICE, held(NOW0 + 2 * H)));
    await s.insert(rec("user-a", "3", DEVICE, held(NOW0 - 1))); // expired: the server no longer counts it
    await s.insert(rec("user-a", "4", DEVICE, { state: "none", reason: "none_available" }));
    await s.insert(rec("user-a", "5", "22222222-2222-4222-8222-222222222222", held(NOW0 + H))); // another device
    await s.insert(rec("user-b", "6", DEVICE, held(NOW0 + H))); // another user
    expect(await heldOpenCount(s, "user-a", DEVICE, NOW0)).toBe(2);
    expect(await heldOpenCount(s, "user-a", DEVICE, NOW0 + 90 * 60_000)).toBe(1);
  });

  it("(b) the prefetch top-up subtracts the held marker challenges: the client's room estimate matches the server's cap of 10 open", async () => {
    const { ChallengeManager, MemoryChallengeStore } = await import("../src/challenges");
    const mk = (held: number, withHook = true) => {
      const api = new FakeCheckinApi();
      const store = new MemoryChallengeStore();
      const m = new ChallengeManager({
        store,
        api,
        session: { currentUserId: () => "user-a", accessTokenFor: () => Promise.resolve("t") },
        deviceId: () => Promise.resolve(DEVICE),
        now: () => NOW0,
        ...(withHook ? { openElsewhere: () => Promise.resolve(held) } : {}),
      });
      return { api, store, m };
    };
    const seven = async (x: ReturnType<typeof mk>) => x.store.insertMany("user-a", DEVICE, Array.from({ length: 7 }, (_, i) => ({ id: `p${i}`, nonce: "bm9uY2U", kind: "prefetched" as const, facilityId: null, expiresAt: NOW0 + 24 * H })), NOW0 - 1);
    const a = mk(2);
    await seven(a);
    expect(await a.m.prefetch()).toMatchObject({ kind: "filled", added: 1 }); // 10 - 7 usable - 2 held marker challenges
    expect(a.api.requests).toEqual([{ deviceId: DEVICE, prefetchCount: 1 }]);
    const b = mk(3);
    await seven(b);
    expect(await b.m.prefetch()).toEqual({ kind: "full", usable: 7 }); // 7 + 3 held = 10 open at the server: no request at all
    expect(b.api.requests).toEqual([]);
    const c = mk(0, false);
    await seven(c);
    await c.m.prefetch();
    expect(c.api.requests).toEqual([{ deviceId: DEVICE, prefetchCount: 3 }]); // no hook: unchanged behaviour
    const d = mk(0);
    d.m["deps"].openElsewhere = () => Promise.reject(new Error("boom")); // a failing estimate never blocks the top-up
    await seven(d);
    await d.m.prefetch();
    expect(d.api.requests).toEqual([{ deviceId: DEVICE, prefetchCount: 3 }]);
  });
});
