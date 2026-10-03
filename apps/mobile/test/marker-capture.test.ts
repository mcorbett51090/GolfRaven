/**
 * P4.2c: "Buying a marker" (build plan §7.6 G2-03): the capture and the LOCAL queue. What is deliberately NOT here: any sending (no server path accepts a marker-purchase co-signal yet;
 * `test/marker-no-sender.test.ts`-style scans below pin that nothing reads the queue to send it).
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { deleteAccountAndWipeLocal } from "../src/account";
import { MemoryChallengeStore, SqliteChallengeStore } from "../src/challenges";
import { markerCosignalUiAvailable } from "../src/checkin";
import { captureMarkerCoSignal, MemoryMarkerCosignalStore, SqliteMarkerCosignalStore, type MarkerCaptureDeps, type MarkerCosignalStore } from "../src/marker";
import { MemoryOutboxStore } from "../src/outbox";
import { MemorySecureStore } from "../src/secure";
import { DEVICE, NASHVILLE, NOW0, SITE_VERSION, entryOf, facility, makeRig, rawFix } from "./support/checkin-rig";
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
    await rig.seedPool(3, NOW0 - 2 * H);
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
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(2);
  });

  it("the record's challenge window contains the fix: it was consumed with the fix's own time", async () => {
    const { rig, run } = rigWith(await make());
    rig.api.online = false;
    await rig.seedPool(1, NOW0 + 10_000); // received AFTER the fix: cannot cover it
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    expect((await run()).kind).toBe("no_challenge");
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0 + 20_000)).toBe(1); // not consumed
  });

  it("no prefetched challenge left: refused (a co-signal without one is worth nothing) and NOTHING is stored", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    expect(await run()).toEqual({ kind: "no_challenge" });
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it("the player must be AT the facility: a fix outside its circle plus the 50 m buffer is 'not here', no challenge spent, nothing stored", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    await rig.seedPool(2, NOW0 - H);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0, { latitude: NASHVILLE.lat + 0.01 }) }]; // ~1.1 km
    const o = await run();
    expect(o).toMatchObject({ kind: "not_here" });
    expect(await store.listByOwner("user-a")).toEqual([]);
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(2);
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

  it("an unverified facility (no geometry on the device) is refused after the fix, with the matcher's reason, nothing stored", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    await rig.seedPool(1, NOW0 - H);
    rig.location.fixes = [{ ok: true, fix: rawFix(NOW0) }];
    expect((await run(undefined, entryOf(facility({ status: "unverified" })))).kind).toBe("no_geometry");
    expect(await store.listByOwner("user-a")).toEqual([]);
  });

  it.each([
    ["denied", { status: "denied", canAskAgain: false } as const, { kind: "permission", status: "blocked" }],
    ["approximate", { status: "granted", approximate: true } as const, { kind: "permission", status: "approximate" }],
  ])("permission %s: refused with the same outcome as the check-in", async (_l, perm, expected) => {
    const { rig, run } = rigWith(await make());
    rig.location.perm = perm;
    expect(await run()).toEqual(expected);
  });

  it("refuses a simulated, inaccurate, stale or missing fix like the check-in does (no challenge spent)", async () => {
    const store = await make();
    const { rig, run } = rigWith(store);
    await rig.seedPool(2, NOW0 - H);
    for (const [attempt, kind] of [
      [{ ok: true, fix: rawFix(NOW0, { simulated: true }) }, "simulated"],
      [{ ok: true, fix: rawFix(NOW0, { accuracyMeters: 120 }) }, "inaccurate"],
      [{ ok: true, fix: rawFix(NOW0 - 120_000) }, "stale_fix"],
      [{ ok: false, reason: "timeout" }, "no_fix"],
    ] as const) {
      rig.location.fixes = [attempt];
      expect((await run()).kind).toBe(kind);
    }
    expect(await rig.challengeStore.countUsable("user-a", DEVICE, NOW0)).toBe(2);
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

describe("NOTHING SENDS A MARKER CO-SIGNAL (no server path exists yet): the queue has a producer and no consumer", () => {
  const root = dirname(dirname(fileURLToPath(import.meta.url)));
  const files = (dir: string): string[] => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? files(join(dir, n)) : /\.tsx?$/.test(n) ? [join(dir, n)] : []));
  const all = [...files(join(root, "src")), ...files(join(root, "app"))];
  const where = (needle: RegExp, from = all): string[] => from.filter((f) => needle.test(readFileSync(f, "utf8"))).map((f) => relative(root, f)).sort();

  const strip = (t: string): string => t.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  const code = (f: string): string => strip(readFileSync(join(root, f), "utf8"));

  it("the queue is read by nobody: the only code that touches the store is the capture (insert), the composition root (wiring) and account deletion (deleteOwner)", () => {
    expect(all.filter((f) => /\bmarkerStore\b/.test(strip(readFileSync(f, "utf8")))).map((f) => relative(root, f)).sort()).toEqual(["src/runtime/AppProvider.tsx", "src/runtime/services.ts"]);
    for (const f of all) expect(strip(readFileSync(f, "utf8")), relative(root, f)).not.toMatch(/\bmarkerStore\s*\.\s*listByOwner|\bstore\s*\.\s*listByOwner[^;]*marker/);
    expect(code("src/marker/capture.ts")).not.toMatch(/listByOwner/);
    for (const f of ["src/api/http-client.ts", "src/api/types.ts", "src/outbox/runner.ts", "src/evidence/send.ts", "src/evidence/payload.ts"]) expect(code(f), f).not.toMatch(/marker/i);
  });

  it("no API member, evidence source or wire name for a marker purchase exists on the client (no wire shape is invented)", () => {
    const needle = /marker_purchase|marker-scan|purchase_evidence|staff_presence/;
    expect(all.filter((f) => needle.test(strip(readFileSync(f, "utf8")))).map((f) => relative(root, f))).toEqual([]);
  });

  it("it is behind BOTH switches: the marker one and the check-in one", () => {
    expect([markerCosignalUiAvailable(true, true), markerCosignalUiAvailable(true, false), markerCosignalUiAvailable(false, true), markerCosignalUiAvailable(false, false)]).toEqual([true, false, false, false]);
    expect(markerCosignalUiAvailable()).toBe(false); // today: both are false
  });
});
