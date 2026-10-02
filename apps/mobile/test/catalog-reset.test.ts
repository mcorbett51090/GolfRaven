/**
 * LOW-B (PR #26 gate): `TRUST_STATE_CORRUPT` had no in-app way out. `resetCatalogData` is the Me-tab "Reset catalog
 * data" action. What it must do — drop the cache, clear ONLY unreadable trust rows, re-seed a cleared floor from the
 * compiled-in minimum — and, as important, what it must NOT do: clear a VALID floor (one-tap rollback) or a VALID
 * revoked set (one-tap un-revocation). Run on both the memory store and the real SQL store.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { nobleCatalogCrypto } from "../src/catalog/crypto";
import { CatalogManager, isTrustStateCorrupt, type CatalogManagerOptions, type CatalogState, type FetchBytes } from "../src/catalog/manager";
import { META_MAX_VERIFIED_VERSION, MemoryCatalogCacheStore, SqliteCatalogCacheStore, type CatalogCacheStore } from "../src/catalog/store";
import { openNodeSqlite } from "./support/node-sqlite";
import { CatalogPublisher, FakeCdn, makeKey, type SignedCatalog } from "./support/signed-catalog";

const KEY_A = makeKey("k-reset-a");
const KEY_B = makeKey("k-reset-b");
const REVOKED = "revokedKids";
const REQUIRED = "updateRequired";
const V1 = "20260101-aaaaaaa";
const V4 = "20260401-ddddddd";

const pub = new CatalogPublisher();
const late = new CatalogPublisher();
const older = new CatalogPublisher();
let c1: SignedCatalog; // V1 by A
let c4: SignedCatalog; // V4 by B, revokes A
let lateByA: SignedCatalog; // 20260601, genuinely by A (a revoked key by then)
let oldByB: SignedCatalog; // 20260101, genuinely by B (older than V4, by a key that is NOT revoked)
beforeAll(async () => {
  c1 = await pub.emit({ version: V1, generatedAt: "2026-01-01T00:00:00.000Z", key: KEY_A, trailName: "Trail 1" });
  c4 = await pub.emit({ version: V4, generatedAt: "2026-04-01T00:00:00.000Z", key: KEY_B, revokedKids: [KEY_A.kid], trailName: "Trail 4" });
  lateByA = await late.emit({ version: "20260601-fffffff", generatedAt: "2026-06-01T00:00:00.000Z", key: KEY_A });
  oldByB = await older.emit({ version: V1, generatedAt: "2026-01-01T00:00:00.000Z", key: KEY_B });
});
afterAll(async () => {
  await pub.dispose();
  await late.dispose();
  await older.dispose();
});

describe("isTrustStateCorrupt", () => {
  const base: Pick<CatalogState, "cacheDropped" | "lastOutcome"> = { cacheDropped: null, lastOutcome: null };
  it("is true only for a TRUST_STATE_CORRUPT cache drop or rejection", () => {
    expect(isTrustStateCorrupt(base)).toBe(false);
    expect(isTrustStateCorrupt({ ...base, cacheDropped: [{ code: "BAD_SIGNATURE", message: "x" }] })).toBe(false);
    expect(isTrustStateCorrupt({ ...base, lastOutcome: { kind: "rejected", issues: [{ code: "BAD_SIGNATURE", message: "x" }] } })).toBe(false);
    expect(isTrustStateCorrupt({ ...base, lastOutcome: { kind: "network_error", message: "x" } })).toBe(false);
    expect(isTrustStateCorrupt({ ...base, cacheDropped: [{ code: "TRUST_STATE_CORRUPT", message: "x" }] })).toBe(true);
    expect(isTrustStateCorrupt({ ...base, lastOutcome: { kind: "rejected", issues: [{ code: "TRUST_STATE_CORRUPT", message: "x" }] } })).toBe(true);
  });
});

function gate(): { reached: Promise<void>; release: () => void; hit: () => Promise<void> } {
  let release!: () => void;
  let reach!: () => void;
  const wait = new Promise<void>((r) => (release = r));
  const reached = new Promise<void>((r) => (reach = r));
  return { reached, release, hit: async () => (reach(), wait) };
}

const STORES: [string, () => Promise<CatalogCacheStore>][] = [
  ["memory store", async () => new MemoryCatalogCacheStore()],
  ["SQLite store", async () => new SqliteCatalogCacheStore(await openNodeSqlite())],
];

describe.each(STORES)("resetCatalogData (%s)", (_n, makeStore) => {
  let store: CatalogCacheStore;
  let cdn: FakeCdn;
  const manager = (over: Partial<CatalogManagerOptions> = {}): CatalogManager =>
    new CatalogManager({ baseUrl: cdn.base, store, crypto: nobleCatalogCrypto, trustedKeys: [KEY_A.trusted, KEY_B.trusted], appVersion: "1.0.0", supportedContractMajor: 0, fetchBytes: cdn.fetchBytes, ...over });
  const codes = (o: Awaited<ReturnType<CatalogManager["refresh"]>>): string[] => (o.kind === "rejected" ? o.issues.map((i) => i.code) : [o.kind]);

  beforeEach(async () => {
    store = await makeStore();
    cdn = new FakeCdn();
  });

  describe("a corrupt revoked-key set", () => {
    it("is flagged for the dedicated message; the reset clears it, drops the cache, KEEPS the valid floor, and the app then recovers", async () => {
      cdn.serve(c1);
      expect((await manager().refresh()).kind).toBe("updated");
      await store.writeMeta(REVOKED, "not json");

      const m = manager();
      await m.loadCached();
      expect(isTrustStateCorrupt(m.getState())).toBe(true); // cache dropped on load
      expect(codes(await m.refresh())).toEqual(["TRUST_STATE_CORRUPT"]);
      expect(isTrustStateCorrupt(m.getState())).toBe(true);
      expect(m.getState().outOfDateBanner).toBe(true);

      const report = await m.resetCatalogData();
      expect(report).toEqual({ revokedCleared: true, floorCleared: false, floorReseededTo: null, stillCorrupt: false });
      expect(await store.loadCatalog()).toBeNull(); // the cache is gone
      expect(await store.readMeta(REVOKED)).toBeNull(); // the unreadable row is gone
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V1); // the VALID floor is untouched
      expect(isTrustStateCorrupt(m.getState())).toBe(false);
      expect(m.getState()).toMatchObject({ snapshot: null, cacheDropped: null, outOfDateBanner: false, lastOutcome: null });

      expect((await m.refresh()).kind).toBe("updated"); // recovered: fetched and verified again
      expect(m.getState().snapshot?.catalogVersion).toBe(V1);
    });

    it("the surviving floor still refuses an older genuine catalog after the reset (no one-tap rollback)", async () => {
      cdn.serve(c4); // floor V4
      await manager().refresh();
      await store.writeMeta(REVOKED, "{}");
      const m = manager();
      await m.resetCatalogData();
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V4);
      cdn.serve(oldByB); // older, genuine, by a key that is not revoked
      expect(codes(await m.refresh())).toEqual(["CATALOG_VERSION_ROLLBACK"]);
    });
  });

  describe("a corrupt version floor", () => {
    it("is flagged; the reset clears it and re-seeds it from the compiled-in minimum", async () => {
      cdn.serve(c4);
      await manager().refresh();
      await store.writeMeta(META_MAX_VERIFIED_VERSION, "garbage");

      const m = manager({ compiledMinCatalogVersion: V1 });
      expect(codes(await m.refresh())).toEqual(["TRUST_STATE_CORRUPT"]);
      expect(isTrustStateCorrupt(m.getState())).toBe(true);

      const report = await m.resetCatalogData();
      expect(report).toEqual({ revokedCleared: false, floorCleared: true, floorReseededTo: V1, stillCorrupt: false });
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V1);
      expect(await store.loadCatalog()).toBeNull();
      expect(isTrustStateCorrupt(m.getState())).toBe(false);
      expect((await m.refresh()).kind).toBe("updated");
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V4); // raised again by the next verified manifest
    });

    it("with no compiled-in minimum the cleared floor is simply absent (a fresh install's state)", async () => {
      cdn.serve(c1);
      await manager().refresh();
      await store.writeMeta(META_MAX_VERIFIED_VERSION, "");
      const m = manager({ compiledMinCatalogVersion: "" });
      expect(await m.resetCatalogData()).toEqual({ revokedCleared: false, floorCleared: true, floorReseededTo: null, stillCorrupt: false });
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBeNull();
      expect((await m.refresh()).kind).toBe("updated");
    });

    it("the re-seed never goes below the compiled-in minimum: an older catalog is refused after the reset", async () => {
      await store.writeMeta(META_MAX_VERIFIED_VERSION, "garbage");
      const m = manager({ compiledMinCatalogVersion: V4 });
      await m.resetCatalogData();
      cdn.serve(oldByB);
      expect(codes(await m.refresh())).toEqual(["CATALOG_VERSION_ROLLBACK"]);
    });

    it("a stored update requirement is cleared with a cleared floor (it can no longer be ordered against it), but kept with a valid one", async () => {
      await store.writeMeta(REQUIRED, JSON.stringify({ minAppVersion: "9.0.0", catalogVersion: V4 }));
      await store.writeMeta(META_MAX_VERIFIED_VERSION, "garbage");
      await manager().resetCatalogData();
      expect(await store.readMeta(REQUIRED)).toBeNull();

      await store.writeMeta(REQUIRED, JSON.stringify({ minAppVersion: "9.0.0", catalogVersion: V4 }));
      await store.writeMeta(META_MAX_VERIFIED_VERSION, V4);
      await manager().resetCatalogData();
      expect(await store.readMeta(REQUIRED)).not.toBeNull();
    });
  });

  describe("what a reset must NOT clear", () => {
    it("on a healthy install it drops only the cache: a valid floor and a valid revoked set both survive", async () => {
      cdn.serve(c1);
      await manager().refresh();
      cdn.serve(c4); // by B, revokes A
      await manager().refresh();
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V4);
      expect(JSON.parse((await store.readMeta(REVOKED))!)).toEqual([KEY_A.kid]);

      const m = manager();
      expect(await m.resetCatalogData()).toEqual({ revokedCleared: false, floorCleared: false, floorReseededTo: null, stillCorrupt: false });
      expect(await store.loadCatalog()).toBeNull();
      expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V4); // would be null / lower if the floor were cleared
      expect(JSON.parse((await store.readMeta(REVOKED))!)).toEqual([KEY_A.kid]); // would be null if the revoked set were cleared

      cdn.serve(oldByB); // older and genuine, by a trusted key: still a rollback
      expect(codes(await m.refresh())).toEqual(["CATALOG_VERSION_ROLLBACK"]);
      cdn.serve(lateByA); // newer, genuine, but by a revoked key: still refused
      expect(codes(await m.refresh())).toEqual(["REVOKED_KID"]);
    });

    it("a corrupt FLOOR with a valid revoked set: only the floor goes; the revoked key stays revoked", async () => {
      cdn.serve(c4);
      await manager().refresh(); // revoked [A]
      await store.writeMeta(META_MAX_VERIFIED_VERSION, "garbage");
      const m = manager();
      expect(await m.resetCatalogData()).toMatchObject({ revokedCleared: false, floorCleared: true });
      expect(JSON.parse((await store.readMeta(REVOKED))!)).toEqual([KEY_A.kid]);
      cdn.serve(lateByA);
      expect(codes(await m.refresh())).toEqual(["REVOKED_KID"]);
    });

    it("both rows corrupt: both go, and the app recovers", async () => {
      cdn.serve(c1);
      await manager().refresh();
      await store.writeMeta(REVOKED, "[1]");
      await store.writeMeta(META_MAX_VERIFIED_VERSION, "20260101");
      const m = manager();
      expect(await m.resetCatalogData()).toEqual({ revokedCleared: true, floorCleared: true, floorReseededTo: null, stillCorrupt: false });
      expect((await m.refresh()).kind).toBe("updated");
    });

    it("a corrupt row appearing as a valid one is judged by the SAME parsers the manager uses ('[]' is a valid, empty revoked set)", async () => {
      await store.writeMeta(REVOKED, "[]");
      const m = manager();
      expect((await m.resetCatalogData()).revokedCleared).toBe(false);
      expect(await store.readMeta(REVOKED)).toBe("[]");
    });
  });

  it("reports stillCorrupt when the compiled-in minimum itself is malformed (a build defect no reset can fix)", async () => {
    const m = manager({ compiledMinCatalogVersion: "not-a-version" });
    expect((await m.resetCatalogData()).stillCorrupt).toBe(true);
  });

  it("never interleaves with a refresh in flight: it waits for it, then wipes what it saved", async () => {
    cdn.serve(c1);
    const g = gate();
    const slow: FetchBytes = async (url, o) => {
      if (url.endsWith("/trails.json")) await g.hit();
      return cdn.fetchBytes(url, o);
    };
    const m = manager({ fetchBytes: slow });
    const refreshing = m.refresh();
    await g.reached;
    let done = false;
    const resetting = m.resetCatalogData().then((r) => ((done = true), r));
    await new Promise((r) => setTimeout(r, 20));
    expect(done).toBe(false);
    g.release();
    expect((await refreshing).kind).toBe("updated");
    await resetting;
    expect(await store.loadCatalog()).toBeNull();
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V1); // the refresh's floor survives the reset
  });
});
