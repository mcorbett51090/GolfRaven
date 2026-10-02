/**
 * The anti-rollback floor only ever RISES: `raisedFloor` is the rule behind `CatalogManager.raiseFloor`, tested
 * directly (a pure function) and through the real method on both stores (PR #26 gate NIT: there was no direct test).
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { compareCatalogVersions } from "@golfraven/catalog-tools/manifest-core";
import { nobleCatalogCrypto } from "../src/catalog/crypto";
import { CatalogManager } from "../src/catalog/manager";
import { MemoryCatalogCacheStore, META_MAX_VERIFIED_VERSION, SqliteCatalogCacheStore, raisedFloor, type CatalogCacheStore } from "../src/catalog/store";
import { openNodeSqlite } from "./support/node-sqlite";
import { CatalogPublisher, FakeCdn, makeKey, type SignedCatalog } from "./support/signed-catalog";

const V1 = "20260101-aaaaaaa";
const V2 = "20260201-bbbbbbb";
const V3 = "20260301-ccccccc";

describe("raisedFloor (pure rule)", () => {
  it("raises to a higher version, and sets the first one", () => {
    expect(raisedFloor(V1, V2)).toBe(V2);
    expect(raisedFloor(null, V1)).toBe(V1);
  });

  it("NEVER lowers the floor: an older version leaves the row unchanged", () => {
    expect(raisedFloor(V2, V1)).toBeUndefined();
    expect(raisedFloor(V3, V1)).toBeUndefined();
    expect(raisedFloor("20260201-bbbbbbb", "20260131-fffffff")).toBeUndefined(); // one day older, sha irrelevant
  });

  it("leaves an equal version unchanged", () => {
    expect(raisedFloor(V2, V2)).toBeUndefined();
  });

  it("never heals a corrupt row (that is the explicit reset action's job)", () => {
    for (const junk of ["", "garbage", "20260101", "99999999-zzzzzzz"]) expect(raisedFloor(junk, V3), junk).toBeUndefined();
  });

  it("applied in any order, the stored value is the maximum and never decreases", () => {
    const versions = [V2, V1, V3, V1, V2, "20251231-0000000", V3];
    let floor: string | null = null;
    for (const v of versions) {
      const next = raisedFloor(floor, v);
      if (next !== undefined) {
        if (floor !== null) expect(compareCatalogVersions(next, floor)).toBeGreaterThan(0);
        floor = next;
      }
    }
    expect(floor).toBe(V3);
  });
});

const KEY = makeKey("k-floor-a");
const pub = new CatalogPublisher();
let v2: SignedCatalog;
beforeAll(async () => {
  v2 = await pub.emit({ version: V2, generatedAt: "2026-02-01T00:00:00.000Z", key: KEY });
});
afterAll(async () => {
  await pub.dispose();
});

const STORES: [string, () => Promise<CatalogCacheStore>][] = [
  ["memory store", async () => new MemoryCatalogCacheStore()],
  ["SQLite store", async () => new SqliteCatalogCacheStore(await openNodeSqlite())],
];

describe.each(STORES)("CatalogManager.raiseFloor (%s)", (_n, makeStore) => {
  const setup = async (): Promise<{ store: CatalogCacheStore; raise: (v: string) => Promise<void> }> => {
    const store = await makeStore();
    const cdn = new FakeCdn();
    cdn.serve(v2);
    const m = new CatalogManager({ baseUrl: cdn.base, store, crypto: nobleCatalogCrypto, trustedKeys: [KEY.trusted], appVersion: "1.0.0", supportedContractMajor: 0, fetchBytes: cdn.fetchBytes });
    expect((await m.refresh()).kind).toBe("updated"); // verifies v2, so the floor is V2
    return { store, raise: (v) => (m as unknown as { raiseFloor(v: string): Promise<void> }).raiseFloor(v) };
  };

  it("never lowers the stored floor", async () => {
    const { store, raise } = await setup();
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V2);
    await raise(V1);
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V2);
    await raise("20200101-0000000");
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V2);
    await raise(V2);
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V2);
  });

  it("raises it for a newer version, and leaves a corrupt row exactly as it was", async () => {
    const { store, raise } = await setup();
    await raise(V3);
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe(V3);
    await store.writeMeta(META_MAX_VERIFIED_VERSION, "garbage");
    await raise("20270101-fffffff");
    expect(await store.readMeta(META_MAX_VERIFIED_VERSION)).toBe("garbage");
  });
});
