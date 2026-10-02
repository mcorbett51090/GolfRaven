/**
 * The cache/refresh state machine (build plan §3.5, §7.6; P4 AT 12), run
 * against catalogs signed by the real `tools/catalog` signer, through both
 * the in-memory store and the real SQL store (node:sqlite).
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { nobleCatalogCrypto } from "../src/catalog/crypto";
import { TRUSTED_KEYSET } from "../src/catalog/keys";
import { CatalogManager, type CatalogManagerOptions, type FetchBytes } from "../src/catalog/manager";
import { MemoryCatalogCacheStore, SqliteCatalogCacheStore, type CatalogCacheStore } from "../src/catalog/store";
import { openNodeSqlite } from "./support/node-sqlite";
import { CatalogPublisher, FakeCdn, flipByte, makeKey, replaceText, type SignedCatalog } from "./support/signed-catalog";

const KEY_A = makeKey("k-prod-a");
const KEY_B = makeKey("k-prod-b");
const pub = new CatalogPublisher();
let v1: SignedCatalog;
let v2: SignedCatalog;
let v3NeedsNewApp: SignedCatalog;
let v3RevokesA: SignedCatalog; // signed by B, revokes A, minAppVersion 0.0.0
let v5ByB: SignedCatalog; // a later catalog by B that revokes nothing
// Separate lineages (each its own versions.json), for the anti-rollback exploit and the races.
const extra: CatalogPublisher[] = [];
const lineage = async (spec: Parameters<CatalogPublisher["emit"]>[0]): Promise<SignedCatalog> => {
  const p = new CatalogPublisher();
  extra.push(p);
  return p.emit(spec);
};
let oldByB: SignedCatalog; // 20260101 genuinely signed by B (the replayed manifest)
let forceRevokeByB: SignedCatalog; // 20260301 by B: revokes A, minAppVersion 9.0.0
let raceV2: SignedCatalog;
let raceV3: SignedCatalog;
let revokeA: SignedCatalog; // by B, 20260402, revokes A
let revokeC: SignedCatalog; // by B, 20260401, revokes k-prod-c
const KEY_C_KID = "k-prod-c";
const FLOOR = "maxVerifiedCatalogVersion";

const NOW = () => new Date("2026-02-15T12:00:00.000Z");

beforeAll(async () => {
  // One publisher => one append-only versions.json lineage, like production.
  v1 = await pub.emit({ version: "20260101-aaaaaaa", generatedAt: "2026-01-01T00:00:00.000Z", key: KEY_A, trailName: "Trail v1" });
  v2 = await pub.emit({ version: "20260201-bbbbbbb", generatedAt: "2026-02-01T00:00:00.000Z", key: KEY_A, trailName: "Trail v2" });
  v3NeedsNewApp = await pub.emit({ version: "20260301-ccccccc", generatedAt: "2026-03-01T00:00:00.000Z", key: KEY_A, minAppVersion: "2.0.0", trailName: "Trail v3" });
  v3RevokesA = await pub.emit({ version: "20260401-ddddddd", generatedAt: "2026-04-01T00:00:00.000Z", key: KEY_B, revokedKids: [KEY_A.kid], trailName: "Trail v4 by B" });
  v5ByB = await pub.emit({ version: "20260501-eeeeeee", generatedAt: "2026-05-01T00:00:00.000Z", key: KEY_B, trailName: "placeholder" });
});
beforeAll(async () => {
  oldByB = await lineage({ version: "20260101-aaaaaaa", generatedAt: "2026-01-01T00:00:00.000Z", key: KEY_B, trailName: "Trail old by B" });
  forceRevokeByB = await lineage({ version: "20260301-1111111", generatedAt: "2026-03-01T00:00:00.000Z", key: KEY_B, minAppVersion: "9.0.0", revokedKids: [KEY_A.kid] });
  const race = new CatalogPublisher();
  extra.push(race);
  raceV2 = await race.emit({ version: "20260201-bbbbbbb", generatedAt: "2026-02-01T00:00:00.000Z", key: KEY_A, trailName: "Trail v2" });
  raceV3 = await race.emit({ version: "20260301-ccccccc", generatedAt: "2026-03-01T00:00:00.000Z", key: KEY_A, trailName: "Trail v3" });
  revokeA = await lineage({ version: "20260402-2222222", generatedAt: "2026-04-02T00:00:00.000Z", key: KEY_B, revokedKids: [KEY_A.kid] });
  revokeC = await lineage({ version: "20260401-3333333", generatedAt: "2026-04-01T00:00:00.000Z", key: KEY_B, revokedKids: [KEY_C_KID] });
});
afterAll(async () => {
  await pub.dispose();
  await Promise.all(extra.map((p) => p.dispose()));
});

/** Holds a request until `release()`, and says when it got there. */
function gate(): { wait: Promise<void>; reached: Promise<void>; release: () => void; hit: () => Promise<void> } {
  let release!: () => void;
  let reach!: () => void;
  const wait = new Promise<void>((r) => (release = r));
  const reached = new Promise<void>((r) => (reach = r));
  return {
    wait,
    reached,
    release,
    hit: async () => {
      reach();
      await wait;
    },
  };
}
/** Wraps a CDN's fetch so the request for `path` blocks on the gate. */
function gated(cdn: FakeCdn, path: string, g: ReturnType<typeof gate>): FetchBytes {
  return async (url, o) => {
    if (url.endsWith(`/${path}`)) await g.hit();
    return cdn.fetchBytes(url, o);
  };
}

type StoreFactory = () => Promise<CatalogCacheStore>;
const STORES: [string, StoreFactory][] = [
  ["memory store", async () => new MemoryCatalogCacheStore()],
  ["SQLite store", async () => new SqliteCatalogCacheStore(await openNodeSqlite())],
];

describe.each(STORES)("CatalogManager (%s)", (_name, makeStore) => {
  let store: CatalogCacheStore;
  let cdn: FakeCdn;

  const manager = (over: Partial<CatalogManagerOptions> = {}): CatalogManager =>
    new CatalogManager({
      baseUrl: cdn.base,
      store,
      crypto: nobleCatalogCrypto,
      trustedKeys: [KEY_A.trusted, KEY_B.trusted],
      appVersion: "1.0.0",
      supportedContractMajor: 0,
      fetchBytes: cdn.fetchBytes,
      now: NOW,
      ...over,
    });

  beforeEach(async () => {
    store = await makeStore();
    cdn = new FakeCdn();
  });

  it("applies a genuine catalog and serves it back after a restart (cache is re-verified on load)", async () => {
    cdn.serve(v1);
    const m = manager();
    expect((await m.refresh()).kind).toBe("updated");
    expect(m.getState().snapshot?.trails.map((t) => t.name)).toEqual(["Trail v1"]);
    expect(m.getState().snapshot?.facilities.map((f) => f.region).sort()).toEqual(["CA-QC", "US-TN"]);

    cdn.offline = true; // a new process, no network
    const restarted = manager();
    const state = await restarted.loadCached();
    expect(state.snapshot?.catalogVersion).toBe("20260101-aaaaaaa");
    expect(state.cacheDropped).toBeNull();
  });

  it("downloads every shard the manifest lists, including non-JSON ones, and nothing else", async () => {
    cdn.serve(v1);
    await manager().refresh();
    const listed = v1.manifest.shards.map((s) => s.path).sort();
    const fetchedShards = cdn.log.map((l) => l.path).filter((p) => !/^(manifest|versions)(\.sig)?\.json$/.test(p)).sort();
    expect(fetchedShards).toEqual(listed);
    expect(listed).toContain("osm/attribution.txt");
  });

  it("uses the stored ETag: an unchanged catalog is a 304 and downloads nothing", async () => {
    cdn.serve(v1);
    const m = manager();
    await m.refresh();
    cdn.log.length = 0;
    expect(await m.refresh()).toEqual({ kind: "up_to_date", catalogVersion: "20260101-aaaaaaa" });
    expect(cdn.log.map((l) => `${l.path}:${l.status}`)).toEqual(["manifest.json:304"]);
  });

  it("moves to a newer signed catalog", async () => {
    cdn.serve(v1);
    const m = manager();
    await m.refresh();
    cdn.serve(v2);
    expect(await m.refresh()).toEqual({ kind: "updated", from: "20260101-aaaaaaa", to: "20260201-bbbbbbb" });
    expect(m.getState().snapshot?.trails[0]?.name).toBe("Trail v2");
  });

  describe("fail-closed caching (P4 AT 12: a manifest with a bad signature is not applied)", () => {
    it("a forged signature on a NEW version leaves the cached catalog untouched and raises the banner", async () => {
      cdn.serve(v1);
      const m = manager();
      await m.refresh();
      const before = await store.loadCatalog();

      cdn.serve(v2);
      cdn.tamper("manifest.sig.json", (b) => {
        const sig = (JSON.parse(Buffer.from(b).toString("utf8")) as { sig: string }).sig;
        const raw = Buffer.from(sig, "base64");
        raw[3] = raw[3]! ^ 0x10;
        return replaceText(b, sig, raw.toString("base64"));
      });
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toContain("BAD_SIGNATURE");
      expect(m.getState().outOfDateBanner).toBe(true);
      expect(m.getState().snapshot?.catalogVersion).toBe("20260101-aaaaaaa");
      expect(await store.loadCatalog()).toEqual(before);
      // and no shard of the rejected version was ever downloaded
      expect(cdn.requested("trails.json")).toBe(true); // from the v1 refresh
      expect(cdn.log.filter((l) => l.path === "trails.json")).toHaveLength(1);
    });

    it("with nothing cached, a bad signature leaves the app empty — never half-applied", async () => {
      cdn.serve(v1);
      cdn.tamper("manifest.json", (b) => flipByte(b, 40));
      const m = manager();
      expect((await m.refresh()).kind).toBe("rejected");
      expect(m.getState().snapshot).toBeNull();
      expect(await store.loadCatalog()).toBeNull();
    });

    it("the production keyset today is empty, so every manifest fails closed", async () => {
      cdn.serve(v1);
      const m = manager({ trustedKeys: TRUSTED_KEYSET });
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toContain("UNKNOWN_KID");
      expect(m.getState().snapshot).toBeNull();
    });

    it("a shard whose bytes do not match the signed manifest rejects the whole update", async () => {
      cdn.serve(v1);
      const m = manager();
      await m.refresh();
      cdn.serve(v2);
      cdn.tamper("trails.json", (b) => replaceText(b, "Trail v2", "Trail XX"));
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues[0]?.code).toBe("SHARD_MISMATCH");
      expect(m.getState().snapshot?.trails[0]?.name).toBe("Trail v1");
    });

    it("a shard that cannot be fetched keeps the old catalog and is a retryable network error, not a rejection", async () => {
      cdn.serve(v1);
      const m = manager();
      await m.refresh();
      cdn.serve(v2);
      cdn.fail("facilities/us-tn.json");
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("network_error");
      expect(m.getState().snapshot?.trails[0]?.name).toBe("Trail v1");
      expect(m.getState().outOfDateBanner).toBe(false);
      cdn.serve(v2); // CDN recovers
      expect((await m.refresh()).kind).toBe("updated");
    });

    it("a rollback to an older signed catalog is refused", async () => {
      cdn.serve(v2);
      const m = manager();
      await m.refresh();
      cdn.serve(v1);
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toEqual(["CATALOG_VERSION_ROLLBACK"]);
      expect(m.getState().snapshot?.catalogVersion).toBe("20260201-bbbbbbb");
    });

    it("a cache tampered with at rest is dropped on load, not trusted", async () => {
      cdn.serve(v1);
      await manager().refresh();
      const stored = (await store.loadCatalog())!;
      const trails = stored.shards.find((s) => s.path === "trails.json")!;
      trails.text = trails.text.replace("Trail v1", "Evil v1");
      await store.saveCatalog(stored);

      const state = await manager({ baseUrl: null }).loadCached();
      expect(state.snapshot).toBeNull();
      expect(state.cacheDropped?.map((i) => i.code)).toEqual(["MANIFEST_TAMPERED"]);
    });

    it("a network failure is not a rejection: the cache stays and no banner is raised", async () => {
      cdn.serve(v1);
      const m = manager();
      await m.refresh();
      cdn.offline = true;
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("network_error");
      expect(m.getState().outOfDateBanner).toBe(false);
      expect(m.getState().snapshot?.catalogVersion).toBe("20260101-aaaaaaa");
    });

    it("an unconfigured base URL disables refresh but still serves the cache", async () => {
      cdn.serve(v1);
      await manager().refresh();
      const m = manager({ baseUrl: null });
      await m.loadCached();
      expect(await m.refresh()).toEqual({ kind: "disabled" });
      expect(m.getState().snapshot?.catalogVersion).toBe("20260101-aaaaaaa");
    });
  });

  describe("minAppVersion (P4 AT 12: force-update screen, cached catalog stays readable)", () => {
    it("a manifest above this build is update_required: nothing downloaded, cache still readable", async () => {
      cdn.serve(v2);
      const m = manager();
      await m.refresh();
      cdn.log.length = 0;

      cdn.serve(v3NeedsNewApp);
      const outcome = await m.refresh();
      expect(outcome).toEqual({ kind: "update_required", minAppVersion: "2.0.0", catalogVersion: "20260301-ccccccc" });
      expect(cdn.log.map((l) => l.path)).not.toContain("trails.json"); // no shard of the new catalog
      expect(m.getState().updateRequired).toEqual({ minAppVersion: "2.0.0", catalogVersion: "20260301-ccccccc" });
      expect(m.getState().snapshot?.trails[0]?.name).toBe("Trail v2"); // still readable
      expect(m.getState().outOfDateBanner).toBe(false);
    });

    it("the requirement survives a restart with no network, and the cache is still readable", async () => {
      cdn.serve(v2);
      await manager().refresh();
      cdn.serve(v3NeedsNewApp);
      await manager().refresh();

      cdn.offline = true;
      const state = await manager().loadCached();
      expect(state.updateRequired?.minAppVersion).toBe("2.0.0");
      expect(state.snapshot?.catalogVersion).toBe("20260201-bbbbbbb");
    });

    it("with no cache at all the force-update state is reported and the app is simply empty", async () => {
      cdn.serve(v3NeedsNewApp);
      const m = manager();
      expect((await m.refresh()).kind).toBe("update_required");
      expect(m.getState().snapshot).toBeNull();
    });

    it("a build at or above minAppVersion applies it; upgrading the app clears a stored requirement", async () => {
      cdn.serve(v3NeedsNewApp);
      await manager().refresh(); // 1.0.0 build: update_required
      const upgraded = manager({ appVersion: "2.0.0" });
      expect((await upgraded.loadCached()).updateRequired).toBeNull();
      expect((await upgraded.refresh()).kind).toBe("updated");
      expect(upgraded.getState().snapshot?.trails[0]?.name).toBe("Trail v3");
    });

    it("minAppVersion is checked only AFTER the signature: an unsigned 'update required' is just a rejection", async () => {
      cdn.serve(v3NeedsNewApp);
      cdn.tamper("manifest.sig.json", (b) => flipByte(b, 60));
      const m = manager();
      expect((await m.refresh()).kind).toBe("rejected");
      expect(m.getState().updateRequired).toBeNull();
    });
  });

  describe("revokedKids[]", () => {
    it("a manifest signed by a surviving key revokes the old kid at once; the install then refuses the revoked kid", async () => {
      cdn.serve(v1); // signed by A
      const m = manager();
      await m.refresh();

      cdn.serve(v3RevokesA); // signed by B, lists A
      expect((await m.refresh()).kind).toBe("updated");
      expect(m.getState().snapshot?.trails[0]?.name).toBe("Trail v4 by B");

      // A later artifact signed by the revoked key is refused even though its signature is genuine.
      const p = new CatalogPublisher();
      try {
        const late = await p.emit({ version: "20260601-fffffff", generatedAt: "2026-06-01T00:00:00.000Z", key: KEY_A });
        cdn.serve(late);
        const outcome = await m.refresh();
        expect(outcome.kind).toBe("rejected");
        if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toContain("REVOKED_KID");
      } finally {
        await p.dispose();
      }
    });

    it("the revoked set persists across restarts and only ever grows", async () => {
      cdn.serve(v3RevokesA);
      await manager().refresh();
      expect(JSON.parse((await store.readMeta("revokedKids"))!)).toEqual([KEY_A.kid]);

      cdn.serve(v5ByB); // a later manifest that revokes nothing
      await manager().refresh();
      expect(JSON.parse((await store.readMeta("revokedKids"))!)).toEqual([KEY_A.kid]);
    });

    it("a cache signed by a kid that is later revoked is dropped on load (keys stop being trusted at once)", async () => {
      cdn.serve(v1);
      await manager().refresh();
      await store.writeMeta("revokedKids", JSON.stringify([KEY_A.kid]));
      const state = await manager({ baseUrl: null }).loadCached();
      expect(state.snapshot).toBeNull();
      expect(state.cacheDropped?.map((i) => i.code)).toContain("REVOKED_KID");
    });

    it("learning a revocation through an update_required manifest also drops the revoked-signer cache", async () => {
      cdn.serve(v1); // cache: signed by A
      const m = manager();
      await m.refresh();
      const p = new CatalogPublisher();
      try {
        const forceUpdate = await p.emit({ version: "20260701-1111111", generatedAt: "2026-07-01T00:00:00.000Z", key: KEY_B, minAppVersion: "9.0.0", revokedKids: [KEY_A.kid] });
        cdn.serve(forceUpdate);
        expect((await m.refresh()).kind).toBe("update_required");
        expect(m.getState().snapshot).toBeNull(); // A is revoked: the A-signed cache is no longer trusted
        expect(m.getState().updateRequired?.minAppVersion).toBe("9.0.0");
      } finally {
        await p.dispose();
      }
    });
  });

  describe("anti-rollback floor (the persisted high-water mark, not the cache)", () => {
    it("the exploit: a force-update manifest that revokes the cache's key drops the cache — replaying an OLDER genuine manifest is still refused", async () => {
      cdn.serve(v2); // cache 20260201 signed by A
      const m = manager();
      expect((await m.refresh()).kind).toBe("updated");

      cdn.serve(forceRevokeByB); // signed by B at 20260301: revokes A, needs 9.0.0
      expect((await m.refresh()).kind).toBe("update_required");
      expect(m.getState().snapshot).toBeNull(); // the A-signed cache is gone
      expect(await store.loadCatalog()).not.toBeNull(); // (still on disk, just untrusted)
      expect(await store.readMeta(FLOOR)).toBe("20260301-1111111");

      cdn.serve(oldByB); // a genuine, B-signed 20260101 manifest, replayed
      cdn.log.length = 0;
      const outcome = await m.refresh();
      expect(outcome).toEqual({ kind: "rejected", issues: [{ code: "CATALOG_VERSION_ROLLBACK", message: expect.any(String) as string }] });
      // refused by the VERIFIER (before any shard is downloaded), not merely by the save-time guard behind it
      expect(cdn.log.map((l) => l.path).sort()).toEqual(["manifest.json", "manifest.sig.json", "versions.json", "versions.sig.json"]);
      expect(m.getState().snapshot).toBeNull();
      expect(m.getState().updateRequired).toEqual({ minAppVersion: "9.0.0", catalogVersion: "20260301-1111111" });
      expect(await store.readMeta("updateRequired")).not.toBeNull();

      // ... and after a restart
      const again = manager();
      await again.loadCached();
      expect((await again.refresh()).kind).toBe("rejected");
      expect(again.getState().updateRequired?.minAppVersion).toBe("9.0.0");
    });

    it("the floor is raised by every verified manifest: an update_required one, an equal-version one, and a normal update", async () => {
      cdn.serve(v1);
      const m = manager();
      await m.refresh();
      expect(await store.readMeta(FLOOR)).toBe("20260101-aaaaaaa");
      await store.saveCatalog({ ...(await store.loadCatalog())!, etag: null }); // force a 200 for the same version
      expect((await m.refresh()).kind).toBe("up_to_date");
      expect(await store.readMeta(FLOOR)).toBe("20260101-aaaaaaa");
      cdn.serve(v2);
      await m.refresh();
      expect(await store.readMeta(FLOOR)).toBe("20260201-bbbbbbb");
      cdn.serve(v3NeedsNewApp);
      expect((await m.refresh()).kind).toBe("update_required");
      expect(await store.readMeta(FLOOR)).toBe("20260301-ccccccc"); // raised although nothing was downloaded
    });

    it("the floor survives the cache being corrupted (dropped on load): an older genuine catalog is still refused", async () => {
      cdn.serve(v2);
      await manager().refresh();
      const stored = (await store.loadCatalog())!;
      stored.shards.find((s) => s.path === "trails.json")!.text += " ";
      await store.saveCatalog(stored);

      const m = manager();
      const state = await m.loadCached();
      expect(state.snapshot).toBeNull();
      expect(state.cacheDropped?.map((i) => i.code)).toEqual(["MANIFEST_TAMPERED"]);

      cdn.serve(v1); // older, genuine, A-signed
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toEqual(["CATALOG_VERSION_ROLLBACK"]);
      expect(m.getState().snapshot).toBeNull();
    });

    it("the floor survives a keyset change that drops the cache: an older catalog by a still-trusted key is refused", async () => {
      cdn.serve(v2); // by A
      await manager().refresh();

      cdn.serve(oldByB); // genuine, by B, older
      const rotated = manager({ trustedKeys: [KEY_B.trusted] }); // a release that no longer trusts A
      const state = await rotated.loadCached();
      expect(state.snapshot).toBeNull();
      expect(state.cacheDropped?.map((i) => i.code)).toContain("UNKNOWN_KID");
      const outcome = await rotated.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toEqual(["CATALOG_VERSION_ROLLBACK"]);
      expect(rotated.getState().snapshot).toBeNull();
    });

    it("a fresh install (no floor) accepts the first genuine catalog, and a compiled-in minimum is honoured when set", async () => {
      cdn.serve(v1);
      const m = manager({ compiledMinCatalogVersion: "20260201-bbbbbbb" });
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toEqual(["CATALOG_VERSION_ROLLBACK"]);
      expect(await store.loadCatalog()).toBeNull();
      cdn.serve(v2); // exactly at the minimum is fine
      expect((await m.refresh()).kind).toBe("updated");
    });

    it("an unreadable floor row refuses every catalog (never reads as 'no floor')", async () => {
      cdn.serve(v2);
      await manager().refresh();
      for (const junk of ["", "garbage", "20260101", "99999999-zzzzzzz"]) {
        await store.writeMeta(FLOOR, junk);
        const m = manager();
        const outcome = await m.refresh();
        expect(outcome.kind, junk).toBe("rejected");
        if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code), junk).toEqual(["TRUST_STATE_CORRUPT"]);
      }
    });

    it("an unreadable compiled-in minimum refuses every catalog", async () => {
      cdn.serve(v1);
      const outcome = await manager({ compiledMinCatalogVersion: "not-a-version" }).refresh();
      expect(outcome.kind).toBe("rejected");
    });
  });

  describe("a corrupt revokedKids row fails CLOSED", () => {
    it.each([["not json"], ["{}"], ['{"a":1}'], ['[1,2]'], ['["k-prod-a", 7]'], ["null"]])("%s: refresh refuses and the cache is not trusted", async (junk) => {
      cdn.serve(v1);
      await manager().refresh();
      await store.writeMeta("revokedKids", junk);

      const m = manager();
      const state = await m.loadCached();
      expect(state.snapshot).toBeNull();
      expect(state.cacheDropped?.map((i) => i.code)).toEqual(["TRUST_STATE_CORRUPT"]);

      cdn.serve(v2);
      const outcome = await m.refresh();
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toEqual(["TRUST_STATE_CORRUPT"]);
      expect(m.getState().snapshot).toBeNull();
      expect(m.getState().outOfDateBanner).toBe(true);
      expect(await store.readMeta("revokedKids")).toBe(junk); // not silently healed
    });

    it("an empty array and an absent row are genuinely 'nothing revoked'", async () => {
      cdn.serve(v1);
      await store.writeMeta("revokedKids", "[]");
      expect((await manager().refresh()).kind).toBe("updated");
    });
  });

  describe("concurrency", () => {
    it("refresh() is single-flight: overlapping callers share one run (one set of fetches)", async () => {
      cdn.serve(v1);
      const m = manager();
      const p1 = m.refresh();
      const p2 = m.refresh();
      const p3 = m.refresh();
      expect(p2).toBe(p1);
      expect(p3).toBe(p1);
      expect(await p1).toEqual({ kind: "updated", from: null, to: "20260101-aaaaaaa" });
      expect(cdn.log.filter((l) => l.path === "manifest.json")).toHaveLength(1);

      // once it has settled, the next call is a NEW run
      const p4 = m.refresh();
      expect(p4).not.toBe(p1);
      expect((await p4).kind).toBe("up_to_date");
      expect(cdn.log.filter((l) => l.path === "manifest.json")).toHaveLength(2);
    });

    it("loadCached() waits for a refresh in flight instead of interleaving with it", async () => {
      cdn.serve(v1);
      const g = gate();
      const m = manager({ fetchBytes: gated(cdn, "trails.json", g) });
      const refreshing = m.refresh();
      await g.reached;
      let loaded = false;
      const loading = m.loadCached().then((st) => ((loaded = true), st));
      await new Promise((r) => setTimeout(r, 20));
      expect(loaded).toBe(false);
      g.release();
      await refreshing;
      expect((await loading).snapshot?.catalogVersion).toBe("20260101-aaaaaaa");
    });

    it("a slow older refresh cannot save over a newer catalog that landed while it downloaded (also after a reload)", async () => {
      // Two refreshers on ONE database (e.g. a second instance after a hot reload): the slow one verified v2,
      // the fast one v3 and finished first.
      const slowCdn = new FakeCdn();
      slowCdn.serve(raceV2);
      const g = gate();
      const slow = manager({ fetchBytes: gated(slowCdn, "trails.json", g) });
      const slowRun = slow.refresh();
      await g.reached; // v2 verified; its shards are held

      cdn.serve(raceV3);
      const fast = manager();
      expect((await fast.refresh()).kind).toBe("updated");

      g.release();
      const outcome = await slowRun;
      expect(outcome.kind).toBe("rejected");
      if (outcome.kind === "rejected") expect(outcome.issues.map((i) => i.code)).toEqual(["CATALOG_VERSION_ROLLBACK"]);
      expect(slow.getState().snapshot?.trails[0]?.name).toBe("Trail v3"); // the stale instance re-reads what is stored
      expect(slow.getState().outOfDateBanner).toBe(false);

      expect((await store.loadCatalog())?.manifestText).toContain("20260301-ccccccc");
      const reloaded = await manager({ baseUrl: null }).loadCached();
      expect(reloaded.snapshot?.catalogVersion).toBe("20260301-ccccccc");
      expect(reloaded.snapshot?.trails[0]?.name).toBe("Trail v3");
      expect(await store.readMeta(FLOOR)).toBe("20260301-ccccccc");
    });

    it("two overlapping revocations both persist (the union is one atomic store update)", async () => {
      const slowCdn = new FakeCdn();
      slowCdn.serve(revokeA);
      const g = gate();
      const slow = manager({ fetchBytes: gated(slowCdn, "manifest.json", g) });
      const slowRun = slow.refresh();
      await g.reached; // the slow refresher has already read the (empty) revoked set

      cdn.serve(revokeC);
      expect((await manager().refresh()).kind).toBe("updated");
      expect(JSON.parse((await store.readMeta("revokedKids"))!)).toEqual([KEY_C_KID]);

      g.release();
      expect((await slowRun).kind).toBe("updated");
      expect(JSON.parse((await store.readMeta("revokedKids"))!)).toEqual([KEY_A.kid, KEY_C_KID].sort());
    });
  });

  describe("a stored force-update requirement (MEDIUM-3)", () => {
    it("replaying the cached manifest does not clear a requirement set by a newer one — and it survives a restart", async () => {
      cdn.serve(v2);
      await manager().refresh();
      cdn.serve(v3NeedsNewApp);
      expect((await manager().refresh()).kind).toBe("update_required");

      // An install from before the floor was persisted: no floor row, and the cached v2's etag is gone,
      // so the stale edge's v2 is a full 200 that reaches the clearing logic.
      await store.deleteMeta(FLOOR);
      await store.saveCatalog({ ...(await store.loadCatalog())!, etag: null });
      cdn.serve(v2);
      const m = manager();
      await m.loadCached();
      expect((await m.refresh()).kind).toBe("up_to_date");
      expect(await store.readMeta("updateRequired")).not.toBeNull();
      expect(m.getState().updateRequired).toEqual({ minAppVersion: "2.0.0", catalogVersion: "20260301-ccccccc" });

      cdn.offline = true;
      const restarted = await manager().loadCached();
      expect(restarted.updateRequired).toEqual({ minAppVersion: "2.0.0", catalogVersion: "20260301-ccccccc" });
      expect(restarted.snapshot?.catalogVersion).toBe("20260201-bbbbbbb");
    });

    it("a stale CDN edge serving v1 after v2 required 9.0.0 keeps the requirement across restarts", async () => {
      const edge = await lineage({ version: "20260101-eeeeeee", generatedAt: "2026-01-01T00:00:00.000Z", key: KEY_A });
      const needs = await lineage({ version: "20260201-fffffff", generatedAt: "2026-02-01T00:00:00.000Z", key: KEY_A, minAppVersion: "9.0.0" });
      cdn.serve(edge);
      await manager().refresh(); // v1 cached
      cdn.serve(needs);
      expect((await manager().refresh()).kind).toBe("update_required");

      cdn.serve(edge); // a stale edge goes back to v1
      const m = manager();
      await m.loadCached();
      expect((await m.refresh()).kind).toBe("up_to_date"); // 304 on the cached v1's etag
      await store.saveCatalog({ ...(await store.loadCatalog())!, etag: null });
      expect((await manager().refresh()).kind).toBe("rejected"); // a full 200 of v1: below the floor
      expect(await store.readMeta("updateRequired")).not.toBeNull();

      cdn.offline = true;
      const restarted = await manager().loadCached();
      expect(restarted.updateRequired).toEqual({ minAppVersion: "9.0.0", catalogVersion: "20260201-fffffff" });
    });

    it("a verified manifest at least as new as the requirement clears it once this build satisfies it", async () => {
      cdn.serve(v3NeedsNewApp);
      await manager().refresh(); // 1.0.0: update_required
      expect(await store.readMeta("updateRequired")).not.toBeNull();
      const upgraded = manager({ appVersion: "2.0.0" });
      expect((await upgraded.refresh()).kind).toBe("updated"); // same version as the requirement: >=
      expect(await store.readMeta("updateRequired")).toBeNull();
      expect(upgraded.getState().updateRequired).toBeNull();
    });
  });

  describe("revocation and the equal-version path", () => {
    it("a same-version manifest that revokes the cache's key does not report up_to_date with nothing loaded: it re-downloads", async () => {
      cdn.serve(v2); // 20260201-bbbbbbb by A
      const m = manager();
      await m.refresh();
      const reissued = await lineage({ version: "20260201-bbbbbbb", generatedAt: "2026-02-01T00:00:00.000Z", key: KEY_B, revokedKids: [KEY_A.kid], trailName: "Trail v2 reissued by B" });
      cdn.serve(reissued);
      const outcome = await m.refresh();
      expect(outcome).toEqual({ kind: "updated", from: null, to: "20260201-bbbbbbb" });
      expect(m.getState().snapshot?.trails[0]?.name).toBe("Trail v2 reissued by B");
      expect(m.getState().cacheDropped).toBeNull();
    });
  });
});
