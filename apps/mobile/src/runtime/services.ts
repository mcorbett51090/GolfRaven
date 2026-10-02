/**
 * The composition root: builds every service the screens use from the
 * config + the app database. Everything here is wiring; the logic lives in
 * the modules it composes (and is tested there).
 */
import { fetch as expoFetch } from "expo/fetch";
import { MemoryDeviceFlagStore, SqliteDeviceFlagStore, AgeGate, type DeviceFlagStore } from "../age";
import { createMockApi, type MockApi } from "../api";
import { nobleCatalogCrypto } from "../catalog/crypto";
import { resolveTrustAnchors, TRUSTED_KEYSET } from "../catalog/keys";
import { CatalogManager, createFetchBytes } from "../catalog/manager";
import { MemoryCatalogCacheStore, SqliteCatalogCacheStore } from "../catalog/store";
import { readAppConfig, type AppConfig } from "../config";
import { openAppDatabase } from "../db/expo-sqlite-adapter";
import { MemoryOutboxStore, OutboxRunner, SqliteOutboxStore, type OutboxItem, type OutboxStore, type RematchResult } from "../outbox";
import { stubProviders } from "../signin";
import { buildIndex } from "../browse";

export interface AppServices {
  config: AppConfig;
  catalog: CatalogManager;
  outboxStore: OutboxStore;
  outboxRunner: OutboxRunner;
  api: MockApi;
  ageGate: AgeGate;
  flags: DeviceFlagStore;
  providers: ReturnType<typeof stubProviders>;
  /** False when SQLite could not be opened and the app fell back to memory. */
  persistent: boolean;
  /** Why the compiled-in keyset was refused (release builds only), or `null`.
   * When set the catalog is untrusted and network refresh is off (fail closed;
   * `resolveTrustAnchors`). */
  keysetProblem: string | null;
}

export async function createServices(): Promise<AppServices> {
  const config = readAppConfig();
  let persistent = true;
  let catalogStore: ConstructorParameters<typeof CatalogManager>[0]["store"];
  let outboxStore: OutboxStore;
  let flags: DeviceFlagStore;
  try {
    const db = await openAppDatabase();
    catalogStore = new SqliteCatalogCacheStore(db);
    outboxStore = new SqliteOutboxStore(db);
    flags = new SqliteDeviceFlagStore(db);
  } catch {
    // Never lose the app to a storage failure: browse with a memory cache.
    // (An unopenable database is surfaced in Me → Catalog; plays cannot be
    // recorded safely without persistence, which is why this path is
    // reachable only for guest browse in practice.)
    persistent = false;
    catalogStore = new MemoryCatalogCacheStore();
    outboxStore = new MemoryOutboxStore();
    flags = new MemoryDeviceFlagStore();
  }

  // LOW-12: `assertReleaseKeyset`, applied without throwing. A release build whose keyset
  // is not releasable (today: empty, until the P3 gate) trusts NOTHING and does not fetch.
  const anchors = resolveTrustAnchors(TRUSTED_KEYSET, __DEV__);

  const catalog = new CatalogManager({
    baseUrl: anchors.problem === null ? config.catalogBaseUrl : null,
    store: catalogStore,
    crypto: nobleCatalogCrypto,
    trustedKeys: anchors.trustedKeys,
    appVersion: config.appVersion,
    supportedContractMajor: config.supportedContractMajor,
    // LOW-C: RN's default `fetch` is believed to expose no body stream, so a byte cap there could
    // only apply AFTER the download. `expo/fetch` streams the body natively, so `createFetchBytes`
    // cancels an over-cap download mid-flight. `[unverified — device: streaming + redirect:"error" on iOS/Android]`
    fetchBytes: createFetchBytes(expoFetch),
  });

  const api = createMockApi({
    programmes: {},
    plays: [],
    achievements: [],
  });

  const outboxRunner = new OutboxRunner({
    store: outboxStore,
    api,
    now: () => Date.now(),
    rng: Math.random,
    refreshCatalog: async () => {
      await catalog.refresh();
    },
    // P4.1 STUBS — what they do, and what that means on a device:
    //  * `rematch`: the on-device matcher (`@golfraven/matching`) is wired in a later
    //    slice. Until then a re-match only checks that the stored course still exists in
    //    the current catalog, and it never invents a match. With NO verified snapshot —
    //    which is every build until the production keyset exists, because an empty
    //    keyset verifies nothing — it returns `{ ok: false }`, so a 422 `catalog_stale`
    //    answer DEAD-LETTERS the item (`needs_attention` / `rematch_failed`) rather than
    //    re-matching it.
    //  * `findCourseForUnlisted` always answers `null`: an "Unlisted course" item never
    //    becomes sendable on the device (§7.6, G3-01).
    //  * `resolveQueued` (outbox/machine.ts) has no caller: nothing observes the server
    //    resolving a `queued_catalog` item, so on the device a queued play stays `queued`
    //    (it never becomes `accepted` or `queue_expired`).
    rematch: (item: OutboxItem): Promise<RematchResult> => {
      const snap = catalog.getState().snapshot;
      if (!snap) return Promise.resolve({ ok: false });
      const index = buildIndex(snap);
      const courseId = item.courseId !== null && index.courses.has(item.courseId) ? item.courseId : null;
      return Promise.resolve({ ok: true, courseId, catalogVersion: snap.catalogVersion, payload: item.payload });
    },
    findCourseForUnlisted: () => Promise.resolve(null), // P4.1 STUB, see above
  });

  return {
    config,
    catalog,
    outboxStore,
    outboxRunner,
    api,
    ageGate: new AgeGate(flags),
    flags,
    providers: stubProviders(),
    persistent,
    keysetProblem: anchors.problem,
  };
}
