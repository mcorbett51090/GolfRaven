/**
 * The composition root: builds every service the screens use from the
 * config + the app database. Everything here is wiring; the logic lives in
 * the modules it composes (and is tested there).
 */
import { MemoryDeviceFlagStore, SqliteDeviceFlagStore, AgeGate, type DeviceFlagStore } from "../age";
import { createMockApi, type MockApi } from "../api";
import { nobleCatalogCrypto } from "../catalog/crypto";
import { TRUSTED_KEYSET } from "../catalog/keys";
import { CatalogManager } from "../catalog/manager";
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

  const catalog = new CatalogManager({
    baseUrl: config.catalogBaseUrl,
    store: catalogStore,
    crypto: nobleCatalogCrypto,
    trustedKeys: TRUSTED_KEYSET,
    appVersion: config.appVersion,
    supportedContractMajor: config.supportedContractMajor,
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
    // P4.1 STUB: the on-device matcher (`@golfraven/matching`) is wired in a
    // later slice. Until then a re-match only checks that the stored course
    // still exists in the current catalog; if not, the play becomes an
    // "Unlisted course" item and waits (§7.6, G3-01). It never invents a match.
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
  };
}
