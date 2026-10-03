import { getLocales } from "expo-localization";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ActivityIndicator, View } from "react-native";
import { deleteAccountAndWipeLocal, type DeleteOutcome } from "../account";
import type { Session } from "../api";
import { buildIndex, type CatalogIndex } from "../browse";
import { prefetchChallenges } from "../challenges/prefetch-gate";
import { provisionOfflineSeedOnLaunch } from "../offline-code/gate";
import { resetCatalogAndMaybeRedownload, type CatalogResetReport, type CatalogState, type RefreshOutcome } from "../catalog/manager";
import type { CatalogSnapshot } from "../catalog/snapshot";
import { resolveLocale, translate, plural, LOCALES, type Locale, type MessageKey, type Params, type PluralBase } from "../i18n";
import { filterVisibleOutboxItems, visibleOutboxItems, type OutboxItem } from "../outbox";
import type { ProgrammeStatus } from "../wallet";
import { walletTabVisible } from "../wallet";
import { createServices, type AppServices } from "./services";

const LOCALE_FLAG = "locale";

/** The labelled demo catalog exists only in development builds: it is
 * `require`d lazily under `__DEV__` so Metro drops it from release bundles
 * (a static import would ship it, merely unused). */
const DEMO_SNAPSHOT: CatalogSnapshot | null = __DEV__ ? (require("../demo/demo-catalog") as typeof import("../demo/demo-catalog")).DEMO_SNAPSHOT : null;

export interface AppContextValue {
  services: AppServices;
  locale: Locale;
  /** `null` = follow the device language. */
  explicitLocale: Locale | null;
  setExplicitLocale: (l: Locale | null) => void;
  t: (key: MessageKey, params?: Params) => string;
  tp: (base: PluralBase, count: number, params?: Params) => string;

  catalogState: CatalogState;
  /** The snapshot the screens read: the verified cache, or (dev builds with no
   * catalog source only) the labelled demo snapshot. */
  snapshot: CatalogSnapshot | null;
  isDemo: boolean;
  index: CatalogIndex | null;
  refreshCatalog: () => Promise<RefreshOutcome>;
  /** Me → "Reset catalog data" (the way out of `TRUST_STATE_CORRUPT`): drops the cache and any UNREADABLE trust
   * rows, keeps valid ones, then re-downloads (`CatalogManager.resetCatalogData`). */
  resetCatalog: () => Promise<CatalogResetReport>;
  /** Force-update screen was dismissed for this session. */
  updateDismissed: boolean;
  dismissUpdate: () => void;

  session: Session | null;
  /** Ends the session (revoked at the server best-effort, removed from the secure store always). The signed-out user's queued plays are NOT deleted
   * (they stay on the device, dormant: invisible and unsendable to anyone else, and back when that user signs in again). */
  signOut: () => Promise<void>;
  /** Me → Delete account: the server deletion, then the local wipe (session, outbox, caches; the age flag is kept). */
  deleteAccount: () => Promise<DeleteOutcome>;
  programmes: Record<string, ProgrammeStatus>;
  walletVisible: boolean;

  /** The SIGNED-IN user's outbox items only; empty when signed out (`filterVisibleOutboxItems`). */
  outboxItems: OutboxItem[];
  reloadOutbox: () => Promise<void>;
  syncOutbox: () => Promise<void>;
}

const Ctx = createContext<AppContextValue | null>(null);

export function useApp(): AppContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useApp must be used inside <AppProvider>");
  return v;
}

export function AppProvider({ children }: { children: ReactNode }) {
  const [services, setServices] = useState<AppServices | null>(null);
  const [failed, setFailed] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    createServices().then(
      (s) => alive && setServices(s),
      (e: unknown) => alive && setFailed(e instanceof Error ? e.message : String(e)),
    );
    return () => {
      alive = false;
    };
  }, []);

  if (failed) throw new Error(`GolfRaven failed to start: ${failed}`);
  if (!services) {
    return (
      <View style={{ flex: 1, alignItems: "center", justifyContent: "center" }}>
        <ActivityIndicator />
      </View>
    );
  }
  return <Ready services={services}>{children}</Ready>;
}

function Ready({ services, children }: { services: AppServices; children: ReactNode }) {
  const [explicitLocale, setExplicit] = useState<Locale | null>(null);
  const [catalogState, setCatalogState] = useState<CatalogState>(services.catalog.getState());
  const [session, setSession] = useState<Session | null>(services.auth.current());
  const [programmes, setProgrammes] = useState<Record<string, ProgrammeStatus>>({});
  const [outboxLoaded, setOutboxLoaded] = useState<OutboxItem[]>([]);
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const deviceTags = useRef(getLocales().map((l) => l.languageTag));

  const locale = resolveLocale(deviceTags.current, explicitLocale);
  const t = useCallback((key: MessageKey, params?: Params) => translate(locale, key, params), [locale]);
  const tp = useCallback((base: PluralBase, count: number, params?: Params) => plural(locale, base, count, params), [locale]);

  const reloadOutbox = useCallback(async () => {
    const userId = services.auth.current()?.userId ?? null;
    const items = await visibleOutboxItems(services.outboxStore, userId);
    // The user may have changed while the read was in flight: a list read for one user is dropped, not shown to the next.
    if ((services.auth.current()?.userId ?? null) === userId) setOutboxLoaded(items);
  }, [services]);

  const refreshCatalog = useCallback(async () => {
    const outcome = await services.catalog.refresh();
    setCatalogState(services.catalog.getState());
    return outcome;
  }, [services]);

  const resetCatalog = useCallback(
    // fetch and verify the catalog again after a reset that deleted something (the decision lives in `shouldRedownloadAfterReset`)
    () => resetCatalogAndMaybeRedownload(services.catalog, () => setCatalogState(services.catalog.getState()), refreshCatalog),
    [services, refreshCatalog],
  );

  const syncOutbox = useCallback(async () => {
    await services.outboxRunner.run();
    await reloadOutbox();
    // After the send, not before: redeeming a challenge at send time frees the server's cap of 10 open prefetched ones, which a top-up needs.
    void prefetchChallenges(services.challenges);
  }, [services, reloadOutbox]);

  // The session follows the auth service (sign-in, sign-out, a refresh the server refused).
  useEffect(() => services.auth.subscribe(setSession), [services]);

  // The outbox list follows the signed-in USER: a different user's items are never kept in state across a switch, and signed out shows none.
  const userId = session?.userId ?? null;
  useEffect(() => {
    setOutboxLoaded([]);
    void reloadOutbox();
    // Online and signed in: keep this user's pool of single-use check-in challenges topped up (offline check-ins consume them, FM-10).
    // A no-op until a screen can use a challenge (`CHECKIN_UI_ENABLED`, src/features.ts): unused ones only expire and eat the hourly limit.
    if (userId !== null) void prefetchChallenges(services.challenges);
    // Same shape for the offline code's seed: a no-op until a screen can show the code (`OFFLINE_CODE_UI_ENABLED`, src/features.ts).
    if (userId !== null) void provisionOfflineSeedOnLaunch(services.offlineCode);
  }, [userId, reloadOutbox, services]);
  const outboxItems = useMemo(() => filterVisibleOutboxItems(outboxLoaded, userId), [outboxLoaded, userId]);

  // Startup: stored session, stored language, cached catalog (re-verified), then one refresh.
  useEffect(() => {
    let alive = true;
    void (async () => {
      const restored = await services.auth.restore();
      if (alive) setSession(restored);
      const stored = await services.flags.get(LOCALE_FLAG);
      if (alive && stored && (LOCALES as readonly string[]).includes(stored)) setExplicit(stored as Locale);
      const loaded = await services.catalog.loadCached();
      if (alive) setCatalogState(loaded);
      await reloadOutbox();
      setProgrammes(await services.api.listTrailProgrammes());
      void refreshCatalog();
    })();
    return () => {
      alive = false;
    };
  }, [services, reloadOutbox, refreshCatalog]);

  const setExplicitLocale = useCallback(
    (l: Locale | null) => {
      setExplicit(l);
      void services.flags.set(LOCALE_FLAG, l ?? "");
    },
    [services],
  );

  const isDemo = catalogState.snapshot === null && services.config.catalogBaseUrl === null && __DEV__;
  const snapshot = catalogState.snapshot ?? (isDemo ? DEMO_SNAPSHOT : null);
  const index = useMemo(() => (snapshot ? buildIndex(snapshot) : null), [snapshot]);

  const value: AppContextValue = {
    services,
    locale,
    explicitLocale,
    setExplicitLocale,
    t,
    tp,
    catalogState,
    snapshot,
    isDemo,
    index,
    refreshCatalog,
    resetCatalog,
    updateDismissed,
    dismissUpdate: () => setUpdateDismissed(true),
    session,
    signOut: async () => {
      await services.auth.signOut();
      setSession(null);
      // Deliberately NOT `outbox.deleteAll()` / any delete: the signing-out user's queued plays stay in the store, dormant. They are filtered out
      // of every read (`listByOwner`) and never selected by the runner for anyone else, and they are theirs again when they sign back in (a
      // sign-out is not an account deletion, and losing queued plays on sign-out would break FM-03). Only `deleteAccount` wipes the outbox.
    },
    deleteAccount: async () => {
      const outcome = await deleteAccountAndWipeLocal({
        api: services.api,
        auth: services.auth,
        outbox: services.outboxStore,
        challenges: services.challengeStore,
        attestState: { wipeUser: async (userId) => services.attestState.wipeUser(userId, await services.deviceId()) },
        offlineSeed: { wipeUser: (userId) => services.offlineCode.wipeUser(userId) },
        markerCosignals: services.markerStore,
        sharer: services.sharer,
        currentUserId: () => services.auth.current()?.userId ?? null,
        secure: services.secure,
        clearUserCaches: () => setProgrammes({}),
      });
      if (outcome.status === "deleted" || outcome.status === "deleted_or_session_ended") {
        setSession(null);
        await reloadOutbox();
      }
      return outcome;
    },
    programmes,
    walletVisible: walletTabVisible(programmes),
    outboxItems,
    reloadOutbox,
    syncOutbox,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
