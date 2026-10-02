import { getLocales } from "expo-localization";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { ActivityIndicator, View } from "react-native";
import type { Session } from "../api";
import { buildIndex, type CatalogIndex } from "../browse";
import type { CatalogResetReport, CatalogState, RefreshOutcome } from "../catalog/manager";
import type { CatalogSnapshot } from "../catalog/snapshot";
import { resolveLocale, translate, plural, LOCALES, type Locale, type MessageKey, type Params, type PluralBase } from "../i18n";
import type { OutboxItem } from "../outbox";
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
  startMockSession: (provider: Session["provider"]) => void;
  endSession: () => void;
  programmes: Record<string, ProgrammeStatus>;
  walletVisible: boolean;

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
  const [session, setSession] = useState<Session | null>(services.api.getSession());
  const [programmes, setProgrammes] = useState<Record<string, ProgrammeStatus>>({});
  const [outboxItems, setOutboxItems] = useState<OutboxItem[]>([]);
  const [updateDismissed, setUpdateDismissed] = useState(false);
  const deviceTags = useRef(getLocales().map((l) => l.languageTag));

  const locale = resolveLocale(deviceTags.current, explicitLocale);
  const t = useCallback((key: MessageKey, params?: Params) => translate(locale, key, params), [locale]);
  const tp = useCallback((base: PluralBase, count: number, params?: Params) => plural(locale, base, count, params), [locale]);

  const reloadOutbox = useCallback(async () => {
    setOutboxItems(await services.outboxStore.list());
  }, [services]);

  const refreshCatalog = useCallback(async () => {
    const outcome = await services.catalog.refresh();
    setCatalogState(services.catalog.getState());
    return outcome;
  }, [services]);

  const resetCatalog = useCallback(async () => {
    const report = await services.catalog.resetCatalogData();
    setCatalogState(services.catalog.getState());
    if (report.performed && !report.stillCorrupt) void refreshCatalog(); // fetch and verify the catalog again (a no-op reset deleted nothing)
    return report;
  }, [services, refreshCatalog]);

  const syncOutbox = useCallback(async () => {
    await services.outboxRunner.run();
    await reloadOutbox();
  }, [services, reloadOutbox]);

  // Startup: stored language, cached catalog (re-verified), then one refresh.
  useEffect(() => {
    let alive = true;
    void (async () => {
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
    startMockSession: (provider) => setSession(services.api.startMockSession(provider)),
    endSession: () => {
      services.api.endSession();
      setSession(null);
    },
    programmes,
    walletVisible: walletTabVisible(programmes),
    outboxItems,
    reloadOutbox,
    syncOutbox,
  };
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
