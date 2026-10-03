/**
 * LOW-3 (PR #29 gate): the Me tab's "Reset catalog data" button was always shown. On a healthy install in the
 * force-update state (or with refresh off / offline) a reset deleted the readable older catalog and the refresh after it
 * could not replace it. The button is now rendered only when `isTrustStateCorrupt(catalogState)`.
 *
 * `me.tsx` is a React Native screen and there is no renderer here (no new dependencies), so the screen FUNCTION is called
 * directly with `useState`, the app context and the UI components stubbed, and the returned element tree is inspected.
 * What this proves is the screen's own decision (which elements it returns for a given catalog state), not native layout.
 */
import { isValidElement, type ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { en } from "../src/i18n/messages/en";
import { frCA } from "../src/i18n/messages/fr-CA";
import type { CatalogState } from "../src/catalog/manager";

const h = vi.hoisted(() => {
  Reflect.set(globalThis, "__DEV__", false); // me.tsx reads it at import time (the DevPanel is dev-only)
  return {
    app: null as unknown,
    alerts: [] as { title: string; body: string; buttons: { text: string; style?: string; onPress?: () => void }[] }[],
    resetCatalog: vi.fn(async () => ({ performed: true, revokedCleared: true, floorCleared: false, floorReseededTo: null, stillCorrupt: false })),
  };
});

vi.mock("react", async (importOriginal) => {
  const real = await importOriginal<typeof import("react")>();
  const useState = <S>(init: S | (() => S)): [S, (v: S) => void] => [typeof init === "function" ? (init as () => S)() : init, () => undefined];
  return { ...real, default: { ...real, useState }, useState };
});
vi.mock("react-native", () => ({
  Alert: { alert: (title: string, body: string, buttons: { text: string; style?: string; onPress?: () => void }[]) => h.alerts.push({ title, body, buttons }) },
}));
vi.mock("expo-router", () => ({ useRouter: () => ({ push: () => undefined }) }));
vi.mock("../src/runtime/AppProvider", () => ({ useApp: () => h.app }));
vi.mock("../src/screens/CatalogBanners", () => ({ CatalogBanners: () => null }));
vi.mock("../src/ui/components", () => {
  const stub = () => null;
  return { Body: stub, Button: stub, Card: stub, Chip: stub, H2: stub, Row: stub, Screen: stub };
});

import { Button } from "../src/ui/components";
import MeScreen from "../app/(tabs)/me";

type El = { type: unknown; props: { children?: ReactNode; title?: string; onPress?: () => void } };
function elements(node: ReactNode, out: El[] = []): El[] {
  if (Array.isArray(node)) for (const n of node) elements(n, out);
  else if (isValidElement(node)) {
    out.push(node as unknown as El);
    elements((node.props as { children?: ReactNode }).children, out);
  }
  return out;
}

const T = (k: string): string => k; // identity: the test asserts on message KEYS
const snapshot = { catalogVersion: "20260101-aaaaaaa" } as unknown as NonNullable<CatalogState["snapshot"]>;
const healthy: CatalogState = { snapshot, cacheDropped: null, updateRequired: null, outOfDateBanner: false, lastOutcome: { kind: "up_to_date", catalogVersion: "20260101-aaaaaaa" } };

function resetButton(state: CatalogState, over: Record<string, unknown> = {}): El | undefined {
  h.app = {
    t: T,
    session: null,
    explicitLocale: null,
    setExplicitLocale: () => undefined,
    catalogState: state,
    refreshCatalog: async () => ({ kind: "up_to_date" }),
    resetCatalog: h.resetCatalog,
    signOut: () => Promise.resolve(),
    deleteAccount: () => Promise.reject(new Error("not used here")),
    services: { keysetProblem: null, config: { appVersion: "1.0.0" }, push: { isAvailable: () => false } },
    ...over,
  };
  return elements(MeScreen() as ReactNode).find((e) => e.type === Button && e.props.title === "me.catalog.reset");
}

beforeEach(() => {
  h.alerts.length = 0;
  h.resetCatalog.mockClear();
});

describe("Me tab: the Reset catalog data button", () => {
  it("is HIDDEN on a healthy install", () => {
    expect(resetButton(healthy)).toBeUndefined();
  });

  it("is hidden in the force-update state (the older catalog is readable; a reset would strand the user)", () => {
    const forceUpdate: CatalogState = {
      ...healthy,
      updateRequired: { minAppVersion: "9.0.0", catalogVersion: "20260701-1111111" },
      lastOutcome: { kind: "update_required", minAppVersion: "9.0.0", catalogVersion: "20260701-1111111" },
    };
    expect(resetButton(forceUpdate)).toBeUndefined();
  });

  it("is hidden for every other non-corrupt state: offline, refresh off, out of date, a dropped cache that is not a trust-state fault, no catalog", () => {
    const states: CatalogState[] = [
      { ...healthy, lastOutcome: { kind: "network_error", message: "offline" } },
      { ...healthy, lastOutcome: { kind: "disabled" } },
      { ...healthy, outOfDateBanner: true, lastOutcome: { kind: "rejected", issues: [{ code: "BAD_SIGNATURE", message: "x" }] } },
      { ...healthy, snapshot: null, cacheDropped: [{ code: "BAD_SIGNATURE", message: "x" }] },
      { snapshot: null, cacheDropped: null, updateRequired: null, outOfDateBanner: false, lastOutcome: null },
    ];
    for (const s of states) expect(resetButton(s), JSON.stringify(s)).toBeUndefined();
    expect(resetButton(healthy, { services: { keysetProblem: "no valid keys", config: { appVersion: "1.0.0" }, push: { isAvailable: () => false } } })).toBeUndefined(); // keyset problem: still healthy data
  });

  it("is SHOWN when the saved catalog was dropped for a corrupt trust state", () => {
    expect(resetButton({ ...healthy, snapshot: null, cacheDropped: [{ code: "TRUST_STATE_CORRUPT", message: "x" }] })).toBeDefined();
  });

  it("is SHOWN when a refresh was rejected for a corrupt trust state", () => {
    expect(resetButton({ ...healthy, outOfDateBanner: true, lastOutcome: { kind: "rejected", issues: [{ code: "TRUST_STATE_CORRUPT", message: "x" }] } })).toBeDefined();
  });

  it("confirming asks first, and only the destructive confirm runs the reset", async () => {
    const b = resetButton({ ...healthy, snapshot: null, cacheDropped: [{ code: "TRUST_STATE_CORRUPT", message: "x" }] })!;
    b.props.onPress!();
    expect(h.alerts).toHaveLength(1);
    expect(h.alerts[0]!.title).toBe("me.catalog.reset.confirmTitle");
    expect(h.resetCatalog).not.toHaveBeenCalled();
    const confirm = h.alerts[0]!.buttons.find((x) => x.style === "destructive")!;
    expect(confirm.text).toBe("me.catalog.reset.confirm");
    confirm.onPress!();
    await vi.waitFor(() => expect(h.resetCatalog).toHaveBeenCalledTimes(1));
  });
});

describe("the reset confirm text no longer over-promises (the reset only TRIES to download again)", () => {
  it.each([
    ["en", en],
    ["fr-CA", frCA],
  ] as const)("%s: states that a failed download leaves no catalog, and carries a message for the no-op case", (_l, m) => {
    expect(m["me.catalog.reset.confirmBody"]).not.toMatch(/, then downloads the catalog again\.|puis télécharge de nouveau le catalogue\./);
    expect(m["me.catalog.reset.done"]).not.toMatch(/^Catalog data was reset\. Downloading|Nouveau téléchargement/);
    expect(m["me.catalog.reset.nothing"].length).toBeGreaterThan(0);
  });
  it("en: warns that there is no catalog until a download succeeds", () => {
    expect(en["me.catalog.reset.confirmBody"]).toMatch(/tries to download/);
    expect(en["me.catalog.reset.confirmBody"]).toMatch(/no catalog until it succeeds/);
  });
  it("fr-CA: says the same (tente de télécharger / aucun catalogue tant qu'il n'aura pas réussi)", () => {
    expect(frCA["me.catalog.reset.confirmBody"]).toMatch(/tente de télécharger/);
    expect(frCA["me.catalog.reset.confirmBody"]).toMatch(/aucun catalogue tant qu'il n'aura pas réussi/);
  });
});
