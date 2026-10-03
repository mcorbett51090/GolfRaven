/**
 * NIT (PR #30 gate): `AppProvider` re-downloads the catalog after a reset ONLY when the reset actually ran
 * (`report.performed`) and the trust state is readable again (`!report.stillCorrupt`). Deleting the `performed` check
 * survived mutation: nothing exercised the decision, because it was inline in a React hook with no renderer here.
 *
 * The post-reset flow is now `resetCatalogAndMaybeRedownload` (`catalog/manager.ts`), which `AppProvider.resetCatalog`
 * calls with its own state-sync and `refreshCatalog`, and the decision is `shouldRedownloadAfterReset`. Both are tested
 * here directly. What stays untested (no renderer, no new dependencies) is the one-line delegation in `AppProvider`.
 */
import { describe, expect, it, vi } from "vitest";
import { resetCatalogAndMaybeRedownload, shouldRedownloadAfterReset, type CatalogResetReport } from "../src/catalog/manager";

const report = (over: Partial<CatalogResetReport> = {}): CatalogResetReport => ({
  performed: true,
  revokedCleared: true,
  floorCleared: false,
  floorReseededTo: null,
  stillCorrupt: false,
  ...over,
});

describe("shouldRedownloadAfterReset", () => {
  it.each([
    [true, false, true],
    [false, false, false], // a no-op reset deleted nothing: nothing to replace
    [true, true, false], // still corrupt: a refetch would be rejected again
    [false, true, false],
  ])("performed=%s stillCorrupt=%s -> %s", (performed, stillCorrupt, want) => {
    expect(shouldRedownloadAfterReset(report({ performed, stillCorrupt }))).toBe(want);
  });
});

describe("resetCatalogAndMaybeRedownload (the AppProvider wiring)", () => {
  function setup(r: CatalogResetReport) {
    const calls: string[] = [];
    const catalog = { resetCatalogData: vi.fn(async () => (calls.push("reset"), r)) };
    const syncState = vi.fn(() => void calls.push("sync"));
    const redownload = vi.fn(async () => (calls.push("redownload"), undefined));
    return { calls, catalog, syncState, redownload };
  }

  it("a reset that ran and left the trust state readable: syncs the UI state, THEN starts the re-download", async () => {
    const s = setup(report());
    const got = await resetCatalogAndMaybeRedownload(s.catalog, s.syncState, s.redownload);
    expect(s.calls).toEqual(["reset", "sync", "redownload"]);
    expect(s.redownload).toHaveBeenCalledTimes(1);
    expect(got).toEqual(report());
  });

  it("a no-op reset (performed: false): the state is re-read but NOTHING is re-downloaded, and the report is passed through", async () => {
    const r = report({ performed: false, revokedCleared: false });
    const s = setup(r);
    expect(await resetCatalogAndMaybeRedownload(s.catalog, s.syncState, s.redownload)).toBe(r);
    expect(s.calls).toEqual(["reset", "sync"]);
    expect(s.redownload).not.toHaveBeenCalled();
  });

  it("a reset that ran but is STILL corrupt (a malformed compiled-in minimum): no re-download", async () => {
    const s = setup(report({ stillCorrupt: true }));
    await resetCatalogAndMaybeRedownload(s.catalog, s.syncState, s.redownload);
    expect(s.calls).toEqual(["reset", "sync"]);
    expect(s.redownload).not.toHaveBeenCalled();
  });

  it("the re-download is started, not awaited: a re-download that never settles does not hold the report back", async () => {
    const s = setup(report());
    const never = vi.fn(() => new Promise<unknown>(() => undefined));
    await expect(resetCatalogAndMaybeRedownload(s.catalog, s.syncState, never)).resolves.toEqual(report());
    expect(never).toHaveBeenCalledTimes(1);
  });
});
