/**
 * "Never publish demo data" (stage-1 scope item 3): `GOLFRAVEN_ENV=production`
 * plus a demo-data fallback must be a hard build failure. Tested directly
 * against `loadSiteCatalog()`, not through a full `astro build` (that path
 * is exercised by `test/global-setup.mjs` + `acceptance.test.ts`, always
 * with `GOLFRAVEN_ENV` unset).
 */
import { describe, expect, it } from "vitest";
import { isCatalogEmpty } from "@golfraven/catalog";
import { loadSiteCatalog } from "../src/lib/derive";

describe("loadSiteCatalog — demo-data production guard", () => {
  it("refuses GOLFRAVEN_ENV=production + GOLFRAVEN_DEMO=1", async () => {
    await expect(
      loadSiteCatalog({ GOLFRAVEN_ENV: "production", GOLFRAVEN_DEMO: "1" }),
    ).rejects.toThrow(/production/i);
  });

  it("refuses GOLFRAVEN_ENV=production when the real data/ dir is simply empty", async () => {
    // The real data/ dir has no facility/trail content today (data/README.md),
    // so an unset GOLFRAVEN_DEMO still falls back to the demo catalog — and
    // that fallback must still be refused in production.
    await expect(loadSiteCatalog({ GOLFRAVEN_ENV: "production" })).rejects.toThrow(/production/i);
  });

  it("loads the demo catalog outside production when forced", async () => {
    const { catalog, usedDemoData } = await loadSiteCatalog({ GOLFRAVEN_DEMO: "1" });
    expect(usedDemoData).toBe(true);
    expect(isCatalogEmpty(catalog)).toBe(false);
    expect(catalog.trails.length).toBeGreaterThan(0);
  });

  it("loads the demo catalog outside production even when not forced (real data/ is empty)", async () => {
    const { usedDemoData } = await loadSiteCatalog({});
    expect(usedDemoData).toBe(true);
  });
});
