#!/usr/bin/env node
/**
 * emit-indexability.mjs — build plan §5.3: "prebuild runs
 * scripts/emit-indexability.mjs, which uses the SAME loadCatalog() +
 * isIndexable() as the pages and writes build/indexability.json. The
 * sitemap filter and the page `noindex` prop both read that file."
 *
 * **B2 (gate review): writes the FULL indexable page set**, not just
 * courses — the hub, every trail, every region's first (page-1) directory
 * page, `/fr/`, and every verified-AND-indexable course. Anything not in
 * this set (a `page/n/` beyond 1, `/claim/`, a thin/unverified course) is
 * never in the sitemap and always `noindex`.
 *
 * **B3: a demo build's indexable set is ALWAYS empty** — "A demo build is
 * ... noindex on every page, has an empty sitemap." `astro.config.mjs`'s
 * sitemap filter reads this file's exact set, so an empty set alone makes
 * the sitemap empty; each page ALSO passes `demo={usedDemoData}` to
 * `BaseLayout` (which forces `noindex` and shows the banner) as the
 * belt-and-suspenders per-page enforcement.
 *
 * Run directly by `node` (not through Astro/Vite), as `apps/site`'s
 * `build` script's first step — see `package.json`. It therefore cannot
 * import `src/lib/derive.ts` (a `.ts` file Node can't load without a
 * loader); the demo-fallback/production-refusal logic it needs mirrors
 * `derive.ts`'s `loadSiteCatalog()` (the `GOLFRAVEN_ENV` normalisation
 * itself is shared, not duplicated — both import `src/lib/env.mjs`,
 * which is plain JS so either side can load it).
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isCatalogEmpty, isIndexable, loadCatalog, loadCatalogFromBundle } from "@golfraven/catalog";
import { demoBundleForSite } from "../fixtures/demo-catalog/build-bundle.mjs";
import { isProductionEnv } from "../src/lib/env.mjs";

const here = dirname(fileURLToPath(import.meta.url));
// Overridable via GOLFRAVEN_DATA_DIR — see derive.ts's realDataDir() doc.
const REAL_DATA_DIR = process.env.GOLFRAVEN_DATA_DIR ?? join(here, "..", "..", "..", "data");
const OUT_PATH = process.env.INDEXABILITY_OUT_PATH ?? join(here, "..", "build", "indexability.json");

async function loadSiteCatalog() {
  const isProduction = isProductionEnv(process.env);
  const demoRequested = process.env.GOLFRAVEN_DEMO === "1";

  if (demoRequested) {
    if (isProduction) {
      throw new Error(
        "GOLFRAVEN_ENV=production refuses demo data (GOLFRAVEN_DEMO=1 was set).",
      );
    }
    return { catalog: loadCatalogFromBundle(demoBundleForSite()), usedDemoData: true };
  }

  const real = await loadCatalog({ dataDir: REAL_DATA_DIR });
  if (isCatalogEmpty(real)) {
    throw new Error(
      'data/ has no facility/trail content and GOLFRAVEN_DEMO was not set to "1". ' +
        "Set GOLFRAVEN_DEMO=1 to build with the synthetic demo dataset, or add real content to data/.",
    );
  }
  return { catalog: real, usedDemoData: false };
}

const { catalog, usedDemoData } = await loadSiteCatalog();

let indexablePaths = [];
if (!usedDemoData) {
  const paths = new Set(["/", "/fr/"]);
  for (const trail of catalog.trails) {
    paths.add(`/trails/${trail.slug}/`);
  }
  for (const regionCode of new Set(catalog.facilities.map((f) => f.region))) {
    const authored = catalog.regions.find((r) => r.code === regionCode);
    const [countryFromCode = "", subdivisionFromCode = ""] = regionCode.split("-");
    const country = (authored?.country ?? countryFromCode).toLowerCase();
    const regionSlug = authored?.slug ?? subdivisionFromCode.toLowerCase();
    paths.add(`/${country}/${regionSlug}/`);
  }
  for (const facility of catalog.facilities) {
    if (isIndexable(facility)) paths.add(`/courses/${facility.slug}/`);
  }
  indexablePaths = [...paths].sort();
}

await mkdir(dirname(OUT_PATH), { recursive: true });
await writeFile(OUT_PATH, JSON.stringify({ indexablePaths }, null, 2) + "\n");

console.log(
  usedDemoData
    ? "emit-indexability: DEMO DATA in use — wrote an EMPTY indexable set (0 paths)"
    : `emit-indexability: wrote ${indexablePaths.length} indexable path(s) to build/indexability.json`,
);
