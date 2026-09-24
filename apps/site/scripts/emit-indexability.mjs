#!/usr/bin/env node
/**
 * emit-indexability.mjs — build plan §5.3: "prebuild runs
 * scripts/emit-indexability.mjs, which uses the SAME loadCatalog() +
 * isIndexable() as the pages and writes build/indexability.json. The
 * sitemap filter and the page `noindex` prop both read that file."
 *
 * Run directly by `node` (not through Astro/Vite), as `apps/site`'s
 * `build` script's first step — see `package.json`. It therefore cannot
 * import `src/lib/derive.ts` (a `.ts` file Node can't load without a
 * loader); the small demo-fallback/production-refusal logic it needs is
 * duplicated here from `derive.ts`'s `loadSiteCatalog()`, deliberately
 * kept tiny so the duplication stays cheap to keep in sync.
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  isCatalogEmpty,
  isIndexable,
  loadCatalog,
  loadCatalogFromBundle,
} from "@golfraven/catalog";

const here = dirname(fileURLToPath(import.meta.url));
const REAL_DATA_DIR = join(here, "..", "..", "..", "data");
const DEMO_BUNDLE_PATH = join(here, "..", "fixtures", "demo-catalog", "bundle.json");
const OUT_PATH = join(here, "..", "build", "indexability.json");

async function loadSiteCatalog() {
  const isProduction = process.env.GOLFRAVEN_ENV === "production";
  const forceDemo = process.env.GOLFRAVEN_DEMO === "1";

  const real = await loadCatalog({ dataDir: REAL_DATA_DIR });
  const realIsEmpty = isCatalogEmpty(real);
  const useDemo = forceDemo || realIsEmpty;

  if (useDemo && isProduction) {
    const reason = forceDemo ? "GOLFRAVEN_DEMO=1 was set" : "data/ is empty";
    throw new Error(
      `GOLFRAVEN_ENV=production but the build would fall back to the synthetic ` +
        `demo catalog (${reason}). Refusing to publish demo data.`,
    );
  }

  if (!useDemo) return real;
  const bundleRaw = JSON.parse(await readFile(DEMO_BUNDLE_PATH, "utf8"));
  return loadCatalogFromBundle(bundleRaw);
}

const catalog = await loadSiteCatalog();
const indexablePaths = catalog.facilities
  .filter((f) => isIndexable(f))
  .map((f) => `/courses/${f.slug}/`)
  .sort();

await mkdir(dirname(OUT_PATH), { recursive: true });
await writeFile(OUT_PATH, JSON.stringify({ indexablePaths }, null, 2) + "\n");

console.log(
  `emit-indexability: wrote ${indexablePaths.length} indexable path(s) to build/indexability.json`,
);
