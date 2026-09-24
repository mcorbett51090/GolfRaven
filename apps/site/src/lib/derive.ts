/**
 * derive.ts — the build-time catalog load + the site-specific derived
 * views over it. Pairs with `packages/catalog/src/load.ts`'s
 * `loadCatalog()` to complete SWC's `src/lib/geo.ts` port (build plan
 * §5.1: "Rewrite | `packages/catalog/src/load.ts` + `apps/site/src/lib/derive.ts`
 * | One `loadCatalog()`").
 *
 * **Demo-data fallback (stage-1 "Build-time data").** The real `data/`
 * directory carries no facility/trail content yet (network-blocked
 * research; `data/README.md`), so this module falls back to the
 * synthetic demo dataset under `apps/site/fixtures/demo-catalog/` when
 * either `GOLFRAVEN_DEMO=1` is set or the real catalog is empty
 * (`isCatalogEmpty`). **The prod build refuses to run with demo data**:
 * `GOLFRAVEN_ENV=production` together with a demo-data fallback is a hard
 * failure, never a silent publish.
 *
 * `VARIETAL_COLOR`'s replacement (§5.1: "`VARIETAL_COLOR` is replaced by
 * `accessColor` plus a designer facet") is map-UI scope (MapLibre
 * clustering, `CourseMap.astro`) — out of scope for stage 1 (this repo's
 * stage-1 "Out of scope" list: "The map (MapLibre)"), so it is not ported
 * here; the map itself lands in stage 2.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  isCatalogEmpty,
  isIndexable,
  loadCatalog,
  loadCatalogFromBundle,
  type Catalog,
  type Facility,
} from "@golfraven/catalog";

const here = fileURLToPath(new URL(".", import.meta.url));

/** The real, git-held catalog root (build plan §3.1 row B: `data/`). */
const REAL_DATA_DIR = fileURLToPath(new URL("../../../../data", import.meta.url));
/** The synthetic demo dataset — see this module's doc. */
const DEMO_BUNDLE_PATH = fileURLToPath(
  new URL("../../fixtures/demo-catalog/bundle.json", import.meta.url),
);

export interface LoadedCatalog {
  catalog: Catalog;
  usedDemoData: boolean;
}

/**
 * Loads the catalog the site should build from. See this module's doc for
 * the demo-fallback and production-refusal rules.
 */
export async function loadSiteCatalog(
  env: NodeJS.ProcessEnv = process.env,
): Promise<LoadedCatalog> {
  const isProduction = env.GOLFRAVEN_ENV === "production";
  const forceDemo = env.GOLFRAVEN_DEMO === "1";

  const real = await loadCatalog({ dataDir: REAL_DATA_DIR });
  const realIsEmpty = isCatalogEmpty(real);
  const useDemo = forceDemo || realIsEmpty;

  if (useDemo && isProduction) {
    const reason = forceDemo
      ? "GOLFRAVEN_DEMO=1 was set"
      : "data/ is empty (no real facility/trail content yet)";
    throw new Error(
      `GOLFRAVEN_ENV=production but the build would fall back to the synthetic ` +
        `demo catalog (${reason}). Refusing to publish demo data — see the ` +
        `build plan §5, stage-1 scope item 3 ("Never publish demo data").`,
    );
  }

  if (!useDemo) return { catalog: real, usedDemoData: false };

  const bundleRaw = JSON.parse(await readFile(DEMO_BUNDLE_PATH, "utf8"));
  return { catalog: loadCatalogFromBundle(bundleRaw), usedDemoData: true };
}

/** Every facility that passes the R1 `isIndexable` predicate — the set a
 * course detail page is generated for (§5.1 `wineries/[slug].astro` →
 * `courses/[slug].astro`: "One page per **verified** facility"), sorted
 * by name for a stable build. */
export function indexableFacilities(catalog: Catalog): Facility[] {
  return [...catalog.facilities]
    .filter((f) => isIndexable(f))
    .sort((a, b) => (a.name ?? a.slug).localeCompare(b.name ?? b.slug));
}

/** Every facility in one region (by `RegionCode`), name-sorted. Powers
 * `[country]/[region]/` (§5.1 `states/*`: "Directory of all entries"). */
export function facilitiesInRegion(catalog: Catalog, regionCode: string): Facility[] {
  return [...catalog.facilities]
    .filter((f) => f.region === regionCode)
    .sort((a, b) => (a.name ?? a.slug).localeCompare(b.name ?? b.slug));
}

export interface RegionInfo {
  code: string;
  /** URL segment, lowercase (`us`, `ca`). */
  country: string;
  /** URL segment (`tn`, `bc`, ...). */
  slug: string;
  name: string;
}

/**
 * Resolves a `RegionCode` (e.g. `"US-TN"`) to the URL/display info
 * `[country]/[region]/` needs. Prefers a real `Region` catalog record
 * (`catalog.regions`) when one exists (it carries the authored `slug` and
 * display `name`); falls back to deriving both mechanically from the code
 * itself (`RegionCodeSchema` guarantees the `<COUNTRY>-<SUBDIVISION>`
 * shape) when `data/regions/` hasn't authored that region yet — the same
 * "don't fail just because `data/` is thin" posture `load.ts` takes.
 */
export function regionInfo(catalog: Catalog, code: string): RegionInfo {
  const authored = catalog.regions.find((r) => r.code === code);
  if (authored) {
    return {
      code,
      country: authored.country.toLowerCase(),
      slug: authored.slug,
      name: authored.name,
    };
  }
  const [country = "", subdivision = ""] = code.split("-");
  return { code, country: country.toLowerCase(), slug: subdivision.toLowerCase(), name: code };
}

/** Every distinct region code present on at least one facility, sorted. */
export function regionCodesInUse(catalog: Catalog): string[] {
  return [...new Set(catalog.facilities.map((f) => f.region))].sort();
}

/** Region directories paginate at 200 (build plan §5.1 `states/*`:
 * "paginated at 200"). Always returns at least one (possibly empty) page,
 * so `page 1` always has somewhere to render even with zero rows. */
export const REGION_PAGE_SIZE = 200;
export function regionPages(catalog: Catalog, regionCode: string): Facility[][] {
  const rows = facilitiesInRegion(catalog, regionCode);
  const pages: Facility[][] = [];
  for (let i = 0; i < rows.length; i += REGION_PAGE_SIZE) {
    pages.push(rows.slice(i, i + REGION_PAGE_SIZE));
  }
  return pages.length > 0 ? pages : [[]];
}

export { here as siteLibDir };
