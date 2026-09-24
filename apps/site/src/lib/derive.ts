/**
 * derive.ts — the build-time catalog load + the site-specific derived
 * views over it. Pairs with `packages/catalog/src/load.ts`'s
 * `loadCatalog()` to complete SWC's `src/lib/geo.ts` port (build plan
 * §5.1: "Rewrite | `packages/catalog/src/load.ts` + `apps/site/src/lib/derive.ts`
 * | One `loadCatalog()`").
 *
 * **Fail-closed demo guard (B3, gate review).**
 * - Demo data is used ONLY when `GOLFRAVEN_DEMO=1` is set explicitly —
 *   never as a silent fallback on an empty `data/`.
 * - An empty `data/` WITHOUT `GOLFRAVEN_DEMO=1` is a hard build failure,
 *   with a clear message (never a silent empty site).
 * - `GOLFRAVEN_ENV=production` refuses demo data outright, whatever
 *   `GOLFRAVEN_DEMO` says.
 * - Every page must know `usedDemoData` (`LoadedCatalog.usedDemoData`) and
 *   force `noindex` + a visible "DEMO DATA" banner (`BaseLayout`'s `demo`
 *   prop) — enforced at the page level, not here; this module only reports
 *   the flag honestly.
 *
 * `VARIETAL_COLOR`'s replacement (§5.1: "`VARIETAL_COLOR` is replaced by
 * `accessColor` plus a designer facet") is map-UI scope, out of stage-1
 * scope — not ported here; the map lands in stage 2.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import {
  isCatalogEmpty,
  isIndexable,
  isVerified,
  loadCatalog,
  loadCatalogFromBundle,
  type Catalog,
  type Facility,
  type TrailId,
} from "@golfraven/catalog";
import { demoBundleForSite } from "../../fixtures/demo-catalog/build-bundle.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));

/** The real, git-held catalog root (build plan §3.1 row B: `data/`).
 * Overridable via `GOLFRAVEN_DATA_DIR` — used by the test suite to point
 * at a temporary, populated `data/`-shaped directory without touching the
 * real (deliberately empty) committed one. */
function realDataDir(env: NodeJS.ProcessEnv): string {
  return env.GOLFRAVEN_DATA_DIR ?? fileURLToPath(new URL("../../../../data", import.meta.url));
}
/** `data/overrides/primary-trail.json` — read here (the site), never in
 * `packages/catalog` ("Never does: Hold data or fetch", §3.1 row A). */
const PRIMARY_TRAIL_OVERRIDE_PATH = fileURLToPath(
  new URL("../../../../data/overrides/primary-trail.json", import.meta.url),
);

export interface LoadedCatalog {
  catalog: Catalog;
  usedDemoData: boolean;
}

function loadDemoCatalog(): Catalog {
  return loadCatalogFromBundle(demoBundleForSite());
}

/**
 * Loads the catalog the site should build from. See this module's doc for
 * the fail-closed demo-fallback rules (B3).
 */
export async function loadSiteCatalog(
  env: NodeJS.ProcessEnv = process.env,
): Promise<LoadedCatalog> {
  const isProduction = env.GOLFRAVEN_ENV === "production";
  const demoRequested = env.GOLFRAVEN_DEMO === "1";

  if (demoRequested) {
    if (isProduction) {
      throw new Error(
        "GOLFRAVEN_ENV=production refuses demo data: GOLFRAVEN_DEMO=1 was set, but a " +
          "production build must be pointed at real data/ content, never the synthetic " +
          "demo dataset (build plan §5, stage-1 'Never publish demo data').",
      );
    }
    return { catalog: loadDemoCatalog(), usedDemoData: true };
  }

  const real = await loadCatalog({ dataDir: realDataDir(env) });
  if (isCatalogEmpty(real)) {
    throw new Error(
      "data/ has no facility/trail content and GOLFRAVEN_DEMO was not set to \"1\". " +
        "Set GOLFRAVEN_DEMO=1 to build with the synthetic demo dataset (fixtures/demo-catalog/), " +
        "or add real content to data/ before building.",
    );
  }
  return { catalog: real, usedDemoData: false };
}

/** `data/overrides/primary-trail.json` — `{ [facilityId]: trailId }`,
 * "gated to real members" (§4.3) by `primaryTrailOf` itself. Read here,
 * not in `packages/catalog`. Missing file (the common case today — this
 * override list starts empty) reads as no overrides, never an error. */
export async function loadPrimaryTrailOverrides(): Promise<Map<Facility["id"], TrailId>> {
  try {
    const raw = JSON.parse(await readFile(PRIMARY_TRAIL_OVERRIDE_PATH, "utf8")) as Record<
      string,
      string
    >;
    return new Map(Object.entries(raw)) as Map<Facility["id"], TrailId>;
  } catch (err) {
    if ((err as NodeJS.ErrnoException)?.code === "ENOENT") return new Map();
    throw err;
  }
}

/** Every facility that passes the R1 `isIndexable` predicate — the set a
 * course detail page is INDEXED for. Sorted by name for a stable build. */
export function indexableFacilities(catalog: Catalog): Facility[] {
  return [...catalog.facilities]
    .filter((f) => isIndexable(f))
    .sort((a, b) => (a.name ?? a.slug).localeCompare(b.name ?? b.slug));
}

/** Every VERIFIED facility — S4: "Every verified facility gets a page,
 * and R1 decides `noindex` for thin ones." This is the `getStaticPaths`
 * set for `courses/[slug]`; `indexableFacilities` above decides which of
 * those pages are indexed, not which exist. */
export function verifiedFacilities(catalog: Catalog): Facility[] {
  return [...catalog.facilities]
    .filter((f) => isVerified(f))
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
 * (`catalog.regions`) when one exists. When one does NOT exist, this
 * mechanically derives country/slug from the code itself (`RegionCodeSchema`
 * guarantees the `<COUNTRY>-<SUBDIVISION>` shape) — **but only outside
 * production** (gate review: "Production refuses the region-name
 * fallback: it requires Region records"). A production build with a
 * facility in a region that has no authored `Region` record is a build
 * error, not a silently-derived display name.
 */
export function regionInfo(
  catalog: Catalog,
  code: string,
  env: NodeJS.ProcessEnv = process.env,
): RegionInfo {
  const authored = catalog.regions.find((r) => r.code === code);
  if (authored) {
    return {
      code,
      country: authored.country.toLowerCase(),
      slug: authored.slug,
      name: authored.name,
    };
  }
  if (env.GOLFRAVEN_ENV === "production") {
    throw new Error(
      `Region "${code}" has no authored Region record (data/regions/) and ` +
        `GOLFRAVEN_ENV=production refuses the derived-name fallback — add a Region ` +
        `record for it before publishing.`,
    );
  }
  const [country = "", subdivision = ""] = code.split("-");
  return { code, country: country.toLowerCase(), slug: subdivision.toLowerCase(), name: code };
}

/** Every distinct region code present on at least one facility, sorted. */
export function regionCodesInUse(catalog: Catalog): string[] {
  return [...new Set(catalog.facilities.map((f) => f.region))].sort();
}

/** Region directories paginate at 200 by default (build plan §5.1
 * `states/*`: "paginated at 200"). Overridable via `REGION_PAGE_SIZE`
 * (B2: "Run [AT1] with REGION_PAGE_SIZE=1 too, to exercise pagination"). */
export function regionPageSize(env: NodeJS.ProcessEnv = process.env): number {
  const n = Number(env.REGION_PAGE_SIZE);
  return Number.isInteger(n) && n > 0 ? n : 200;
}

/** Always returns at least one (possibly empty) page, so page 1 always has
 * somewhere to render even with zero rows. */
export function regionPages(
  catalog: Catalog,
  regionCode: string,
  pageSize: number = regionPageSize(),
): Facility[][] {
  const rows = facilitiesInRegion(catalog, regionCode);
  const pages: Facility[][] = [];
  for (let i = 0; i < rows.length; i += pageSize) {
    pages.push(rows.slice(i, i + pageSize));
  }
  return pages.length > 0 ? pages : [[]];
}

export { here as siteLibDir };
