#!/usr/bin/env node
/**
 * gen-map-data.mjs — build plan §5.1 (`WineryMap.astro` → `CourseMap.astro`):
 * "per-country GeoJSON from the `scripts/gen-map-data.mjs` prebuild"; §5.2:
 * "The map uses per-country GeoJSON, lazy-loaded, with MapLibre
 * `cluster: true` above 1,000 points."
 *
 * Run directly by `node` as part of `apps/site`'s `build` chain (see
 * `package.json`), between `emit-indexability` and `astro build` — plain
 * `node`, no TS loader, same pattern as `emit-indexability.mjs` (whose doc
 * explains why: this can't import `src/lib/derive.ts` directly).
 *
 * Writes one `FeatureCollection` per ISO country present in the catalog
 * (`public/data/map/<country>.geojson`, lowercase — `us.geojson`,
 * `ca.geojson`) so `CourseMap.astro`'s client script fetches only the
 * country shards a given page actually needs, per §5.2's "sharded ...
 * lazy-loaded" rule. Astro copies `public/` into `dist/` verbatim, so
 * writing here (BEFORE `astro build`) is enough — no `dist/`-write dance
 * (unlike SWC's `WineryMap.astro`, which had to write both because it ran
 * ITS generation from inside the Astro build itself, `swc-analysis.md
 * §10.6`; this is a separate prebuild step instead).
 *
 * Every facility with known coordinates is included, verified or not —
 * `properties.indexable` tells the client whether to render a `/courses/`
 * link (matching S2: an unverified facility never gets a page link, only
 * a "help verify" CTA) or plain text. This mirrors `RegionDirectory.astro`'s
 * existing JS-off behaviour exactly, so the map's own JS-free `<ul>`
 * fallback (`CourseMap.astro`) and the region directories never disagree
 * about which facilities are linkable.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  isCatalogEmpty,
  isIndexable,
  loadCatalog,
  loadCatalogFromBundle,
} from "@golfraven/catalog";
import { demoBundleForSite } from "../fixtures/demo-catalog/build-bundle.mjs";
import { isProductionEnv } from "../src/lib/env.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const REAL_DATA_DIR =
  process.env.GOLFRAVEN_DATA_DIR ?? join(here, "..", "..", "..", "data");
const OUT_DIR =
  process.env.MAP_DATA_OUT_DIR ?? join(here, "..", "public", "data", "map");

async function loadSiteCatalog() {
  const isProduction = isProductionEnv(process.env);
  const demoRequested = process.env.GOLFRAVEN_DEMO === "1";

  if (demoRequested) {
    if (isProduction) {
      throw new Error(
        "GOLFRAVEN_ENV=production refuses demo data (GOLFRAVEN_DEMO=1 was set).",
      );
    }
    return {
      catalog: loadCatalogFromBundle(demoBundleForSite()),
      usedDemoData: true,
    };
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

function facilityFeature(facility) {
  const indexable = isIndexable(facility);
  return {
    type: "Feature",
    geometry: { type: "Point", coordinates: [facility.lng, facility.lat] },
    properties: {
      slug: facility.slug,
      name: facility.name ?? null,
      town: facility.town ?? null,
      region: facility.region,
      access: facility.access ?? null,
      verified: facility.verification.status !== "unverified",
      // Only an indexable facility gets a `/courses/` link client-side —
      // same rule `RegionDirectory.astro` and `isIndexable()` already
      // enforce (R1). A verified-but-thin facility still has a real page
      // (S4) so it still links; see `hasPage` below for the exact rule the
      // client mirrors.
      hasPage: facility.verification.status !== "unverified",
      indexable,
    },
  };
}

const { catalog, usedDemoData } = await loadSiteCatalog();

const byCountry = new Map();
for (const facility of catalog.facilities) {
  if (typeof facility.lat !== "number" || typeof facility.lng !== "number")
    continue;
  const country = facility.region.split("-")[0]?.toLowerCase();
  if (!country) continue;
  if (!byCountry.has(country)) byCountry.set(country, []);
  byCountry.get(country).push(facilityFeature(facility));
}

await mkdir(OUT_DIR, { recursive: true });

// A demo build still writes real per-country files from the demo fixture
// (US-TN + CA-BC facilities carry real lat/lng) — B3's noindex/banner
// guard is enforced at the PAGE level (BaseLayout's `demo` prop), not by
// withholding map data, matching how the region/trail pages already
// render demo content freely under the visible banner.
let written = 0;
for (const [country, features] of byCountry) {
  const fc = { type: "FeatureCollection", features };
  await writeFile(join(OUT_DIR, `${country}.geojson`), JSON.stringify(fc));
  written += features.length;
}

console.log(
  `gen-map-data: wrote ${byCountry.size} per-country file(s), ${written} facility point(s) total` +
    (usedDemoData ? " (demo catalog)" : ""),
);
