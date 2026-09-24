#!/usr/bin/env node
/**
 * verify-input.mjs — B4 (gate review): "Run verify-catalog over the
 * site's input as a prebuild step, so a failure stops the build." Runs
 * `@golfraven/catalog-tools`' `verifyCatalogRaw` (the same P1 gate `data/`
 * PRs are held to) against exactly the catalog the site is about to
 * build from — the real `data/` tree, or the synthetic demo bundle when
 * `GOLFRAVEN_DEMO=1` (this ALSO exercises B4's "make the demo bundle pass
 * verify-catalog" requirement on every build, not just once by hand).
 *
 * Runs before `emit-indexability`/`astro build` in `package.json`'s
 * `build` script — a non-zero exit here stops the chain (`&&`).
 */
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { isCatalogEmpty, loadCatalog, loadCatalogFromBundle } from "@golfraven/catalog";
import { verifyCatalogRaw } from "@golfraven/catalog-tools";
import { demoBundleForSite, demoBundleForVerify } from "../fixtures/demo-catalog/build-bundle.mjs";

const here = dirname(fileURLToPath(import.meta.url));
// Overridable via GOLFRAVEN_DATA_DIR — see derive.ts's realDataDir() doc.
const REAL_DATA_DIR = process.env.GOLFRAVEN_DATA_DIR ?? join(here, "..", "..", "..", "data");
const BOOKING_HOSTS_PATH = join(here, "..", "..", "..", "config", "booking-hosts.json");

async function loadSiteCatalog() {
  const isProduction = process.env.GOLFRAVEN_ENV === "production";
  const demoRequested = process.env.GOLFRAVEN_DEMO === "1";

  if (demoRequested) {
    if (isProduction) {
      throw new Error("GOLFRAVEN_ENV=production refuses demo data (GOLFRAVEN_DEMO=1 was set).");
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

const bookingHostsRaw = JSON.parse(await readFile(BOOKING_HOSTS_PATH, "utf8"));
const bookingHostAllowList = bookingHostsRaw.hosts ?? [];

// tools/catalog's CatalogBundleSchema has no `regions` field (site-only) —
// everything else carries straight over.
const bundleForVerify = usedDemoData
  ? demoBundleForVerify()
  : {
      contractVersion: 0,
      facilities: catalog.facilities,
      trails: catalog.trails,
      designers: catalog.designers,
      achievements: catalog.achievements,
      idLedger: catalog.idLedger,
    };

const result = verifyCatalogRaw(bundleForVerify, { bookingHostAllowList });

if (result.ok) {
  console.log(
    `verify-input: PASS (${usedDemoData ? "demo" : "real"} catalog: ` +
      `${catalog.facilities.length} facilities, ${catalog.trails.length} trails)`,
  );
} else {
  console.error(
    `verify-input: FAIL — ${result.issues.length} issue(s) in the ` +
      `${usedDemoData ? "demo" : "real"} catalog:`,
  );
  for (const issue of result.issues) {
    console.error(`  [${issue.code}] ${issue.path}: ${issue.message}`);
  }
  process.exit(1);
}
