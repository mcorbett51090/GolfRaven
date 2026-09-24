// @ts-check
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

// Static, host-agnostic build (build plan §3.1 row C: "Cloudflare Pages").
// Adapted from southern-wine-country's astro.config.mjs @ 572ff7e (build
// plan §5.1: "New SITE; i18n en + fr (prefixDefaultLocale: false). The
// sitemap filter reads build/indexability.json").
//
// The real domain (golfraven.<tld>) is registered in P0 (build plan §10
// P2 pre-build gates); this placeholder keeps the build runnable before
// that. Swap SITE when the domain is live — every internal link already
// routes through withBase() (src/lib/nav.ts) so this is the only knob.
const SITE = "https://www.golfraven.example";
const BASE = "/";

// §5.3: "prebuild runs scripts/emit-indexability.mjs, which uses the SAME
// loadCatalog() + isIndexable() as the pages and writes
// build/indexability.json. The sitemap filter and the page `noindex` prop
// both read that file." apps/site's own `build` script runs the emitter
// BEFORE `astro build` (see package.json), so this file already exists by
// the time the sitemap integration's filter runs.
const indexabilityPath = fileURLToPath(
  new URL("./build/indexability.json", import.meta.url),
);
/** @type {{ indexablePaths: string[] }} */
let indexability = { indexablePaths: [] };
try {
  indexability = JSON.parse(readFileSync(indexabilityPath, "utf8"));
} catch {
  // Not written yet (e.g. `astro check`/`astro sync` run standalone,
  // outside the `build` script's emit-then-build sequence). An empty set
  // just means the sitemap filter admits nothing extra — never a crash.
}
const indexablePaths = new Set(indexability.indexablePaths);

export default defineConfig({
  site: SITE,
  base: BASE,
  trailingSlash: "always",
  i18n: {
    locales: ["en", "fr"],
    defaultLocale: "en",
    routing: {
      prefixDefaultLocale: false,
    },
  },
  integrations: [
    sitemap({
      // AT(1): "Sitemap <loc> set = indexable set." Utility/noindex pages
      // (claim, 404) are never in the sitemap; a course page is in it only
      // when the R1 predicate (packages/catalog's isIndexable) says so —
      // the identical predicate build/indexability.json was built from
      // (§5.3), never a second, independently-drifting formula.
      filter: (page) => {
        const path = new URL(page).pathname;
        if (path.endsWith("/claim/") || path.includes("/404")) return false;
        if (path.startsWith("/courses/")) return indexablePaths.has(path);
        return true;
      },
    }),
  ],
});
