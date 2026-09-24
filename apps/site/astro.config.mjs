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
// BEFORE `astro build` (see package.json) — a MISSING file here is a real
// bug (the prebuild step didn't run, or wrote to the wrong path), never a
// silent "admit nothing" default (B2, gate review): it throws.
const indexabilityPath =
  process.env.INDEXABILITY_OUT_PATH ??
  fileURLToPath(new URL("./build/indexability.json", import.meta.url));
/** @type {{ indexablePaths: string[] }} */
let indexability;
try {
  indexability = JSON.parse(readFileSync(indexabilityPath, "utf8"));
} catch (err) {
  throw new Error(
    `astro.config.mjs: could not read build/indexability.json (${indexabilityPath}). ` +
      `Run \`node scripts/emit-indexability.mjs\` before \`astro build\` — \`pnpm build\` ` +
      `already does this in order. Original error: ${err instanceof Error ? err.message : String(err)}`,
  );
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
  build: {
    // B1: the site's own CSP is `default-src 'self'` (public/_headers) —
    // no `unsafe-inline` allowance for styles. Astro's default behaviour
    // inlines small per-page stylesheets straight into the HTML
    // (`<style>...</style>`), which that CSP then blocks. Emitting every
    // stylesheet as an external file keeps every page's CSS actually
    // loading under the site's own policy.
    inlineStylesheets: "never",
  },
  integrations: [
    sitemap({
      // AT(1)/B2: the sitemap filter is EXACT set membership against
      // build/indexability.json — not "admit everything except a
      // hard-coded exclude list". indexability.json enumerates every page
      // (hub, trails, region first pages, verified+indexable courses,
      // /fr/) that should be indexed; a demo build writes it EMPTY (every
      // page noindex, B3), which alone makes the sitemap empty too.
      filter: (page) => indexablePaths.has(new URL(page).pathname),
    }),
  ],
});
