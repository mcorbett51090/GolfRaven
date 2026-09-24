# @golfraven/site

Public site (Astro 5 static, build plan §3.1 row C). Ported from
`southern-wine-country` @ `572ff7e` — see the file mapping in the build
plan §5.1.

## Status: P2 stage 1

This is the **stage-1** port: catalog-driven pages (hub, trail, course,
region directory), i18n scaffolding (en/fr), a CSP `_headers` file
(`default-src 'self'`, with no inline `<style>`/`<script>` anywhere in the
build — `astro.config.mjs`'s `inlineStylesheets: "never"`), and the
sitemap/indexability gate. **Out of stage-1 scope** (see the build plan
§5 and this repo's stage-1 instructions): the MapLibre map, OG cards
(satori/sharp), pagefind search, GolfNow's link checker, the claim/feedback
forms' real submission flow, analytics/GTM, the brand pipeline, blog/learn
content, and the service worker. Each has a `TODO(stage 2, ...)` comment
at its call site citing the plan section it belongs to.

## Data — fail-closed demo guard

The site reads the catalog through `@golfraven/catalog`'s `loadCatalog()`
(`src/lib/derive.ts`'s `loadSiteCatalog()`), from the repo's real `data/`
directory. Since `data/` carries no real facility/trail content yet
(`data/README.md`), a build must opt into the **synthetic demo dataset**
(`fixtures/demo-catalog/` — fictional trails and courses, clearly labelled
as such) **explicitly**, with `GOLFRAVEN_DEMO=1`:

- **No `GOLFRAVEN_DEMO` + empty `data/` → the build fails outright**, with
  a clear message. It never silently falls back to demo content.
- **`GOLFRAVEN_DEMO=1` → every page is `noindex`, the sitemap is empty, and
  every page shows a visible "DEMO DATA" banner.** This is enforced twice:
  `scripts/emit-indexability.mjs` writes an empty indexable set (which
  alone empties the sitemap), and every page also passes `demo={true}` to
  `BaseLayout`.
- **`GOLFRAVEN_ENV=production` refuses `GOLFRAVEN_DEMO=1` outright** — a
  production build must be pointed at real `data/` content.

CI sets `GOLFRAVEN_DEMO=1` explicitly (`.github/workflows/ci.yml`), since
this repo's own `data/` is empty today.

## Scripts

`pnpm build` runs, in order: `verify-input` (runs
`@golfraven/catalog-tools`' `verifyCatalogRaw` over exactly the catalog
about to be built, real or demo — a failing gate stops the build)
→ `emit-indexability` (writes `build/indexability.json`, the FULL
indexable page set — hub, trails, region first pages, `/fr/`, and every
verified-AND-R1-indexable course; build plan §5.3) → `astro build` (reads
that file for the sitemap filter — a missing file is a hard error, not a
silent empty set) → `verify-sitemap` (§5.3: asserts the sitemap `<loc>`
set equals the set of built pages without `noindex`).

`pnpm typecheck` runs `astro check` (real Astro+TS diagnostics across
`.astro` files and `src/lib/*.ts`).

`pnpm test` runs `vitest run`. `test/global-setup.mjs` produces THREE
builds before any test runs (see `test/paths.mjs`'s doc for why one isn't
enough): a "real" build (a temporary, populated `data/`-shaped directory,
via `GOLFRAVEN_DATA_DIR`, so indexability/noindex behave exactly as a real
launch would), a "demo" build (`GOLFRAVEN_DEMO=1`, exercising the
fail-closed banner/noindex/empty-sitemap behavior), and a "paginated"
build (the real fixture data with `REGION_PAGE_SIZE=1`, exercising region
pagination). `test/acceptance.test.ts` asserts against all three.
