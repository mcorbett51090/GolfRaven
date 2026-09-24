# @golfraven/site

Public site (Astro 5 static, build plan §3.1 row C). Ported from
`southern-wine-country` @ `572ff7e` — see the file mapping in the build
plan §5.1.

## Status: P2 stage 1

This is the **stage-1** port: catalog-driven pages (hub, trail, course,
region directory), i18n scaffolding (en/fr), a CSP `_headers` file, and the
sitemap/indexability gate. **Out of stage-1 scope** (see the build plan
§5 and this repo's stage-1 instructions): the MapLibre map, OG cards
(satori/sharp), pagefind search, GolfNow's link checker, the claim/feedback
forms' real submission flow, analytics/GTM, the brand pipeline, blog/learn
content, and the service worker. Each has a `TODO(stage 2, ...)` comment
at its call site citing the plan section it belongs to.

## Data

The site reads the catalog through `@golfraven/catalog`'s `loadCatalog()`
(`src/lib/derive.ts`'s `loadSiteCatalog()`), from the repo's real `data/`
directory. Since `data/` carries no real facility/trail content yet
(`data/README.md`), the build falls back to the **synthetic demo dataset**
under `fixtures/demo-catalog/` — fictional trails and courses, clearly
labelled as such (see that directory's own README). The fallback fires
when `GOLFRAVEN_DEMO=1` is set, or automatically when the real catalog is
empty.

**The fallback is refused outright when `GOLFRAVEN_ENV=production`** — a
production build must be pointed at real `data/` content.

## Scripts

- `pnpm build` — `scripts/emit-indexability.mjs` (writes
  `build/indexability.json`, build plan §5.3) then `astro build`.
- `pnpm typecheck` — `astro check` (real Astro+TS diagnostics across
  `.astro` files and `src/lib/*.ts`).
- `pnpm test` — `vitest run`. A `globalSetup` (`test/global-setup.mjs`)
  builds the site once (demo data forced on) before the acceptance tests
  in `test/acceptance.test.ts` read `dist/`.
