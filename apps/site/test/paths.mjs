/**
 * Shared build-output locations for the test suite, imported by both
 * `global-setup.mjs` (which produces them) and the `*.test.ts` files
 * (which read them). `TMP_BASE` is a fresh `mkdtemp()` directory per test
 * run (see `tmp-base.mjs`'s doc for how that path crosses the
 * globalSetup/test-file process boundary) — never a fixed, shared `/tmp`
 * path.
 *
 * Three separate builds, because B2/B3 need genuinely different catalog
 * inputs that can't share one `dist/`:
 *   - `real`      — a temporary, POPULATED `data/`-shaped directory (the
 *                    demo fixture's own content, written as real `data/`
 *                    files) with NO `GOLFRAVEN_DEMO` set, so the site
 *                    takes the real-data code path: indexability, the
 *                    sitemap and per-page `noindex` all behave exactly as
 *                    a real launch would (AT1/AT3/AT6/AT7/AT10/AT13, S1/S2).
 *   - `demo`      — `GOLFRAVEN_DEMO=1`, the actual demo-fallback path
 *                    (B3): every page noindex, empty sitemap, banner shown.
 *   - `paginated` — the SAME real fixture data, with `REGION_PAGE_SIZE=1`
 *                    (B2: "Run [AT1] with REGION_PAGE_SIZE=1 too").
 */
import { join } from "node:path";
import { readTmpBase } from "./tmp-base.mjs";

// Top-level await: resolved once, at import time. `global-setup.mjs` MUST
// have called `createTmpBase()` (and only then imported this module, or a
// module that imports it) before any test file's import of this module
// runs — see `tmp-base.mjs`'s doc.
export const TMP_BASE = await readTmpBase();
export const FIXTURE_DATA_DIR = join(TMP_BASE, "data");

export const BUILDS = {
  real: {
    dist: join(TMP_BASE, "dist-real"),
    indexability: join(TMP_BASE, "indexability-real.json"),
    env: { GOLFRAVEN_DATA_DIR: FIXTURE_DATA_DIR },
  },
  demo: {
    dist: join(TMP_BASE, "dist-demo"),
    indexability: join(TMP_BASE, "indexability-demo.json"),
    env: { GOLFRAVEN_DEMO: "1" },
  },
  paginated: {
    dist: join(TMP_BASE, "dist-paginated"),
    indexability: join(TMP_BASE, "indexability-paginated.json"),
    env: { GOLFRAVEN_DATA_DIR: FIXTURE_DATA_DIR, REGION_PAGE_SIZE: "1" },
  },
};
