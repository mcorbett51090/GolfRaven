/**
 * Shared build-output locations for the test suite, imported by both
 * `global-setup.mjs` (which produces them) and the `*.test.ts` files
 * (which read them). A FIXED path under the OS temp dir (not `mkdtemp`)
 * so both sides can compute it independently with no manifest file.
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
import { tmpdir } from "node:os";
import { join } from "node:path";

export const TMP_BASE = join(tmpdir(), "golfraven-site-tests");
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
