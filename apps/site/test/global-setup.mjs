/**
 * vitest globalSetup — produces the THREE builds `test/paths.mjs`
 * documents (real / demo / paginated), each by running the exact chain
 * `package.json`'s `build` script runs (verify-input -> emit-indexability
 * -> astro build -> verify-sitemap), so the test dist trees are built the
 * same way a real build would be, just against different inputs/outDirs.
 *
 * Creates a fresh `mkdtemp()` base FIRST (`tmp-base.mjs`'s
 * `createTmpBase()`) and only THEN imports `paths.mjs` (dynamically, so
 * the ordering is explicit) — `paths.mjs`'s own top-level `await` reads
 * the path this just created.
 */
import { execFileSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createTmpBase } from "./tmp-base.mjs";
import { writeFixtureDataDir } from "./write-fixture-data-dir.mjs";

const siteRoot = fileURLToPath(new URL("..", import.meta.url));

function runBuild(name, { dist, indexability, env: extraEnv }) {
  // Drop any stale GOLFRAVEN_ENV=production / GOLFRAVEN_DEMO /
  // GOLFRAVEN_DATA_DIR / REGION_PAGE_SIZE the caller's shell might carry —
  // each build's own `extraEnv` is authoritative.
  const {
    GOLFRAVEN_ENV: _e,
    GOLFRAVEN_DEMO: _d,
    GOLFRAVEN_DATA_DIR: _g,
    REGION_PAGE_SIZE: _r,
    ...restEnv
  } = process.env;
  const env = {
    ...restEnv,
    ASTRO_TELEMETRY_DISABLED: "1",
    INDEXABILITY_OUT_PATH: indexability,
    // gen-map-data writes to its DEFAULT location
    // (`apps/site/public/data/map/`, gitignored — see .gitignore) rather
    // than an override: Astro's `public/` copy only ever copies from the
    // REAL `public/` directory (there is no per-build `publicDir` swap
    // any more — see astro.config.mjs's history), so the generated
    // per-country GeoJSON has to actually land there for `/data/map/*`
    // to resolve in each build's own `dist/`. Harmless to share across
    // the three sequential test builds below: each one's own
    // `gen-map-data` step re-generates it immediately before that
    // build's `astro build` call, and it is never a tracked file.
    //
    // gen-headers/gen-redirects now run POSTBUILD, straight into `dist`
    // (see both scripts' own docs — Opus gate nit: never rewrite a
    // tracked `public/` file), so no output-path override is needed for
    // either; `DIST_DIR` below already makes each build's postbuild step
    // write into ITS OWN dist.
    DIST_DIR: dist,
    GOLFRAVEN_BUILD_STARTED_MS: String(Date.now()),
    ...extraEnv,
  };
  const run = (cmd, args) => execFileSync(cmd, args, { cwd: siteRoot, stdio: "inherit", env });

  console.log(`\n--- test build "${name}" -> ${dist} ---`);
  run("node", ["./scripts/verify-input.mjs"]);
  run("node", ["./scripts/emit-indexability.mjs"]);
  run("node", ["./scripts/gen-map-data.mjs"]);
  run("./node_modules/.bin/astro", ["build", "--outDir", dist]);
  run("node", ["./scripts/gen-headers.mjs", dist]);
  run("node", ["./scripts/gen-redirects.mjs", dist]);
  run("node", ["./scripts/gen-sw.mjs", dist]);
  run("node", ["./scripts/pagefind-index.mjs", dist]);
  run("node", ["./scripts/verify-sitemap.mjs", dist]);
  run("node", ["./scripts/verify-budget.mjs", dist]);
  run("node", ["./scripts/verify-a11y-budget.mjs", dist]);
}

export default async function setup() {
  const tmpBase = await createTmpBase();
  const fixtureDataDir = join(tmpBase, "data");
  await mkdir(fixtureDataDir, { recursive: true });
  await writeFixtureDataDir(fixtureDataDir);

  const { BUILDS } = await import("./paths.mjs");

  runBuild("real", BUILDS.real);
  runBuild("demo", BUILDS.demo);
  runBuild("paginated", BUILDS.paginated);
  runBuild("configured", BUILDS.configured);

  // Teardown: vitest calls the function a globalSetup default-exports.
  return async () => {
    await rm(tmpBase, { recursive: true, force: true });
  };
}
