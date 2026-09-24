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
import { cp, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createTmpBase } from "./tmp-base.mjs";
import { writeFixtureDataDir } from "./write-fixture-data-dir.mjs";

const siteRoot = fileURLToPath(new URL("..", import.meta.url));

async function runBuild(name, { dist, indexability, publicDir, env: extraEnv }) {
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

  // A per-build COPY of the real public/ (icons, manifest, sw.js, the
  // committed _headers/_redirects) that this build's own generated files
  // (gen-map-data/gen-headers/gen-redirects) write INTO — never the real,
  // committed apps/site/public/ (discovered this session: without this,
  // running the test suite left whichever of the three scenarios ran LAST
  // sitting in the real committed `_redirects`, `_headers` and
  // `public/data/map/*.geojson`, corrupting them for anyone building for
  // real afterwards). `astro.config.mjs`'s `publicDir` reads
  // `GOLFRAVEN_PUBLIC_DIR` for exactly this override.
  await mkdir(publicDir, { recursive: true });
  await cp(join(siteRoot, "public"), publicDir, { recursive: true });

  const env = {
    ...restEnv,
    ASTRO_TELEMETRY_DISABLED: "1",
    INDEXABILITY_OUT_PATH: indexability,
    GOLFRAVEN_PUBLIC_DIR: publicDir,
    MAP_DATA_OUT_DIR: join(publicDir, "data", "map"),
    HEADERS_OUT_PATH: join(publicDir, "_headers"),
    REDIRECTS_OUT_PATH: join(publicDir, "_redirects"),
    ...extraEnv,
  };
  const run = (cmd, args) => execFileSync(cmd, args, { cwd: siteRoot, stdio: "inherit", env });

  console.log(`\n--- test build "${name}" -> ${dist} ---`);
  run("node", ["./scripts/verify-input.mjs"]);
  run("node", ["./scripts/emit-indexability.mjs"]);
  run("node", ["./scripts/gen-map-data.mjs"]);
  run("node", ["./scripts/gen-headers.mjs"]);
  run("node", ["./scripts/gen-redirects.mjs"]);
  run("./node_modules/.bin/astro", ["build", "--outDir", dist]);
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

  await runBuild("real", { ...BUILDS.real, publicDir: join(tmpBase, "public-real") });
  await runBuild("demo", { ...BUILDS.demo, publicDir: join(tmpBase, "public-demo") });
  await runBuild("paginated", { ...BUILDS.paginated, publicDir: join(tmpBase, "public-paginated") });

  // Teardown: vitest calls the function a globalSetup default-exports.
  return async () => {
    await rm(tmpBase, { recursive: true, force: true });
  };
}
