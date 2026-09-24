/**
 * vitest globalSetup — produces the THREE builds `test/paths.mjs`
 * documents (real / demo / paginated), each by running the exact chain
 * `package.json`'s `build` script runs (verify-input -> emit-indexability
 * -> astro build -> verify-sitemap), so the test dist trees are built the
 * same way a real build would be, just against different inputs/outDirs.
 */
import { execFileSync } from "node:child_process";
import { mkdir, rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { BUILDS, TMP_BASE, FIXTURE_DATA_DIR } from "./paths.mjs";
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
    ...extraEnv,
  };
  const run = (cmd, args) => execFileSync(cmd, args, { cwd: siteRoot, stdio: "inherit", env });

  console.log(`\n--- test build "${name}" -> ${dist} ---`);
  run("node", ["./scripts/verify-input.mjs"]);
  run("node", ["./scripts/emit-indexability.mjs"]);
  run("./node_modules/.bin/astro", ["build", "--outDir", dist]);
  run("node", ["./scripts/verify-sitemap.mjs", dist]);
}

export default async function setup() {
  await rm(TMP_BASE, { recursive: true, force: true });
  await mkdir(FIXTURE_DATA_DIR, { recursive: true });
  await writeFixtureDataDir(FIXTURE_DATA_DIR);

  runBuild("real", BUILDS.real);
  runBuild("demo", BUILDS.demo);
  runBuild("paginated", BUILDS.paginated);
}
