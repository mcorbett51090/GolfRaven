/**
 * vitest globalSetup — builds the site ONCE (with the synthetic demo
 * catalog forced on, `GOLFRAVEN_DEMO=1`) before any AT(*) test file reads
 * `dist/`. Building once here, rather than per-test-file, keeps the
 * (real) `astro build` cost paid a single time.
 */
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const siteRoot = fileURLToPath(new URL("..", import.meta.url));

export default async function setup() {
  // Delete any stale GOLFRAVEN_ENV=production the caller's shell might
  // carry — these AT(*) tests build with the demo dataset on purpose, and
  // `loadSiteCatalog()` refuses that combination outright (by design).
  const { GOLFRAVEN_ENV: _dropped, ...restEnv } = process.env;
  const env = { ...restEnv, GOLFRAVEN_DEMO: "1" };

  execFileSync("node", ["./scripts/emit-indexability.mjs"], {
    cwd: siteRoot,
    stdio: "inherit",
    env,
  });
  execFileSync("./node_modules/.bin/astro", ["build"], {
    cwd: siteRoot,
    stdio: "inherit",
    env,
  });
}
