#!/usr/bin/env node
/**
 * run-e2e.mjs — wires the Playwright runtime-CSP test
 * (`test/e2e/map-csp-check.mjs`) into `@golfraven/site`'s `test` script
 * (Opus gate B2: "...wire it into `@golfraven/site`'s test script. If
 * Chromium can't launch in CI, gate it behind an env var and say so.").
 *
 * **Re-gate correction: a launch failure is no longer a silent skip IN
 * CI.** `.github/workflows/ci.yml` now installs the pinned Chromium
 * (`pnpm exec playwright install --with-deps chromium`, that job only) —
 * so a launch failure there is a REAL regression (a broken install, a
 * pin drift against the runner image), not an expected environment gap,
 * and stays a hard failure (`process.exitCode = 1`) unless explicitly
 * silenced. Outside CI (this repo's own sandboxed sessions, a
 * contributor's machine with no browser installed) the launch-probe skip
 * stays graceful — the environment gap there is real and not this
 * script's job to fix.
 *
 * Two independent gates:
 *
 *   1. `GOLFRAVEN_E2E_SKIP=1` — an explicit opt-out, honoured EVERYWHERE
 *      (including `CI=true`) — for a host known in advance not to
 *      support launching a browser, deliberately overriding the "CI must
 *      have Chromium" expectation above.
 *   2. An ACTUAL launch probe — if `chromium.launch()` throws: outside CI
 *      this is caught and reported plainly, exit 0 (an environment gap
 *      this repo does not control); under `CI=true` (unset by
 *      `GOLFRAVEN_E2E_SKIP`) the SAME failure is fatal, because CI is now
 *      expected to have installed the matching browser itself.
 *
 * Confirmed THIS session (not assumed): `@playwright/test@1.56.1`
 * launches Chromium successfully from `PLAYWRIGHT_BROWSERS_PATH=
 * /opt/pw-browsers` with no `playwright install` in THIS sandbox — that
 * pin (chromium revision 1194) was chosen specifically to match what's
 * already there. CI installs the SAME pinned version via `playwright
 * install`, which downloads whichever revision `@playwright/test@1.56.1`
 * itself declares, so the two stay in lockstep without hard-coding a
 * revision number in the workflow.
 */
import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { serveDistWithHeaders } from "../test/e2e/serve-with-headers.mjs";
import {
  runMapCspTest,
  checkSearch,
  FAKE_STYLE_URL,
} from "../test/e2e/map-csp-check.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const siteRoot = join(here, "..");

async function main() {
  if (process.env.GOLFRAVEN_E2E_SKIP === "1") {
    console.log(
      "run-e2e: GOLFRAVEN_E2E_SKIP=1 — skipping the runtime CSP e2e test.",
    );
    return;
  }

  const inCi = process.env.CI === "true" || process.env.CI === "1";

  let browser;
  try {
    browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  } catch (err) {
    const reason =
      err instanceof Error ? err.message.split("\n")[0] : String(err);
    if (inCi) {
      // CI now installs the pinned Chromium itself (.github/workflows/ci.yml)
      // — a launch failure here is a real regression, not an expected gap.
      console.error(
        `run-e2e: Chromium could not be launched (${reason}) — this is CI (CI=true), which now ` +
          "installs the pinned browser itself, so this is a FAILURE, not a skip. Set " +
          "GOLFRAVEN_E2E_SKIP=1 to deliberately opt this CI run out instead.",
      );
      process.exitCode = 1;
      return;
    }
    console.log(
      `run-e2e: Chromium could not be launched in this environment (${reason}) — skipping the ` +
        "runtime CSP e2e test rather than failing the build over it. Set GOLFRAVEN_E2E_SKIP=1 to " +
        "silence this message explicitly once the environment is known not to support it.",
    );
    return;
  }

  const scratch = await mkdtemp(join(tmpdir(), "golfraven-e2e-"));
  const dist = join(scratch, "dist");
  try {
    console.log("run-e2e: building the demo site with a stubbed tile host...");
    execFileSync("node", ["./scripts/verify-input.mjs"], {
      cwd: siteRoot,
      stdio: "inherit",
      env: { ...process.env, GOLFRAVEN_DEMO: "1" },
    });
    execFileSync("node", ["./scripts/emit-indexability.mjs"], {
      cwd: siteRoot,
      stdio: "inherit",
      env: { ...process.env, GOLFRAVEN_DEMO: "1" },
    });
    const buildEnv = {
      ...process.env,
      GOLFRAVEN_DEMO: "1",
      ASTRO_TELEMETRY_DISABLED: "1",
      GOLFRAVEN_TILE_STYLE_URL: FAKE_STYLE_URL,
      // gen-map-data writes to its default location
      // (apps/site/public/data/map/, gitignored) — see global-setup.mjs's
      // matching note; Astro's `public/` copy only ever reads the real
      // `public/` directory.
    };
    execFileSync("node", ["./scripts/gen-map-data.mjs"], {
      cwd: siteRoot,
      stdio: "inherit",
      env: buildEnv,
    });
    execFileSync("./node_modules/.bin/astro", ["build", "--outDir", dist], {
      cwd: siteRoot,
      stdio: "inherit",
      env: buildEnv,
    });
    execFileSync("node", ["./scripts/gen-headers.mjs", dist], {
      cwd: siteRoot,
      stdio: "inherit",
      env: buildEnv,
    });
    // Search runs against Pagefind's own generated index — build it here
    // too, or /pagefind/pagefind.js (and the WASM shards it loads) simply
    // wouldn't exist for checkSearch() to exercise below.
    execFileSync("node", ["./scripts/pagefind-index.mjs", dist], {
      cwd: siteRoot,
      stdio: "inherit",
      env: buildEnv,
    });

    const port = 4500 + Math.floor(Math.random() * 1000);
    const server = await serveDistWithHeaders(dist, port);
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
      // The demo fixture's own known routes (apps/site/fixtures/demo-catalog) —
      // a real page of each kind AT(2)/B2 both name.
      await runMapCspTest(browser, baseUrl, {
        hub: "/",
        trail: "/trails/fictional-ridge-golf-trail/",
        course: "/courses/ridge-overlook-golf-club/",
      });
      // Re-gate: "Add an e2e search assertion: type a query, and expect
      // results under the CSP with zero violations." "Ridge" matches the
      // demo fixture's own facility ("Ridge Overlook Golf Club") and
      // trail ("Fictional Ridge Golf Trail") names.
      await checkSearch(browser, baseUrl, "/", "Ridge");
    } finally {
      server.close();
    }
  } finally {
    await browser.close();
    await rm(scratch, { recursive: true, force: true });
  }
}

await main();
