/**
 * map-csp-check.mjs — the Opus gate B2 blocking requirement: "Add a
 * Playwright runtime CSP test: serve the built site with the generated
 * `_headers` CSP, boot the map with a stubbed tile host, and assert zero
 * `securitypolicyviolation` events on the hub, a trail page and a course
 * page."
 *
 * A plain script (not the `@playwright/test` test-runner CLI) driven by
 * `scripts/run-e2e.mjs`, which decides whether Chromium can even launch
 * in this environment BEFORE calling in here (see that script's doc) —
 * this file assumes a launchable browser and just runs the checks.
 *
 * For each page: an `addInitScript` installs a
 * `securitypolicyviolation` listener BEFORE navigation (so nothing fired
 * during the initial HTML parse is missed), the browser intercepts the
 * fake tile host and returns a minimal-but-valid MapLibre style (no real
 * network egress — this environment's own proxy blocks most external
 * hosts anyway, and a stub keeps the test hermetic), the map section is
 * scrolled into view to trigger its lazy `IntersectionObserver` boot, and
 * the test waits for either a real MapLibre canvas to appear or a bounded
 * timeout — proving the map ACTUALLY booted (so a zero-violation result
 * can't be a false pass from the map silently failing to load at all).
 */
import assert from "node:assert/strict";

const FAKE_TILE_HOST = "tiles.test";
const FAKE_STYLE_URL = `https://${FAKE_TILE_HOST}/style.json`;
const MINIMAL_STYLE = { version: 8, sources: {}, layers: [] };

/**
 * @param {import('@playwright/test').Browser} browser
 * @param {string} baseUrl
 * @param {string} path
 */
async function checkPage(browser, baseUrl, path) {
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.addInitScript(() => {
    window.__cspViolations = [];
    window.addEventListener("securitypolicyviolation", (ev) => {
      window.__cspViolations.push({
        directive: ev.violatedDirective,
        blockedURI: ev.blockedURI,
        sourceFile: ev.sourceFile,
        lineNumber: ev.lineNumber,
      });
    });
  });

  // Stub the tile host entirely — no real network egress, and this
  // proves the CSP genuinely ALLOWS fetching it (a request that CSP
  // blocked never reaches this route handler at all; it would show up as
  // a securitypolicyviolation instead, which the assertion below catches).
  await page.route(`${FAKE_STYLE_URL}**`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(MINIMAL_STYLE),
    }),
  );
  await page.route(`https://${FAKE_TILE_HOST}/**`, (route) =>
    route.fulfill({ status: 404, body: "not stubbed" }),
  );

  const consoleErrors = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") consoleErrors.push(msg.text());
  });

  const response = await page.goto(`${baseUrl}${path}`, { waitUntil: "load" });
  assert.equal(response?.status(), 200, `${path}: expected HTTP 200`);

  const mapRoot = page.locator("[data-map-root]");
  const hasMap = (await mapRoot.count()) > 0;
  if (hasMap) {
    await mapRoot.scrollIntoViewIfNeeded();
    // Bounded wait for the real MapLibre canvas — proves the map actually
    // booted under this page's live CSP, not just that nothing crashed.
    await page
      .locator(".maplibregl-canvas")
      .waitFor({ state: "attached", timeout: 8000 })
      .catch(() => {
        throw new Error(
          `${path}: map root present but no .maplibregl-canvas appeared within 8s — ` +
            `the map failed to boot (a zero-CSP-violation result here would be a false pass)`,
        );
      });
  }

  const violations = await page.evaluate(() => window.__cspViolations ?? []);
  await context.close();

  return { path, hasMap, violations, consoleErrors };
}

/**
 * @param {import('@playwright/test').Browser} browser
 * @param {string} baseUrl
 * @param {{hub: string; trail: string; course: string}} paths
 */
export async function runMapCspTest(browser, baseUrl, paths) {
  const results = [];
  for (const [kind, path] of Object.entries(paths)) {
    console.log(`  [e2e] checking ${kind} (${path})...`);
    const result = await checkPage(browser, baseUrl, path);
    results.push({ kind, ...result });
    const violationSummary = result.violations
      .map((v) => `${v.directive} blocked ${v.blockedURI}`)
      .join("; ");
    console.log(
      `    hasMap=${result.hasMap} violations=${result.violations.length}${
        violationSummary ? ` (${violationSummary})` : ""
      }`,
    );
  }

  const withViolations = results.filter((r) => r.violations.length > 0);
  if (withViolations.length > 0) {
    for (const r of withViolations) {
      console.error(`\n[e2e] FAIL ${r.kind} (${r.path}) — CSP violations:`);
      for (const v of r.violations) {
        console.error(
          `  - ${v.directive} blocked ${v.blockedURI} (${v.sourceFile}:${v.lineNumber})`,
        );
      }
    }
    throw new Error(
      `runtime CSP e2e: ${withViolations.length} of ${results.length} page(s) had securitypolicyviolation events`,
    );
  }

  const hubOrTrailOrCourseWithMap = results.filter((r) => r.hasMap);
  if (hubOrTrailOrCourseWithMap.length === 0) {
    throw new Error(
      "runtime CSP e2e: no page under test rendered a [data-map-root] at all — the map's own CSP " +
        "compliance was never actually exercised (fix the test's page list, not this assertion)",
    );
  }

  console.log(
    `\n[e2e] PASS — ${results.length} page(s), 0 CSP violations, map booted on ${hubOrTrailOrCourseWithMap.length} of them.`,
  );
  return results;
}

/**
 * Blocking re-gate finding: "Add an e2e search assertion: type a query,
 * and expect results under the CSP with zero violations." Pagefind's own
 * WASM search index is exactly the thing the `/pagefind/*` CSP block
 * exists for (`gen-headers.mjs`'s doc) — this exercises it for real:
 * types into `SiteSearch.astro`'s input, waits for a real result to
 * render, and asserts zero `securitypolicyviolation` events the whole
 * time (a WASM-compile block would show up here, not as a thrown JS
 * error Playwright would otherwise surface on its own).
 *
 * @param {import('@playwright/test').Browser} browser
 * @param {string} baseUrl
 * @param {string} path
 * @param {string} query
 */
export async function checkSearch(browser, baseUrl, path, query) {
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.addInitScript(() => {
    window.__cspViolations = [];
    window.addEventListener("securitypolicyviolation", (ev) => {
      window.__cspViolations.push({
        directive: ev.violatedDirective,
        blockedURI: ev.blockedURI,
      });
    });
  });

  const response = await page.goto(`${baseUrl}${path}`, { waitUntil: "load" });
  assert.equal(response?.status(), 200, `${path}: expected HTTP 200`);

  const input = page.locator("[data-search-input]");
  await input.click();
  await input.fill(query);

  const results = page.locator("[data-search-results] li");
  await results
    .first()
    .waitFor({ state: "attached", timeout: 8000 })
    .catch(() => {
      throw new Error(
        `search for "${query}" on ${path} produced no results within 8s — either Pagefind's WASM ` +
          `index failed to load under this page's CSP, or the query genuinely matched nothing ` +
          `(check the query against the built site's actual content first)`,
      );
    });
  const resultCount = await results.count();
  const firstResultText = await results.first().innerText();

  const violations = await page.evaluate(() => window.__cspViolations ?? []);
  await context.close();

  if (violations.length > 0) {
    throw new Error(
      `search e2e: ${violations.length} CSP violation(s) while searching — ` +
        violations
          .map((v) => `${v.directive} blocked ${v.blockedURI}`)
          .join("; "),
    );
  }
  if (resultCount === 0) {
    throw new Error(
      `search e2e: 0 results for "${query}" — the assertion needs a query that actually matches`,
    );
  }

  console.log(
    `  [e2e] search "${query}" on ${path}: ${resultCount} result(s), 0 CSP violations (first: "${firstResultText}")`,
  );
  return { resultCount, violations };
}

export { FAKE_STYLE_URL, FAKE_TILE_HOST };
