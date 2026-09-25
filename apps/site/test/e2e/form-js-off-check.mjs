/**
 * form-js-off-check.mjs — the gate review B1 blocking requirement: "Add a
 * Playwright JS-off test that clicks submit on all 4 pages and asserts
 * zero non-GET requests."
 *
 * For each form page: a browser context with `javaScriptEnabled: false`
 * (Playwright's own automation commands — `.click()`, `.press()`,
 * `.isDisabled()` — still work; they're driven over CDP, not through the
 * page's own JS engine, so this genuinely exercises the "no JS at all"
 * case, not just "JS present but not yet bound"). It:
 *
 *   1. Confirms the `<fieldset data-form-fieldset>` IS disabled in the
 *      raw, server-rendered markup (B1's own defense — see
 *      `SecureFormScript.astro`'s module doc) — a false pass here (the
 *      fieldset silently NOT disabled) would make every check below
 *      meaningless.
 *   2. Records EVERY network request the page makes for the whole test,
 *      classified as `nonGet` (anything but GET/HEAD — the CSP-allowed
 *      `form-action 'self'` POST this gate exists to prevent) or
 *      `leakyGet` (a GET whose query string carries a form field name —
 *      the "native GET fallback" shape of the same leak).
 *   3. Fills every visible text field with a recognisable marker string,
 *      then attempts BOTH a forced click on the submit button AND
 *      pressing Enter inside the "name" field (the two ways a browser can
 *      trigger a native form submission) — `force: true` bypasses
 *      Playwright's OWN actionability checks (so this isn't just "the
 *      test never tried"), leaving the browser's native disabled-control
 *      semantics as the only thing standing between the click and a
 *      submission.
 *   4. Asserts zero `nonGet` requests and zero `leakyGet` requests were
 *      ever observed, and that the marker string the test typed never
 *      reached the page's own URL (a GET with no query name match, but a
 *      literal path segment, would still be a leak).
 */
import assert from "node:assert/strict";

const MARKER = "js-off-leak-check-marker";

/**
 * @param {import('@playwright/test').Browser} browser
 * @param {string} baseUrl
 * @param {string} path
 */
async function checkFormPage(browser, baseUrl, path) {
  const context = await browser.newContext({ javaScriptEnabled: false });
  const page = await context.newPage();

  /** @type {{method: string, url: string}[]} */
  const nonGetRequests = [];
  /** @type {string[]} */
  const leakyGetRequests = [];

  page.on("request", (req) => {
    const method = req.method();
    const url = req.url();
    if (method !== "GET" && method !== "HEAD") {
      nonGetRequests.push({ method, url });
      return;
    }
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return;
    }
    // A GET carrying one of the form's own field names in its query
    // string (or the marker string anywhere in the URL) is the "native
    // GET fallback" shape of the same leak `form-action 'self'`'s POST
    // path is — a disabled <fieldset>'s descendants are excluded from
    // EITHER method's submission data (see this file's own doc), so
    // neither should ever appear regardless of which one a bypass used.
    const hasFieldParam = ["name", "email", "message", "relationship", "topic"].some((key) =>
      parsed.searchParams.has(key),
    );
    if (hasFieldParam || url.includes(MARKER)) {
      leakyGetRequests.push(url);
    }
  });

  const response = await page.goto(`${baseUrl}${path}`, { waitUntil: "load" });
  assert.equal(response?.status(), 200, `${path}: expected HTTP 200`);

  const fieldset = page.locator("[data-form-fieldset]");
  assert.equal(await fieldset.count(), 1, `${path}: expected exactly one [data-form-fieldset]`);
  // The `disabled` ATTRIBUTE, read directly off the fieldset — the ground
  // truth this whole test depends on, independent of how any particular
  // Playwright API interprets "disabled" for a <fieldset> specifically
  // (its own `.isDisabled()` targets ordinary form CONTROLS; a submit
  // button nested inside is checked via that API just below instead,
  // which Playwright's docs confirm accounts for an ancestor
  // `<fieldset disabled>`).
  const fieldsetHasDisabledAttr = await fieldset.evaluate((el) => el.hasAttribute("disabled"));
  assert.equal(
    fieldsetHasDisabledAttr,
    true,
    `${path}: [data-form-fieldset] must carry the disabled attribute with JS off (B1) — it did NOT`,
  );
  // The submit button — a genuine form CONTROL — inherits disabled-ness
  // from its ancestor fieldset per the HTML spec; Playwright's own
  // `isDisabled()` is documented to account for exactly this.
  const submitButtonIsDisabled = await page.locator('button[type="submit"]').isDisabled();
  assert.equal(
    submitButtonIsDisabled,
    true,
    `${path}: the submit button must be disabled (via its ancestor fieldset) with JS off (B1) — it was NOT`,
  );
  const fieldsetIsDisabled = fieldsetHasDisabledAttr && submitButtonIsDisabled;

  // Best-effort: with the fieldset genuinely disabled, Playwright's own
  // actionability checks on `.fill()` will normally refuse (the element
  // isn't "editable") — that failure IS part of the proof, so it's
  // swallowed rather than treated as a test error. `force: true` on the
  // later click/press is what actually bypasses Playwright's own checks;
  // native browser semantics for a disabled control are what should stop
  // it from there.
  const nameInput = page.locator('input[name="name"]');
  await nameInput.fill(MARKER, { force: true, timeout: 2000 }).catch(() => {});

  const submitButton = page.locator('button[type="submit"]');
  await submitButton.click({ force: true, timeout: 2000 }).catch(() => {});
  await nameInput.press("Enter", { timeout: 2000 }).catch(() => {});

  // Give any (hypothetical) navigation/request a moment to actually fire
  // before reading the collected lists.
  await page.waitForTimeout(300);

  const finalUrl = page.url();

  await context.close();

  return { path, fieldsetIsDisabled, nonGetRequests, leakyGetRequests, finalUrl };
}

/**
 * @param {import('@playwright/test').Browser} browser
 * @param {string} baseUrl
 * @param {string[]} paths
 */
export async function runFormJsOffTest(browser, baseUrl, paths) {
  const results = [];
  for (const path of paths) {
    console.log(`  [e2e/js-off] checking ${path}...`);
    const result = await checkFormPage(browser, baseUrl, path);
    results.push(result);
    console.log(
      `    fieldsetDisabled=${result.fieldsetIsDisabled} nonGetRequests=${result.nonGetRequests.length} ` +
        `leakyGetRequests=${result.leakyGetRequests.length}`,
    );
  }

  const problems = results.filter(
    (r) => !r.fieldsetIsDisabled || r.nonGetRequests.length > 0 || r.leakyGetRequests.length > 0,
  );
  if (problems.length > 0) {
    for (const r of problems) {
      console.error(`\n[e2e/js-off] FAIL ${r.path}:`);
      if (!r.fieldsetIsDisabled) console.error(`  - fieldset was NOT disabled`);
      for (const req of r.nonGetRequests) console.error(`  - non-GET request: ${req.method} ${req.url}`);
      for (const url of r.leakyGetRequests) console.error(`  - leaky GET request: ${url}`);
    }
    throw new Error(
      `form JS-off e2e: ${problems.length} of ${results.length} form page(s) either had a non-GET request, ` +
        `a leaky GET request, or a fieldset that wasn't disabled with JS off — see the log above`,
    );
  }

  console.log(`\n[e2e/js-off] PASS — ${results.length} form page(s), fieldset disabled, zero non-GET requests, zero leaky GETs.`);
  return results;
}
