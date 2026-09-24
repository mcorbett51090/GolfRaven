/**
 * booking-bypass-html.test.ts — Opus gate should-fix ("a real booking
 * bypass test"): the existing AT(4) "MIXED booking[]" test in
 * `stage2-acceptance.test.ts` only exercises `allowedBookingEntries()`
 * directly (a unit-level call) — it would NOT fail if
 * `courses/[slug].astro` itself regressed to rendering `facility.booking`
 * straight through instead of the filtered result. This test closes that
 * gap: it runs a REAL `astro build` of the ACTUAL `courses/[slug].astro`
 * page against a fixture facility whose `booking[]` contains one
 * allow-listed entry and one host NOT on the allow-list, then asserts the
 * disallowed entry's URL does not appear anywhere in the BUILT HTML.
 *
 * Deliberately runs `astro build` directly rather than going through
 * `scripts/verify-input.mjs` first: `verify-input.mjs` runs
 * `verifyCatalogRaw` with the SAME allow-list and would correctly refuse
 * this fixture before the site ever builds it (defense layer 1, upstream
 * of the site). The render-time filter this test exercises is defense
 * layer 2 — the one that still has to hold if a disallowed entry ever
 * reaches the renderer some other way (a stale build, a manually-edited
 * `data/` file, a narrowed allow-list applied after the data was last
 * verified). Both layers are real; this test is only responsible for the
 * second one.
 */
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { writeFixtureDataDir } from "./write-fixture-data-dir.mjs";

const siteRoot = fileURLToPath(new URL("..", import.meta.url));

let scratch: string;
let dist: string;
let disallowedUrl: string;
let allowedUrl: string;

beforeAll(async () => {
  scratch = await mkdtemp(join(tmpdir(), "golfraven-booking-bypass-"));
  const dataDir = join(scratch, "data");
  dist = join(scratch, "dist");

  await writeFixtureDataDir(dataDir);

  const facPath = join(dataDir, "facilities", "highland-meadows-golf-course.json");
  const facility = JSON.parse(await readFile(facPath, "utf8"));
  const allowedEntry = facility.booking[0]; // real fixture: www.golfnow.com, allow-listed
  const disallowedEntry = {
    ...allowedEntry,
    provider: "chronogolf",
    url: "https://booking.not-allow-listed.example/highland-meadows-bypass-check",
  };
  facility.booking = [allowedEntry, disallowedEntry];
  await writeFile(facPath, JSON.stringify(facility));
  allowedUrl = allowedEntry.url;
  disallowedUrl = disallowedEntry.url;

  execFileSync("./node_modules/.bin/astro", ["build", "--outDir", dist], {
    cwd: siteRoot,
    stdio: "inherit",
    env: { ...process.env, ASTRO_TELEMETRY_DISABLED: "1", GOLFRAVEN_DATA_DIR: dataDir },
  });
}, 120_000);

afterAll(async () => {
  if (scratch) await rm(scratch, { recursive: true, force: true });
});

describe("AT(4) HTML-level regression guard: courses/[slug].astro never renders a disallowed booking entry", () => {
  it("the built page's HTML contains the allow-listed URL and does NOT contain the disallowed one", async () => {
    const html = await readFile(
      join(dist, "courses", "highland-meadows-golf-course", "index.html"),
      "utf8",
    );
    expect(html).toContain(allowedUrl);
    expect(html).not.toContain(disallowedUrl);

    // PROOF the fixture itself really carries the disallowed entry (so a
    // pass here is not vacuous because the entry never made it into the
    // data at all) — this is exactly the shape a bypass (rendering
    // `facility.booking` directly instead of `allowedBookingEntries(...)`)
    // would flip to `.toContain(disallowedUrl)`.
    const facPath = join(scratch, "data", "facilities", "highland-meadows-golf-course.json");
    const facility = JSON.parse(await readFile(facPath, "utf8"));
    expect(facility.booking.some((b: { url: string }) => b.url === disallowedUrl)).toBe(true);
  });
});
