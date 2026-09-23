/**
 * CLI-level integration tests: spawn the built `dist/*.js` CLIs exactly as
 * documented in README.md, using `--from-file` / `--responses` so nothing
 * touches the network (task requirement: no network calls in tests). These
 * only run once `pnpm build` has produced `dist/` — they self-skip
 * otherwise, since `pnpm test` can legitimately run standalone against
 * source (the other test files already cover the underlying logic without
 * needing a build).
 */
import { describe, expect, it } from "vitest";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.join(__dirname, "..");
const DIST = path.join(PKG_ROOT, "dist");
const FIXTURES = path.join(__dirname, "fixtures");

const distBuilt = existsSync(path.join(DIST, "x5-overpass.js")) && existsSync(path.join(DIST, "x1-ios-export.js"));

describe.skipIf(!distBuilt)("CLI integration (requires `pnpm build` first)", () => {
  it("x5-overpass n-osm --from-file prints N_osm with no network call", async () => {
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "x5-overpass.js"),
      "n-osm",
      "--from-file",
      path.join(FIXTURES, "overpass", "n-osm-response.json"),
    ]);
    expect(stdout).toContain("N_osm (US+CA leisure=golf_course count): 16212");
  });

  it("x5-overpass coverage --responses prints coverage and the pass/kill line, offline", async () => {
    const coursesPath = path.join(FIXTURES, "overpass", "courses.json");
    const { stdout } = await execFileAsync(
      "node",
      [
        path.join(DIST, "x5-overpass.js"),
        "coverage",
        "--courses",
        coursesPath,
        "--responses",
        path.join(FIXTURES, "overpass", "coverage-responses.json"),
        "--out",
        path.join(PKG_ROOT, ".tmp-test-x5-coverage-result"),
      ],
      { cwd: PKG_ROOT },
    );
    expect(stdout).toMatch(/X5 coverage: 1\/2 \(50\.0%\) vs 60% bar — KILL/);
  });

  it("x1-ios-export CLI writes JSON + markdown for the fixture export dir", async () => {
    const outPrefix = path.join(PKG_ROOT, ".tmp-test-x1-ios-export-result");
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "x1-ios-export.js"),
      FIXTURES,
      "--out",
      outPrefix,
    ]);
    expect(stdout).toContain("golf workout(s) found");
    expect(existsSync(`${outPrefix}.json`)).toBe(true);
    expect(existsSync(`${outPrefix}.md`)).toBe(true);
  });

  // NOTE: hitting the real default Overpass endpoint is deliberately NOT
  // exercised here (task requirement: no network calls in tests). That is
  // done once, manually, outside the test suite — see the task report and
  // README "Known risk" / STATUS notes.
});
