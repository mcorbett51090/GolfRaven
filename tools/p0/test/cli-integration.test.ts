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
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.join(__dirname, "..");
const DIST = path.join(PKG_ROOT, "dist");
const FIXTURES = path.join(__dirname, "fixtures");
// Per-run scratch dir for CLI outputs, so tests never write into the source tree.
const OUT_DIR = mkdtempSync(path.join(tmpdir(), "golfraven-p0-tools-"));

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
        path.join(OUT_DIR, "x5-coverage-result"),
      ],
      { cwd: PKG_ROOT },
    );
    expect(stdout).toMatch(/X5 coverage: 1\/2 \(50\.0%\) vs 60% bar — KILL/);
  });

  // Decision 0001 Addendum F: the CLI ALWAYS reads the repo's own real
  // docs/p0/X1.md for its logged round window(s) — there is no override
  // flag (same philosophy as the K2 CLI's no-`--k2-doc` rule). Pre-round,
  // that section is genuinely blank, so this is a real end-to-end proof the
  // refusal is wired all the way through the built CLI, not just unit-level.
  it("x1-ios-export CLI refuses (non-zero exit) against the real, pre-round docs/p0/X1.md with no round window logged", async () => {
    const outPrefix = path.join(OUT_DIR, "x1-ios-export-result");
    await expect(
      execFileAsync("node", [path.join(DIST, "x1-ios-export.js"), FIXTURES, "--out", outPrefix]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("round window") });
    expect(existsSync(`${outPrefix}.json`)).toBe(false);
  });

  // NOTE: hitting the real default Overpass endpoint is deliberately NOT
  // exercised here (task requirement: no network calls in tests). That is
  // done once, manually, outside the test suite — see the task report and
  // README "Known risk" / STATUS notes.

  // k1-verdict/k3-verdict read fixed repo docs directly (no network, no
  // input flags) — same "no override flag" philosophy as x1-ios-export's
  // round-window read above. Proving both against the REAL, pre-read repo
  // docs is a real end-to-end check that the refusal/pass-through wiring
  // reaches all the way from the CLI to `docs/partners/k1-outreach.md` and
  // `docs/p0/K3.md`.
  // Decision 0001, Addendum I: before the early-read window closes
  // (2026-10-20), the CLI's own default --as-of (today's UTC date, which
  // is 2026-09-24 in this repo's fixed "today") reports PENDING, not a
  // miss — the read is genuinely not due yet. An explicit --as-of past
  // both window closes proves the miss/pending distinction end to end.
  it("k1-verdict CLI runs cleanly against the real, pre-outreach k1-outreach.md (default as-of: pending)", async () => {
    const outPrefix = path.join(OUT_DIR, "k1-verdict-result");
    const { stdout } = await execFileAsync("node", [path.join(DIST, "k1-verdict.js"), "--out", outPrefix]);
    expect(stdout).toContain("PENDING");
    expect(stdout).toContain("Full gate state: pending");
    expect(existsSync(`${outPrefix}.json`)).toBe(true);
  });

  it("k1-verdict CLI --as-of past both windows reports early-read MISS and full-gate operator-miss", async () => {
    const outPrefix = path.join(OUT_DIR, "k1-verdict-result-later");
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "k1-verdict.js"),
      "--as-of",
      "2026-12-01",
      "--out",
      outPrefix,
    ]);
    expect(stdout).toContain("MISS");
    expect(stdout).toContain("Full gate state: operator-miss");
  });

  it("k3-verdict CLI refuses (non-zero exit) against the real, pre-read K3.md (blank property id)", async () => {
    const outPrefix = path.join(OUT_DIR, "k3-verdict-result");
    await expect(
      execFileAsync("node", [path.join(DIST, "k3-verdict.js"), "--out", outPrefix]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("property id") });
    expect(existsSync(`${outPrefix}.json`)).toBe(false);
  });
});
