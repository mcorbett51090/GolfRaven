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
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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

  // Decision 0005: the CLI ALWAYS reads the repo's own real docs/p0/X1.md
  // for its recorded-export date(s) — there is no override flag (same
  // philosophy as the K2 CLI's no-`--k2-doc` rule). Pre-round, that section
  // is genuinely blank, so this is a real end-to-end proof the refusal is
  // wired all the way through the built CLI, not just unit-level. (The
  // OLD refusal here was "no round window logged" — decision 0005
  // supersedes it; round windows no longer gate anything.)
  it("x1-ios-export CLI refuses (non-zero exit) against the real, pre-round docs/p0/X1.md with no recorded-export date logged", async () => {
    const outPrefix = path.join(OUT_DIR, "x1-ios-export-result");
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-ios-export.js"),
        FIXTURES,
        "--os",
        "ios",
        "--out",
        outPrefix,
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("Recorded export") });
    expect(existsSync(`${outPrefix}.json`)).toBe(false);
  });

  // Decision 0005: --informational runs anyway, against the same blank
  // real docs/p0/X1.md, marked recorded: false with a loud banner.
  it("x1-ios-export CLI --informational runs against the real, pre-round docs/p0/X1.md and marks recorded: false", async () => {
    const outPrefix = path.join(OUT_DIR, "x1-ios-export-informational-result");
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "x1-ios-export.js"),
      FIXTURES,
      "--os",
      "ios",
      "--informational",
      "--out",
      outPrefix,
    ]);
    expect(stdout).toContain("recorded=false");
    const json = JSON.parse(readFileSync(`${outPrefix}.json`, "utf8"));
    expect(json.recorded).toBe(false);
    expect(json.os).toBe("ios");
    expect(json.source.sha256).toMatch(/^[0-9a-f]{64}$/);
    const md = readFileSync(`${outPrefix}.md`, "utf8");
    expect(md).toContain("INFORMATIONAL — NOT THE RECORDED X1 RESULT");
  });

  // Opus-gate correction (post-d0de4b8), decision 0005 "No recency limit":
  // --since is refused on a recorded run. This never touches docs/p0/X1.md
  // at all (the check runs in argument parsing, before any file is read),
  // so it's a safe, isolated CLI test.
  it("x1-ios-export CLI refuses --since without --informational", async () => {
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-ios-export.js"),
        FIXTURES,
        "--os",
        "ios",
        "--since",
        "2026-09-15",
        "--out",
        path.join(OUT_DIR, "x1-ios-export-since-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("--since is refused") });
  });

  it("x1-ios-export CLI allows --since WITH --informational", async () => {
    const outPrefix = path.join(OUT_DIR, "x1-ios-export-since-informational-result");
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "x1-ios-export.js"),
      FIXTURES,
      "--os",
      "ios",
      "--since",
      "2026-09-15",
      "--informational",
      "--out",
      outPrefix,
    ]);
    expect(stdout).toContain("recorded=false");
  });

  // Round-3 Opus-gate correction (post-8e5a29b): `x1-verdict` no longer
  // takes `--ios`/`--os`; it takes `--ios-export <dir>` (the raw Apple
  // Health export directory — FIXTURES itself, same as x1-ios-export's own
  // tests) and/or `--android <json>`, and refuses to run without at least
  // one of them.
  const minimalAndroidJson = path.join(OUT_DIR, "x1-verdict-minimal-android.json");
  const minimalSourceMapJson = path.join(OUT_DIR, "x1-verdict-minimal-source-map.json");
  writeFileSync(
    minimalAndroidJson,
    JSON.stringify({
      generatedAt: "2026-09-20T09:00:00Z",
      windowDays: 7,
      sessionCount: 0,
      sessions: [],
      os: "android",
    }),
  );
  writeFileSync(
    minimalSourceMapJson,
    JSON.stringify({
      garmin: { iosSourceNames: [], androidDataOrigins: [] },
      appleWatch: { iosSourceNames: [] },
      phoneApp: { iosSourceNames: [], androidDataOrigins: [], appUsed: "18Birdies" },
    }),
  );

  it("x1-verdict CLI refuses when neither --ios-export nor --android is supplied", async () => {
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-verdict.js"),
        "--source-map",
        minimalSourceMapJson,
        "--out",
        path.join(OUT_DIR, "x1-verdict-refuse-no-input-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("Usage:") });
  });

  it("x1-verdict CLI refuses (non-zero exit) a recorded run for iOS against the real, blank recorded-export date", async () => {
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-verdict.js"),
        "--ios-export",
        FIXTURES,
        "--source-map",
        minimalSourceMapJson,
        "--out",
        path.join(OUT_DIR, "x1-verdict-refuse-ios-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("Recorded export") });
  });

  it("x1-verdict CLI refuses (non-zero exit) a recorded run for Android against the real, blank recorded-export date", async () => {
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-verdict.js"),
        "--android",
        minimalAndroidJson,
        "--source-map",
        minimalSourceMapJson,
        "--out",
        path.join(OUT_DIR, "x1-verdict-refuse-android-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("Recorded export") });
  });

  // Round-3 Opus-gate correction: "The Android reader output must carry os
  // and generatedAt" — a basic shape check, refused unconditionally.
  it("x1-verdict CLI refuses when --android's JSON has no os field", async () => {
    const badAndroidJson = path.join(OUT_DIR, "x1-verdict-android-no-os.json");
    writeFileSync(
      badAndroidJson,
      JSON.stringify({ generatedAt: "2026-09-20T09:00:00Z", windowDays: 7, sessionCount: 0, sessions: [] }),
    );
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-verdict.js"),
        "--android",
        badAndroidJson,
        "--source-map",
        minimalSourceMapJson,
        "--informational",
        "--out",
        path.join(OUT_DIR, "x1-verdict-bad-android-os-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining('not "android"') });
  });

  // Round-3 Opus-gate correction: same shape check, the other required
  // field — "os and generatedAt" (Tests item: "Android JSON without os/
  // generatedAt fields is refused").
  it("x1-verdict CLI refuses when --android's JSON has no generatedAt field", async () => {
    const badAndroidJson = path.join(OUT_DIR, "x1-verdict-android-no-generated-at.json");
    writeFileSync(
      badAndroidJson,
      JSON.stringify({ os: "android", windowDays: 7, sessionCount: 0, sessions: [] }),
    );
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-verdict.js"),
        "--android",
        badAndroidJson,
        "--source-map",
        minimalSourceMapJson,
        "--informational",
        "--out",
        path.join(OUT_DIR, "x1-verdict-bad-android-generated-at-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("no generatedAt") });
  });

  // Round-3 Opus-gate correction: "No informational runs on real data while
  // an OS is unbound" — minimalAndroidJson is a real (non-fixture) path,
  // and Android has no bound hash in the real, blank docs/p0/X1.md.
  it("x1-verdict CLI refuses --informational on a real (non-fixture) Android path while unbound", async () => {
    await expect(
      execFileAsync("node", [
        path.join(DIST, "x1-verdict.js"),
        "--android",
        minimalAndroidJson,
        "--source-map",
        minimalSourceMapJson,
        "--informational",
        "--out",
        path.join(OUT_DIR, "x1-verdict-informational-real-refuse-result"),
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("no informational runs on real data") });
  });

  it("x1-verdict CLI --informational allows a fixture path (--ios-export FIXTURES) and marks recorded: false", async () => {
    const outPrefix = path.join(OUT_DIR, "x1-verdict-informational-result");
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "x1-verdict.js"),
      "--ios-export",
      FIXTURES,
      "--source-map",
      minimalSourceMapJson,
      "--informational",
      "--out",
      outPrefix,
    ]);
    const json = JSON.parse(readFileSync(`${outPrefix}.json`, "utf8"));
    expect(json.recorded).toBe(false);
    expect(json.provenance.exportXml.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(json.provenance.sourceMapJson.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(json.provenance.x1Doc.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(stdout).toContain("INFORMATIONAL — NOT THE RECORDED X1 RESULT");
  });

  // NOTE: hitting the real default Overpass endpoint is deliberately NOT
  // exercised here (task requirement: no network calls in tests). That is
  // done once, manually, outside the test suite — see the task report and
  // README "Known risk" / STATUS notes.

  // k1-verdict / k3-verdict: each CLI test reads a FROZEN copy of the log
  // (test/fixtures/k1-log-empty.md, test/fixtures/k3-memo-blank.md, copied
  // from the repo docs before any data was logged), passed with --log /
  // --memo. Reading the live repo docs would make these tests change result
  // as the calendar moves past 2026-10-20 or as soon as Matt logs real data.
  // Pinned as-of 2026-09-24 is before both K1 windows close, so the read is
  // pending ("n so far"), never MISS/PASS (decision 0001, Addendum I).
  it("k1-verdict CLI: empty log, as-of 2026-09-24 → pending, no MISS/PASS", async () => {
    const outPrefix = path.join(OUT_DIR, "k1-verdict-result");
    const { stdout } = await execFileAsync("node", [
      path.join(DIST, "k1-verdict.js"),
      "--log", path.join(FIXTURES, "k1-log-empty.md"),
      "--as-of", "2026-09-24",
      "--out", outPrefix,
    ]);
    expect(stdout).toContain("so far");
    expect(stdout).toContain("Full gate state: pending");
    expect(stdout).not.toMatch(/\bMISS\b/);
    expect(stdout).not.toMatch(/\bPASS\b/);
    // A --log run is stamped as NOT the recorded log (provenance, gate round 3).
    expect(stdout).toContain("NOT THE RECORDED K1 LOG");
    const json = JSON.parse(readFileSync(`${outPrefix}.json`, "utf8"));
    expect(json.source.isRepoLog).toBe(false);
    expect(json.source.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  // Decision 0001, Addendum I ("the read date is real"): a --as-of later than
  // today (UTC, the real system clock) is refused. "Tomorrow" is computed at
  // run time so the test never goes stale.
  it("k1-verdict CLI refuses a --as-of later than today", async () => {
    const outPrefix = path.join(OUT_DIR, "k1-verdict-result-future");
    const tomorrow = new Date(Date.now() + 86_400_000).toISOString().slice(0, 10);
    await expect(
      execFileAsync("node", [
        path.join(DIST, "k1-verdict.js"),
        "--log", path.join(FIXTURES, "k1-log-empty.md"),
        "--as-of", tomorrow,
        "--out", outPrefix,
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("later than today") });
    expect(existsSync(`${outPrefix}.json`)).toBe(false);
  });

  it("k3-verdict CLI refuses (non-zero exit) on a memo with a blank property id", async () => {
    const outPrefix = path.join(OUT_DIR, "k3-verdict-result");
    await expect(
      execFileAsync("node", [
        path.join(DIST, "k3-verdict.js"),
        "--memo", path.join(FIXTURES, "k3-memo-blank.md"),
        "--out", outPrefix,
      ]),
    ).rejects.toMatchObject({ stderr: expect.stringContaining("property id") });
    expect(existsSync(`${outPrefix}.json`)).toBe(false);
  });
});
