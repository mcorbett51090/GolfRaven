/**
 * Real-git integration test for the K2 exclusion-dating rule (decision
 * 0001 Addendum F, gate findings A-5/A-6): builds a THROWAWAY git repo
 * (never this repo) with controlled `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE`
 * commits, mirroring the method gate-round-3 used, and runs the REAL
 * `scripts/k2-count.mjs` + built `dist/` against it as an actual child
 * process — no mocking of git at all. Self-skips if `dist/` hasn't been
 * built yet (same pattern as tools/p0's cli-integration.test.ts). All work
 * happens under `os.tmpdir()`; nothing is written into this repo's source
 * tree.
 */
import { describe, expect, it } from "vitest";
import {
  existsSync,
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  cpSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = path.join(__dirname, "..");
const DIST = path.join(PKG_ROOT, "dist");
const distBuilt =
  existsSync(path.join(DIST, "k2-count.js")) &&
  existsSync(path.join(DIST, "k2-blame.js"));

// Gate finding F-N8: a plain `pnpm -r test` (no prior build) used to make
// this — the only REAL-git test of the K2 exclusion-dating rule — silently
// skip itself with a GREEN result. That's fine for local iteration (a
// build is a deliberate extra step), but in CI it must be a hard failure,
// not a quiet no-op that a `pnpm -r build && pnpm -r test` pipeline order
// mistake could hide.
if (!distBuilt && process.env.CI) {
  throw new Error(
    "k2-git-integration.test.mjs: dist/k2-count.js / dist/k2-blame.js are missing in CI (gate finding F-N8) " +
      '— run "pnpm --filter @golfraven/signup-worker build" before "pnpm -r test" so this real-git test ' +
      "actually runs, instead of silently skipping.",
  );
}

function git(cwd, args, env = {}) {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

/** Builds a throwaway repo at `repoDir`, mirroring the real repo's
 * relative layout (`apps/signup-worker/{scripts,dist}`, `docs/p0/K2.md`),
 * with the REAL scripts/dist copied in. Returns `{ k2DocPath, scriptsDir }`. */
function scaffoldRepo(repoDir) {
  const appDir = path.join(repoDir, "apps", "signup-worker");
  mkdirSync(path.join(appDir, "scripts"), { recursive: true });
  mkdirSync(path.join(appDir, "dist"), { recursive: true });
  mkdirSync(path.join(repoDir, "docs", "p0"), { recursive: true });
  cpSync(
    path.join(PKG_ROOT, "scripts", "k2-count.mjs"),
    path.join(appDir, "scripts", "k2-count.mjs"),
  );
  cpSync(
    path.join(DIST, "k2-count.js"),
    path.join(appDir, "dist", "k2-count.js"),
  );
  cpSync(
    path.join(DIST, "k2-blame.js"),
    path.join(appDir, "dist", "k2-blame.js"),
  );
  git(repoDir, ["init", "-q"]);
  git(repoDir, ["config", "user.email", "test@example.com"]);
  git(repoDir, ["config", "user.name", "K2 Integration Test"]);
  return {
    k2DocPath: path.join(repoDir, "docs", "p0", "K2.md"),
    scriptsDir: path.join(appDir, "scripts"),
  };
}

function writeK2Doc(k2DocPath, day0Section, excludedBody) {
  writeFileSync(
    k2DocPath,
    `## Day 0\n\n${day0Section}\n\n## Excluded addresses (pre-Day-0 list)\n\n${excludedBody}\n`,
    "utf8",
  );
}

function commitAll(repoDir, message, isoDate) {
  git(repoDir, ["add", "-A"]);
  git(repoDir, ["commit", "-q", "-m", message], {
    GIT_AUTHOR_DATE: isoDate,
    GIT_COMMITTER_DATE: isoDate,
  });
}

describe.skipIf(!distBuilt)(
  "K2 exclusion dating — real git integration (decision 0001 Addendum F)",
  () => {
    it("A-5: a LATER REFORMAT of an old, still-excluded line does not change its first-appearance date", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-"));
      const { k2DocPath, scriptsDir } = scaffoldRepo(repoDir);

      // Commit 1 (2026-09-30): address first appears, well before day 0.
      writeK2Doc(k2DocPath, "_(blank)_", "- a@x.com");
      commitAll(repoDir, "add excluded address", "2026-09-30T00:00:00Z");

      // Commit 2 (2026-10-20, AFTER day 0 will be set below): pure reformat
      // — same address, now backtick-wrapped. Per Addendum F this must NOT
      // re-date the exclusion (it dates the ADDRESS, not the line).
      writeK2Doc(k2DocPath, "2026-10-05", "- `a@x.com`");
      commitAll(repoDir, "reformat + set day 0", "2026-10-20T00:00:00Z");

      const exportPath = path.join(repoDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          { email_lc: "a@x.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
        ]),
      );

      const { stdout } = await execFileAsync(
        "node",
        ["k2-count.mjs", "--export", exportPath],
        { cwd: scriptsDir },
      );
      expect(stdout).toContain("excluded addresses (1): a@x.com");
    });

    it("A-6: an address whose first appearance is on/after day 0 is NOT excluded, and is flagged (day-0 warning)", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-"));
      const { k2DocPath, scriptsDir } = scaffoldRepo(repoDir);

      writeK2Doc(k2DocPath, "2026-10-05", "_(blank)_");
      commitAll(repoDir, "set day 0", "2026-10-01T00:00:00Z");

      // The e2e test address, added ON day 0 itself (the runbook-step-9
      // mistake this fix targets) — must NOT be excluded.
      writeK2Doc(k2DocPath, "2026-10-05", "- late@x.com");
      commitAll(repoDir, "add test address on day 0", "2026-10-05T12:00:00Z");

      const exportPath = path.join(repoDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          { email_lc: "late@x.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
        ]),
      );

      const { stdout } = await execFileAsync(
        "node",
        ["k2-count.mjs", "--export", exportPath],
        { cwd: scriptsDir },
      );
      expect(stdout).toContain("excluded addresses (0)");
      expect(stdout).toContain("late@x.com (K2.md:7) — not excluded");
      expect(stdout).toMatch(/distinct confirmed \(post-exclusion\): 1/);
      // A-6: the day-0-itself warning names the address.
      expect(stdout).toContain("first appeared ON day 0 itself");
      expect(stdout).toContain("late@x.com");
    });

    it("F-S2: an address DELETED from K2.md after day 0 stays excluded, and is flagged as no-longer-listed", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-"));
      const { k2DocPath, scriptsDir } = scaffoldRepo(repoDir);

      // Commit 1 (before day 0): a@x.com and b@x.com both excluded.
      writeK2Doc(k2DocPath, "_(blank)_", "- a@x.com\n- b@x.com");
      commitAll(repoDir, "add both addresses", "2026-10-05T00:00:00Z");

      // Commit 2: set day 0.
      writeK2Doc(k2DocPath, "2026-10-10", "- a@x.com\n- b@x.com");
      commitAll(repoDir, "set day 0", "2026-10-10T00:00:00Z");

      // Commit 3 (AFTER day 0): a@x.com's line is DELETED from K2.md.
      writeK2Doc(k2DocPath, "2026-10-10", "- b@x.com");
      commitAll(repoDir, "delete a@x.com line", "2026-10-20T00:00:00Z");

      const exportPath = path.join(repoDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          { email_lc: "a@x.com", confirmed_at: "2026-10-25T00:00:00.000Z" },
          { email_lc: "b@x.com", confirmed_at: "2026-10-25T00:00:00.000Z" },
        ]),
      );

      const { stdout } = await execFileAsync(
        "node",
        ["k2-count.mjs", "--export", exportPath],
        { cwd: scriptsDir },
      );
      expect(stdout).toContain("excluded addresses (2)");
      expect(stdout).toContain("a@x.com");
      expect(stdout).toContain("b@x.com");
      expect(stdout).toMatch(/distinct confirmed \(post-exclusion\): 0/);
      expect(stdout).toContain("no longer listed in K2.md (1): a@x.com");
    });

    it("F-S3: case differences are the SAME address (A@X.com == a@x.com)", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-"));
      const { k2DocPath, scriptsDir } = scaffoldRepo(repoDir);

      // Listed with different casing than it's looked up with.
      writeK2Doc(k2DocPath, "_(blank)_", "- A@X.com");
      commitAll(repoDir, "add uppercase address", "2026-10-01T00:00:00Z");
      writeK2Doc(k2DocPath, "2026-10-05", "- A@X.com");
      commitAll(repoDir, "set day 0", "2026-10-05T00:00:00Z");

      const exportPath = path.join(repoDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          { email_lc: "a@x.com", confirmed_at: "2026-10-10T00:00:00.000Z" },
        ]),
      );

      const { stdout } = await execFileAsync(
        "node",
        ["k2-count.mjs", "--export", exportPath],
        { cwd: scriptsDir },
      );
      expect(stdout).toContain("excluded addresses (1): a@x.com");
      expect(stdout).toMatch(/distinct confirmed \(post-exclusion\): 0/);
    });

    it("F-S3: ba@x.com excluded before day 0 does NOT exclude a@x.com first added later (no substring cross-match)", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-"));
      const { k2DocPath, scriptsDir } = scaffoldRepo(repoDir);

      writeK2Doc(k2DocPath, "_(blank)_", "- ba@x.com");
      commitAll(repoDir, "add ba@x.com", "2026-10-01T00:00:00Z");
      writeK2Doc(k2DocPath, "2026-10-05", "- ba@x.com");
      commitAll(repoDir, "set day 0", "2026-10-05T00:00:00Z");
      // a@x.com first appears AFTER day 0 — must not be excluded even though
      // it's a substring of the already-excluded ba@x.com.
      writeK2Doc(k2DocPath, "2026-10-05", "- ba@x.com\n- a@x.com");
      commitAll(repoDir, "add a@x.com after day 0", "2026-10-10T00:00:00Z");

      const exportPath = path.join(repoDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          { email_lc: "ba@x.com", confirmed_at: "2026-10-15T00:00:00.000Z" },
          { email_lc: "a@x.com", confirmed_at: "2026-10-15T00:00:00.000Z" },
        ]),
      );

      const { stdout } = await execFileAsync(
        "node",
        ["k2-count.mjs", "--export", exportPath],
        { cwd: scriptsDir },
      );
      expect(stdout).toContain("excluded addresses (1): ba@x.com");
      expect(stdout).toContain("a@x.com (K2.md:8) — not excluded");
      expect(stdout).toMatch(/distinct confirmed \(post-exclusion\): 1/);
    });

    it("F-S2: reformatting an excluded address after day 0 keeps its original (pre-day-0) date", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-"));
      const { k2DocPath, scriptsDir } = scaffoldRepo(repoDir);

      writeK2Doc(k2DocPath, "_(blank)_", "- reformat@x.com");
      commitAll(repoDir, "add address", "2026-09-30T00:00:00Z");
      writeK2Doc(k2DocPath, "2026-10-05", "- reformat@x.com");
      commitAll(repoDir, "set day 0", "2026-10-05T00:00:00Z");
      // Reformat AFTER day 0 — same address, different decoration.
      writeK2Doc(k2DocPath, "2026-10-05", "- `reformat@x.com`");
      commitAll(repoDir, "reformat after day 0", "2026-10-20T00:00:00Z");

      const exportPath = path.join(repoDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          {
            email_lc: "reformat@x.com",
            confirmed_at: "2026-10-25T00:00:00.000Z",
          },
        ]),
      );

      const { stdout } = await execFileAsync(
        "node",
        ["k2-count.mjs", "--export", exportPath],
        { cwd: scriptsDir },
      );
      expect(stdout).toContain("excluded addresses (1): reformat@x.com");
      expect(stdout).toMatch(/distinct confirmed \(post-exclusion\): 0/);
    });

    it("A-5/A-6: refuses (non-zero exit) in a shallow clone", async () => {
      const repoDir = mkdtempSync(path.join(tmpdir(), "golfraven-k2-git-src-"));
      const { k2DocPath, scriptsDir: _unused } = scaffoldRepo(repoDir);
      writeK2Doc(k2DocPath, "2026-10-05", "- a@x.com");
      commitAll(repoDir, "initial", "2026-09-30T00:00:00Z");

      const shallowDir = mkdtempSync(
        path.join(tmpdir(), "golfraven-k2-git-shallow-"),
      );
      git(tmpdir(), [
        "clone",
        "-q",
        "--depth",
        "1",
        `file://${repoDir}`,
        shallowDir,
      ]);
      expect(
        git(shallowDir, ["rev-parse", "--is-shallow-repository"]).trim(),
      ).toBe("true");

      const exportPath = path.join(shallowDir, "export.json");
      writeFileSync(
        exportPath,
        JSON.stringify([
          { email_lc: "a@x.com", confirmed_at: "2026-10-06T00:00:00.000Z" },
        ]),
      );

      const scriptsDirShallow = path.join(
        shallowDir,
        "apps",
        "signup-worker",
        "scripts",
      );
      await expect(
        execFileAsync("node", ["k2-count.mjs", "--export", exportPath], {
          cwd: scriptsDirShallow,
        }),
      ).rejects.toMatchObject({
        code: 1,
        stderr: expect.stringContaining("shallow"),
      });
    });
  },
);
