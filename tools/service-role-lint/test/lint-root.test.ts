// A lint that finds nothing reports `clean`, so a lint run over a root that does not exist, is not a directory, or holds no files is a pass over NOTHING: a typo in the path
// (`supabase/functionz`), a renamed or moved functions directory, or an empty checkout would silently turn this secrets gate off. The CLI already refused a path with no `.git`
// ancestor (deriveRepoRoot); a path INSIDE the repo got through and reported `clean`, exit 0 (design 121).

import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkLintRoot } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..", "..");
const scratch = () => mkdtempSync(join(tmpdir(), "lint-root-"));

describe("checkLintRoot", () => {
  it("refuses a root that does not exist", () => {
    const r = checkLintRoot(join(scratch(), "functionz"));
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toMatch(/does not exist/);
  });

  it("refuses a path that is a file, not a directory", () => {
    const dir = scratch();
    writeFileSync(join(dir, "a.ts"), "export {};\n");
    const r = checkLintRoot(join(dir, "a.ts"));
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toMatch(/not a directory/);
  });

  it("refuses an empty directory, and a tree of empty directories (no file anywhere)", () => {
    const empty = scratch();
    expect(checkLintRoot(empty).ok).toBe(false);
    mkdirSync(join(empty, "a", "b"), { recursive: true });
    const r = checkLintRoot(empty);
    expect(r.ok).toBe(false);
    expect(r.ok === false && r.reason).toMatch(/holds no files/);
  });

  it("accepts a directory with a file anywhere under it and counts the files", () => {
    const dir = scratch();
    mkdirSync(join(dir, "fn", "deep"), { recursive: true });
    writeFileSync(join(dir, "fn", "deep", "index.ts"), "export {};\n");
    writeFileSync(join(dir, "fn", "other.ts"), "export {};\n");
    expect(checkLintRoot(dir)).toEqual({ ok: true, fileCount: 2 });
  });

  it("accepts the real functions tree (so the guard cannot lock the gate out of its own subject)", () => {
    const r = checkLintRoot(join(repoRoot, "supabase", "functions"));
    expect(r.ok).toBe(true);
    expect(r.ok && r.fileCount).toBeGreaterThan(50);
  });
});

// The CLI cells spawn the built linter, and the one over the real functions tree parses ~170 files with typescript-estree: about 2 s alone and about 4 s with four copies running at once on a 4-core
// machine. A 2-core CI runner running every package's tests in parallel took 5136 ms and failed vitest's 5000 ms default (design 124), so these cells are given the time a loaded runner needs and
// the child is bounded below it, so a hung linter fails the cell (status null) instead of waiting out the test timeout.
const CLI_TEST_TIMEOUT_MS = 60_000;
const CLI_CHILD_TIMEOUT_MS = 55_000;

describe("the CLI", () => {
  const cli = join(here, "..", "dist", "cli.js");
  const run = (root: string) => {
    expect(
      existsSync(cli),
      "tools/service-role-lint/dist/cli.js is not built: run `pnpm --filter @golfraven/service-role-lint build` first (CI builds before it tests)",
    ).toBe(true);
    return spawnSync(process.execPath, [cli, root], {
      encoding: "utf8",
      cwd: repoRoot,
      timeout: CLI_CHILD_TIMEOUT_MS,
    });
  };

  it("exits 2 (not 0, not a finding's 1) for a typo'd path inside the repo, and says why", () => {
    const r = run("supabase/functionz");
    expect(r.status, r.stdout + r.stderr).toBe(2);
    expect(r.stderr).toMatch(/refusing to lint supabase\/functionz/);
    expect(r.stdout).not.toMatch(/clean/);
  }, CLI_TEST_TIMEOUT_MS);

  it("exits 2 for an empty directory", () => {
    expect(run(scratch()).status).toBe(2);
  }, CLI_TEST_TIMEOUT_MS);

  it("still reports the real functions tree as clean, with the number of files it covered", () => {
    const r = run("supabase/functions");
    expect(r.status, r.stdout + r.stderr).toBe(0);
    expect(r.stdout).toMatch(
      /service-role-lint: clean \(supabase\/functions, \d+ file\(s\)\)/,
    );
  }, CLI_TEST_TIMEOUT_MS);

  it("checks the root BEFORE linting it (pins the order in cli.ts)", () => {
    const src = readFileSync(join(here, "..", "src", "cli.ts"), "utf8");
    expect(src.indexOf("checkLintRoot(root)")).toBeGreaterThan(-1);
    expect(src.indexOf("checkLintRoot(root)")).toBeLessThan(
      src.indexOf("lintDirectory(root)"),
    );
  });
});
