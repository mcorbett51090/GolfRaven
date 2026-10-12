// supabase/tests/unit/ci-h2-gate.test.ts
//
// The H2 gate: no migration may name the harness-only `migration_owner` role outside a comment (tools/db/check-no-migration-owner-refs.sh, run from tools/db/test.sh).
// The inline loop it replaced, `grep -v '^\s*--' "$f" | grep -q 'migration_owner'` under `set -o pipefail`, FAILED OPEN: `grep -q` quits at its first match, the writer is still
// writing for a file larger than the 64 KB pipe buffer, takes SIGPIPE, `pipefail` makes the pipeline's status 141, and the `if` read a MATCH as no match. On a must-fail fixture
// (a violation on line 2 of a 670 KB file) the old form detected 0 of 1500 runs and the form below 1500 of 1500. 7 of the migrations are larger than the buffer. No migration was
// missed (the real scan below finds none), but a gate that can pass on the very thing it exists to catch is not a gate (design 120).

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const gate = join(root, "tools", "db", "check-no-migration-owner-refs.sh");
const run = (...args: string[]) =>
  spawnSync("bash", [gate, ...args], { encoding: "utf8" });

/** More than the 64 KB pipe buffer, so an early-exit reader would have quit while the writer was still writing. */
const filler = Array.from(
  { length: 6000 },
  (_, i) =>
    `CREATE TABLE IF NOT EXISTS app.zz_filler_${i} (id int); -- padding past the pipe buffer`,
).join("\n");

describe("the H2 gate must not fail open", () => {
  it("a violation on line 2 of a file far larger than the pipe buffer makes it exit 1 and name the file", () => {
    const dir = mkdtempSync(join(tmpdir(), "h2-gate-"));
    writeFileSync(
      join(dir, "0001_big.sql"),
      `-- header\nGRANT SELECT ON app.offer TO migration_owner;\n${filler}\n`,
    );
    writeFileSync(join(dir, "0002_clean.sql"), "SELECT 1;\n");
    const r = run(dir);
    expect(r.status, r.stderr).toBe(1);
    expect(r.stderr).toContain("0001_big.sql");
    expect(r.stderr).not.toContain("0002_clean.sql");
  });

  it("a violation at the bottom of a large file and in a small file are found too", () => {
    const dir = mkdtempSync(join(tmpdir(), "h2-gate-"));
    writeFileSync(
      join(dir, "0001_late.sql"),
      `${filler}\nGRANT SELECT ON app.offer TO migration_owner;\n`,
    );
    writeFileSync(
      join(dir, "0002_small.sql"),
      "GRANT SELECT ON app.offer TO migration_owner;\n",
    );
    const r = run(dir);
    expect(r.status, r.stderr).toBe(1);
    expect(r.stderr).toContain("0001_late.sql");
    expect(r.stderr).toContain("0002_small.sql");
  });

  it("a comment-only mention passes, and an empty directory is refused rather than passed vacuously", () => {
    const dir = mkdtempSync(join(tmpdir(), "h2-gate-"));
    writeFileSync(
      join(dir, "0001_comment.sql"),
      "-- migration_owner is the harness role\nSELECT 1;\n",
    );
    expect(run(dir).status).toBe(0);
    expect(run(mkdtempSync(join(tmpdir(), "h2-gate-empty-"))).status).toBe(2);
  });

  it("proves itself (--self-test) and passes on the real migrations", () => {
    const self = run("--self-test");
    expect(self.status, self.stderr).toBe(0);
    expect(self.stdout).toContain("--self-test: OK");
    const real = run();
    expect(real.status, real.stderr).toBe(0);
  });
});

describe("tools/db/test.sh", () => {
  const lines = readFileSync(join(root, "tools", "db", "test.sh"), "utf8")
    .split("\n")
    .filter((l) => !/^\s*#/.test(l));

  it("delegates to the gate (self-test first, then the scan)", () => {
    const calls = lines.filter((l) =>
      l.includes("check-no-migration-owner-refs.sh"),
    );
    expect(
      calls.map((l) => (l.includes("--self-test") ? "self-test" : "scan")),
    ).toEqual(["self-test", "scan"]);
  });

  it("no longer carries the inline `grep -v '^\\s*--' ... | grep -q` loop", () => {
    expect(
      lines.filter((l) => /grep -v '\^\\s\*--'.*\|\s*grep -q/.test(l)),
    ).toEqual([]);
  });
});
