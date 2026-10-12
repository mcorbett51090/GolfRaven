// supabase/tests/unit/ci-tap-verdict.test.ts
//
// tools/db/tap-verdict.sh judges one pgTAP file's output for tools/db/test.sh's psql fallback (the path taken when pg_prove is not installed), the way pg_prove does: no `not ok`, no ERROR,
// and exactly as many `ok` / `not ok` lines as the `1..N` plan says (design 124). The fallback used to `grep` the output instead, which failed two files that pg_prove passes (their groups are each
// a BEGIN ... ROLLBACK, which rolls pgTAP's counter back, so its `# Looks like you planned 13 tests but ran 4` comment disagrees with the 13 ok lines that were printed) and, being an early-exit
// `grep -q` under `set -o pipefail`, could have read a match as no match on an output larger than the pipe buffer.

import { spawnSync } from "node:child_process";
import { readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repo = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const script = join(repo, "tools", "db", "tap-verdict.sh");

/** Runs the verdict over `tap`; `big` runs it as the fallback does, with the text in a variable, under pipefail. */
const verdict = (tap: string) => {
  const r = spawnSync("bash", [script], { input: tap, encoding: "utf8" });
  return { status: r.status, out: r.stdout.trim() };
};
const verdictViaVariable = (tap: string) => {
  const r = spawnSync(
    "bash",
    ["-c", `set -euo pipefail; OUTPUT="$(cat)"; if V="$(printf '%s\\n' "$OUTPUT" | bash '${script}')"; then echo "pass"; else echo "fail: $V"; fi`],
    { input: tap, encoding: "utf8" },
  );
  return r.stdout.trim();
};

const oks = (n: number, from = 1) =>
  Array.from({ length: n }, (_, i) => `ok ${from + i} - test ${from + i}`).join("\n");

describe("tap-verdict.sh", () => {
  it("passes a complete file", () => {
    expect(verdict(`1..3\n${oks(3)}\n`)).toEqual({ status: 0, out: "" });
  });

  it("passes the shape of 52_partner_auth_alarm_purge.sql and 67_partner_credential_list_reach.sql: every ok line printed, but pgTAP's counter rolled back so its comment disagrees", () => {
    const tap = `1..13\nCREATE FUNCTION\n${oks(4)}\nBEGIN\n${oks(5, 5)}\nROLLBACK\nBEGIN\n${oks(4, 10)}\nROLLBACK\n# Looks like you planned 13 tests but ran 4\n`;
    expect(verdict(tap)).toEqual({ status: 0, out: "" });
  });

  it("fails a `not ok` line, and says which", () => {
    const r = verdict(`1..2\nok 1 - a\nnot ok 2 - b\n`);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/`not ok` line: not ok 2 - b/);
  });

  it("fails a psql ERROR line, even when every planned test printed ok", () => {
    const r = verdict(`1..2\nok 1 - a\npsql:f.sql:9: ERROR:  permission denied\nok 2 - b\n`);
    expect(r.status).toBe(1);
    expect(r.out).toMatch(/ERROR line/);
  });

  it("fails a file with no plan, an empty output, and a count that is not the plan's (fewer or more)", () => {
    expect(verdict(`${oks(2)}\n`).out).toMatch(/no `1\.\.N` plan/);
    expect(verdict("").status).toBe(1);
    expect(verdict(`1..5\n${oks(3)}\n`).out).toMatch(/planned 5 but printed 3/);
    expect(verdict(`1..2\n${oks(3)}\n`).out).toMatch(/planned 2 but printed 3/);
  });

  it("finds a `not ok` on line 2 of an output far larger than the pipe buffer when the text sits in a variable under pipefail (the early-exit grep -q class)", () => {
    const filler = oks(12000, 2);
    const big = `1..12001\nnot ok 1 - early failure\n${filler}\n`;
    expect(big.length).toBeGreaterThan(200_000);
    expect(verdictViaVariable(big)).toMatch(/^fail: a `not ok` line: not ok 1 - early failure/);
    // and the same size, clean, passes: reading everything is not a way of failing
    expect(verdictViaVariable(`1..12001\n${oks(12001)}\n`)).toBe("pass");
  });
});

describe("tools/db/test.sh's psql fallback", () => {
  const testSh = readFileSync(join(repo, "tools", "db", "test.sh"), "utf8")
    .split("\n")
    .filter((l) => !/^\s*#/.test(l));

  it("judges each file with tap-verdict.sh", () => {
    expect(testSh.some((l) => /printf '%s\\n' "\$OUTPUT" \| bash "\$ROOT_DIR\/tools\/db\/tap-verdict\.sh"/.test(l))).toBe(true);
  });

  it("no longer greps the output (an early-exit `grep -q` after echo or printf of $OUTPUT is the fail-open shape)", () => {
    expect(testSh.filter((l) => /(?:echo|printf)\b[^|]*\$OUTPUT[^|]*\|\s*grep\b/.test(l))).toEqual([]);
  });

  it("the verdict script is executable (a mode lost on a checkout would make the fallback fail every file)", () => {
    expect(statSync(script).mode & 0o111).not.toBe(0);
  });
});
