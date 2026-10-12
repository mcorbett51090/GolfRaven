// supabase/tests/unit/ci-script-sigpipe.test.ts
//
// A CI gate script that runs under `set -o pipefail` must not put an EARLY-EXIT reader (`head -n1`, `grep -q`) on the right of a pipe whose writer can still be writing when
// the reader quits: the writer takes SIGPIPE, the pipeline reports 141, and `set -e` aborts the script (or an `if` reads a MATCH as no match). `tools/db/check-migrations-immutable.sh`'s
// self-test did exactly that with `git ls-tree ... | head -n1`: its listing is a few KB (more than git's 4 KB stdout buffer, so more than one write), and the race was lost in
// about 1 of 50 runs (14 of 600 measured), failing the CI database job in milliseconds on PRs that had nothing to do with migrations (design 119).
//
// The mechanism is shown here DETERMINISTICALLY (a producer that is still writing after the reader has quit, so nothing depends on timing luck); the script is then pinned.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const bash = (script: string): number =>
  spawnSync("bash", ["-c", script], { encoding: "utf8" }).status ?? -1;

/** One line at once, then more after a pause: still writing when `head -n1` has already quit. */
const SLOW_WRITER =
  "(printf 'first\\n'; sleep 0.15; printf 'second\\n'; printf 'third\\n')";

describe("the mechanism: an early-exit reader under pipefail", () => {
  it("makes a still-writing producer exit 141 (SIGPIPE), which pipefail promotes to the pipeline's status", () => {
    expect(bash(`set -o pipefail; ${SLOW_WRITER} | head -n1 >/dev/null`)).toBe(
      141,
    );
  });

  it("is harmless without pipefail (the status is the reader's), which is why the bug only bites strict scripts", () => {
    expect(bash(`${SLOW_WRITER} | head -n1 >/dev/null`)).toBe(0);
  });

  it("does not happen with a reader that consumes all of its input (sed -n 1p), whatever the timing", () => {
    expect(
      bash(`set -o pipefail; ${SLOW_WRITER} | sed -n '1p' >/dev/null`),
    ).toBe(0);
  });

  it("an `if` over `... | grep -q` reads a MATCH as no match when the writer takes SIGPIPE (a gate that fails open)", () => {
    const hit = `set -o pipefail; if (printf 'MATCH\\n'; sleep 0.15; printf 'more\\n') | grep -q MATCH; then exit 0; else exit 1; fi`;
    expect(bash(hit)).toBe(1); // the match was there; the pipeline status said otherwise
    const fixed = `set -o pipefail; if (printf 'MATCH\\n'; sleep 0.15; printf 'more\\n') | grep MATCH >/dev/null; then exit 0; else exit 1; fi`;
    expect(bash(fixed)).toBe(0);
  });
});

describe("the script that lost the race", () => {
  const dir = join(
    dirname(fileURLToPath(import.meta.url)),
    "..",
    "..",
    "..",
    "tools",
    "db",
  );
  const active = (file: string): string[] =>
    readFileSync(join(dir, file), "utf8")
      .split("\n")
      .filter((l) => !/^\s*#/.test(l));

  it("check-migrations-immutable.sh picks its sample with a reader that reads everything, and uses no `| head` anywhere", () => {
    const lines = active("check-migrations-immutable.sh");
    expect(
      lines.some((l) => /git ls-tree .*\|\s*sed -n '1p'/.test(l)),
      "the sample pick",
    ).toBe(true);
    expect(lines.filter((l) => /\|\s*head\b/.test(l))).toEqual([]);
    expect(
      lines.some((l) => /set -euo pipefail/.test(l)),
      "the script is strict, so this class applies",
    ).toBe(true);
  });
});
