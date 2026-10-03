/**
 * LOW-1 (PR #38 gate): the fixture recorder's VERIFY mode must run in CI, or a server change to a wire shape leaves `test/fixtures/edge-contract.json`
 * (and every mobile test built on it) silently stale. Pins the step in `.github/workflows/ci.yml`: present in the `verify` job, the exact command,
 * after the install and build, and a plain step that cannot be skipped or made non-fatal (the same rule `supabase/tests/unit/ci-function-lists.test.ts`
 * holds the deno steps to: a step-level `if:` reports success when skipped, `continue-on-error:` reports success when it fails).
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const CI = readFileSync(new URL("../../../.github/workflows/ci.yml", import.meta.url), "utf8");
const COMMAND = "pnpm --filter @golfraven/rules exec vitest run --config ../../apps/mobile/scripts/record-edge-contract.vitest.config.ts";
const PREFIX = "Mobile edge-contract fixture drift check";

function jobBlock(name: string): string {
  const start = CI.indexOf(`\n  ${name}:`);
  if (start < 0) throw new Error(`ci.yml has no job "${name}"`);
  const next = CI.slice(start + 1).search(/\n  [A-Za-z0-9_-]+:\n/);
  return next < 0 ? CI.slice(start) : CI.slice(start, start + 1 + next);
}
function stepBlock(job: string, prefix: string): string {
  const at = job.indexOf(`- name: ${prefix}`);
  if (at < 0) throw new Error(`no step named "${prefix}..."`);
  const start = job.lastIndexOf("\n", at) + 1; // include the step's own indentation
  const next = job.indexOf("\n      - name:", start + 1);
  return job.slice(start, next < 0 ? undefined : next);
}

describe("ci.yml runs the edge-contract recorder in verify mode", () => {
  const verify = jobBlock("verify");
  const step = stepBlock(verify, PREFIX);

  it("is a step of the verify job, running exactly the documented verify command", () => {
    const runLine = step.split("\n").find((l) => /^ {8}run:/.test(l));
    expect(runLine).toBe(`        run: ${COMMAND}`);
    expect(runLine).not.toContain("RECORD_EDGE_CONTRACT"); // verify mode: the recording flag would REWRITE the fixture instead of checking it
    expect(jobBlock("db-tests")).not.toContain(PREFIX);
  });

  it("the command is the one the recorder documents in its own header", () => {
    const header = readFileSync(new URL("../scripts/record-edge-contract.rec.ts", import.meta.url), "utf8");
    expect(header).toContain(`${COMMAND}            # verify`);
  });

  it("runs after the frozen install and the build", () => {
    expect(verify.indexOf(PREFIX)).toBeGreaterThan(verify.indexOf("- name: Install (frozen lockfile)"));
    expect(verify.indexOf(PREFIX)).toBeGreaterThan(verify.indexOf("run: pnpm -r build"));
  });

  it("has no step-level if: and no continue-on-error: (it always runs, and its failure fails the job)", () => {
    const keys = step
      .split("\n")
      .filter((l) => !/^\s*#/.test(l))
      .filter((l) => /^ {8}[A-Za-z_-]+:/.test(l) || /^ {6}- [A-Za-z_-]+:/.test(l))
      .map((l) => l.trim().replace(/^- /, "").split(":")[0]!);
    expect(keys, "the step's keys were parsed").toEqual(["name", "run"]);
  });

  it("the config the command names exists", () => {
    expect(() => readFileSync(new URL("../scripts/record-edge-contract.vitest.config.ts", import.meta.url), "utf8")).not.toThrow();
  });
});
