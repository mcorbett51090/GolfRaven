// supabase/tests/unit/ci-function-lists.test.ts
//
// Edge role PR4c (PR4b gate LOW-4): every Edge Function entrypoint is in the CI `deno check` list AND the CI `deno cache --frozen` lists (the pin proof and its tamper test). Both lists
// were maintained by hand and had drifted: `me-export` and `me-push-token` were not in either, so a type error or an unpinned import in those two
// functions would have shipped past CI (the pin proof, `deno cache --frozen`, is the one that catches a tampered or unlocked dependency, and it only
// proves the files it is given). A function added tomorrow fails THIS test until it is added to both.
//
// The test reads the workflow text (not YAML-parsed: the lists are the shell lines of two `run:` blocks) and the directory listing of
// supabase/functions, so the lists cannot be wrong in the same direction as the thing they are checked against.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = join(import.meta.dirname, "..", "..", "..");
const FUNCTIONS_DIR = join(REPO_ROOT, "supabase", "functions");
const CI = readFileSync(join(REPO_ROOT, ".github", "workflows", "ci.yml"), "utf8");

/** Every directory under supabase/functions that holds an `index.ts` (an Edge Function entrypoint). `_shared` is a library, not a function. */
function functionEntrypoints(): string[] {
  return readdirSync(FUNCTIONS_DIR, { withFileTypes: true })
    .filter((d) => d.isDirectory() && !d.name.startsWith("_") && existsSync(join(FUNCTIONS_DIR, d.name, "index.ts")))
    .map((d) => `supabase/functions/${d.name}/index.ts`)
    .sort();
}

/** The `supabase/functions/**` paths named in the `run:` block of the step whose name starts with `stepNamePrefix`. */
function listedPaths(stepNamePrefix: string): string[] {
  const start = CI.indexOf(`- name: ${stepNamePrefix}`);
  if (start < 0) throw new Error(`ci.yml has no step named "${stepNamePrefix}..."`);
  const next = CI.indexOf("\n      - name:", start + 1);
  const block = CI.slice(start, next < 0 ? undefined : next);
  const run = block.slice(block.indexOf("\n        run:"));
  if (!/\n        run: \|/.test(run)) throw new Error(`step "${stepNamePrefix}" has no multi-line run block`);
  return [...run.matchAll(/^\s+(supabase\/functions\/[^\s\\]+)/gm)].map((m) => m[1]!);
}

describe("CI runs deno check and deno cache --frozen over EVERY Edge Function entrypoint", () => {
  const entrypoints = functionEntrypoints();

  it("finds the functions it is meant to check (so an empty directory listing cannot pass vacuously)", () => {
    expect(entrypoints.length).toBeGreaterThanOrEqual(13);
    expect(entrypoints).toContain("supabase/functions/retention-purge/index.ts");
    expect(entrypoints).toContain("supabase/functions/me-export/index.ts");
    expect(entrypoints).toContain("supabase/functions/me-push-token/index.ts");
  });

  // the third list is the tamper test's: it runs `deno cache --frozen` against a tampered lockfile over the same files and must reject it
  const STEPS = ["deno check (frozen lockfile)", "deno cache --frozen (proves the pinned hashes, tamper-evident)", "deno cache --frozen tamper test (proves the pin-proof step itself catches a real tamper)"];
  for (const step of STEPS) {
    it(`"${step}" lists every supabase/functions/*/index.ts`, () => {
      const listed = listedPaths(step);
      expect(listed.length, "the step's run block was parsed").toBeGreaterThan(0);
      const missing = entrypoints.filter((e) => !listed.includes(e));
      expect(missing, `missing from the CI step "${step}" (add each to its run block)`).toEqual([]);
      // and nothing in the list that is not a function (a stale entry after a rename would fail deno, but say so plainly)
      const stale = listed.filter((l) => l.endsWith("/index.ts") && !entrypoints.includes(l));
      expect(stale, `listed in "${step}" but no such function`).toEqual([]);
      // the shared module the functions all import is checked too
      expect(listed).toContain("supabase/functions/_shared/privileged.ts");
    });
  }

  it("the three lists are the same list (a function in one and not the others is the drift this test exists for)", () => {
    const [a, b, c] = STEPS.map((st) => [...new Set(listedPaths(st))].sort());
    expect(b).toEqual(a);
    expect(c).toEqual(a);
  });

  it("the parser reads a block the way the workflow writes it (a self-test on a made-up CI text is not possible here, so pin the real shape)", () => {
    expect(listedPaths("deno check (frozen lockfile)")).toContain("supabase/functions/evidence/index.ts");
    expect(listedPaths("deno check (frozen lockfile)")).not.toContain("supabase/functions/evidence/");
  });
});
