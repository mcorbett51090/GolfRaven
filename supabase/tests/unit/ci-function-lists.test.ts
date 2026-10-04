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

/** The full text of the step whose name starts with `stepNamePrefix` (its `- name:` line up to the next step). */
function stepBlock(stepNamePrefix: string): string {
  const start = CI.indexOf(`- name: ${stepNamePrefix}`);
  if (start < 0) throw new Error(`ci.yml has no step named "${stepNamePrefix}..."`);
  const next = CI.indexOf("\n      - name:", start + 1);
  return CI.slice(start, next < 0 ? undefined : next);
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

  // PR #34 gate NIT: a list that is complete is still no proof if the step can be skipped or made non-fatal. None of the three may carry a step-level
  // `if:` (a skipped step reports success) or `continue-on-error:` (a failing step reports success). Comment lines are not YAML keys and are ignored.
  for (const step of STEPS) {
    it(`"${step}" has no step-level if: and no continue-on-error: (it always runs, and its failure fails the job)`, () => {
      const keys = stepBlock(step)
        .split("\n")
        .filter((l) => !/^\s*#/.test(l))
        // a step-level key sits at the step's own indent (8 spaces: `      - name:` is the dash at 6, its keys at 8); deeper lines are inside run: / env: / with:
        .filter((l) => /^ {8}[A-Za-z_-]+:/.test(l) || /^ {6}- [A-Za-z_-]+:/.test(l))
        .map((l) => l.trim().replace(/^- /, "").split(":")[0]!);
      expect(keys, "the step's keys were parsed").toContain("run");
      expect(keys).not.toContain("if");
      expect(keys).not.toContain("continue-on-error");
    });
  }

  it("the three lists are the same list (a function in one and not the others is the drift this test exists for)", () => {
    const [a, b, c] = STEPS.map((st) => [...new Set(listedPaths(st))].sort());
    expect(b).toEqual(a);
    expect(c).toEqual(a);
  });

  // Partner auth S0 (PA-0a, PA-0b): the WebAuthn wrapper is a shared module, not an entrypoint, so the loops above do not reach it; it is named in all three lists
  // (type-checked, hash-proved, and run under the tampered lock), and the pure Deno suite over it runs with the network denied.
  for (const step of STEPS) {
    it(`"${step}" lists the partner WebAuthn wrapper`, () => {
      expect(listedPaths(step)).toContain("supabase/functions/_shared/partner/webauthn.ts");
    });
  }

  const DENO_UNIT_STEP = "Run supabase/tests/deno-unit";
  const PARTNER_NPM_TAMPER_STEP = "deno cache --frozen npm tamper test (partner auth S0";

  /** The shell lines of a step's run block with the YAML comments and line continuations removed, so a flag is matched where it is really passed. */
  function runText(stepNamePrefix: string): string {
    const block = stepBlock(stepNamePrefix);
    return block.slice(block.indexOf("\n        run:")).replace(/\\\n\s*/g, " ");
  }

  it("the pure Deno suite step runs `deno test` over supabase/tests/deno-unit with --deny-net and --cached-only, against the committed frozen lock, and never grants net", () => {
    const run = runText(DENO_UNIT_STEP);
    const testLine = run.split("\n").find((l) => /^\s+deno test /.test(l));
    expect(testLine, "a `deno test` line").toBeDefined();
    expect(testLine).toContain("--deny-net");
    expect(testLine).toContain("--cached-only");
    expect(testLine).toContain("--frozen");
    expect(testLine).toContain("--lock=supabase/tests/deno.lock");
    expect(testLine).toContain("--config supabase/functions/deno.json");
    expect(testLine).toContain("supabase/tests/deno-unit/");
    expect(run).not.toMatch(/--allow-(net|all)|\s-A\b/);
    expect(run).toMatch(/deno cache [^\n]*--frozen/);
  });

  for (const step of [DENO_UNIT_STEP, PARTNER_NPM_TAMPER_STEP]) {
    it(`"${step}..." has no step-level if: and no continue-on-error: (it always runs, and its failure fails the job)`, () => {
      const keys = stepBlock(step)
        .split("\n")
        .filter((l) => !/^\s*#/.test(l))
        .filter((l) => /^ {8}[A-Za-z_-]+:/.test(l) || /^ {6}- [A-Za-z_-]+:/.test(l))
        .map((l) => l.trim().replace(/^- /, "").split(":")[0]!);
      expect(keys).toContain("run");
      expect(keys).not.toContain("if");
      expect(keys).not.toContain("continue-on-error");
    });
  }

  it("the partner npm tamper step names the direct pin, uses a fresh DENO_DIR per target and requires the specific checksum message", () => {
    const run = runText(PARTNER_NPM_TAMPER_STEP);
    expect(run).toContain("@simplewebauthn/server@14.0.3");
    expect(run).toMatch(/DENO_DIR="\$TAMPER_DIR\/deno-dir-\$SLUG"/);
    expect(run).toContain("Tarball checksum did not match");
    expect(run).toContain("--frozen");
  });

  it("every deno test file under supabase/tests/deno-unit is a pure suite: no database, no network, no process or file access", () => {
    const dir = join(REPO_ROOT, "supabase", "tests", "deno-unit");
    const files = readdirSync(dir).filter((f) => f.endsWith(".ts"));
    expect(files).toContain("partner-webauthn.deno.test.ts");
    for (const f of files) {
      const text = readFileSync(join(dir, f), "utf8");
      expect(text, f).not.toMatch(/\bfetch\(|Deno\.connect|Deno\.listen|WebSocket|postgres|Deno\.(readFile|writeFile|Command|env)|Deno\.run/);
    }
  });

  it("the parser reads a block the way the workflow writes it (a self-test on a made-up CI text is not possible here, so pin the real shape)", () => {
    expect(listedPaths("deno check (frozen lockfile)")).toContain("supabase/functions/evidence/index.ts");
    expect(listedPaths("deno check (frozen lockfile)")).not.toContain("supabase/functions/evidence/");
  });
});
