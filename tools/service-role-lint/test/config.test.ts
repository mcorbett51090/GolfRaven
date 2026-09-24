import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildConfigIndex, deriveRepoRoot, stripJsonComments } from "../src/config.js";
import { lintDirectory } from "../src/index.js";

// ⛔ M2 BLOCKING (post-P3a re-gate): "the lint's import-map model
// diverges from what Deno actually loads." Each fixture directory below
// reproduces one of the reviewer's four confirmed real-Deno-2.5.2
// bypasses (n1-n4), plus the disallowed-key case and a good control —
// tools/service-role-lint/test/fixtures/m2-config/<case>/, pointed at
// directly as its own `functionsRoot` (these live under this package's
// OWN test fixtures dir, never under a real supabase/functions tree at
// all — see index.ts's MEDIUM-2 note — so a real
// `lintDirectory(supabase/functions)` run never touches them; exercised
// here explicitly instead).
//
// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): moved from
// supabase/functions/__fixtures__/m2-config to
// tools/service-role-lint/test/fixtures/m2-config (fixtures no longer
// live anywhere under supabase/functions).

const FIXTURES_ROOT = join(import.meta.dirname, "fixtures", "m2-config");
const PINNED = new Set(["https://esm.sh/zod@3.23.8"]);

describe("config.ts — M2 (post-P3a re-gate): config files anywhere, regardless of importers", () => {
  it("n1: flags a `scopes` key in deno.json (never inspected by the old host-trust model)", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n1-scopes"), PINNED, join(FIXTURES_ROOT, "n1-scopes"));
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('disallowed top-level key "scopes"'))),
    ).toBe(true);
  });

  it("n2: deno.json AND import_map.json both present is flagged as ambiguous -- neither silently wins", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n2-both-present"), PINNED, join(FIXTURES_ROOT, "n2-both-present"));
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes("more than one config file present"))).toBe(true);
    // Fails CLOSED: the directory resolves to an EMPTY map, so import_map.json's
    // "admin" target never silently wins and never resolves to anything.
    const resolved = index.resolveFor(join(FIXTURES_ROOT, "n2-both-present", "index.ts"));
    expect(resolved).toEqual({});
  });

  it("n3: a per-function fn/deno.json is found by walking UP from fn/lib/x.ts (two directory levels), not just checking the file's own directory merged with the root", () => {
    const results = lintDirectory(join(FIXTURES_ROOT, "n3-nested-function"), join(FIXTURES_ROOT, "n3-nested-function"));
    const flat = results.flatMap((r) => r.findings);
    expect(
      flat.some((f) => f.rule === "banned-import-specifier" && f.message.includes("not on the committed pinned-import-targets allow-list")),
    ).toBe(true);
  });

  it("n4: deno.jsonc is read (was never read at all by the old model)", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n4-jsonc"), PINNED, join(FIXTURES_ROOT, "n4-jsonc"));
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes('imports["admin"]') && m.includes("not on the committed pinned-import-targets allow-list"))).toBe(true);
  });

  it("disallowed-key: an `importMap` key is rejected outright, even alongside an otherwise-clean, pinned `imports` entry", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "disallowed-key"), PINNED, join(FIXTURES_ROOT, "disallowed-key"));
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('disallowed top-level key "importMap"'))),
    ).toBe(true);
  });

  it("good control: a per-function deno.json whose only target is pinned produces ZERO findings, config or otherwise", () => {
    const results = lintDirectory(join(FIXTURES_ROOT, "good-control"), join(FIXTURES_ROOT, "good-control"));
    expect(results).toEqual([]);
  });
});

describe("config.ts — allowed top-level keys", () => {
  it("does not flag compilerOptions/lint/fmt/tasks alongside imports", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "good-control", "somefn"), PINNED, join(FIXTURES_ROOT, "good-control", "somefn"));
    expect(index.results).toEqual([]);
  });
});

// ⛔ BLOCKING round 2 (post-P3a re-gate): "config-level remaps and
// lockfile redirects." R1/R2/R3/R5 + the lockfile cases, each built as
// its own /tmp tree (unlike n1-n4, these need real ancestor/ambient
// directory structure that a static fixture under the lint's own
// __fixtures__ directory can't cleanly represent, since __fixtures__ is
// itself always INSIDE supabase/functions — the whole point of R2/R3/R5
// is a config file OUTSIDE functionsRoot).
describe("config.ts — round 2 (post-P3a re-gate): config-level remaps and lockfile redirects", () => {
  let tmpRoot: string | undefined;

  afterEach(() => {
    if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
    tmpRoot = undefined;
  });

  it("R1: a relative-path KEY inside the reviewed deno.json ('./fn/lib/x.ts') is rejected outright, regardless of its target", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-r1-"));
    const functionsRoot = join(tmpRoot, "functions");
    mkdirSync(functionsRoot, { recursive: true });
    writeFileSync(
      join(functionsRoot, "deno.json"),
      JSON.stringify({ imports: { "./fn/lib/x.ts": "../../outside/admin.ts" } }),
    );

    const index = buildConfigIndex(functionsRoot, new Set(), functionsRoot);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('imports key "./fn/lib/x.ts" is not a bare specifier'))),
    ).toBe(true);
    // The invalid key never resolves to anything -- fails closed.
    expect(index.resolveFor(join(functionsRoot, "fn", "lib", "x.ts"))).toEqual({});
  });

  it("R1b: even with a VALID bare key, a relative TARGET is banned outright (not deferred to the per-specifier escape check)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-r1b-"));
    const functionsRoot = join(tmpRoot, "functions");
    mkdirSync(functionsRoot, { recursive: true });
    writeFileSync(join(functionsRoot, "deno.json"), JSON.stringify({ imports: { admin: "../../outside/admin.ts" } }));

    const index = buildConfigIndex(functionsRoot, new Set(), functionsRoot);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('imports["admin"] = "../../outside/admin.ts" is a relative/absolute-path target'))),
    ).toBe(true);
  });

  it("R2: a repo-ROOT config with a workspace + remap is flagged by its mere PRESENCE above functionsRoot, regardless of content", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-r2-"));
    writeFileSync(
      join(tmpRoot, "deno.json"),
      JSON.stringify({ workspace: ["./supabase/functions"], imports: { admin: "https://evil.example.com/admin.ts" } }),
    );
    const functionsRoot = join(tmpRoot, "supabase", "functions");
    mkdirSync(functionsRoot, { recursive: true });

    const index = buildConfigIndex(functionsRoot, new Set(), tmpRoot);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes("a deno.json file exists ABOVE the functions root"))),
    ).toBe(true);
  });

  it("R3: a repo/deno.json (one level above a nested functionsRoot) remapping a path inside it is flagged by presence alone", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-r3-"));
    const repoDir = join(tmpRoot, "repo");
    mkdirSync(repoDir, { recursive: true });
    writeFileSync(join(repoDir, "deno.json"), JSON.stringify({ imports: { "./supabase/functions/fn/lib/x.ts": "https://evil.example.com/x.ts" } }));
    const functionsRoot = join(repoDir, "supabase", "functions");
    mkdirSync(functionsRoot, { recursive: true });

    const index = buildConfigIndex(functionsRoot, new Set(), repoDir);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes("a deno.json file exists ABOVE the functions root"))),
    ).toBe(true);
  });

  it("R5: a supabase/deno.json (directly above functionsRoot) is flagged the same way", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-r5-"));
    const supabaseDir = join(tmpRoot, "supabase");
    mkdirSync(supabaseDir, { recursive: true });
    writeFileSync(join(supabaseDir, "deno.json"), JSON.stringify({ imports: { admin: "https://evil.example.com/admin.ts" } }));
    const functionsRoot = join(supabaseDir, "functions");
    mkdirSync(functionsRoot, { recursive: true });

    const index = buildConfigIndex(functionsRoot, new Set(), tmpRoot);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes("a deno.json file exists ABOVE the functions root"))),
    ).toBe(true);
  });

  it("no ancestor finding when functionsRoot IS repoRoot (nothing above it to scan)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-noancestor-"));
    const index = buildConfigIndex(tmpRoot, new Set(), tmpRoot);
    expect(index.results).toEqual([]);
  });

  it("lock redirect: a non-empty deno.lock 'redirects' table is banned outright", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-redirect-"));
    const pinned = new Set(["https://esm.sh/zod@3.23.8"]);
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "https://esm.sh/zod@3.23.8" } }));
    writeFileSync(
      join(tmpRoot, "deno.lock"),
      JSON.stringify({
        version: "4",
        remote: { "https://esm.sh/zod@3.23.8": "sha256-aaaa" },
        redirects: { "https://esm.sh/zod@3.23.8": "https://evil.example.com/zod.ts" },
      }),
    );

    const index = buildConfigIndex(tmpRoot, pinned, tmpRoot);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('non-empty "redirects" table'))),
    ).toBe(true);
  });

  it("lock non-pinned remote key: every 'remote' entry must itself be an exact pinned target", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-remote-"));
    const pinned = new Set(["https://esm.sh/zod@3.23.8"]);
    writeFileSync(
      join(tmpRoot, "deno.lock"),
      JSON.stringify({ version: "4", remote: { "https://esm.sh/zod@3.23.8": "sha256-aaaa", "https://evil.example.com/x.ts": "sha256-bbbb" } }),
    );

    const index = buildConfigIndex(tmpRoot, pinned, tmpRoot);
    expect(
      index.results.some((r) => r.findings.some((f) => f.message.includes('"remote" key "https://evil.example.com/x.ts" is not on the committed pinned-import-targets allow-list'))),
    ).toBe(true);
  });

  it("lock disallowed top-level key / workspace imports override are both flagged", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-badkeys-"));
    writeFileSync(
      join(tmpRoot, "deno.lock"),
      JSON.stringify({ version: "4", remote: {}, npm: { evil: true }, workspace: { members: { "./fn": { imports: { admin: "https://evil.example.com/x.ts" } } } } }),
    );

    const index = buildConfigIndex(tmpRoot, new Set(), tmpRoot);
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes('disallowed top-level key "npm"'))).toBe(true);
    expect(messages.some((m) => m.includes('"workspace" contains an "imports"/"importMap" override'))).toBe(true);
  });

  it("good control: a deno.lock with ONLY pinned remotes, alongside a valid pinned import, produces zero findings", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-good-"));
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "https://esm.sh/zod@3.23.8" } }));
    writeFileSync(join(tmpRoot, "deno.lock"), JSON.stringify({ version: "4", remote: { "https://esm.sh/zod@3.23.8": "sha256-aaaa" } }));
    writeFileSync(join(tmpRoot, "index.ts"), `import { z } from "zod"; export const s = z.object({});`);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toEqual([]);
  });

  it("good control: a relative import done directly (never through the map) produces zero findings", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-relative-good-"));
    mkdirSync(join(tmpRoot, "_shared"), { recursive: true });
    mkdirSync(join(tmpRoot, "fn"), { recursive: true });
    writeFileSync(join(tmpRoot, "_shared", "helper.ts"), `export function helper(x: unknown) { return x; }`);
    writeFileSync(join(tmpRoot, "fn", "index.ts"), `import { helper } from "../_shared/helper.ts"; export const h = helper;`);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toEqual([]);
  });
});

// ⛔ Follow-up (post-P3a re-gate round 2): "the lint walker must track
// visited real paths. A symlink loop should produce a clear finding (or
// be skipped), never a stack crash."
describe("config.ts / index.ts — symlink loop protection (follow-up, post-P3a re-gate round 2)", () => {
  let tmpRoot: string | undefined;

  afterEach(() => {
    if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
    tmpRoot = undefined;
  });

  it("a directory symlinked to its own ancestor produces a clear finding, not a stack overflow", async () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-symlink-loop-"));
    mkdirSync(join(tmpRoot, "fn"), { recursive: true });
    writeFileSync(join(tmpRoot, "fn", "index.ts"), `export const ok = 1;`);
    const { symlinkSync } = await import("node:fs");
    // fn/loop -> tmpRoot itself: walking into it would re-descend into
    // "fn" again, forever, without the visited-real-path guard.
    symlinkSync(tmpRoot, join(tmpRoot, "fn", "loop"), "dir");

    let results: ReturnType<typeof lintDirectory> | undefined;
    expect(() => {
      results = lintDirectory(tmpRoot!, tmpRoot);
    }).not.toThrow();
    const messages = (results ?? []).flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes("already-visited real path"))).toBe(true);
  });
});

// ⛔ FIX (should-fix, post-P3a re-gate round 3): "deriveRepoRoot fails
// open when there's no `.git`. It must throw unless `repoRoot` is passed
// explicitly." SUPERSEDES the old fail-open fallback (silently returning
// startDir with no ancestor-config scan at all, and no error telling
// anyone that had happened) -- see config.ts's own note on this, right
// above the function.
describe("deriveRepoRoot — should-fix (post-P3a re-gate round 3): throws instead of failing open", () => {
  let tmpRoot: string | undefined;

  afterEach(() => {
    if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
    tmpRoot = undefined;
  });

  it("throws when no .git ancestor exists anywhere above startDir", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-derive-repo-root-"));
    // mkdtemp()'d directories live under the OS temp dir, which has no
    // `.git` ancestor in any normal environment -- this is exactly the
    // "checkout/cache layout lost .git" shape the fix targets.
    expect(() => deriveRepoRoot(tmpRoot!)).toThrow(/no ".git" ancestor/);
  });

  it("still returns the ancestor directory normally when a .git IS found (no regression to the happy path)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-derive-repo-root-git-"));
    mkdirSync(join(tmpRoot, ".git"), { recursive: true });
    const nested = join(tmpRoot, "supabase", "functions");
    mkdirSync(nested, { recursive: true });
    expect(deriveRepoRoot(nested)).toBe(tmpRoot);
  });

  it("lintDirectory(functionsRoot) with NO explicit repoRoot now throws the same way, end to end, when functionsRoot has no .git ancestor", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-derive-repo-root-e2e-"));
    expect(() => lintDirectory(tmpRoot!)).toThrow(/no ".git" ancestor/);
  });
});

describe("stripJsonComments", () => {
  it("strips // and /* */ comments", () => {
    const out = stripJsonComments('{\n  // a comment\n  "a": 1, /* inline */ "b": 2\n}');
    expect(JSON.parse(out)).toEqual({ a: 1, b: 2 });
  });

  it("does NOT strip a // or /* sequence that appears INSIDE a string literal", () => {
    const out = stripJsonComments('{"url": "https://esm.sh/zod@3.23.8", "note": "a /* not a comment */ still a string"}');
    expect(JSON.parse(out)).toEqual({
      url: "https://esm.sh/zod@3.23.8",
      note: "a /* not a comment */ still a string",
    });
  });
});
