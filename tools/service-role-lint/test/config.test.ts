import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { buildConfigIndex, deriveRepoRoot, lockLayoutProblems, npmLockTableProblems, semverRangeProblem, stripJsonComments } from "../src/config.js";
import { lintDirectory } from "../src/index.js";
import { importMapTargetProblem } from "../src/lint.js";

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
// A well-formed sha512 integrity string (86 base64 chars + "=="); the value is arbitrary.
const VALID_INTEGRITY = "sha512-" + "A".repeat(86) + "==";

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
      flat.some((f) => f.rule === "banned-import-specifier" && /not on the committed pinned-import-targets allow-list|positive allow-list/.test(f.message)),
    ).toBe(true);
  });

  it("n4: deno.jsonc is read (was never read at all by the old model)", () => {
    const index = buildConfigIndex(join(FIXTURES_ROOT, "n4-jsonc"), PINNED, join(FIXTURES_ROOT, "n4-jsonc"));
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes('imports["admin"]') && /not on the committed pinned-import-targets allow-list|positive allow-list/.test(m))).toBe(true);
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

describe("config.ts — exact-pinned npm: targets (esm.sh stub -> npm: migration)", () => {
  const PINNED_NPM = new Set(["npm:zod@4.6.5", "npm:@noble/hashes@2.4.0/utils.js"]);

  it("good control: exact-pinned npm: targets (bare package, and scoped package with a sub-path) that ARE on the allow-list produce zero findings", () => {
    const dir = join(FIXTURES_ROOT, "npm-pinned-good");
    expect(buildConfigIndex(dir, PINNED_NPM, dir).results).toEqual([]);
  });

  it("must-fail: `npm:zod@^4` (a range) is rejected as not an exact pin", () => {
    const dir = join(FIXTURES_ROOT, "npm-unpinned");
    const messages = buildConfigIndex(dir, PINNED_NPM, dir).results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes('imports["zod"]') && m.includes("not an exact version pin"))).toBe(true);
  });

  it("must-fail: an unpinned npm: target is rejected EVEN WHEN it is (wrongly) listed on the pinned allow-list", () => {
    const dir = join(FIXTURES_ROOT, "npm-unpinned");
    const listed = new Set(["npm:zod@^4"]);
    const messages = buildConfigIndex(dir, listed, dir).results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes("not an exact version pin"))).toBe(true);
  });

  it.each(["npm:zod", "npm:zod@4", "npm:zod@4.6", "npm:zod@latest", "npm:zod@*", "npm:zod@>=4", "npm:zod@~4.6.5", "npm:/zod@4.6.5", "npm:zod@4.6.5/../evil.js"])(
    "must-fail: `%s` is not an exact pin",
    (target) => {
      const dir = mkdtempSync(join(tmpdir(), "srl-npm-unpinned-"));
      try {
        writeFileSync(join(dir, "deno.json"), JSON.stringify({ imports: { zod: target } }));
        const messages = buildConfigIndex(dir, new Set([target]), dir).results.flatMap((r) => r.findings.map((f) => f.message));
        expect(messages.some((m) => m.includes("not an exact version pin"))).toBe(true);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it("an exact pin that is NOT on the allow-list is still rejected by the allow-list (exactness is necessary, not sufficient)", () => {
    const dir = mkdtempSync(join(tmpdir(), "srl-npm-notlisted-"));
    try {
      writeFileSync(join(dir, "deno.json"), JSON.stringify({ imports: { lodash: "npm:lodash@4.17.21" } }));
      const messages = buildConfigIndex(dir, PINNED_NPM, dir).results.flatMap((r) => r.findings.map((f) => f.message));
      expect(messages.some((m) => m.includes("not on the committed pinned-import-targets allow-list"))).toBe(true);
      expect(messages.some((m) => m.includes("not an exact version pin"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("config.ts — import-map target bypasses (supply-chain gate: Deno normalises what the lint compared literally)", () => {
  const BYPASS_ROOT = join(FIXTURES_ROOT, "target-bypass");
  const cases = readdirSync(BYPASS_ROOT).sort();

  it("has a fixture per bypass shape (guards against the fixture dir silently emptying)", () => {
    expect(cases).toEqual([
      "backslash-mixed-segments",
      "backslash-std-dotdot",
      "backslash-x-dotdot",
      "blob-scheme",
      "cdn-esm-run",
      "cdn-esm-sh-trailing-dot",
      "cdn-jsdelivr-range",
      "cdn-jspm",
      "data-base64-no-spaces",
      "deno-land-port",
      "deno-land-unversioned",
      "deno-land-x-no-v",
      "dot-segment-normalised",
      "esm-sh-range",
      "file-scheme",
      "http-deno-land",
      "idn-cyrillic-host",
      "idn-punycode-host",
      "jsonc-uppercase-scheme",
      "jsr-range",
      "node-scheme",
      "npm-build-metadata",
      "npm-embedded-tab",
      "npm-leading-space",
      "npm-percent-subpath",
      "npm-uppercase-scheme",
      "userinfo-host",
    ]);
  });

  it.each(cases)("must-fail fixture %s: rejected at the config level even though the target is LISTED on the allow-list", (name) => {
    const dir = join(BYPASS_ROOT, name);
    const file = existsSync(join(dir, "deno.jsonc")) ? "deno.jsonc" : "deno.json";
    const raw = readFileSync(join(dir, file), "utf8");
    const parsed = JSON.parse(file.endsWith("c") ? stripJsonComments(raw) : raw) as { imports: Record<string, string> };
    const listed = new Set(Object.values(parsed.imports));
    const messages = buildConfigIndex(dir, listed, dir).results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.length).toBeGreaterThan(0);
    expect(messages.some((m) => m.includes("rejected even if listed on the pinned-import-targets allow-list"))).toBe(true);
  });

  it("must-pass control: the REAL committed import map (npm: pins + the two deno.land URLs) has zero target problems", () => {
    const imports = (JSON.parse(readFileSync(join(import.meta.dirname, "..", "..", "..", "supabase", "functions", "deno.json"), "utf8")) as { imports: Record<string, string> }).imports;
    expect(Object.keys(imports).length).toBeGreaterThanOrEqual(6);
    for (const target of Object.values(imports)) expect(importMapTargetProblem(target), target).toBeUndefined();
  });

  it("must-pass control: an exact jsr: pin that is on the allow-list produces zero findings", () => {
    const dir = mkdtempSync(join(tmpdir(), "srl-jsr-ok-"));
    try {
      writeFileSync(join(dir, "deno.json"), JSON.stringify({ imports: { assert: "jsr:@std/assert@1.0.0" } }));
      expect(buildConfigIndex(dir, new Set(["jsr:@std/assert@1.0.0"]), dir).results).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it.each(["https://unpkg.com/zod@4.6.5/index.js", "https://cdn.skypack.dev/zod@4.6.5", "https://sub.esm.sh/zod@4.6.5", "HTTPS://ESM.SH/zod@4.6.5"])(
    "CDN routing host target %s is rejected even when listed",
    (target) => {
      const dir = mkdtempSync(join(tmpdir(), "srl-cdn-"));
      try {
        writeFileSync(join(dir, "deno.json"), JSON.stringify({ imports: { zod: target } }));
        const messages = buildConfigIndex(dir, new Set([target]), dir).results.flatMap((r) => r.findings.map((f) => f.message));
        expect(messages.some((m) => m.includes("rejected even if listed"))).toBe(true);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    },
  );

  it("the legacy supabase-js esm.sh URL is NOT exempted as an import-map target (the @supabase/ ban and the positive allow-list both reject it; privileged.ts is exempt by path, not by target string)", () => {
    expect(importMapTargetProblem("https://esm.sh/@supabase/supabase-js@2.45.4")).toBeDefined();
  });
});

describe("config.ts — npmLockTableProblems (the deno.lock npm table; Deno --frozen accepts all of these mutations)", () => {
  const lock = (): Record<string, unknown> => ({
    version: "5",
    specifiers: { "npm:zod@4.6.5": "4.6.5", "npm:@types/node@*": "24.2.0" },
    npm: {
      "zod@4.6.5": { integrity: VALID_INTEGRITY },
      "@types/node@24.2.0": { integrity: VALID_INTEGRITY, dependencies: ["undici-types"] },
      "undici-types@7.10.0": { integrity: VALID_INTEGRITY },
    },
  });

  it("good control: a well-formed npm table (scoped package, dependencies field) has no problems", () => {
    expect(npmLockTableProblems(lock())).toEqual([]);
  });

  it("must-fail: an entry with its integrity REMOVED (silently unpinned)", () => {
    const l = lock();
    delete (l.npm as Record<string, Record<string, unknown>>)["zod@4.6.5"]!.integrity;
    expect(npmLockTableProblems(l).some((m) => m.includes('"zod@4.6.5"') && m.includes("integrity"))).toBe(true);
  });

  it("must-fail: a sha1- integrity (weak, wrong algorithm)", () => {
    const l = lock();
    (l.npm as Record<string, Record<string, unknown>>)["zod@4.6.5"]!.integrity = "sha1-" + "A".repeat(27) + "=";
    expect(npmLockTableProblems(l).some((m) => m.includes("integrity"))).toBe(true);
  });

  it("must-fail: a sha512 integrity of the wrong length", () => {
    const l = lock();
    (l.npm as Record<string, Record<string, unknown>>)["zod@4.6.5"]!.integrity = "sha512-" + "A".repeat(10) + "==";
    expect(npmLockTableProblems(l).some((m) => m.includes("integrity"))).toBe(true);
  });

  it("must-fail: a tarball override", () => {
    const l = lock();
    (l.npm as Record<string, Record<string, unknown>>)["zod@4.6.5"]!.tarball = "https://registry.npmjs.org/zod/-/zod-4.6.5.tgz";
    expect(npmLockTableProblems(l).some((m) => m.includes('"tarball"'))).toBe(true);
  });

  it("must-fail: tarball+integrity SWAP (a different version's tarball with that version's own valid integrity under the 4.6.5 name)", () => {
    const l = lock();
    Object.assign((l.npm as Record<string, Record<string, unknown>>)["zod@4.6.5"]!, {
      tarball: "https://registry.npmjs.org/zod/-/zod-4.6.4.tgz",
      integrity: "sha512-" + "B".repeat(86) + "==",
    });
    expect(npmLockTableProblems(l).some((m) => m.includes('"tarball"'))).toBe(true);
  });

  it("must-fail: a dangling specifier (an npm: specifier whose npm entry does not exist)", () => {
    const l = lock();
    (l.specifiers as Record<string, string>)["npm:tz-lookup@6.1.25"] = "6.1.25";
    expect(npmLockTableProblems(l).some((m) => m.includes("npm:tz-lookup@6.1.25") && m.includes("dangling"))).toBe(true);
  });

  it("must-fail: a specifier that maps to a version with no npm entry", () => {
    const l = lock();
    (l.specifiers as Record<string, string>)["npm:zod@4.6.5"] = "4.6.4";
    expect(npmLockTableProblems(l).some((m) => m.includes("dangling"))).toBe(true);
  });

  it("must-fail: a specifier DOWNGRADE (npm:zod@4.6.5 -> 4.6.4 with a 4.6.4 entry present)", () => {
    const l = lock();
    (l.specifiers as Record<string, string>)["npm:zod@4.6.5"] = "4.6.4";
    (l.npm as Record<string, unknown>)["zod@4.6.4"] = { integrity: VALID_INTEGRITY };
    delete (l.npm as Record<string, unknown>)["zod@4.6.5"];
    expect(npmLockTableProblems(l).some((m) => m.includes("not the exact version it names"))).toBe(true);
  });

  it("must-fail: an ORPHAN npm entry; but an entry reachable only through another entry's dependencies is fine", () => {
    const l = lock();
    (l.npm as Record<string, unknown>)["left-pad@1.3.0"] = { integrity: VALID_INTEGRITY };
    expect(npmLockTableProblems(l).some((m) => m.includes("orphan") && m.includes("left-pad@1.3.0"))).toBe(true);
    // undici-types@7.10.0 is in the fixture and reachable ONLY through @types/node's dependencies: no orphan finding.
    expect(npmLockTableProblems(lock())).toEqual([]);
  });

  it("a `_peer` suffix on a specifier value is ignored when comparing to the named exact version", () => {
    const l = lock();
    (l.specifiers as Record<string, string>)["npm:zod@4.6.5"] = "4.6.5_peer@1.0.0";
    (l.npm as Record<string, unknown>)["zod@4.6.5_peer@1.0.0"] = { integrity: VALID_INTEGRITY };
    delete (l.npm as Record<string, unknown>)["zod@4.6.5"];
    expect(npmLockTableProblems(l)).toEqual([]);
  });

  it("lockLayoutProblems: only version 5 and the allow-listed tables", () => {
    expect(lockLayoutProblems({ version: "5", specifiers: {}, npm: {}, redirects: {}, remote: {}, workspace: {} })).toEqual([]);
    expect(lockLayoutProblems({ version: "3", packages: { specifiers: {}, npm: {} } }).length).toBe(2);
  });

  it("LOW: a dependency edge must resolve to exactly one npm key (an extra package cannot ride along through a name-prefix match)", () => {
    const l = lock();
    (l.npm as Record<string, unknown>)["undici-types@6.0.0"] = { integrity: VALID_INTEGRITY };
    const messages = npmLockTableProblems(l);
    expect(messages.some((m) => m.includes("ambiguous") && m.includes("undici-types"))).toBe(true);
  });

  it("LOW: a `dependencies` edge that resolves to no npm entry is flagged", () => {
    const l = lock();
    ((l.npm as Record<string, Record<string, unknown>>)["@types/node@24.2.0"]!).dependencies = ["nonexistent-pkg"];
    expect(npmLockTableProblems(l).some((m) => m.includes("resolves to no npm entry"))).toBe(true);
  });

  it("must-fail: `npm` is not an object", () => {
    expect(npmLockTableProblems({ npm: [] }).some((m) => m.includes("not a JSON object"))).toBe(true);
  });

  it("through lintDirectory: a deno.lock UNDER the linted root with an integrity-less npm entry is flagged", () => {
    const dir = mkdtempSync(join(tmpdir(), "srl-lock-npm-int-"));
    try {
      writeFileSync(join(dir, "deno.json"), JSON.stringify({ imports: { zod: "npm:zod@4.6.5" } }));
      const l = lock();
      delete (l.npm as Record<string, Record<string, unknown>>)["zod@4.6.5"]!.integrity;
      writeFileSync(join(dir, "deno.lock"), JSON.stringify(l));
      const results = lintDirectory(dir, dir);
      expect(results.some((r) => r.findings.some((f) => f.message.includes("integrity")))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("config.ts — allowed top-level keys", () => {
  it("does not flag compilerOptions/lint/fmt/tasks alongside imports", () => {
    // P3c: this fixture's own deno.json pins zod@4.6.5 (bumped alongside
    // the real supabase/functions/deno.json — see index.test.ts's note),
    // so it needs its OWN pinned set here rather than the module-level
    // PINNED (still zod@3.23.8, used by unrelated scopes/workspace/jsonc
    // fixtures elsewhere in this file that were never updated).
    const pinnedForThisFixture = new Set(["npm:zod@4.6.5"]);
    const index = buildConfigIndex(join(FIXTURES_ROOT, "good-control", "somefn"), pinnedForThisFixture, join(FIXTURES_ROOT, "good-control", "somefn"));
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
      JSON.stringify({ version: "4", remote: {}, jsr: { evil: true }, workspace: { members: { "./fn": { imports: { admin: "https://evil.example.com/x.ts" } } } } }),
    );

    const index = buildConfigIndex(tmpRoot, new Set(), tmpRoot);
    const messages = index.results.flatMap((r) => r.findings.map((f) => f.message));
    expect(messages.some((m) => m.includes('disallowed top-level key "jsr"'))).toBe(true);
    expect(messages.some((m) => m.includes('"workspace" contains an "imports"/"importMap" override'))).toBe(true);
  });

  it("npm lock entry carrying a `tarball` URL override is rejected (would route a pinned npm: package to a non-registry host)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-npm-tarball-"));
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "npm:zod@4.6.5" } }));
    writeFileSync(
      join(tmpRoot, "deno.lock"),
      JSON.stringify({ version: "5", specifiers: { "npm:zod@4.6.5": "4.6.5" }, npm: { "zod@4.6.5": { integrity: VALID_INTEGRITY, tarball: "https://evil.example.com/zod.tgz" } } }),
    );
    const index = buildConfigIndex(tmpRoot, new Set(["npm:zod@4.6.5"]), tmpRoot);
    expect(index.results.some((r) => r.findings.some((f) => f.message.includes('"tarball" URL override')))).toBe(true);
  });

  it("npm lock entry with no integrity hash is rejected", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-npm-noint-"));
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "npm:zod@4.6.5" } }));
    writeFileSync(join(tmpRoot, "deno.lock"), JSON.stringify({ version: "5", specifiers: { "npm:zod@4.6.5": "4.6.5" }, npm: { "zod@4.6.5": {} } }));
    const index = buildConfigIndex(tmpRoot, new Set(["npm:zod@4.6.5"]), tmpRoot);
    expect(index.results.some((r) => r.findings.some((f) => f.message.includes('missing or malformed "integrity"')))).toBe(true);
  });

  it("good control: a deno.lock with ONLY pinned remotes, alongside a valid pinned import, produces zero findings", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-lock-good-"));
    // P3c: bumped from zod@3.23.8 to zod@4.6.5 — see index.test.ts's own
    // note on this same bump; this test reads the REAL committed
    // pinned-import-targets.json (no explicit pinned set passed to
    // lintDirectory), so it must match whatever's actually pinned there.
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "npm:zod@4.6.5" } }));
    writeFileSync(join(tmpRoot, "deno.lock"), JSON.stringify({ version: "5", specifiers: { "npm:zod@4.6.5": "4.6.5" }, npm: { "zod@4.6.5": { integrity: VALID_INTEGRITY } }, remote: {} }));
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

describe("config.ts — semverRangeProblem (redirect target must satisfy the esm.sh key's range; unknown syntax fails closed)", () => {
  it.each([
    ["^8.14.2", "8.14.2"],
    ["^8.14.2", "8.22.0"],
    ["^8.14.2", "8.99.99"],
    ["^1.2.3", "1.9.0"],
    ["^0.2.3", "0.2.3"],
    ["^0.2.3", "0.2.9"],
    ["^0.0.3", "0.0.3"],
    ["~0.0.3", "0.0.3"],
    ["~0.0.3", "0.0.9"],
    ["~8.18.1", "8.18.2"],
    ["%3E=5.0.2", "5.0.2"],
    ["%3E=5.0.2", "6.0.6"],
    ["%3e=5.0.2", "5.0.3"],
    [">5.0.2", "5.0.3"],
    ["<=5.0.2", "5.0.2"],
    ["%3C5.0.2", "5.0.1"],
  ])("must-pass: %s accepts %s", (range, version) => {
    expect(semverRangeProblem(range, version)).toBeUndefined();
  });

  it.each([
    ["^8.14.2", "8.0.0"],
    ["^8.14.2", "8.14.1"],
    ["^8.14.2", "9.0.0"],
    ["^0.2.3", "0.3.0"],
    ["^0.2.3", "0.2.2"],
    ["^0.2.3", "1.0.0"],
    ["^0.0.3", "0.0.4"],
    ["^0.0.3", "0.0.2"],
    ["~8.18.1", "8.19.0"],
    ["~8.18.1", "8.18.0"],
    ["~8.18.1", "9.0.0"],
    ["~0.0.3", "0.1.0"],
    ["%3E=5.0.2", "5.0.1"],
    [">5.0.2", "5.0.2"],
    ["<=5.0.2", "5.0.3"],
    ["%3C5.0.2", "5.0.2"],
  ])("must-fail: %s rejects %s", (range, version) => {
    expect(semverRangeProblem(range, version)).toMatch(/does not satisfy the range/);
  });

  it.each(["*", "x", "^8", "~8.14", "8.14.2", "^8.14.2 ", ">=1.0.0 <2.0.0", "^1.0.0||^2.0.0", "1.0.0 - 2.0.0", "^8.14.2-beta.1", "^8.14.2+build", "^08.14.2", "%3E5", "%5E8.14.2", "=8.14.2", "latest", ""])(
    "must-fail closed: unknown range syntax %j",
    (range) => {
      expect(semverRangeProblem(range, "8.14.2")).toMatch(/not a supported semver range/);
    },
  );

  it.each(["8.22.0-beta.1", "8.22.0+build", "8.22", "v8.22.0", "08.22.0", ""])("must-fail closed: target version %j is not a plain x.y.z", (version) => {
    expect(semverRangeProblem("^8.14.2", version)).toMatch(/not a plain x\.y\.z/);
  });

  it("does not lose precision on versions beyond Number.MAX_SAFE_INTEGER", () => {
    expect(semverRangeProblem(">=9007199254740993.0.0", "9007199254740992.0.0")).toMatch(/does not satisfy/);
  });
});
