import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { committedLockProblems } from "../src/config.js";
import { lintDirectory } from "../src/index.js";
import { importMapTargetProblem } from "../src/lint.js";

// M3 (post-P3a gate): "Stop excluding dist and __fixtures__ under
// supabase/functions except the lint's own fixtures dir, matched
// exactly." These exercise listFiles()/lintDirectory() directly (not
// lintSource()) against a real filesystem tree, since the bug lived in
// the WALKER's directory-exclusion logic, not in lintSource itself.
//
// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): the "lint's own fixtures
// dir, matched exactly" carve-out named above is GONE -- see the last
// test in this describe block for the superseding assertion.

const BAD_SOURCE = `
  import { createClient } from "@supabase/supabase-js";
  const client = createClient("url", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));
  declare const Deno: { env: { get(name: string): string | undefined } };
`;

// ⛔ FIX (should-fix, post-P3a re-gate round 3): deriveRepoRoot now THROWS
// when no `.git` ancestor is found and no repoRoot was passed explicitly
// (it used to fail open, silently falling back to startDir -- see
// config.ts's own note on this, and config.test.ts's dedicated
// "deriveRepoRoot" describe block for the throw itself). A mkdtemp()'d
// /tmp directory has no `.git` ancestor, so every `lintDirectory(tmpRoot)`
// call below now passes tmpRoot as its own repoRoot (`lintDirectory(
// tmpRoot, tmpRoot)`) -- none of these tests care about ancestor-config
// scanning, so this preserves their original behaviour exactly (no
// ancestor beyond tmpRoot itself, same as the old silent fallback would
// have produced) while going through the now-mandatory explicit path
// instead of relying on the removed fail-open default.
let tmpRoot: string | undefined;

afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
  tmpRoot = undefined;
});

// ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): "importing from
// __fixtures__ bypasses the lint." Committed fixture (not a tmpdir, since
// nothing here needs cleanup) at
// test/fixtures/bad/medium2-sibling-service-key/ -- a real-looking
// function (index.ts) with a plain relative import into a sibling file
// (_internal/service-key-reader.ts) that itself reads the service-role
// key. Proves end to end, through the real lintDirectory() walker (not
// lintSource() on one file), that a file reached only via an ordinary
// relative sibling import is discovered and flagged on its own content --
// this is what a directory-based exclusion (the lint's own now-removed
// __fixtures__ carve-out) used to hide.
describe("MEDIUM-2: a real function's relative sibling import is walked and its target flagged on its own content", () => {
  it("flags _internal/service-key-reader.ts's own literal service-role-key read, reached only via index.ts's plain relative import", () => {
    const fixtureRoot = join(import.meta.dirname, "fixtures", "bad", "medium2-sibling-service-key");
    const results = lintDirectory(fixtureRoot);
    const readerResult = results.find((r) => r.filePath.endsWith("service-key-reader.ts"));
    expect(readerResult).toBeDefined();
    expect(readerResult?.findings.some((f) => f.rule === "literal-secret-env-var" && f.message.includes("SUPABASE_SERVICE_ROLE_KEY"))).toBe(true);
  });
});

describe("lintDirectory — directory-exclusion fix (M3)", () => {
  it("LINTS a directory literally named `dist` (no longer blanket-excluded)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-dist-"));
    const distDir = join(tmpRoot, "some-fn", "dist");
    mkdirSync(distDir, { recursive: true });
    writeFileSync(join(distDir, "index.js"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  it("LINTS a `__fixtures__` directory that is NOT the lint's own top-level one", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-fixtures-"));
    const nestedFixtures = join(tmpRoot, "some-fn", "__fixtures__");
    mkdirSync(nestedFixtures, { recursive: true });
    writeFileSync(join(nestedFixtures, "leak.ts"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  // ⛔ FIX (MEDIUM-2, post-P3a re-gate round 3): SUPERSEDES the prior
  // version of this test, which asserted the OPPOSITE -- that a
  // top-level `__fixtures__` directory under the linted root was
  // excluded by exact path (the lint's OWN fixtures dir, back when it
  // lived under supabase/functions/__fixtures__). That exclusion is what
  // let a real function `import` a relative path INTO it and bypass the
  // lint entirely (repro: `fn/index.ts` importing
  // `../__fixtures__/bad/g1-pinned-build-esm-sh.ts`). The fix is
  // structural, not a smarter exclusion rule: the lint's own fixtures no
  // longer live anywhere under a linted functions root at all (moved to
  // tools/service-role-lint/test/fixtures/**) -- so NO directory named
  // `__fixtures__`, top-level or nested, is ever excluded here now.
  it("LINTS a top-level `__fixtures__` directory too, now that nothing under the linted root is ever excluded by that name", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-own-fixtures-"));
    const ownFixtures = join(tmpRoot, "__fixtures__");
    mkdirSync(ownFixtures, { recursive: true });
    writeFileSync(join(ownFixtures, "leak.ts"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  // ⛔ FIX (BLOCKING, post-P3a re-gate round 4): SUPERSEDES the prior
  // version of this test, which asserted the OPPOSITE -- that
  // `node_modules` was excluded by basename and a file inside it was
  // invisible to the lint. That was itself the bug (repro N1/N2: a real
  // function importing a sibling inside node_modules that reads
  // SUPABASE_SERVICE_ROLE_KEY, and the lint exited 0). Deno Edge
  // Functions have no npm-install step, so there is no legitimate
  // node_modules tree this exclusion was ever protecting -- removed
  // entirely, same as `dist`/`__fixtures__` before it (M3/MEDIUM-2).
  it("N1: LINTS a node_modules directory NESTED inside a function directory -- both the presence AND the file's own content are flagged", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-nm-n1-"));
    const fnDir = join(tmpRoot, "fn");
    const nmDir = join(fnDir, "node_modules", "x");
    mkdirSync(nmDir, { recursive: true });
    writeFileSync(join(nmDir, "admin.ts"), BAD_SOURCE);
    writeFileSync(join(fnDir, "index.ts"), `import { admin } from "./node_modules/x/admin.ts"; export const handler = () => admin;`);

    const results = lintDirectory(tmpRoot, tmpRoot);

    const presence = results.find((r) => r.filePath === join("fn", "node_modules"));
    expect(presence).toBeDefined();
    expect(presence?.findings.some((f) => f.rule === "vendored-dependency-tree")).toBe(true);

    const adminResult = results.find((r) => r.filePath.endsWith(join("node_modules", "x", "admin.ts")));
    expect(adminResult).toBeDefined();
    expect(adminResult?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  it("N2: LINTS a node_modules directory at the TOP LEVEL of the functions root the same way", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-nm-n2-"));
    const nmDir = join(tmpRoot, "node_modules", "y");
    mkdirSync(nmDir, { recursive: true });
    writeFileSync(join(nmDir, "a.ts"), BAD_SOURCE);
    writeFileSync(join(tmpRoot, "index.ts"), `import { admin } from "./node_modules/y/a.ts"; export const handler = () => admin;`);

    const results = lintDirectory(tmpRoot, tmpRoot);

    const presence = results.find((r) => r.filePath === "node_modules");
    expect(presence).toBeDefined();
    expect(presence?.findings.some((f) => f.rule === "vendored-dependency-tree")).toBe(true);

    const aResult = results.find((r) => r.filePath.endsWith(join("node_modules", "y", "a.ts")));
    expect(aResult).toBeDefined();
    expect(aResult?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });
});

// MEDIUM 3 (post-P3a re-gate), bypass 10 — end to end through the REAL
// deno.json-reading path in index.ts (lint.test.ts's own "bypass 10" case
// exercises lintSource's importMap option directly; this exercises the
// file-discovery + merge logic that produces it).
describe("import-map alias resolution (MEDIUM 3)", () => {
  const ALIASED_IMPORT_SOURCE = `
    import { createClient } from "supabase";
    const client = createClient(Deno.env.get("SUPABASE_URL") ?? "", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "");
    declare const Deno: { env: { get(name: string): string | undefined } };
  `;

  it("resolves a FUNCTION-LEVEL deno.json alias (\"supabase\" -> \"npm:@supabase/supabase-js@2\")", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-importmap-fn-"));
    const fnDir = join(tmpRoot, "some-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "deno.json"), JSON.stringify({ imports: { supabase: "npm:@supabase/supabase-js@2" } }));
    writeFileSync(join(fnDir, "index.ts"), ALIASED_IMPORT_SOURCE);

    const results = lintDirectory(tmpRoot, tmpRoot);
    // M2 (post-P3a re-gate): config files are now validated in their own
    // right, "regardless of importers" -- this deno.json's own
    // npm:@supabase/supabase-js@2 target is ALSO flagged as its own
    // config-level finding, a SEPARATE result entry from the importing
    // source file's own per-specifier finding.
    expect(results).toHaveLength(2);
    const result = results.find((r) => r.filePath.endsWith("index.ts"));
    expect(result?.findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("supabase"))).toBe(true);
    const configResult = results.find((r) => r.filePath.endsWith("deno.json"));
    expect(configResult?.findings.some((f) => f.message.includes("supabase"))).toBe(true);
  });

  it("resolves a SHARED ROOT import_map.json alias (functions/import_map.json, no per-function file)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-importmap-root-"));
    writeFileSync(join(tmpRoot, "import_map.json"), JSON.stringify({ imports: { supabase: "npm:@supabase/supabase-js@2" } }));
    const fnDir = join(tmpRoot, "another-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), ALIASED_IMPORT_SOURCE);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toHaveLength(2);
    const result = results.find((r) => r.filePath.endsWith("index.ts"));
    expect(result?.findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("supabase"))).toBe(true);
    const configResult = results.find((r) => r.filePath.endsWith("import_map.json"));
    expect(configResult?.findings.some((f) => f.message.includes("supabase"))).toBe(true);
  });

  // ⛔ FIX (M2 BLOCKING, post-P3a re-gate): SUPERSEDES the prior version of
  // this test, which asserted the OPPOSITE — that an unmapped bare
  // specifier was NOT flagged. M2's own decision reverses that
  // deliberately: "bare specifiers that are exact keys in a reviewed
  // import map" are the ONLY legitimate non-relative import; an unmapped
  // bare specifier is deny-by-default now, whether or not it happens to
  // be named "supabase" — naming is not the mechanism any more, coverage
  // by a reviewed import map is.
  it("flags the bare specifier \"supabase\" when NO import map resolves it (M2: deny-by-default -- an unmapped bare specifier is never legitimate, not just a suspiciously-named one)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-importmap-none-"));
    const fnDir = join(tmpRoot, "no-map-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), ALIASED_IMPORT_SOURCE);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(
      result?.findings.some(
        (f) => f.rule === "banned-import-specifier" && f.message.includes("not a relative import and not an exact key"),
      ),
    ).toBe(true);
    expect(result?.findings.some((f) => f.rule === "literal-secret-env-var")).toBe(true);
  });
});

// M2 (post-P3a re-gate): the pinned-import-targets allow-list, end to end
// through the REAL lintDirectory path (reads
// tools/service-role-lint/pinned-import-targets.json, not a value passed
// in by the caller).
describe("pinned import-target allow-list (M2)", () => {
  it("passes a bare specifier resolved through a real deno.json to a target that IS on the committed pinned-import-targets.json (zod, one real entry)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-pinned-ok-"));
    // P3c: bumped from zod@3.23.8 to zod@4.6.5 — matches packages/rules'
    // own zod dependency, now that supabase/functions/_shared/scoring/
    // vendor/ actually imports it for real (see that directory's own
    // generate-bundle.sh doc). Nothing else in supabase/functions/**
    // depended on the old pin.
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "npm:zod@4.6.5" } }));
    const fnDir = join(tmpRoot, "some-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), `import { z } from "zod"; export const schema = z.object({});`);

    const results = lintDirectory(tmpRoot, tmpRoot);
    expect(results).toHaveLength(0);
  });

  it.each(["npm:zod", "npm:zod@^4"])(
    "end to end through the committed allow-list: an unpinned `%s` target in a real deno.json is flagged (config level AND at the importing file)",
    (target) => {
      tmpRoot = mkdtempSync(join(tmpdir(), "srl-npm-unpinned-"));
      writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: target } }));
      const fnDir = join(tmpRoot, "some-fn");
      mkdirSync(fnDir, { recursive: true });
      writeFileSync(join(fnDir, "index.ts"), `import { z } from "zod"; export const schema = z.object({});`);

      const results = lintDirectory(tmpRoot, tmpRoot);
      const configResult = results.find((r) => r.filePath.endsWith("deno.json"));
      expect(configResult?.findings.some((f) => f.message.includes("not an exact version pin"))).toBe(true);
      const srcResult = results.find((r) => r.filePath.endsWith("index.ts"));
      expect(srcResult?.findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("not an exact version pin"))).toBe(true);
    },
  );

  it("the committed pinned-import-targets.json passes the lint's own target rules: no CDN routing host (any case), every npm:/jsr: entry an exact pin, no whitespace/odd-case scheme", () => {
    const list = JSON.parse(readFileSync(join(import.meta.dirname, "..", "pinned-import-targets.json"), "utf8")) as string[];
    expect(list.some((t) => /esm\.sh|jsdelivr|unpkg|skypack/i.test(t))).toBe(false);
    expect(list.filter((t) => /^\s*(npm|jsr):/i.test(t)).length).toBeGreaterThan(0);
    for (const t of list) expect(importMapTargetProblem(t), t).toBeUndefined();
  });

  // The REAL lock is supabase/tests/deno.lock, which sits outside the
  // linted supabase/functions tree, so validateLockFile never sees it
  // (supply-chain gate HIGH). This committed-file test is what makes the
  // npm-table rules apply to it; it runs in CI via `pnpm -r test` (the
  // `verify` job), not just locally. Deno --frozen accepts a removed
  // integrity and a tarball+integrity swap, so nothing else catches them.
  describe("committed supabase/tests/deno.lock (npm table)", () => {
    const repoRoot = join(import.meta.dirname, "..", "..", "..");
    const lock = JSON.parse(readFileSync(join(repoRoot, "supabase", "tests", "deno.lock"), "utf8")) as Record<string, Record<string, unknown>>;
    // Redirect keys may not equal a pinned target or an import-map value.
    const ctx = {
      pinnedImportTargets: JSON.parse(readFileSync(join(repoRoot, "tools", "service-role-lint", "pinned-import-targets.json"), "utf8")) as string[],
      importMapValues: Object.values((JSON.parse(readFileSync(join(repoRoot, "supabase", "functions", "deno.json"), "utf8")) as { imports: Record<string, string> }).imports),
    };

    it("passes the layout and npm-table rules (version 5, allow-listed tables, sha512 integrity on every entry, no tarball override, no dangling/downgraded specifier, no orphan entry)", () => {
      expect(Object.keys(lock.npm ?? {}).length).toBeGreaterThan(0);
      expect(committedLockProblems(lock, ctx)).toEqual([]);
      expect(lock.version).toBe("5");
    });

    it("every npm: import-map target in supabase/functions/deno.json is pinned by a lock specifier, and the lock has no esm.sh stub entry for it", () => {
      const imports = (JSON.parse(readFileSync(join(repoRoot, "supabase", "functions", "deno.json"), "utf8")) as { imports: Record<string, string> }).imports;
      const npmTargets = Object.values(imports).filter((t) => t.startsWith("npm:"));
      expect(npmTargets.length).toBeGreaterThan(0);
      for (const t of npmTargets) {
        const base = t.replace(/^(npm:(?:@[^/]+\/)?[^/@]+@[^/]+).*$/, "$1");
        expect(Object.keys(lock.specifiers ?? {}), t).toContain(base);
      }
      for (const key of Object.keys(lock.remote ?? {})) expect(key).not.toMatch(/esm\.sh\/(zod|@noble|tz-lookup)@/);
    });

    const mutations: Array<[string, (l: Record<string, Record<string, Record<string, unknown>>>) => void]> = [
      ["integrity removed", (l) => delete l.npm!["zod@4.6.5"]!.integrity],
      ["sha1- integrity", (l) => (l.npm!["zod@4.6.5"]!.integrity = "sha1-" + "A".repeat(27) + "=")],
      ["tarball override", (l) => (l.npm!["zod@4.6.5"]!.tarball = "https://registry.npmjs.org/zod/-/zod-4.6.5.tgz")],
      [
        "tarball + integrity swap to 4.6.4",
        (l) => Object.assign(l.npm!["zod@4.6.5"]!, { tarball: "https://registry.npmjs.org/zod/-/zod-4.6.4.tgz", integrity: "sha512-" + "C".repeat(86) + "==" }),
      ],
      ["dangling specifier", (l) => ((l.specifiers as unknown as Record<string, string>)["npm:left-pad@1.3.0"] = "1.3.0")],
      [
        "specifier downgrade: npm:zod@4.6.5 -> 4.6.4 with a (real-shaped) 4.6.4 entry, 4.6.5 entry removed",
        (l) => {
          (l.specifiers as unknown as Record<string, string>)["npm:zod@4.6.5"] = "4.6.4";
          delete l.npm!["zod@4.6.5"];
          l.npm!["zod@4.6.4"] = { integrity: "sha512-" + "D".repeat(86) + "==" };
        },
      ],
      [
        "specifier downgrade variant: the 4.6.5 entry is KEPT beside the 4.6.4 one (orphan)",
        (l) => {
          (l.specifiers as unknown as Record<string, string>)["npm:zod@4.6.5"] = "4.6.4";
          l.npm!["zod@4.6.4"] = { integrity: "sha512-" + "D".repeat(86) + "==" };
        },
      ],
      ["orphan npm entry (nothing refers to it)", (l) => (l.npm!["left-pad@1.3.0"] = { integrity: "sha512-" + "E".repeat(86) + "==" })],
      [
        'older layout: "version": "3" with specifiers/npm under "packages", integrity removed',
        (l) => {
          const npm = l.npm!;
          const specifiers = l.specifiers!;
          delete npm["zod@4.6.5"]!.integrity;
          delete l.npm;
          delete l.specifiers;
          (l as Record<string, unknown>).version = "3";
          (l as Record<string, unknown>).packages = { specifiers, npm };
        },
      ],
      [
        'older layout: "version": "3" with specifiers/npm under "packages", tarball + integrity swap',
        (l) => {
          const npm = l.npm!;
          const specifiers = l.specifiers!;
          Object.assign(npm["zod@4.6.5"]!, { tarball: "https://registry.npmjs.org/zod/-/zod-4.6.4.tgz", integrity: "sha512-" + "C".repeat(86) + "==" });
          delete l.npm;
          delete l.specifiers;
          (l as Record<string, unknown>).version = "3";
          (l as Record<string, unknown>).packages = { specifiers, npm };
        },
      ],
      ['an unknown top-level table ("packages") alongside the v5 tables', (l) => ((l as Record<string, unknown>).packages = { npm: {} })],
      [
        "redirect: same-host, deno.land postgresjs v3.4.5 -> v3.4.4 (plus a matching remote hash)",
        (l) => {
          (l.redirects as Record<string, unknown>)["https://deno.land/x/postgresjs@v3.4.5/mod.js"] = "https://deno.land/x/postgresjs@v3.4.4/mod.js";
          (l.remote as Record<string, unknown>)["https://deno.land/x/postgresjs@v3.4.4/mod.js"] = "f".repeat(64);
        },
      ],
      [
        "redirect: cross-host, deno.land postgresjs -> esm.sh/postgres@3.4.4 (plus a matching remote hash)",
        (l) => {
          (l.redirects as Record<string, unknown>)["https://deno.land/x/postgresjs@v3.4.5/mod.js"] = "https://esm.sh/postgres@3.4.4";
          (l.remote as Record<string, unknown>)["https://esm.sh/postgres@3.4.4"] = "f".repeat(64);
        },
      ],
      [
        "redirect FROM a pinned target / import-map value (std/http/server)",
        (l) => ((l.redirects as Record<string, unknown>)["https://deno.land/std@0.224.0/http/server.ts"] = "https://deno.land/std@0.224.1/http/server.ts"),
      ],
      [
        "redirect from a floating esm.sh key to a DIFFERENT package",
        (l) => ((l.redirects as Record<string, unknown>)["https://esm.sh/ws@^8.14.2?target=denonext"] = "https://esm.sh/evil-ws@8.22.0?target=denonext"),
      ],
      [
        "redirect from a floating esm.sh key to a different ORIGIN",
        (l) => ((l.redirects as Record<string, unknown>)["https://esm.sh/ws@^8.14.2?target=denonext"] = "https://evil.example.com/ws@8.22.0?target=denonext"),
      ],
      [
        "redirect from a floating esm.sh key to a non-exact version",
        (l) => ((l.redirects as Record<string, unknown>)["https://esm.sh/ws@^8.14.2?target=denonext"] = "https://esm.sh/ws@^8?target=denonext"),
      ],
      [
        "redirect from an esm.sh key WITHOUT a range operator (an exact stub)",
        (l) => ((l.redirects as Record<string, unknown>)["https://esm.sh/@supabase/supabase-js@2.45.4"] = "https://esm.sh/@supabase/supabase-js@2.45.3"),
      ],
      ["remote key on a foreign host", (l) => ((l.remote as Record<string, unknown>)["https://evil.example.com/x.js"] = "f".repeat(64))],
      ["remote deno.land key that is not a versioned path", (l) => ((l.remote as Record<string, unknown>)["https://deno.land/x/postgresjs/mod.js"] = "f".repeat(64))],
      ['version "4" with otherwise-valid v5 tables', (l) => ((l as Record<string, unknown>).version = "4")],
    ];
    it.each(mutations)("must-fail mutation of the REAL lock: %s", (_name, mutate) => {
      const copy = JSON.parse(JSON.stringify(lock)) as Record<string, Record<string, Record<string, unknown>>>;
      mutate(copy);
      expect(committedLockProblems(copy, ctx).length).toBeGreaterThan(0);
    });

    // Supply-chain gate (PR #20, MEDIUM): the redirect target must SATISFY the
    // key's range. Each case below changes ONLY the target's version (or the
    // key's range syntax) and is asserted on the range-specific message, so a
    // different rule cannot make it pass by accident.
    const WS_KEY = "https://esm.sh/ws@^8.14.2?target=denonext";
    const redirects = (l: Record<string, Record<string, unknown>>): Record<string, unknown> => l.redirects!;
    const rangeMutations: Array<[string, (l: Record<string, Record<string, unknown>>) => void, RegExp]> = [
      ["ws@^8.14.2 -> ws@8.0.0 (downgrade below the range)", (l) => (redirects(l)[WS_KEY] = "https://esm.sh/ws@8.0.0?target=denonext"), /does not satisfy the range \^8\.14\.2/],
      ["ws@^8.14.2 -> ws@9.0.0 (major bump above the range)", (l) => (redirects(l)[WS_KEY] = "https://esm.sh/ws@9.0.0?target=denonext"), /does not satisfy/],
      [
        "~ range with a minor bump: @types/ws@~8.18.1 -> 8.19.0",
        (l) => (redirects(l)["https://esm.sh/@types/ws@~8.18.1/index.d.mts"] = "https://esm.sh/@types/ws@8.19.0/index.d.mts"),
        /does not satisfy the range ~8\.18\.1/,
      ],
      ["~ range below its floor: tr46@~0.0.3 -> 0.0.2", (l) => (redirects(l)["https://esm.sh/tr46@~0.0.3?target=denonext"] = "https://esm.sh/tr46@0.0.2?target=denonext"), /does not satisfy/],
      [
        ">= range below its floor: utf-8-validate@>=5.0.2 -> 5.0.1",
        (l) => (redirects(l)["https://esm.sh/utf-8-validate@%3E=5.0.2?target=denonext"] = "https://esm.sh/utf-8-validate@5.0.1?target=denonext"),
        /does not satisfy/,
      ],
      [
        "^0.x crossing a minor: ^0.2.3 -> 0.3.0",
        (l) => (redirects(l)["https://esm.sh/zero-minor@^0.2.3?target=denonext"] = "https://esm.sh/zero-minor@0.3.0?target=denonext"),
        /does not satisfy the range \^0\.2\.3/,
      ],
      [
        "^0.0.x crossing a patch: ^0.0.3 -> 0.0.4",
        (l) => (redirects(l)["https://esm.sh/zero-patch@^0.0.3?target=denonext"] = "https://esm.sh/zero-patch@0.0.4?target=denonext"),
        /does not satisfy/,
      ],
      ["a pre-release target never satisfies a range", (l) => (redirects(l)[WS_KEY] = "https://esm.sh/ws@8.22.0-beta.1?target=denonext"), /not a plain x\.y\.z/],
      ["unknown range syntax: *", (l) => (redirects(l)["https://esm.sh/starry@*?target=denonext"] = "https://esm.sh/starry@1.0.0?target=denonext"), /not a supported semver range/],
      ["unknown range syntax: partial ^8", (l) => (redirects(l)["https://esm.sh/partial@^8?target=denonext"] = "https://esm.sh/partial@8.0.0?target=denonext"), /not a supported semver range/],
      ["unknown range syntax: ~8.14", (l) => (redirects(l)["https://esm.sh/partial@~8.14?target=denonext"] = "https://esm.sh/partial@8.14.0?target=denonext"), /not a supported semver range/],
      [
        "unknown range syntax: union ^1.0.0||^2.0.0",
        (l) => (redirects(l)["https://esm.sh/union@^1.0.0||^2.0.0?target=denonext"] = "https://esm.sh/union@2.0.0?target=denonext"),
        /not a supported semver range/,
      ],
      [
        "unknown range syntax: pre-release in the range ^1.0.0-beta.1",
        (l) => (redirects(l)["https://esm.sh/pre@^1.0.0-beta.1?target=denonext"] = "https://esm.sh/pre@1.0.0?target=denonext"),
        /not a supported semver range/,
      ],
      ["unknown range syntax: %3E operator with a partial", (l) => (redirects(l)["https://esm.sh/gt@%3E=5?target=denonext"] = "https://esm.sh/gt@5.0.0?target=denonext"), /not a supported semver range/],
    ];
    it.each(rangeMutations)("must-fail range-satisfaction mutation of the REAL lock: %s", (_name, mutate, message) => {
      const copy = JSON.parse(JSON.stringify(lock)) as Record<string, Record<string, unknown>>;
      mutate(copy);
      const problems = committedLockProblems(copy, ctx);
      expect(problems.some((p) => message.test(p)), problems.join("\n")).toBe(true);
    });

    const passMutations: Array<[string, (l: Record<string, Record<string, unknown>>) => void]> = [
      ["ws@^8.14.2 -> ws@8.14.2 (the range floor itself)", (l) => (redirects(l)[WS_KEY] = "https://esm.sh/ws@8.14.2?target=denonext")],
      ["ws@^8.14.2 -> ws@8.99.99 (in range)", (l) => (redirects(l)[WS_KEY] = "https://esm.sh/ws@8.99.99?target=denonext")],
      ["@types/ws@~8.18.1 -> 8.18.9 (in the ~ range)", (l) => (redirects(l)["https://esm.sh/@types/ws@~8.18.1/index.d.mts"] = "https://esm.sh/@types/ws@8.18.9/index.d.mts")],
    ];
    it.each(passMutations)("must-pass in-range target on the REAL lock: %s", (_name, mutate) => {
      const copy = JSON.parse(JSON.stringify(lock)) as Record<string, Record<string, unknown>>;
      mutate(copy);
      expect(committedLockProblems(copy, ctx)).toEqual([]);
    });
  });

  it("flags a bare specifier resolved to a target that looks legitimate but is NOT on the pinned allow-list (adding a dependency must be a reviewed diff)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-pinned-missing-"));
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { "left-pad": "npm:left-pad@1.3.0" } }));
    const fnDir = join(tmpRoot, "some-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), `import leftPad from "left-pad"; export const p = leftPad;`);

    const results = lintDirectory(tmpRoot, tmpRoot);
    // M2: the deno.json's own unpinned target is ALSO its own config-level
    // finding now, a separate result entry from the importing source file.
    expect(results).toHaveLength(2);
    const result = results.find((r) => r.filePath.endsWith("index.ts"));
    expect(
      result?.findings.some(
        (f) => f.rule === "banned-import-specifier" && f.message.includes("not on the committed pinned-import-targets allow-list"),
      ),
    ).toBe(true);
    const configResult = results.find((r) => r.filePath.endsWith("deno.json"));
    expect(
      configResult?.findings.some((f) => f.message.includes("not on the committed pinned-import-targets allow-list")),
    ).toBe(true);
  });
});
