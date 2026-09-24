import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { lintDirectory } from "../src/index.js";

// M3 (post-P3a gate): "Stop excluding dist and __fixtures__ under
// supabase/functions except the lint's own fixtures dir, matched
// exactly." These exercise listFiles()/lintDirectory() directly (not
// lintSource()) against a real filesystem tree, since the bug lived in
// the WALKER's directory-exclusion logic, not in lintSource itself.

const BAD_SOURCE = `
  import { createClient } from "@supabase/supabase-js";
  const client = createClient("url", Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"));
  declare const Deno: { env: { get(name: string): string | undefined } };
`;

let tmpRoot: string | undefined;

afterEach(() => {
  if (tmpRoot) rmSync(tmpRoot, { recursive: true, force: true });
  tmpRoot = undefined;
});

describe("lintDirectory — directory-exclusion fix (M3)", () => {
  it("LINTS a directory literally named `dist` (no longer blanket-excluded)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-dist-"));
    const distDir = join(tmpRoot, "some-fn", "dist");
    mkdirSync(distDir, { recursive: true });
    writeFileSync(join(distDir, "index.js"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  it("LINTS a `__fixtures__` directory that is NOT the lint's own top-level one", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-fixtures-"));
    const nestedFixtures = join(tmpRoot, "some-fn", "__fixtures__");
    mkdirSync(nestedFixtures, { recursive: true });
    writeFileSync(join(nestedFixtures, "leak.ts"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  it("still EXCLUDES the lint's own top-level __fixtures__ directory, matched by exact path", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-own-fixtures-"));
    const ownFixtures = join(tmpRoot, "__fixtures__");
    mkdirSync(ownFixtures, { recursive: true });
    writeFileSync(join(ownFixtures, "leak.ts"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot);
    expect(results.length).toBe(0);
  });

  it("still excludes node_modules", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-nm-"));
    const nm = join(tmpRoot, "node_modules", "some-pkg");
    mkdirSync(nm, { recursive: true });
    writeFileSync(join(nm, "index.js"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot);
    expect(results.length).toBe(0);
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

    const results = lintDirectory(tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("supabase"))).toBe(true);
  });

  it("resolves a SHARED ROOT import_map.json alias (functions/import_map.json, no per-function file)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-importmap-root-"));
    writeFileSync(join(tmpRoot, "import_map.json"), JSON.stringify({ imports: { supabase: "npm:@supabase/supabase-js@2" } }));
    const fnDir = join(tmpRoot, "another-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), ALIASED_IMPORT_SOURCE);

    const results = lintDirectory(tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(result?.findings.some((f) => f.rule === "banned-import-specifier" && f.message.includes("supabase"))).toBe(true);
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

    const results = lintDirectory(tmpRoot);
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
  it("passes a bare specifier resolved through a real deno.json to a target that IS on the committed pinned-import-targets.json (zod, the one real entry)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-pinned-ok-"));
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { zod: "https://esm.sh/zod@3.23.8" } }));
    const fnDir = join(tmpRoot, "some-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), `import { z } from "zod"; export const schema = z.object({});`);

    const results = lintDirectory(tmpRoot);
    expect(results).toHaveLength(0);
  });

  it("flags a bare specifier resolved to a target that looks legitimate but is NOT on the pinned allow-list (adding a dependency must be a reviewed diff)", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-pinned-missing-"));
    writeFileSync(join(tmpRoot, "deno.json"), JSON.stringify({ imports: { "left-pad": "https://esm.sh/left-pad@1.3.0" } }));
    const fnDir = join(tmpRoot, "some-fn");
    mkdirSync(fnDir, { recursive: true });
    writeFileSync(join(fnDir, "index.ts"), `import leftPad from "left-pad"; export const p = leftPad;`);

    const results = lintDirectory(tmpRoot);
    expect(results).toHaveLength(1);
    const [result] = results;
    expect(
      result?.findings.some(
        (f) => f.rule === "banned-import-specifier" && f.message.includes("not on the committed pinned-import-targets allow-list"),
      ),
    ).toBe(true);
  });
});
