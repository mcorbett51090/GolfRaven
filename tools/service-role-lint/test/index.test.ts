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
    expect(results.length).toBe(1);
    expect(results[0].findings.some((f) => f.rule === "service-role-construction")).toBe(true);
  });

  it("LINTS a `__fixtures__` directory that is NOT the lint's own top-level one", () => {
    tmpRoot = mkdtempSync(join(tmpdir(), "srl-fixtures-"));
    const nestedFixtures = join(tmpRoot, "some-fn", "__fixtures__");
    mkdirSync(nestedFixtures, { recursive: true });
    writeFileSync(join(nestedFixtures, "leak.ts"), BAD_SOURCE);

    const results = lintDirectory(tmpRoot);
    expect(results.length).toBe(1);
    expect(results[0].findings.some((f) => f.rule === "service-role-construction")).toBe(true);
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
