/**
 * What is IN the bundle, judged by esbuild's own metafile (LOW-2). The old check was a regex over `import ... from "x"` in the source, which cannot
 * see a side-effect `import "pkg"`, a dynamic `import("pkg")`, a `require("pkg")` or an `export * from "pkg"`. The bundler's list of inputs sees every
 * one of them, because it had to read each file to build the output. These cells run a real esbuild over temp-dir fixtures and over the real build.
 */
import { appendFile, cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { build } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildPartners } from "../scripts/build.mjs";
import { checkBundleInputs, SHARED_FILES } from "../scripts/lib/inputs.mjs";

let scratch: string;
beforeAll(async () => {
  scratch = await mkdtemp(join(tmpdir(), "gr-partners-inputs-"));
});
afterAll(async () => {
  await rm(scratch, { recursive: true, force: true });
});

/** The regex the old test used (test/source-scan.test.ts before LOW-2): only `import|export ... from "x"` forms. */
const LEGACY = /(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s+["']([^"']+)["']/g;
const legacyFindsThirdParty = (code: string) => [...code.matchAll(LEGACY)].some((m) => !/^\.\.?\//.test(m[1]!));

/** A one-file project under `src/` plus a package in `node_modules/pkg`, bundled the way build.mjs bundles. Returns the inputs check's findings. */
async function bundleFixture(name: string, main: string, extra: Record<string, string> = {}): Promise<{ findings: string[]; inputs: string[] }> {
  const dir = join(scratch, name);
  await mkdir(join(dir, "src"), { recursive: true });
  await mkdir(join(dir, "node_modules", "pkg"), { recursive: true });
  await writeFile(join(dir, "node_modules", "pkg", "package.json"), JSON.stringify({ name: "pkg", version: "1.0.0", main: "index.js" }));
  await writeFile(join(dir, "node_modules", "pkg", "index.js"), "module.exports = { thing: 1 }; globalThis.__pkg_ran = true;\n");
  await writeFile(join(dir, "outside.js"), "export const outside = 1;\n");
  await writeFile(join(dir, "src", "main.ts"), main);
  for (const [f, body] of Object.entries(extra)) await writeFile(join(dir, f), body);
  const result = await build({ absWorkingDir: dir, entryPoints: ["src/main.ts"], outdir: join(dir, "out"), bundle: true, write: false, metafile: true, format: "esm", platform: "browser", logLevel: "silent" });
  return { findings: checkBundleInputs(result.metafile), inputs: Object.keys(result.metafile.inputs) };
}

describe("checkBundleInputs on fixtures: every way of pulling a package in is caught", () => {
  it("control: a project that imports only relative files under src/ is clean", async () => {
    const r = await bundleFixture("clean", `import { x } from "./other";\nexport const y = x;\n`, { "src/other.ts": "export const x = 1;\n" });
    expect(r.inputs.sort()).toEqual(["src/main.ts", "src/other.ts"]);
    expect(r.findings).toEqual([]);
  });

  it.each([
    ["a named import", `import { thing } from "pkg";\nexport const y = thing;\n`, false],
    ["a SIDE-EFFECT import", `import "pkg";\nexport const y = 1;\n`, true],
    ["a DYNAMIC import", `export const y = import("pkg");\n`, true],
    ["a re-export", `export * from "pkg";\n`, false],
    ["a require() call", `declare const require: (id: string) => unknown;\nexport const y = require("pkg");\n`, true],
  ] as const)("%s of a package is reported as coming from node_modules", async (name, main, legacyMisses) => {
    const r = await bundleFixture(name.replace(/\W+/g, "-"), main);
    expect(r.inputs.some((i) => i.startsWith("node_modules/pkg/")), name).toBe(true);
    expect(r.findings.some((f) => /node_modules\/pkg\/index\.js: comes from node_modules/.test(f)), `${name}: ${r.findings.join("|")}`).toBe(true);
    // why the old regex was not enough: the forms below are invisible to it
    if (legacyMisses) expect(legacyFindsThirdParty(main), `${name} should have slipped past the old regex`).toBe(false);
  });

  it("a relative import that climbs OUT of src/ is reported too", async () => {
    const r = await bundleFixture("climb", `import { outside } from "../outside";\nexport const y = outside;\n`);
    expect(r.findings).toEqual(["outside.js: is outside src/"]);
  });

  it("an empty metafile is a finding, not a vacuous pass", () => {
    expect(checkBundleInputs({ inputs: {} })).toEqual(["the bundle has no inputs (the check would pass vacuously)"]);
  });

  it("the e2e harness path is allowed only when asked for", () => {
    const mf = { inputs: { "src/main.ts": {}, "test/e2e/harness/harness.ts": {} } };
    expect(checkBundleInputs(mf)).toEqual(["test/e2e/harness/harness.ts: is outside src/"]);
    expect(checkBundleInputs(mf, { harness: true })).toEqual([]);
    expect(checkBundleInputs({ inputs: { "node_modules/x/test/e2e/harness/a.js": {} } }, { harness: true })).toHaveLength(1);
  });
});

describe("the build itself fails on a package import (the check is wired in, not just available)", () => {
  /**
   * A scratch copy of this package's buildable files (src/, index.html, public/), so the build can be pointed at a source that imports a package. It sits at
   * `<name>/apps/partners` with the three shared PIN-contract files at `<name>/supabase/functions/_shared/partner/`, the same relative place they have in the repository.
   */
  async function project(name: string, extraMain: string): Promise<string> {
    const base = join(scratch, name);
    const dir = join(base, "apps", "partners");
    const pkg = new URL("..", import.meta.url).pathname;
    await mkdir(dir, { recursive: true });
    for (const rel of SHARED_FILES) {
      const dest = join(dir, rel);
      await mkdir(join(dest, ".."), { recursive: true });
      await cp(join(pkg, rel), dest);
    }
    await cp(join(pkg, "src"), join(dir, "src"), { recursive: true });
    await cp(join(pkg, "public"), join(dir, "public"), { recursive: true });
    await cp(join(pkg, "index.html"), join(dir, "index.html"));
    await mkdir(join(dir, "node_modules", "pkg"), { recursive: true });
    await writeFile(join(dir, "node_modules", "pkg", "package.json"), JSON.stringify({ name: "pkg", version: "1.0.0", main: "index.js" }));
    await writeFile(join(dir, "node_modules", "pkg", "index.js"), "globalThis.__pkg_ran = true;\n");
    if (extraMain !== "") await appendFile(join(dir, "src", "main.ts"), extraMain);
    return dir;
  }
  const env = { GOLFRAVEN_PARTNERS_API_BASE: "https://abc123.example.org/functions/v1" };

  it("control: an unmodified copy of the package builds", async () => {
    const root = await project("build-ok", "");
    const r = await buildPartners({ dist: join(root, "dist"), env, root });
    expect(r.inputs.every((i) => i.startsWith("src/") || SHARED_FILES.includes(i))).toBe(true);
  });

  it("a FOURTH file outside src/ (any other shared module) fails the build: the allow-list is exact, not a directory", async () => {
    const root = await project("build-extra-shared", `
import "../../../supabase/functions/_shared/partner/other.ts";
`);
    await writeFile(join(root, "..", "..", "supabase", "functions", "_shared", "partner", "other.ts"), "export const other = 1;\n");
    await expect(buildPartners({ dist: join(root, "dist"), env, root })).rejects.toThrow(/bundle inputs outside src\/:\n\s+\.\.\/\.\.\/supabase\/functions\/_shared\/partner\/other\.ts: is outside src\//);
  });

  it.each([
    ["a side-effect import", `\nimport "pkg";\n`],
    ["a dynamic import", `\nvoid import("pkg");\n`],
  ])("%s of a package makes the build fail with the offending input named", async (name, extra) => {
    const root = await project(`build-bad-${name.replace(/\W+/g, "-")}`, extra);
    await expect(buildPartners({ dist: join(root, "dist"), env, root })).rejects.toThrow(/bundle inputs outside src\/:\n\s+node_modules\/pkg\/index\.js: comes from node_modules/);
  });
});

describe("the real build", () => {
  it("every input of the production bundle is under src/, none under node_modules (and the build itself fails otherwise)", async () => {
    const r = await buildPartners({ dist: join(scratch, "real"), env: { GOLFRAVEN_PARTNERS_API_BASE: "https://abc123.example.org/functions/v1" } });
    expect(r.inputs).toContain("src/main.ts");
    expect(r.inputs.length).toBeGreaterThan(10);
    // src/ and nothing else, except the three shared PIN-contract files (an exact list: a fourth would fail the build)
    for (const i of r.inputs) {
      expect(i.startsWith("src/") || SHARED_FILES.includes(i), i).toBe(true);
      expect(i.includes("node_modules"), i).toBe(false);
    }
    expect(r.inputs.filter((i) => !i.startsWith("src/")).sort()).toEqual([...SHARED_FILES].sort());
    expect(checkBundleInputs({ inputs: Object.fromEntries(r.inputs.map((i) => [i, {}])) })).toEqual([]);
  });

  it("the e2e build's inputs are src/ plus the harness, and nothing from node_modules", async () => {
    const r = await buildPartners({ dist: join(scratch, "real-e2e"), env: { GOLFRAVEN_PARTNERS_E2E: "1", GOLFRAVEN_PARTNERS_API_BASE: "http://localhost:4999/functions/v1" } });
    expect(r.inputs).toContain("test/e2e/harness/harness.ts");
    expect(r.inputs.filter((i) => !i.startsWith("src/") && !i.startsWith("test/e2e/harness/") && !SHARED_FILES.includes(i))).toEqual([]);
    expect(r.inputs.some((i) => i.includes("node_modules"))).toBe(false);
  });
});
