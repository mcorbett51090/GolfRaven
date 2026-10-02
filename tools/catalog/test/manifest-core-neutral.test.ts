/**
 * `manifest-core.ts` is shared with the mobile app (apps/mobile), which is
 * bundled by Metro and runs on Hermes: it must import nothing but `zod` and
 * stay free of Node globals (`Buffer`, `process`, `require`). This is the guard for that contract, plus a
 * check that the Node-side wrappers in `manifest.ts` encode exactly the
 * strings the core produces (so the split cannot drift the signed bytes).
 */
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { bundleNeutral, bundleViolations, neutralityViolations, typeViolations } from "./neutrality.js";
import {
  MANIFEST_DOMAIN,
  VERSIONS_DOMAIN,
  manifestStatementText,
  strictParseAndValidateText,
  versionsStatementText,
  CatalogManifestSchema,
} from "../src/manifest-core.js";
import {
  manifestStatementBytes,
  strictParseAndValidate,
  versionsStatementBytes,
} from "../src/manifest.js";

const KID = "k-test-1";
const SHA = "a".repeat(64);

const CORE = fileURLToPath(new URL("../src/manifest-core.ts", import.meta.url));
const ALLOWED = ["zod"];

describe("manifest-core is platform-neutral (enumerated by a real bundler, not a lexer)", () => {
  it("bundles for the neutral platform with exactly one import — a static one of zod — and no Node global", async () => {
    const r = await bundleNeutral({ file: CORE }, ALLOWED);
    // The check is not vacuous: it really saw this file, and the one import it has.
    expect(r.errors).toEqual([]);
    expect(r.inputs).toEqual(["src/manifest-core.ts"]);
    expect(r.imports).toEqual([{ from: "src/manifest-core.ts", path: "zod", kind: "import-statement", external: true }]);
    expect(bundleViolations(r, ALLOWED)).toEqual([]);
  });

  it("type-checks with no Node types at all (the layer a bundler cannot see: erased type-only imports and annotations)", async () => {
    expect(await typeViolations({ core: { file: CORE } })).toEqual({});
  });
});

type Layer = "bundle" | "types";
describe("the neutrality check cannot be bypassed", () => {
  // [name, source, the layer that must catch it]. "types" = esbuild erases it, only the type layer sees it.
  const bad: [string, string, Layer][] = [
    ["a builtin without the node: prefix", 'import { createHash } from "crypto";\n', "bundle"],
    ["a node: import", 'import fs from "node:fs";\n', "bundle"],
    ["a comment before the import", '/* harmless */ import fs from "node:fs";\n', "bundle"],
    ["a line comment on the previous line", '// import z from "zod";\nimport fs from "node:fs";\n', "bundle"],
    ["a bare side-effect import", 'import "node:fs";\n', "bundle"],
    ["a bare side-effect import of a package", 'import "left-pad";\n', "bundle"],
    ["a RESOLVABLE package that would be bundled in", 'import { ZodError } from "zod/v4";\nexport const e = ZodError;\n', "bundle"],
    ["a dynamic import()", 'export async function f() { return import("node:fs"); }\n', "bundle"],
    ["a dynamic import() of an allowed name (dynamic is itself refused)", 'export const z = () => import("zod");\n', "bundle"],
    ["a dynamic import() with a computed specifier", "export const f = (n: string) => import(n);\n", "bundle"],
    ["a dynamic import() with a concatenated specifier", 'export const f = () => import("node:" + "fs");\n', "bundle"],
    ["a re-export from a builtin", 'export * from "node:fs";\n', "bundle"],
    ["a named re-export from a builtin", 'export { readFileSync } from "fs";\n', "bundle"],
    ["a namespace re-export", 'export * as fs from "node:fs";\n', "bundle"],
    ["require()", 'const fs = require("fs");\nexport { fs };\n', "bundle"],
    ["require() with a computed specifier", "declare const name: string;\nexport const fs = require(name);\n", "bundle"],
    ["import x = require()", 'import fs = require("fs");\nexport { fs };\n', "bundle"],
    ["an import hidden after a template literal with braces", 'const t = `${ { a: 1 }.a } }`;\nimport fs from "node:fs";\nexport { t, fs };\n', "bundle"],
    ["an import after a regex literal containing quotes", 'const r = /"\'/;\nimport fs from "node:fs";\nexport { r, fs };\n', "bundle"],
    // LOW-A (PR #26 gate): the lexer's blind spots.
    ["an import after a regex literal that follows `)` (the old lexer read it as a division and swallowed the import)", 'const x = 1;\nconst y = "";\nif (x) /`/.test(y);\nimport fs from "node:fs";\nexport { fs };\n', "bundle"],
    ["the Buffer global", "export const b = Buffer.from('x');\n", "bundle"],
    ["the process global", "export const e = process.env['X'];\n", "bundle"],
    ["globalThis.Buffer", "export const b = globalThis.Buffer;\n", "bundle"],
    ["globalThis['process'] (computed member)", "export const e = globalThis['process'];\n", "bundle"],
    ["`global`", "export const g = global;\n", "bundle"],
    ['module.require("node:crypto")', 'export const c = module.require("node:crypto");\n', "bundle"],
    ['eval("req" + "uire")', 'export const r = eval("req" + "uire");\n', "bundle"],
    ["the Function constructor", 'export const g = new Function("return this")();\n', "bundle"],
    ["a good import AND a bad one", 'import { z } from "zod";\nimport fs from "node:fs";\nexport { z, fs };\n', "bundle"],
    // What a bundler erases:
    ["a type-only import (still a dependency edge)", 'import type { Buffer as B } from "node:buffer";\nexport type X = B;\n', "types"],
    ["the Buffer type in an annotation", "export const f = (b: Buffer): number => b.length;\n", "types"],
  ];

  let types: Record<string, string[]>;
  beforeAll(async () => {
    types = await typeViolations(Object.fromEntries(bad.map(([name, text]) => [name, { text }] as const)));
  });

  it("the type checker ran for every fixture (no diagnostic went unattributed)", () => {
    expect(types["*"]).toBeUndefined();
  });

  it.each(bad)("fails on %s", async (name, src, layer) => {
    const viaBundle = await neutralityViolations({ text: src }, ALLOWED);
    const viaTypes = types[name] ?? [];
    expect([...viaBundle, ...viaTypes].length).toBeGreaterThan(0);
    if (layer === "bundle") expect(viaBundle.length, "the bundle layer must catch this by itself").toBeGreaterThan(0);
    else {
      expect(viaTypes.length, "the type layer must catch this").toBeGreaterThan(0);
      expect(viaBundle, "(documenting the gap: a bundler erases it)").toEqual([]);
    }
  });

  const good = [
    'import { z } from "zod";\nexport const x = z;\n',
    "import { z } from 'zod';\nexport const x = z;\n",
    'import * as z from "zod";\nexport const x = z;\n',
    'import type { ZodType } from "zod";\nexport type X = ZodType;\n',
    'export { z } from "zod";\n',
    'import { z } from "zod";\nexport const x = z; // import fs from "node:fs"\n',
    '/* import fs from "node:fs"; require("fs"); Buffer process globalThis eval */\nimport { z } from "zod";\nexport const x = z;\n',
    'import { z } from "zod";\nexport const s = \'import fs from "node:fs"\' + `require("fs")${1}` + z;\n',
    'import { z } from "zod";\nexport const o = { a: 1, process: 2 }.process; export const m = import.meta; export const z2 = z;\n',
    // a local that merely shares a forbidden name is not a global reference
    "export function f(Buffer: number, process: number): number { const require = 1; return Buffer + process + require; }\n",
    // a division after `)` — the other way the old lexer could be fooled
    'import { z } from "zod";\nconst a = 6;\nexport const q = (a) / 2 / 1;\nexport const x = z;\n',
  ];
  let goodTypes: Record<string, string[]>;
  beforeAll(async () => {
    goodTypes = await typeViolations(Object.fromEntries(good.map((text, i) => [`good-${i}`, { text }] as const)));
  });
  it.each(good.map((src, i) => [i, src] as const))("accepts spelling #%i (zod in every static form; imports only in comments and strings; locals named like globals)", async (i, src) => {
    expect(await neutralityViolations({ text: src }, ALLOWED), src).toEqual([]);
    expect(goodTypes[`good-${i}`], src).toBeUndefined();
  });

  it("reports the edge kinds and specifiers the bundler saw", async () => {
    const r = await bundleNeutral({ text: 'import a from "zod"; export { a }; export const q = () => import("zod");' }, ALLOWED);
    expect(r.errors).toEqual([]);
    expect(bundleViolations(r, ALLOWED).length).toBeGreaterThan(0);
    expect(r.imports.map((i) => `${i.kind}:${i.path}`)).toContain("import-statement:zod");
  });
});

describe("manifest.ts wrappers encode exactly the core's text", () => {
  it("manifestStatementBytes === utf8(manifestStatementText)", () => {
    const stmt = { catalogVersion: "20260101-abcdef0", contractVersion: 0, kid: KID, manifestSha: SHA };
    expect(manifestStatementText(stmt).startsWith(MANIFEST_DOMAIN)).toBe(true);
    expect(manifestStatementBytes(stmt).equals(Buffer.from(manifestStatementText(stmt), "utf8"))).toBe(true);
  });

  it("versionsStatementBytes === utf8(versionsStatementText)", () => {
    const stmt = { kid: KID, versionsSha: SHA };
    expect(versionsStatementText(stmt).startsWith(VERSIONS_DOMAIN)).toBe(true);
    expect(versionsStatementBytes(stmt).equals(Buffer.from(versionsStatementText(stmt), "utf8"))).toBe(true);
  });

  it("strictParseAndValidate(Buffer) agrees with strictParseAndValidateText(string)", () => {
    const text = '{"a": 1, "a": 2}';
    const viaBuffer = strictParseAndValidate(Buffer.from(text), CatalogManifestSchema, "x");
    const viaText = strictParseAndValidateText(text, CatalogManifestSchema, "x");
    expect(viaBuffer).toEqual(viaText);
    expect(viaText.ok).toBe(false);
  });
});
