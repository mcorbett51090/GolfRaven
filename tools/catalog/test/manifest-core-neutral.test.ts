/**
 * `manifest-core.ts` is shared with the mobile app (apps/mobile), which is
 * bundled by Metro and runs on Hermes: it must import nothing but `zod` and
 * stay free of Node globals (`Buffer`, `process`, `require`). This is the guard for that contract, plus a
 * check that the Node-side wrappers in `manifest.ts` encode exactly the
 * strings the core produces (so the split cannot drift the signed bytes).
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { enumerateImports, neutralityViolations } from "./module-imports.js";
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

describe("manifest-core is platform-neutral", () => {
  it("imports nothing but zod, statically, and uses no Node global (enumerated with a real lexer)", async () => {
    const src = await readFile(fileURLToPath(new URL("../src/manifest-core.ts", import.meta.url)), "utf8");
    // The check is not vacuous: it really finds the one import this file has.
    expect(enumerateImports(src)).toEqual([{ kind: "import", specifier: "zod" }]);
    expect(neutralityViolations(src, ["zod"])).toEqual([]);
  });
});

describe("the neutrality check cannot be bypassed", () => {
  const ALLOWED = ["zod"];
  const bad: [string, string][] = [
    ["a builtin without the node: prefix", 'import { createHash } from "crypto";\n'],
    ["a node: import", 'import fs from "node:fs";\n'],
    ["a comment before the import", '/* harmless */ import fs from "node:fs";\n'],
    ["a line comment on the previous line", '// import z from "zod";\nimport fs from "node:fs";\n'],
    ["a bare side-effect import", 'import "node:fs";\n'],
    ["a bare side-effect import of a package", 'import "left-pad";\n'],
    ["a dynamic import()", 'export async function f() { return import("node:fs"); }\n'],
    ["a dynamic import() of an allowed name (dynamic is itself refused)", 'export const z = () => import("zod");\n'],
    ["a dynamic import() with a computed specifier", 'export const f = (n: string) => import(n);\n'],
    ["a dynamic import() with a concatenated specifier", 'export const f = () => import("node:" + "fs");\n'],
    ["a re-export from a builtin", 'export * from "node:fs";\n'],
    ["a named re-export from a builtin", 'export { readFileSync } from "fs";\n'],
    ["a namespace re-export", 'export * as fs from "node:fs";\n'],
    ["a type-only import (still a dependency edge)", 'import type { Buffer as B } from "node:buffer";\n'],
    ["require()", 'const fs = require("fs");\n'],
    ["require() with a computed specifier", "const fs = require(name);\n"],
    ["import x = require()", 'import fs = require("fs");\n'],
    ["an import hidden after a template literal with braces", 'const t = `${ { a: 1 }.a } }`;\nimport fs from "node:fs";\n'],
    ["an import after a regex literal containing quotes", 'const r = /"\'/;\nimport fs from "node:fs";\n'],
    ["the Buffer global", "export const b = Buffer.from('x');\n"],
    ["the process global", "export const e = process.env.X;\n"],
    ["a good import AND a bad one", 'import { z } from "zod";\nimport fs from "node:fs";\n'],
  ];
  it.each(bad)("fails on %s", (_name, src) => {
    expect(neutralityViolations(src, ALLOWED).length).toBeGreaterThan(0);
  });

  it("accepts zod, in every static spelling, and ignores imports that only appear in comments and strings", () => {
    const good = [
      'import { z } from "zod";\n',
      "import { z } from 'zod';\n",
      'import * as z from "zod";\n',
      'import type { ZodType } from "zod";\n',
      'export { z } from "zod";\n',
      'import { z } from "zod";\nexport const x = 1; // import fs from "node:fs"\n',
      '/* import fs from "node:fs"; require("fs"); Buffer process */\nimport { z } from "zod";\n',
      'import { z } from "zod";\nexport const s = \'import fs from "node:fs"\' + `require("fs")${1}`;\n',
      'import { z } from "zod";\nexport const o = { a: 1 }.process; export const m = import.meta;\n',
    ];
    for (const src of good) expect(neutralityViolations(src, ALLOWED), src).toEqual([]);
  });

  it("reports each import kind with the specifier the lexer saw", () => {
    expect(enumerateImports('import a from "x"; import "y"; export * from "z"; const q = import("w"); const r = require("v");')).toEqual([
      { kind: "import", specifier: "x" },
      { kind: "import", specifier: "y" },
      { kind: "export-from", specifier: "z" },
      { kind: "dynamic-import", specifier: "w" },
      { kind: "require", specifier: "v" },
    ]);
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
