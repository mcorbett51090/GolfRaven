/**
 * `manifest-core.ts` is shared with the mobile app (apps/mobile), which is
 * bundled by Metro and runs on Hermes: it must import nothing but `zod` and
 * stay free of Node globals (`Buffer`, `process`, `require`). This is the guard for that contract, plus a
 * check that the Node-side wrappers in `manifest.ts` encode exactly the
 * strings the core produces (so the split cannot drift the signed bytes).
 */
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ALLOWED_CONSTRUCTOR_LITERALS, CATALOG_ROOT, bundleNeutral, bundleViolations, neutralityViolations, typeViolations, type BundleReport } from "./neutrality.js";
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
    // LOW-1 (PR #29 gate): string-as-code that never names eval / Function — it reaches Function through a `constructor` property.
    ["(() => {}).constructor(\"…\")()", 'export const g = (() => {}).constructor("return this")();\n', "bundle"],
    ["[].constructor.constructor(\"…\")()", 'export const g = [].constructor.constructor("return this")();\n', "bundle"],
    ["the AsyncFunction constructor via Object.getPrototypeOf", 'export const g = Object.getPrototypeOf(async function () {}).constructor("return this")();\n', "bundle"],
    ["the GeneratorFunction constructor via Object.getPrototypeOf", 'export const g = Object.getPrototypeOf(function* () {}).constructor("return this")();\n', "bundle"],
    ['a quoted key: fn["constructor"](…)', 'export const g = (() => {})["constructor"]("return this")();\n', "bundle"],
    ['a key the bundler folds: fn["construct" + "or"](…)', 'export const g = (() => {})["construct" + "or"]("return this")();\n', "bundle"],
    ["an optional call: fn?.constructor?.(…)", 'export const g = (() => {})?.constructor?.("return this")();\n', "bundle"],
    ["new (x.constructor.constructor)(…)", 'export const g = new ([].constructor.constructor)("return this")();\n', "bundle"],
    ["a tagged template on a constructor", "export const g = [].constructor.constructor`return this`();\n", "bundle"],
    // LOW-1 (PR #30 gate): the constructor passed as a VALUE (each of these had 0 violations under the call-shape rule).
    ["a comma-expression callee: (0, fn.constructor)(…)", 'declare const fn: any;\nexport const g = (0, fn.constructor)("return this")();\n', "bundle"],
    ["a ternary callee", 'declare const fn: any, c: boolean;\nexport const g = (c ? fn.constructor : fn.constructor)("return this")();\n', "bundle"],
    ["an || callee", 'declare const fn: any;\nexport const g = (fn.constructor || fn.constructor)("return this")();\n', "bundle"],
    ["an array element called by index: [fn.constructor][0](…)", 'declare const fn: any;\nexport const g = [fn.constructor][0]("return this")();\n', "bundle"],
    ["an object property called: ({ f: fn.constructor }).f(…)", 'declare const fn: any;\nexport const g = ({ f: fn.constructor }).f("return this")();\n', "bundle"],
    ["a default parameter: (F = fn.constructor) => F(…)", 'declare const fn: any;\nexport const g = (F = fn.constructor) => F("return this")();\n', "bundle"],
    ["an awaited callee: (await fn.constructor)(…)", 'declare const fn: any;\nexport const g = async () => (await fn.constructor)("return this")();\n', "bundle"],
    ["a plain alias: const F = fn.constructor; F(…)", 'declare const fn: any;\nconst F = fn.constructor;\nexport const g = F("return this")();\n', "bundle"],
    ["class X extends fn.constructor {}", "declare const fn: any;\nexport class X extends fn.constructor {}\n", "bundle"],
    ["getOwnPropertyDescriptor(proto, \"constructor\").value(…)", 'declare const proto: any;\nexport const g = Object.getOwnPropertyDescriptor(proto, "constructor").value("return this")();\n', "bundle"],
    // The previously DOCUMENTED residuals, now closed.
    ["a destructured constructor: const { constructor: F } = fn", 'declare const fn: any;\nexport const { constructor: F } = fn;\n', "bundle"],
    ["a destructured quoted key: const { \"constructor\": F } = fn", 'declare const fn: any;\nexport const { "constructor": F } = fn;\n', "bundle"],
    ["a destructured computed key: const { [\"constructor\"]: F } = fn", 'declare const fn: any;\nexport const { ["constructor"]: F } = fn;\n', "bundle"],
    ["a destructured shorthand: const { constructor } = fn", 'declare const fn: any;\nexport const { constructor } = fn;\n', "bundle"],
    ["a destructured shorthand with a default, after another key", 'declare const fn: any;\nexport const { a, constructor = 1 } = fn;\n', "bundle"],
    ["a destructured default parameter pattern: ({ constructor: F } = fn) => F(…)", 'declare const fn: any;\nexport const g = ({ constructor: F }: any = fn) => F("return this")();\n', "bundle"],
    ["Reflect.apply with a constructor value", 'declare const fn: any;\nexport const g = Reflect.apply(fn.constructor, null, ["return this"]);\n', "bundle"],
    ["Reflect.get(x, \"constructor\")", 'declare const fn: any;\nexport const g = Reflect.get(fn, "constructor");\n', "bundle"],
    ["Reflect.get(x, `constructor`) with a template literal key", "declare const fn: any;\nexport const g = Reflect.get(fn, `constructor`);\n", "bundle"],
    ["a variable key the bundler can see: const k = \"constructor\"; fn[k]", 'declare const fn: any;\nconst k = "constructor";\nexport const g = fn[k];\n', "bundle"],
    ["a key assembled from literals the bundler folds: Reflect.get(x, \"constr\" + \"uctor\")", 'declare const fn: any;\nexport const g = Reflect.get(fn, "constr" + "uctor");\n', "bundle"],
    ["a unicode-escaped key: Reflect.get(x, \"\\u0063onstructor\")", 'declare const fn: any;\nexport const g = Reflect.get(fn, "\\u0063onstructor");\n', "bundle"],
    ["a unicode-escaped member: fn.\\u0063onstructor", "declare const fn: any;\nexport const g = fn.\\u0063onstructor;\n", "bundle"],
    ["a member access split over lines", 'declare const fn: any;\nexport const g = fn\n  .constructor\n  ("return this")();\n', "bundle"],
    ["an optional-chain value: fn?.constructor", "declare const fn: any;\nexport const g = fn?.constructor;\n", "bundle"],
    ["the constructor read alone, uncalled", "declare const fn: any;\nexport const g = fn.constructor;\n", "bundle"],
    // The runtime route to the same non-enumerable key, with no `constructor` text at all.
    ["Object.getOwnPropertyNames on a prototype", "declare const fn: any;\nexport const g = Object.getOwnPropertyNames(Object.getPrototypeOf(fn));\n", "bundle"],
    ["Object.getOwnPropertyDescriptors on a prototype", "declare const fn: any;\nexport const g = Object.getOwnPropertyDescriptors(Object.getPrototypeOf(fn));\n", "bundle"],
    ["Reflect.ownKeys on a prototype", "declare const fn: any;\nexport const g = Reflect.ownKeys(Object.getPrototypeOf(fn));\n", "bundle"],
    ["a key-enumerating API reached through a string key: Object[\"getOwnPropertyNames\"]", 'declare const fn: any;\nexport const g = (Object as any)["getOwnPropertyNames"](fn);\n', "bundle"],
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
    // LOW-1: a `constructor` DEFINITION (class / object-literal method), the one blocklist Set, and a mention in a comment are not reads
    "export class A { constructor(readonly x: number) {} }\nexport class B extends A { constructor() { super(1); } }\n",
    "export const o = { constructor() { return 1; }, a: 1 };\nexport const p = { a: 1, constructor() { return 2; } };\n",
    'export const keys = new Set(["__proto__", "constructor", "prototype"]);\n',
    '// fn.constructor("x")\n/* fn["constructor"]("x") Reflect.ownKeys getOwnPropertyNames */\nexport const q = 1;\n',
    // a name that merely STARTS with the word, and the unrelated reflection APIs
    "export const f = (x: { constructors: number; constructor2: number; $constructor: number }): number => x.constructors + x.constructor2 + x.$constructor;\n",
    'export const s = "constructors" + "reconstructor";\nexport const e = (o: object): [string, unknown][] => Object.entries(o);\nexport const k = (o: object): string[] => Object.keys(o);\n',
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

describe("the `constructor` rules (LOW-1) are exact on what they claim, and the residual is pinned", () => {
  // Each rule has fixtures that ONLY it catches (exactly one violation, and the type layer is silent), so deleting
  // any one rule turns exactly its own cases red.
  const MEMBER = /^a \.constructor member access/;
  const STRING = /^a "constructor" string literal/;
  const KEY = /^an unquoted constructor object-pattern \/ shorthand key/;
  const ENUM = /^a key-enumerating reflection API/;
  const byRule: [string, RegExp, string[]][] = [
    [
      "member access",
      MEMBER,
      [
        'export const g = (() => {}).constructor("return this")();\n',
        'export const g = [].constructor.constructor("return this")();\n',
        'export const g = Object.getPrototypeOf(async function () {}).constructor("return this")();\n',
        'declare const fn: any;\nexport const g = (0, fn.constructor)("return this")();\n',
        "declare const fn: any;\nexport const g = [fn.constructor][0](\"return this\")();\n",
        "declare const fn: any;\nexport class X extends fn.constructor {}\n",
        "declare const fn: any;\nexport const g = fn.constructor;\n",
        "declare const fn: any;\nexport const g = fn?.constructor;\n",
        "declare const x: any;\nexport const t = x`a`.constructor`b`;\n",
        "export const n = (x: object): string => x.constructor.name;\n", // refused by design (the real code needs neither of these two)
        "export const isPlain = (x: object): boolean => x.constructor === Object;\n",
      ],
    ],
    [
      "string literal",
      STRING,
      [
        'declare const fn: any;\nexport const g = Reflect.get(fn, "constructor");\n',
        "declare const fn: any;\nexport const g = Reflect.get(fn, `constructor`);\n",
        'declare const proto: any;\nexport const g = Object.getOwnPropertyDescriptor(proto, "constructor")!.value;\n',
        'declare const fn: any;\nexport const g = fn["constructor"];\n',
        'declare const fn: any;\nconst k = "constructor";\nexport const g = fn[k];\n',
        'declare const fn: any;\nexport const g = Reflect.get(fn, "constr" + "uctor");\n',
        'declare const fn: any;\nexport const { "constructor": F } = fn;\n',
        'declare const fn: any;\nexport const { ["constructor"]: F } = fn;\n',
        // the blocklist Set is the ONE allowance — the same word in a Set of anything else, or with one more element, is refused
        'export const keys = new Set(["constructor"]);\n',
        'export const keys = new Set(["__proto__", "constructor", "prototype", "toString"]);\n',
      ],
    ],
    [
      "unquoted pattern / shorthand key",
      KEY,
      [
        "declare const fn: any;\nexport const { constructor: F } = fn;\n",
        "declare const fn: any;\nexport const { constructor } = fn;\n",
        "declare const fn: any;\nexport const { a, constructor = 1 } = fn;\n",
        "declare const fn: any;\nexport const g = ({ constructor: F }: any = fn) => F;\n",
      ],
    ],
    [
      "key enumeration",
      ENUM,
      [
        "declare const fn: any;\nexport const g = Object.getOwnPropertyNames(Object.getPrototypeOf(fn));\n",
        "declare const fn: any;\nexport const g = Object.getOwnPropertyDescriptors(Object.getPrototypeOf(fn));\n",
        "declare const fn: any;\nexport const g = Reflect.ownKeys(Object.getPrototypeOf(fn));\n",
        'declare const o: any;\nexport const g = o["getOwnPropertyNames"];\n',
      ],
    ],
  ];
  const cases = byRule.flatMap(([rule, re, srcs]) => srcs.map((src) => [rule, re, src] as const));

  it.each(cases)("%s: caught by ONLY that rule (no other bundle rule, no type error)", async (_rule, re, src) => {
    const v = await neutralityViolations({ text: src }, ALLOWED);
    expect(v, src).toHaveLength(1);
    expect(v[0], src).toMatch(re);
    const types = await typeViolations({ x: { text: src } });
    // `declare const fn: any` fixtures are type-clean; the two `object` fixtures too.
    expect(types, src).toEqual({});
  });

  it("the Set allowance is exact and narrow: the one blocklist literal is accepted, and nothing else the allowance names leaks", async () => {
    expect(ALLOWED_CONSTRUCTOR_LITERALS.map((a) => a.text)).toEqual(['new Set(["__proto__", "constructor", "prototype"])']);
    for (const a of ALLOWED_CONSTRUCTOR_LITERALS) expect(a.reason.length, "an allowance must carry a reason").toBeGreaterThan(20);
    expect(await neutralityViolations({ text: 'export const keys = new Set(["__proto__", "constructor", "prototype"]);\n' }, ALLOWED)).toEqual([]);
    // the allowance is the Set literal, not the word: the same word one token away is still refused
    expect(await neutralityViolations({ text: 'export const keys = new Set(["__proto__", "constructor", "prototype"]);\ndeclare const f: any;\nexport const g = Reflect.get(f, "constructor");\n' }, ALLOWED)).toHaveLength(1);
  });

  it("the real manifest-core.ts output has no constructor read (its only `constructor` is the allowed string in a Set), and is clean in full", async () => {
    const r = await bundleNeutral({ file: CORE }, ALLOWED);
    expect(r.output).toContain('"constructor"'); // present, as a string element, so the rules are not passing vacuously
    expect(r.output).toContain('new Set(["__proto__", "constructor", "prototype"])'); // ...and it is exactly the allowed literal
    expect(r.output).not.toMatch(/\.\s*constructor/);
    expect(bundleViolations(r, ALLOWED)).toEqual([]);
  });

  // The honest edge: a key that is not a literal at build time. These are NOT caught by the bundle layer; if one is
  // ever closed this test must be updated (and the residual in neutrality.ts' header with it), which is the point of pinning it.
  const gaps: [string, string][] = [
    ["a key assembled in a template with a substitution (esbuild does not fold it without minify)", 'declare const f: any;\nexport const g = Reflect.get(f, `constr${"uctor"}`);\n'],
    ["a key assembled with .concat", 'declare const f: any;\nexport const g = Reflect.get(f, "constr".concat("uctor"));\n'],
    ["a key assembled with .join", 'declare const f: any;\nexport const g = Reflect.get(f, ["con", "structor"].join(""));\n'],
    ["a key assembled with String.fromCharCode", 'declare const f: any;\nexport const g = Reflect.get(f, String.fromCharCode(99, 111, 110, 115, 116, 114, 117, 99, 116, 111, 114));\n'],
    ["a key that is a parameter (data)", "declare const f: any;\nexport const g = (k: string) => Reflect.get(f, k);\n"],
    ["a key that is a computed member of a parameter", "declare const f: any;\nexport const g = (k: string) => f[k];\n"],
    ["a key read back out of the allowed blocklist Set", 'declare const f: any;\nconst S = new Set(["__proto__", "constructor", "prototype"]);\nexport const g = Reflect.get(f, [...S][1]!);\n'],
  ];
  it.each(gaps)("known gap, documented: %s is not flagged", async (_n, src) => {
    expect(await neutralityViolations({ text: src }, ALLOWED), src).toEqual([]);
  });

  it("string-as-code through a host API (setTimeout(\"…\")) is not a bundle finding either; the TYPE layer rejects it (no DOM / Node lib)", async () => {
    const src = 'export const t = setTimeout("alert(1)", 0);\n';
    expect(await neutralityViolations({ text: src }, ALLOWED)).toEqual([]);
    expect(Object.keys(await typeViolations({ x: { text: src } }))).toEqual(["x"]);
  });
});

/**
 * LOW-2 (PR #29 gate): deleting any one of five rules left every test green, because each fixture that reached a rule
 * was also caught by another one. Each case below is built so ONLY its rule fires — asserted as "exactly one violation,
 * and it is this one, and the type layer is silent" — so removing the rule turns exactly its test red. (Proven by
 * deleting each rule in a scratch copy; see the PR notes.)
 */
describe("every rule in bundleViolations / typeViolations has a fixture only it catches", () => {
  let scratch: string;
  beforeAll(async () => {
    scratch = await mkdtemp(join(tmpdir(), "gr-neutral-rules-"));
    await writeFile(join(scratch, "clean.ts"), "export const x = 1;\n");
  });
  afterAll(() => rm(scratch, { recursive: true, force: true }));

  async function only(src: string, rule: RegExp, opts: { types?: boolean } = {}): Promise<void> {
    const v = await neutralityViolations({ text: src }, ALLOWED);
    expect(v, `exactly one rule must fire for:\n${src}`).toHaveLength(1);
    expect(v[0]).toMatch(rule);
    if (opts.types !== false) expect(await typeViolations({ only: { text: src } }), "and the type layer must be silent").toEqual({});
  }

  it('rule "bundled a module from outside src/": a clean, resolvable module outside src/ (nothing in it trips any other rule)', async () => {
    await only(`import { x } from ${JSON.stringify(join(scratch, "clean"))};\nexport const y = x;\n`, /^bundled a module from outside src\/: .*clean\.ts$/);
  });

  describe('rule "non-static import kinds"', () => {
    it("external, non-JS edge kinds: a CSS `@import` and a `url()` of an allowed name (a JS spelling always co-fires `__require`, so CSS is the isolating real shape)", async () => {
      const a = await bundleNeutral({ text: '@import "zod";\n', loader: "css" }, ALLOWED);
      expect(a.imports).toEqual([{ from: "src/fixture.ts", path: "zod", kind: "import-rule", external: true }]);
      expect(bundleViolations(a, ALLOWED)).toEqual(['import-rule of "zod" (only static imports are allowed)']);
      const b = await bundleNeutral({ text: '.a { background: url("zod"); }\n', loader: "css" }, ALLOWED);
      expect(bundleViolations(b, ALLOWED)).toEqual(['url-token of "zod" (only static imports are allowed)']);
    });

    it("external require-call / dynamic-import edges of an allowed name (report-level: esbuild turns a JS `require` into the sentinel and a dynamic `import()` into `__require`, so no real JS source reaches these alone)", () => {
      for (const kind of ["require-call", "dynamic-import", "require-resolve"]) {
        expect(bundleViolations(synthetic({ imports: [{ from: "src/m.ts", path: "zod", kind, external: true }] }), ALLOWED)).toEqual([`${kind} of "zod" (only static imports are allowed)`]);
      }
    });

    it("INTERNAL edges: a dynamic import() of a module inside src/ is refused on its kind alone (report-level: the real bundle also drags in esbuild's `__esm` helper, which names `getOwnPropertyNames`, so that spelling co-fires the key-enumeration rule)", async () => {
      const src = `export const f = () => import(${JSON.stringify(join(CATALOG_ROOT, "src", "manifest-core"))});\n`;
      expect(await neutralityViolations({ text: src }, ALLOWED)).toContain('dynamic-import of "src/manifest-core.ts" (only static imports are allowed)');
      expect(bundleViolations(synthetic({ inputs: ["src/m.ts", "src/manifest-core.ts"], imports: [{ from: "src/m.ts", path: "src/manifest-core.ts", kind: "dynamic-import", external: false }] }), ALLOWED)).toEqual([
        'dynamic-import of "src/manifest-core.ts" (only static imports are allowed)',
      ]);
    });

    it("a static import of an allowed external stays accepted (the rule keys on the kind, not on externality)", () => {
      expect(bundleViolations(synthetic({ imports: [{ from: "src/m.ts", path: "zod", kind: "import-statement", external: true }] }), ALLOWED)).toEqual([]);
    });
  });

  it('rule "build warnings": a warning-only source (a duplicate `case`) that is otherwise clean and type-correct', async () => {
    await only("export const f = (x: number): number => {\n  switch (x) {\n    case 1:\n      return 1;\n    case 1:\n      return 2;\n  }\n  return 0;\n};\n", /^build warning: This case clause will never be evaluated/);
    // and a comparison with -0, a second independent warning
    await only("export const isZero = (x: number): boolean => x === -0;\n", /^build warning: Comparison with -0/);
  });

  it('rule "__require helper": the helper\'s name in the output, with no import edge, no sentinel and no type error', async () => {
    // A real dynamic import()/require() also trips the dynamic-import / `<runtime>` / sentinel rules, so the isolating
    // spelling declares the helper's name itself. That is the rule's own contract: the TELL is the name in the output.
    await only('declare const __require: (n: string) => unknown;\nexport const r = __require("x");\n', /its __require helper was emitted/);
  });

  it('rule "import of X (only the allowed names)": an external edge to a name that is not allowed', () => {
    expect(bundleViolations(synthetic({ imports: [{ from: "src/m.ts", path: "left-pad", kind: "import-statement", external: true }] }), ALLOWED)).toEqual(['import of "left-pad" (only "zod" is allowed)']);
  });

  it("the type layer: a diagnostic that names no checked file is filed under \"*\" and never dropped", async () => {
    // tsc reports a file it cannot load as `error TS6053: File '…' not found.` — no `path(line,col)` prefix to attribute.
    const gone = join(scratch, "does-not-exist.ts");
    const r = await typeViolations({ gone: { file: gone }, fine: { text: "export const x: number = 1;\n" } });
    expect(Object.keys(r)).toEqual(["*"]); // the loadable fixture is clean; the missing file is NOT attributed to any label...
    expect(r["*"]).toHaveLength(1);
    expect(r["*"]![0]).toMatch(/error TS6053: File '.*does-not-exist\.ts' not found\./); // ...and is not lost either
  });
});

function synthetic(over: Partial<BundleReport>): BundleReport {
  return { errors: [], warnings: [], inputs: ["src/m.ts"], imports: [], output: "", ...over };
}

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
