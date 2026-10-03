// supabase/tests/unit/import-closure.test.ts
//
// The walker rewards-isolation.test.ts relies on (import-closure.ts), tested on synthetic graphs: a structural test that cannot see a transitive
// import is worse than none, so what the walker counts, ignores and refuses to guess at is pinned here.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { chainTo, runtimeClosure, scanImports, stripComments } from "./import-closure.js";

const root = mkdtempSync(join(tmpdir(), "import-closure-"));
afterAll(() => rmSync(root, { recursive: true, force: true }));

function graph(files: Record<string, string>): (name: string) => string {
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, name)), { recursive: true });
    writeFileSync(join(root, name), text);
  }
  return (name) => join(root, name);
}
const names = (r: ReturnType<typeof runtimeClosure>) => [...r.files].map((f) => f.slice(root.length + 1)).sort();

describe("scanImports: what is a runtime edge", () => {
  it("counts value imports, namespace imports, default imports, side-effect imports and re-exports", () => {
    const s = scanImports(`
import a from "./a.ts";
import { b, c as d } from "./b.ts";
import * as ns from "./c.ts";
import "./side.ts";
export { e } from "./e.ts";
export * from "./f.ts";
export * as g from "./g.ts";
`);
    expect(s.runtime).toEqual(["./a.ts", "./b.ts", "./c.ts", "./e.ts", "./f.ts", "./g.ts", "./side.ts"].sort((x, y) => s.runtime.indexOf(x) - s.runtime.indexOf(y)));
    expect(new Set(s.runtime)).toEqual(new Set(["./a.ts", "./b.ts", "./c.ts", "./side.ts", "./e.ts", "./f.ts", "./g.ts"]));
    expect(s.typeOnly).toEqual([]);
  });

  it("ignores `import type` and `export type ... from`, including multi-line ones", () => {
    const s = scanImports(`
import type { A } from "./types-a.ts";
import type {
  B,
  C,
} from "./types-b.ts";
export type { D } from "./types-d.ts";
import type Def from "./types-def.ts";
`);
    expect(s.runtime).toEqual([]);
    expect(new Set(s.typeOnly)).toEqual(new Set(["./types-a.ts", "./types-b.ts", "./types-d.ts", "./types-def.ts"]));
  });

  it("COUNTS `import { type A } from` (inline type specifiers only): under verbatimModuleSyntax it survives as a side-effect import", () => {
    expect(scanImports(`import { type A, type B } from "./inline.ts";`).runtime).toEqual(["./inline.ts"]);
    expect(scanImports(`import { x, type B } from "./mixed.ts";`).runtime).toEqual(["./mixed.ts"]);
  });

  it("counts a multi-line value import", () => {
    expect(scanImports(`import {\n  a,\n  type B,\n  c,\n} from "./multi.ts";`).runtime).toEqual(["./multi.ts"]);
  });

  it("counts a dynamic import with a literal argument, and REPORTS one it cannot read", () => {
    const s = scanImports(`const m = await import("./lazy.ts"); const n = await import(name); const o = import(\`./x/\${y}.ts\`);`);
    expect(s.runtime).toEqual(["./lazy.ts"]);
    expect(s.dynamicNonLiteral).toBe(2);
  });

  it("ignores an import that sits inside a comment or a string literal, and does not mistake `https://` for a comment", () => {
    const s = scanImports(`
// import "./line-comment.ts";
/* import { x } from "./block-comment.ts";
   import "./block-comment-2.ts"; */
const s = 'import "./in-string.ts"';
const t = \`import x from "./in-template.ts"\`;
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";
import real from "./real.ts"; // trailing import "./trailing.ts"
`);
    expect(new Set(s.runtime)).toEqual(new Set(["https://esm.sh/@supabase/supabase-js@2.45.4", "./real.ts"]));
  });

  it("does not run an `export interface ... {` clause on into a later statement's `from`", () => {
    const s = scanImports(`export type Foo = { a: string }\nexport interface Bar {\n a: string\n}\nimport type { T } from "./t.ts"\nimport { v } from "./v.ts"\n`);
    expect(s.runtime).toEqual(["./v.ts"]);
    expect(s.typeOnly).toEqual(["./t.ts"]);
  });

  it("stripComments keeps string contents and line structure", () => {
    expect(stripComments('a // c\n"x // y" /* z\n */ b')).toBe('a \n"x // y" \n b');
  });
});

describe("runtimeClosure: transitive, runtime-only", () => {
  it("follows imports through intermediate modules (the case a direct-import check cannot see) and prints the chain", () => {
    const p = graph({
      "t1/entry.ts": `import { ok } from "./allowed.ts";`,
      "t1/allowed.ts": `import { helper } from "./helper.ts";`,
      "t1/helper.ts": `import { bit } from "../t1b/devicecheck-client.ts";`,
      "t1b/devicecheck-client.ts": `export const bit = 1;`,
    });
    const r = runtimeClosure([p("t1/entry.ts")]);
    expect(names(r)).toEqual(["t1/allowed.ts", "t1/entry.ts", "t1/helper.ts", "t1b/devicecheck-client.ts"]);
    expect(chainTo(r, p("t1b/devicecheck-client.ts"), (f) => f.slice(root.length + 1))).toBe("t1/entry.ts -> t1/allowed.ts -> t1/helper.ts -> t1b/devicecheck-client.ts");
  });

  it("does NOT follow `import type` (the only path to the forbidden module is a type import)", () => {
    const p = graph({
      "t2/entry.ts": `import type { Cfg } from "./cfg.ts";\nimport { x } from "./real.ts";`,
      "t2/cfg.ts": `import { bit } from "../t2b/production-ports.ts";`,
      "t2/real.ts": `export const x = 1;`,
      "t2b/production-ports.ts": `export const bit = 1;`,
    });
    expect(names(runtimeClosure([p("t2/entry.ts")]))).toEqual(["t2/entry.ts", "t2/real.ts"]);
  });

  it("terminates on a cycle, records external specifiers without entering them, and reports an unresolved relative import", () => {
    const p = graph({
      "t3/a.ts": `import { b } from "./b.ts";\nimport postgres from "postgres";\nimport { gone } from "./missing.ts";`,
      "t3/b.ts": `import { a } from "./a.ts";`,
    });
    const r = runtimeClosure([p("t3/a.ts")]);
    expect(names(r)).toEqual(["t3/a.ts", "t3/b.ts"]);
    expect([...r.external.keys()]).toEqual(["postgres"]);
    expect(r.unresolved.map((u) => u.specifier)).toEqual(["./missing.ts"]);
  });

  it("maps a `.js` specifier to its `.ts` source, and reports a dynamic import it cannot read against the file that has it", () => {
    const p = graph({
      "t4/a.ts": `import "./b.js";\nconst x = await import(someVariable);`,
      "t4/b.ts": `export const b = 1;`,
    });
    const r = runtimeClosure([p("t4/a.ts")]);
    expect(names(r)).toEqual(["t4/a.ts", "t4/b.ts"]);
    expect(r.dynamicNonLiteral.map((f) => f.slice(root.length + 1))).toEqual(["t4/a.ts"]);
  });
});
