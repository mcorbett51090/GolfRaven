// supabase/tests/unit/import-closure.ts
//
// A small, dependency-free RUNTIME import-graph walker for the structural tests (rewards-isolation.test.ts). It exists because checking only the
// DIRECT imports of a file proves nothing about what the file's imports import: an allow-listed verification-only module that later gains an
// `import "./devicecheck-client.ts"` would reach the persistent-bit adapter with every direct-import assertion still green.
//
// WHAT COUNTS AS A RUNTIME EDGE (conservative: when unsure, it is an edge, because a false edge makes a test stricter and a missed one makes it blind):
//   - `import x from "..."`, `import { a } from "..."`, `import * as ns from "..."`, `import "..."` (side effect)
//   - `export { a } from "..."`, `export * from "..."`
//   - `import { type A } from "..."` (only inline `type` specifiers) COUNTS: under `verbatimModuleSyntax` it is preserved as a side-effect import
//   - a dynamic `import("...")` with a string-literal argument; a dynamic import with a NON-literal argument is reported (`dynamicNonLiteral`), because
//     it can reach anything and cannot be resolved here.
//   NOT an edge: `import type ...` and `export type ... from ...` (erased at compile time), anything inside a comment or a string literal.
//
// Only RELATIVE specifiers are followed (`./`, `../`). Bare specifiers (`postgres`, `std/http/server`), `https:`, `npm:`, `jsr:` are recorded as
// `external` and not entered. A relative specifier that does not resolve to a file is reported (`unresolved`), never silently skipped.

import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

/** Removes comments, and blanks the CONTENT of string/template literals' comment-like text correctly: `"https://x"` is a string, not a comment. */
export function stripComments(text: string): string {
  let out = "";
  let i = 0;
  const n = text.length;
  while (i < n) {
    const c = text[i]!;
    const d = text[i + 1];
    if (c === "/" && d === "/") {
      while (i < n && text[i] !== "\n") i++;
    } else if (c === "/" && d === "*") {
      i += 2;
      while (i < n && !(text[i] === "*" && text[i + 1] === "/")) {
        if (text[i] === "\n") out += "\n"; // keep line numbers honest
        i++;
      }
      i += 2;
    } else if (c === '"' || c === "'" || c === "`") {
      const quote = c;
      out += c;
      i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === "\\" && i + 1 < n) {
          out += text[i]! + text[i + 1]!;
          i += 2;
          continue;
        }
        out += text[i]!;
        i++;
      }
      out += quote;
      i++;
    } else {
      out += c;
      i++;
    }
  }
  return out;
}

export interface ImportScan {
  /** Runtime specifiers, in source order. */
  runtime: string[];
  /** Type-only specifiers (not edges). */
  typeOnly: string[];
  /** `import(<something that is not a string literal>)`: unresolvable, and a hole in any reachability claim. */
  dynamicNonLiteral: number;
}

export function scanImports(source: string): ImportScan {
  const text = stripComments(source);
  const runtime: string[] = [];
  const typeOnly: string[] = [];

  // `import ... from "x"` / `export ... from "x"`. The clause is made only of identifiers, braces, commas, `*` and whitespace (an import/export clause
  // never contains `=`, `:`, `(` or `;`), so the match cannot run on from an unrelated `export interface ... {` into a later statement's `from`.
  const fromRe = /(?:^|[;}\n])\s*(import|export)\s+(type\s+)?([\w$\s{},*]*?)\bfrom\s*(["'])([^"'\n]+)\4/g;
  for (const m of text.matchAll(fromRe)) {
    // `export type Foo = ...` never has `from`; `import type` / `export type {..} from` are erased.
    // (`type` as an imported NAME, `import type from "x"`, is a default import named `type`: its clause is empty after `type`, so it falls to runtime below.)
    const isTypeStatement = m[2] !== undefined && m[3]!.trim() !== "";
    (isTypeStatement ? typeOnly : runtime).push(m[5]!);
  }
  // Side-effect import: `import "x"`.
  for (const m of text.matchAll(/(?:^|[;}\n])\s*import\s*(["'])([^"'\n]+)\1/g)) runtime.push(m[2]!);
  // Dynamic imports. A literal argument is a plain quoted string or a backtick string WITHOUT interpolation; anything else cannot be resolved here.
  const literalDynamic = [...text.matchAll(/\bimport\s*\(\s*(?:(["'])([^"'\n]+)\1|`([^`$\n]+)`)\s*\)/g)];
  for (const m of literalDynamic) runtime.push((m[2] ?? m[3])!);
  const allDynamic = [...text.matchAll(/\bimport\s*\(/g)].length;
  return { runtime, typeOnly, dynamicNonLiteral: allDynamic - literalDynamic.length };
}

export interface ClosureResult {
  /** Every file reachable at runtime from the roots (roots included), as absolute paths. */
  files: Set<string>;
  /** file -> the file that first imported it (undefined for a root): for printing a chain when something forbidden is reached. */
  parent: Map<string, string | undefined>;
  external: Map<string, Set<string>>;
  unresolved: Array<{ from: string; specifier: string }>;
  dynamicNonLiteral: string[];
}

function resolveRelative(from: string, specifier: string): string | null {
  const base = resolve(dirname(from), specifier);
  if (existsSync(base) && !base.endsWith("/")) return base;
  // A `.js` specifier whose source is `.ts` (the tests import through vite; the functions themselves write `.ts`).
  if (base.endsWith(".js") && existsSync(base.slice(0, -3) + ".ts")) return base.slice(0, -3) + ".ts";
  return null;
}

/** The runtime import closure of `roots`. */
export function runtimeClosure(roots: string[]): ClosureResult {
  const files = new Set<string>();
  const parent = new Map<string, string | undefined>();
  const external = new Map<string, Set<string>>();
  const unresolved: ClosureResult["unresolved"] = [];
  const dynamicNonLiteral: string[] = [];
  const queue: string[] = [];
  for (const r of roots) {
    if (!files.has(r)) {
      files.add(r);
      parent.set(r, undefined);
      queue.push(r);
    }
  }
  while (queue.length > 0) {
    const file = queue.shift()!;
    const scan = scanImports(readFileSync(file, "utf8"));
    if (scan.dynamicNonLiteral > 0) dynamicNonLiteral.push(file);
    for (const spec of scan.runtime) {
      if (!spec.startsWith("./") && !spec.startsWith("../")) {
        if (!external.has(spec)) external.set(spec, new Set());
        external.get(spec)!.add(file);
        continue;
      }
      const target = resolveRelative(file, spec);
      if (target === null) {
        unresolved.push({ from: file, specifier: spec });
        continue;
      }
      if (!files.has(target)) {
        files.add(target);
        parent.set(target, file);
        queue.push(target);
      }
    }
  }
  return { files, parent, external, unresolved, dynamicNonLiteral };
}

/** `root -> ... -> file`, as a list of paths made relative by `rel`, for a failure message. */
export function chainTo(closure: ClosureResult, file: string, rel: (p: string) => string): string {
  const chain: string[] = [];
  for (let f: string | undefined = file; f !== undefined; f = closure.parent.get(f)) chain.unshift(rel(f));
  return chain.join(" -> ");
}
