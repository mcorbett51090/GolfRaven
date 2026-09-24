// tools/service-role-lint/src/index.ts
// Directory-walking entry point: lints every .ts/.tsx/.js/.jsx/.mts/.cts/
// .mjs/.cjs file under supabase/functions/** (build plan §4.7.1a; the
// extension list widened per B5, gate round 2 — Deno/Node ESM code
// commonly ships as .mts/.mjs, and a bypass file just needs an extension
// the walker skips).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { lintSource, type LintResult } from "./lint.js";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]);

// B2/nit (gate round 2): `__fixtures__` holds deliberately-bad lint
// fixtures (supabase/functions/__fixtures__/bad/*.ts) that MUST fail
// `lintSource` when targeted directly (see the vitest suite) — but a
// directory-wide CI run over `supabase/functions` must not itself fail
// forever because of them. Excluded from the general walk the same way
// `node_modules`/`dist` are; `lintSource` on an individual fixture file
// is unaffected (tests call it directly, bypassing this walker).
const EXCLUDED_DIRS = new Set(["node_modules", "dist", "__fixtures__"]);

function listFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry)) continue;
        walk(full);
      } else if (SOURCE_EXTENSIONS.has(entry.slice(entry.lastIndexOf(".")))) {
        out.push(full);
      }
    }
  };
  walk(root);
  return out;
}

export function lintDirectory(functionsRoot: string): LintResult[] {
  const results: LintResult[] = [];
  for (const file of listFiles(functionsRoot)) {
    const source = readFileSync(file, "utf8");
    const relPath = relative(functionsRoot, file);
    const findings = lintSource(source, file);
    if (findings.length > 0) {
      results.push({ filePath: relPath, findings });
    }
  }
  return results;
}

export { lintSource } from "./lint.js";
export type { Finding, LintResult, RuleId } from "./lint.js";
