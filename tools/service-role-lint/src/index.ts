// tools/service-role-lint/src/index.ts
// Directory-walking entry point: lints every .ts/.tsx/.js/.jsx/.mts/.cts/
// .mjs/.cjs file under supabase/functions/** (build plan §4.7.1a; the
// extension list widened per B5, gate round 2 — Deno/Node ESM code
// commonly ships as .mts/.mjs, and a bypass file just needs an extension
// the walker skips).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { lintSource, type LintResult } from "./lint.js";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs"]);

// ⛔ FIX (M3, post-P3a gate): "Stop excluding dist and __fixtures__ under
// supabase/functions except the lint's own fixtures dir, matched
// exactly." The old EXCLUDED_DIRS matched by BASENAME anywhere in the
// tree — a directory literally named `dist` or `__fixtures__` ANYWHERE
// under supabase/functions (not just the lint's own top-level one) was
// silently skipped, a real bypass: privileged code hidden in
// `supabase/functions/some-fn/dist/` (a plausible real build-output
// path, not even an attack) or `supabase/functions/some-fn/__fixtures__/`
// was never linted at all. Only `node_modules` (legitimate: vendored
// third-party code, never product code) is still excluded by basename.
// The lint's OWN fixtures directory is excluded by its EXACT resolved
// path — `<functionsRoot>/__fixtures__` — not by name, so a
// differently-located `__fixtures__` is linted like anything else.
const EXCLUDED_BASENAMES = new Set(["node_modules"]);

function listFiles(root: string): string[] {
  const out: string[] = [];
  const ownFixturesDir = resolve(root, "__fixtures__");
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (EXCLUDED_BASENAMES.has(entry)) continue;
        if (resolve(full) === ownFixturesDir) continue;
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
