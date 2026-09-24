// tools/service-role-lint/src/index.ts
// Directory-walking entry point: lints every .ts/.tsx/.js/.jsx file under
// supabase/functions/** (build plan §4.7.1a).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { lintSource, type LintResult } from "./lint.js";

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx"]);

function listFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      const st = statSync(full);
      if (st.isDirectory()) {
        if (entry === "node_modules" || entry === "dist") continue;
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
