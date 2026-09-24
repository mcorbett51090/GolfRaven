// tools/service-role-lint/src/index.ts
// Directory-walking entry point: lints every .ts/.tsx/.js/.jsx/.mts/.cts/
// .mjs/.cjs file under supabase/functions/** (build plan §4.7.1a; the
// extension list widened per B5, gate round 2 — Deno/Node ESM code
// commonly ships as .mts/.mjs, and a bypass file just needs an extension
// the walker skips).

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { buildConfigIndex } from "./config.js";
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

// ⛔ FIX (M2 BLOCKING, post-P3a re-gate): "a pinned allow-list of ...
// exact target strings, kept as a committed fixture file compared by the
// lint, so adding a dependency is a reviewed diff." Read once, relative
// to this PACKAGE's own root (not the linted supabase/functions root, and
// not baked into the compiled dist/ output) so it works identically
// whether this runs from src/ (vitest/ts-node) or dist/ (the built CLI) —
// both sit exactly one directory below the package root.
const PINNED_IMPORT_TARGETS_PATH = resolve(import.meta.dirname, "..", "pinned-import-targets.json");

function loadPinnedImportTargets(): string[] {
  try {
    const parsed: unknown = JSON.parse(readFileSync(PINNED_IMPORT_TARGETS_PATH, "utf8"));
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === "string") : [];
  } catch {
    // Missing/malformed file fails CLOSED — an empty allow-list, not an
    // unchecked one; every bare specifier then fails to resolve, which is
    // the safe direction for this list to fail in.
    return [];
  }
}

// ⛔ REWRITE (M2 BLOCKING, post-P3a re-gate): the old root+local
// two-level merge is GONE, replaced entirely by tools/service-role-lint/
// src/config.ts's directory-walking ConfigIndex — see that module's own
// header comment for the four confirmed bypasses (n1-n4) this closes.
export function lintDirectory(functionsRoot: string): LintResult[] {
  const root = resolve(functionsRoot);
  const pinnedImportTargets = new Set(loadPinnedImportTargets());
  const configIndex = buildConfigIndex(root, pinnedImportTargets);
  const results: LintResult[] = [...configIndex.results];
  for (const file of listFiles(root)) {
    const source = readFileSync(file, "utf8");
    const relPath = relative(root, file);
    const importMap = configIndex.resolveFor(file);
    const findings = lintSource(source, file, { importMap, functionsRoot: root, pinnedImportTargets: [...pinnedImportTargets] });
    if (findings.length > 0) {
      results.push({ filePath: relPath, findings });
    }
  }
  return results;
}

export { buildConfigIndex } from "./config.js";
export { lintSource } from "./lint.js";
export type { Finding, LintOptions, LintResult, RuleId } from "./lint.js";
